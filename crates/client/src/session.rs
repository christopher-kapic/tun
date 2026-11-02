//! The tunnel connection: dial, Yamux, control stream, data streams, and the
//! reconnect loop.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use cockpit_tunnel_protocol::{
    decode_preamble, read_json_line, write_json_line, ws_bridge, ClientMsg, CloseReason, ServerMsg,
    CONNECT_PATH, PING_INTERVAL, PROTOCOL_VERSION, STREAM_NOT_EXPOSED, STREAM_OK, STREAM_REFUSED,
};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Error as WsError;
use cockpit_tunnel_protocol::mux::{self, Stream as StreamHandle};
use tracing::{debug, info, warn};

use crate::daemon::{lock_poisoned, Daemon, Link, Pending, Reply, Welcome};
use crate::ipc::ConnState;

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the backoff.
const STABLE_AFTER: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Max frame on the outer socket (plan: control plane, item 7).
const MAX_FRAME: usize = 512 * 1024;
const ICE_CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);
const ICE_RETRY: Duration = Duration::from_secs(30);
const CONTROL_QUEUE: usize = 64;

enum End {
    Lost(String),
    Revoked(String),
    Replaced,
    Shutdown,
    /// Token or server changed; reconnect immediately.
    Superseded,
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Connect forever. Returns only through `Daemon::terminate` (process exit).
pub async fn run(daemon: Arc<Daemon>) {
    let mut failures: u32 = 0;
    loop {
        let (server, token, generation) = daemon.target();
        daemon.set_conn(ConnState::Connecting);
        let mut connected_at: Option<Instant> = None;
        let end = tokio::select! {
            end = connect(&daemon, &server, &token, generation, &mut connected_at) => end,
            _ = daemon.reconnect.notified() => End::Superseded,
        };
        daemon.disconnected(generation);
        match end {
            End::Revoked(why) => daemon.terminate(ConnState::Revoked, &why),
            End::Replaced => daemon.terminate(ConnState::Replaced, "another client connected with this tunnel token"),
            End::Superseded => {
                failures = 0;
                continue;
            }
            End::Shutdown => {
                info!("tunnel server is shutting down; reconnecting");
                daemon.set_last_error("tunnel server restarted".to_string());
            }
            End::Lost(why) => {
                warn!(error = %why, "tunnel connection lost");
                daemon.set_last_error(why);
            }
        }
        if connected_at.is_some_and(|t| t.elapsed() >= STABLE_AFTER) {
            failures = 0;
        }
        let delay = backoff(failures);
        failures = failures.saturating_add(1);
        debug!(delay_ms = delay.as_millis() as u64, "reconnecting after delay");
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = daemon.reconnect.notified() => {
                failures = 0;
            }
        }
    }
}

/// Exponential 1s → 30s with jitter over the upper half, so a fleet of
/// sandboxes does not reconnect in lockstep after a server restart.
fn backoff(failures: u32) -> Duration {
    let base = BACKOFF_MIN.saturating_mul(1u32 << failures.min(5)).min(BACKOFF_MAX);
    let ms = base.as_millis() as u64;
    Duration::from_millis(rand::thread_rng().gen_range(ms / 2..=ms))
}

async fn connect(
    daemon: &Arc<Daemon>,
    server: &str,
    token: &str,
    generation: u64,
    connected_at: &mut Option<Instant>,
) -> End {
    match establish(daemon, server, token, generation, connected_at).await {
        Ok(end) => end,
        Err(e) => End::Lost(format!("{e:#}")),
    }
}

async fn establish(
    daemon: &Arc<Daemon>,
    server: &str,
    token: &str,
    generation: u64,
    connected_at: &mut Option<Instant>,
) -> anyhow::Result<End> {
    let url = format!("{server}{CONNECT_PATH}");
    let mut request = url.as_str().into_client_request().context("invalid tunnel server URL")?;
    let auth = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| anyhow!("tunnel token contains characters not allowed in a header"))?;
    request.headers_mut().insert(AUTHORIZATION, auth);
    // tungstenite never offers permessage-deflate, which the plan requires off.
    let config = WebSocketConfig::default().max_frame_size(Some(MAX_FRAME));

    let dial = tokio_tungstenite::connect_async_with_config(request, Some(config), true);
    let ws = match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Err(_) => bail!("timed out connecting to {server}"),
        Ok(Err(WsError::Http(resp))) if is_terminal(resp.status()) => {
            return Ok(End::Revoked(format!("tunnel server rejected the token ({})", resp.status())));
        }
        Ok(Err(e)) => return Err(anyhow::Error::new(e).context(format!("connecting to {server}"))),
        Ok(Ok((ws, _response))) => ws,
    };

    let (duplex, pump) = ws_bridge::bridge(ws, PING_INTERVAL);
    let _pump = AbortOnDrop(pump);
    let session = mux::Session::new_client(duplex);
    let mut control = session.control();
    let mut driver = AbortOnDrop(tokio::spawn(drive_session(daemon.clone(), session)));

    let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, control.open_stream()).await {
        Err(_) => bail!("timed out opening the control stream"),
        Ok(Err(e)) => bail!("opening the control stream: {e}"),
        Ok(Ok(stream)) => stream,
    };
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);
    let mut buf = String::new();

    let hello = daemon.ports();
    write_json_line(&mut wr, &ClientMsg::Hello { version: PROTOCOL_VERSION, ports: hello.clone() })
        .await
        .context("sending hello")?;
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_json_line::<_, ServerMsg>(&mut rd, &mut buf))
        .await
        .map_err(|_| anyhow!("timed out waiting for welcome"))?
        .context("reading welcome")?;
    let (welcome, webrtc) = match first {
        Some(ServerMsg::Welcome { tunnel_id, host_template, max_ports, ports, webrtc }) => {
            (Welcome { tunnel_id, host_template, max_ports, ports }, webrtc)
        }
        Some(ServerMsg::Close { reason }) => return Ok(close_end(reason)),
        // Not formatted: a stray Reply could carry TURN credentials.
        Some(ServerMsg::Reply { .. }) => bail!("unexpected reply before welcome"),
        None => bail!("tunnel server closed the control stream before welcome"),
    };
    let tunnel_id = welcome.tunnel_id.clone();

    let (ctrl_tx, ctrl_rx) = mpsc::channel(CONTROL_QUEUE);
    let pending = Pending::default();
    let link = Link { ctrl_tx, pending: pending.clone(), webrtc, generation };
    let _writer = AbortOnDrop(tokio::spawn(write_control(wr, ctrl_rx)));
    let Some(missing) = daemon.connected(link.clone(), welcome, &hello) else {
        return Ok(End::Superseded);
    };
    *connected_at = Some(Instant::now());
    info!(tunnel_id = %tunnel_id, ports = ?daemon.ports(), webrtc, "connected");

    let _declare = AbortOnDrop(tokio::spawn(declare_missing(daemon.clone(), link.clone(), missing)));
    let _ice = webrtc.then(|| AbortOnDrop(tokio::spawn(maintain_ice(daemon.clone(), link.clone()))));
    drop(link);

    loop {
        tokio::select! {
            msg = read_json_line::<_, ServerMsg>(&mut rd, &mut buf) => match msg {
                Ok(Some(ServerMsg::Reply { id, ok, error, ice })) => {
                    let tx = lock_poisoned(&pending).remove(&id);
                    if let Some(tx) = tx {
                        let _ = tx.send(Reply { ok, error, ice });
                    }
                }
                Ok(Some(ServerMsg::Close { reason })) => return Ok(close_end(reason)),
                Ok(Some(ServerMsg::Welcome { .. })) => warn!("ignoring duplicate welcome"),
                Ok(None) => return Ok(End::Lost("control stream closed".to_string())),
                Err(e) => return Ok(End::Lost(format!("control stream: {e}"))),
            },
            // Cancelling the read only happens on this exit path, so a
            // partially read line is never lost mid-session.
            _ = &mut driver.0 => return Ok(End::Lost("tunnel session ended".to_string())),
        }
    }
}

fn is_terminal(status: StatusCode) -> bool {
    status == StatusCode::UNAUTHORIZED || status == StatusCode::GONE
}

fn close_end(reason: CloseReason) -> End {
    match reason {
        CloseReason::Deleted => End::Revoked("tunnel was deleted".to_string()),
        CloseReason::Expired => End::Revoked("tunnel expired".to_string()),
        // Another client holds the tunnel now; reconnecting would just fight it.
        CloseReason::Replaced => End::Replaced,
        CloseReason::Shutdown => End::Shutdown,
    }
}

/// Own the Yamux session: polling it drives all streams. Every inbound stream
/// is a server-opened data stream.
async fn drive_session(daemon: Arc<Daemon>, mut session: mux::Session) {
    while let Some(stream) = session.next().await {
        tokio::spawn(handle_data_stream(daemon.clone(), stream));
    }
    debug!("yamux session ended");
}

async fn write_control<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<ClientMsg>) {
    while let Some(msg) = rx.recv().await {
        if let Err(e) = write_json_line(&mut wr, &msg).await {
            debug!(error = %e, "control stream write failed");
            break;
        }
    }
}

/// Declare ports that were exposed while the Hello was in flight.
async fn declare_missing(daemon: Arc<Daemon>, link: Link, missing: Vec<u16>) {
    for port in missing {
        if !daemon.is_exposed(port) {
            continue;
        }
        if let Err(e) = daemon.declare(&link, port).await {
            let msg = format!("exposing port {port}: {e:#}");
            warn!("{msg}");
            daemon.drop_port(port);
            daemon.set_last_error(msg);
        }
    }
}

/// Request ICE on connect, then whenever less than 25% of the TTL remains.
async fn maintain_ice(daemon: Arc<Daemon>, link: Link) {
    let mut force = true;
    loop {
        let wait = if force || daemon.ice_needs_refresh() {
            match daemon.refresh_ice(&link).await {
                Ok(ice) => {
                    info!(expires_at = ice.expires_at, "ICE credentials refreshed");
                    force = false;
                    ICE_CHECK_INTERVAL
                }
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "ICE refresh failed");
                    ICE_RETRY
                }
            }
        } else {
            ICE_CHECK_INTERVAL
        };
        tokio::time::sleep(wait).await;
    }
}

async fn handle_data_stream(daemon: Arc<Daemon>, mut stream: StreamHandle) {
    let mut preamble = [0u8; 2];
    match tokio::time::timeout(PREAMBLE_TIMEOUT, stream.read_exact(&mut preamble)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let port = decode_preamble(preamble);
    if !daemon.is_exposed(port) {
        debug!(port, "stream for a port that is not exposed");
        let _ = stream.write_all(&[STREAM_NOT_EXPOSED]).await;
        let _ = stream.shutdown().await;
        return;
    }
    let Some(mut local) = connect_local(port).await else {
        debug!(port, "local origin refused the connection");
        let _ = stream.write_all(&[STREAM_REFUSED]).await;
        let _ = stream.shutdown().await;
        return;
    };
    if stream.write_all(&[STREAM_OK]).await.is_err() {
        return;
    }
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut local).await {
        debug!(port, error = %e, "stream ended with error");
    }
}

/// Loopback only: a sandbox port is never forwarded to another host. Node ≥17
/// dev servers often bind `localhost` to `::1` only, hence the fallback.
async fn connect_local(port: u16) -> Option<TcpStream> {
    let candidates = [SocketAddr::from((Ipv4Addr::LOCALHOST, port)), SocketAddr::from((Ipv6Addr::LOCALHOST, port))];
    for addr in candidates {
        if let Ok(Ok(tcp)) = tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            let _ = tcp.set_nodelay(true);
            return Some(tcp);
        }
    }
    None
}
