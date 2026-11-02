//! Sandbox control plane: `wss://<tunnel_host>/v1/connect`.
//!
//! The tunnel token is checked before the upgrade so a revoked client gets a
//! plain `401`/`410` it can act on. After the upgrade the WebSocket becomes a
//! byte stream carrying Yamux; the client's first stream is the control stream.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cockpit_tunnel_protocol::{
    mux, read_json_line, write_json_line, ws_bridge, ClientMsg, CloseReason, ServerMsg, PING_INTERVAL,
    PROTOCOL_VERSION, TUNNEL_TOKEN_PREFIX,
};
use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::io::BufReader;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;

use crate::db::TunnelRow;
use crate::ice;
use crate::registry::LiveTunnel;
use crate::state::AppState;
use crate::tokens::{self, now};
use crate::util::{empty, json_response, text_response, Body};

const CONTROL_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_secs(60);
const CTRL_QUEUE: usize = 64;
const TEARDOWN_GRACE: Duration = Duration::from_secs(2);
/// A control message that cannot be written this long ends the session.
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Matches the plan's 512 KiB outer frame cap; the bridge writes far smaller messages.
const MAX_WS_FRAME: usize = 512 * 1024;

pub async fn handle_connect(state: Arc<AppState>, req: Request<Incoming>) -> Response<Body> {
    if !is_websocket_upgrade(&req) {
        return text_response(StatusCode::BAD_REQUEST, "expected a WebSocket upgrade\n");
    }
    let Some(key) = req.headers().get(header::SEC_WEBSOCKET_KEY) else {
        return text_response(StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key\n");
    };
    let accept = derive_accept_key(key.as_bytes());

    let Some(token) = bearer(&req).filter(|t| t.starts_with(TUNNEL_TOKEN_PREFIX)) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid tunnel token");
    };
    let tunnel = match state.db.find_tunnel_by_token_hash(tokens::hash_token(token)).await {
        Ok(Some(t)) => t,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid tunnel token"),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "tunnel token lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal server error");
        }
    };
    if tunnel.is_expired() {
        return error(StatusCode::GONE, "tunnel_expired", "tunnel has expired");
    }

    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let id = tunnel.id.clone();
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) = run_session(state, tunnel, upgraded).await {
                    tracing::info!(tunnel = %id, error = %format!("{e:#}"), "control session ended with error");
                }
            }
            Err(e) => tracing::debug!(tunnel = %id, error = %e, "control upgrade failed"),
        }
    });

    let mut resp = Response::new(empty());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = resp.headers_mut();
    h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    h.insert(header::SEC_WEBSOCKET_ACCEPT, HeaderValue::from_str(&accept).expect("base64 is a valid header value"));
    resp
}

fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let has_token = |name: header::HeaderName, token: &str| {
        req.headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    };
    req.method() == Method::GET
        && has_token(header::CONNECTION, "upgrade")
        && has_token(header::UPGRADE, "websocket")
        && req.headers().get(header::SEC_WEBSOCKET_VERSION).is_some_and(|v| v.as_bytes() == b"13")
}

fn bearer<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    json_response(status, &json!({ "error": { "code": code, "message": message } }))
}

async fn run_session(state: Arc<AppState>, tunnel: TunnelRow, upgraded: Upgraded) -> anyhow::Result<()> {
    let ws_config = WebSocketConfig::default().max_frame_size(Some(MAX_WS_FRAME)).max_message_size(Some(MAX_WS_FRAME));
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(ws_config)).await;
    let (duplex, mut bridge) = ws_bridge::bridge(ws, PING_INTERVAL);

    let mut session = mux::Session::new_server(duplex);
    let control = session.control();

    let first = tokio::time::timeout(CONTROL_STREAM_TIMEOUT, session.next()).await;
    let ctrl_stream = match first {
        Ok(Some(stream)) => stream,
        Ok(None) => {
            bridge.abort();
            return Err(anyhow::anyhow!("connection closed before control stream"));
        }
        Err(_) => {
            bridge.abort();
            return Err(anyhow::anyhow!("no control stream within {CONTROL_STREAM_TIMEOUT:?}"));
        }
    };

    let cancel = CancellationToken::new();

    // The session must be polled for any stream (ours or the edge's) to make
    // progress. Clients never open further streams; drop any that appear.
    let mut driver = {
        let cancel = cancel.clone();
        let tunnel_id = tunnel.id.clone();
        tokio::spawn(async move {
            while let Some(stream) = session.next().await {
                tracing::debug!(tunnel = %tunnel_id, "dropping unexpected inbound stream");
                drop(stream);
            }
            tracing::debug!(tunnel = %tunnel_id, "yamux session ended");
            cancel.cancel();
        })
    };

    let result = control_loop(&state, &tunnel, control.clone(), ctrl_stream, cancel.clone()).await;

    cancel.cancel();
    let mut control = control;
    let _ = tokio::time::timeout(TEARDOWN_GRACE, control.close()).await;
    if tokio::time::timeout(TEARDOWN_GRACE, &mut driver).await.is_err() {
        driver.abort();
    }
    // Dropping the session closed the duplex; the bridge sends a WebSocket close and exits.
    if tokio::time::timeout(TEARDOWN_GRACE, &mut bridge).await.is_err() {
        bridge.abort();
    }
    result
}

/// Hello/Welcome, registration, then the message loop. Returns when the
/// connection ends for any reason; the caller tears down the transport.
async fn control_loop(
    state: &Arc<AppState>,
    tunnel: &TunnelRow,
    control: mux::Control,
    ctrl_stream: mux::Stream,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let (rd, mut wr) = tokio::io::split(ctrl_stream);
    let mut reader = BufReader::new(rd);
    let mut buf = String::new();

    let hello = tokio::time::timeout(HELLO_TIMEOUT, read_json_line::<_, ClientMsg>(&mut reader, &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("no hello within {HELLO_TIMEOUT:?}"))??;
    let requested = match hello {
        Some(ClientMsg::Hello { version, ports }) if version == PROTOCOL_VERSION => ports,
        Some(ClientMsg::Hello { version, .. }) => {
            // No CloseReason fits a version mismatch, and a terminal reason would
            // make the client exit as revoked; reply with an error and hang up.
            let msg = ServerMsg::Reply {
                id: 0,
                ok: false,
                error: Some(format!("unsupported protocol version {version} (server speaks {PROTOCOL_VERSION})")),
                ice: None,
            };
            let _ = write_json_line(&mut wr, &msg).await;
            anyhow::bail!("client protocol version {version} unsupported");
        }
        Some(_) => anyhow::bail!("first control message was not hello"),
        None => anyhow::bail!("control stream closed before hello"),
    };

    let max_ports = usize::from(tunnel.max_ports);
    let mut accepted = BTreeSet::new();
    for port in requested {
        if accepted.len() >= max_ports {
            break;
        }
        if port != 0 {
            accepted.insert(port);
        }
    }
    let accepted_list: Vec<u16> = accepted.iter().copied().collect();

    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<ServerMsg>(CTRL_QUEUE);
    let live = Arc::new(LiveTunnel {
        conn_id: state.registry.next_conn_id(),
        tunnel_id: tunnel.id.clone(),
        control,
        ports: RwLock::new(accepted),
        ctrl_tx: ctrl_tx.clone(),
        cancel: cancel.clone(),
        connected_at: now(),
        streams: Default::default(),
        pool: Default::default(),
    });

    // Writer: the only task that writes to the control stream. A Close is the
    // last message of a session.
    let writer = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                let msg = tokio::select! {
                    biased;
                    msg = ctrl_rx.recv() => match msg {
                        Some(m) => m,
                        None => break,
                    },
                    _ = cancel.cancelled() => break,
                };
                let is_close = matches!(msg, ServerMsg::Close { .. });
                // A client that stops reading must not keep the writer (and so
                // the session teardown) blocked; a Close still gets its chance.
                let written = tokio::select! {
                    r = write_json_line(&mut wr, &msg) => r.is_ok(),
                    _ = cancel.cancelled(), if !is_close => false,
                    _ = tokio::time::sleep(CONTROL_WRITE_TIMEOUT) => false,
                };
                if !written || is_close {
                    break;
                }
            }
            cancel.cancel();
        })
    };

    // Reader: a separate task so a partially received line is never lost to
    // `select!` cancellation in the loop below.
    let (msg_tx, mut msg_rx) = mpsc::channel::<ClientMsg>(CTRL_QUEUE);
    let reader_task = {
        let tunnel_id = tunnel.id.clone();
        tokio::spawn(async move {
            loop {
                match read_json_line::<_, ClientMsg>(&mut reader, &mut buf).await {
                    Ok(Some(msg)) => {
                        if msg_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(tunnel = %tunnel_id, error = %e, "control stream read failed");
                        break;
                    }
                }
            }
        })
    };

    let welcome = ServerMsg::Welcome {
        tunnel_id: tunnel.id.clone(),
        host_template: state.config.host_template(&tunnel.id),
        max_ports: tunnel.max_ports,
        ports: accepted_list.clone(),
        webrtc: state.config.webrtc.enabled,
    };
    let _ = ctrl_tx.send(welcome).await;

    if let Some(old) = state.registry.insert(live.clone()) {
        old.close(CloseReason::Replaced);
    }
    tracing::info!(tunnel = %tunnel.id, conn = live.conn_id, ports = ?accepted_list, "tunnel connected");

    // A DELETE that ran between authentication and insert would have found
    // nothing to close; make sure this connection does not outlive the tunnel.
    match state.db.get_tunnel(tunnel.id.clone()).await {
        Ok(Some(row)) if !row.is_expired() => {}
        Ok(Some(_)) => live.close(CloseReason::Expired),
        Ok(None) => live.close(CloseReason::Deleted),
        Err(e) => tracing::warn!(tunnel = %tunnel.id, error = %format!("{e:#}"), "tunnel recheck failed"),
    }
    touch(state, &tunnel.id).await;

    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                touch(state, &tunnel.id).await;
                // Expiry deletion is the purge job's; here we only hang up.
                // PATCH may have extended the TTL, so re-read the row.
                match state.db.get_tunnel(tunnel.id.clone()).await {
                    Ok(Some(row)) if row.is_expired() => live.close(CloseReason::Expired),
                    Ok(None) => live.close(CloseReason::Deleted),
                    Ok(Some(_)) => {}
                    Err(e) => tracing::warn!(tunnel = %tunnel.id, error = %format!("{e:#}"), "tunnel recheck failed"),
                }
            }
            msg = msg_rx.recv() => {
                let Some(msg) = msg else { break };
                let reply = handle_msg(state, tunnel, &live, msg);
                if let Some(reply) = reply {
                    let sent = tokio::select! {
                        r = ctrl_tx.send(reply) => r.is_ok(),
                        _ = cancel.cancelled() => false,
                    };
                    if !sent {
                        break;
                    }
                }
            }
        }
    }

    state.registry.remove_if(&tunnel.id, live.conn_id);
    cancel.cancel();
    reader_task.abort();
    let mut writer = writer;
    if tokio::time::timeout(TEARDOWN_GRACE, &mut writer).await.is_err() {
        writer.abort();
    }
    tracing::info!(tunnel = %tunnel.id, conn = live.conn_id, "tunnel disconnected");
    Ok(())
}

fn handle_msg(state: &AppState, tunnel: &TunnelRow, live: &LiveTunnel, msg: ClientMsg) -> Option<ServerMsg> {
    match msg {
        ClientMsg::Expose { id, port } => {
            if port == 0 {
                return Some(reply_err(id, "invalid port"));
            }
            let mut ports = live.ports.write().expect("ports lock");
            if !ports.contains(&port) && ports.len() >= usize::from(tunnel.max_ports) {
                return Some(reply_err(id, &format!("max_ports ({}) reached", tunnel.max_ports)));
            }
            ports.insert(port);
            drop(ports);
            tracing::info!(tunnel = %tunnel.id, port, "port exposed");
            Some(reply_ok(id, None))
        }
        ClientMsg::Unexpose { id, port } => {
            let removed = live.ports.write().expect("ports lock").remove(&port);
            if removed {
                live.pool.clear_port(port);
                tracing::info!(tunnel = %tunnel.id, port, "port unexposed");
            }
            Some(reply_ok(id, None))
        }
        ClientMsg::IceRequest { id } => {
            if !state.config.webrtc.enabled {
                return Some(reply_err(id, "webrtc is not enabled on this server"));
            }
            let ice = ice::mint(&state.config, &tunnel.id, ice::SANDBOX_SUBJECT, state.config.webrtc.sandbox_ttl_s);
            Some(reply_ok(id, Some(ice)))
        }
        ClientMsg::Hello { .. } => {
            tracing::debug!(tunnel = %tunnel.id, "ignoring repeated hello");
            None
        }
    }
}

fn reply_ok(id: u64, ice: Option<cockpit_tunnel_protocol::IceConfig>) -> ServerMsg {
    ServerMsg::Reply { id, ok: true, error: None, ice }
}

fn reply_err(id: u64, error: &str) -> ServerMsg {
    ServerMsg::Reply { id, ok: false, error: Some(error.to_string()), ice: None }
}

async fn touch(state: &AppState, tunnel_id: &str) {
    if let Err(e) = state.db.touch_last_seen(tunnel_id.to_string()).await {
        tracing::warn!(tunnel = %tunnel_id, error = %format!("{e:#}"), "touch_last_seen failed");
    }
}
