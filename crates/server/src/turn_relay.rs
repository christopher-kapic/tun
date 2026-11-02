//! Built-in STUN/TURN relay (RFC 5766 over UDP, TCP, and TLS), replacing
//! coturn so a rootless install can offer WebRTC.
//!
//! - UDP and TCP on `webrtc.stun_port` (3478); TLS arrives on 443 and is
//!   handed over by the listener after SNI routing (`turn_host`).
//! - Credentials are the TURN REST ones `ice::mint` hands out:
//!   `username = "<expiry>:<tunnel>:<subject>"`, checked for expiry, with
//!   `password = base64(HMAC-SHA1(static_auth_secret, username))`.
//! - Relays are UDP sockets in `relay_min_port..=relay_max_port`, advertised
//!   at the public IPv4. Like the coturn setup before, relays never send to or
//!   accept from non-public addresses or the server's own non-relay ports, so
//!   a credential cannot reach the host, its metadata service, or a private
//!   network. Relay-to-relay traffic (both peers on this server) is delivered
//!   in-process instead of hairpinning through the public address.
//! - Limits: `MAX_ALLOCATIONS` relays in total, each limited to `MAX_BPS`
//!   (both directions together); `MAX_STREAM_CONNS` TCP/TLS connections.
//!
//! Each TCP/TLS connection gets its own `turn` server instance, so its
//! allocations end when the connection does (RFC 5766 §2.1).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::RelayAddressGenerator;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use webrtc_util::Conn;

use crate::config::Config;
use crate::metrics::Metrics;

/// Relays (allocations) open at once, server-wide.
pub const MAX_ALLOCATIONS: usize = 1200;
/// Per-relay bandwidth cap, bits per second, both directions together.
const MAX_BPS: u64 = 3_000_000;
/// TURN-over-TCP/TLS connections open at once.
const MAX_STREAM_CONNS: usize = 1000;
/// A TCP/TLS connection that sends nothing for this long is closed (clients
/// refresh allocations every few minutes).
const STREAM_IDLE: Duration = Duration::from_secs(15 * 60);
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest TURN frame accepted over a stream (STUN or ChannelData).
const MAX_FRAME: usize = 4 + 65_535 + 3;
const BIND_ATTEMPTS: usize = 32;
/// Relay-to-relay packets queued for one relay before dropping.
const HUB_QUEUE: usize = 256;

/// A packet from another relay on this server, with its relay address.
type HubPacket = (Vec<u8>, SocketAddr);

pub struct Relay {
    shared: Arc<Shared>,
    streams: Arc<Semaphore>,
}

struct Shared {
    realm: String,
    secret: String,
    public_ip: Ipv4Addr,
    min_port: u16,
    max_port: u16,
    /// Inboxes of live relays by port, for relay-to-relay delivery.
    hub: Mutex<HashMap<u16, mpsc::Sender<HubPacket>>>,
    allocations: AtomicUsize,
    metrics: Arc<MetricsRef>,
    /// Peers that tests may relay to despite being non-public (loopback).
    allow_private_peers: bool,
}

/// The relay only needs the allocation gauge; keeps `Metrics` borrowing simple.
#[derive(Default)]
pub struct MetricsRef {
    pub allocations: std::sync::atomic::AtomicI64,
}

impl Relay {
    /// Bind UDP and TCP `stun_port` and start serving. TLS connections are
    /// passed in through [`Relay::serve_stream`].
    pub async fn start(cfg: &Config, metrics: &Metrics) -> anyhow::Result<Arc<Self>> {
        let w = &cfg.webrtc;
        let public_ip = cfg.public_ipv4.context("WebRTC needs public_ipv4 in the config")?;
        anyhow::ensure!(!w.static_auth_secret.is_empty(), "webrtc.static_auth_secret is empty");
        anyhow::ensure!(w.relay_min_port <= w.relay_max_port, "relay port range is empty");
        let relay = Arc::new(Self::new(Shared {
            realm: cfg.turn_host.clone(),
            secret: w.static_auth_secret.clone(),
            public_ip,
            min_port: w.relay_min_port,
            max_port: w.relay_max_port,
            hub: Mutex::new(HashMap::new()),
            allocations: AtomicUsize::new(0),
            metrics: metrics.turn.clone(),
            allow_private_peers: false,
        }));
        let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, w.stun_port));
        let udp = UdpSocket::bind(bind).await.with_context(|| format!("binding udp {bind}"))?;
        let tcp = TcpListener::bind(bind).await.with_context(|| format!("binding tcp {bind}"))?;
        relay.serve_udp(udp).await?;
        tokio::spawn(relay.clone().accept_tcp(tcp));
        tracing::info!(port = w.stun_port, relays = %format!("{}-{}", w.relay_min_port, w.relay_max_port), %public_ip, "TURN relay started");
        Ok(relay)
    }

    fn new(shared: Shared) -> Self {
        Self { shared: Arc::new(shared), streams: Arc::new(Semaphore::new(MAX_STREAM_CONNS)) }
    }

    fn server_config(&self, conn: Arc<dyn Conn + Send + Sync>) -> ServerConfig {
        ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayGen { shared: self.shared.clone() }),
            }],
            realm: self.shared.realm.clone(),
            auth_handler: Arc::new(RestAuth { secret: self.shared.secret.clone() }),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        }
    }

    async fn serve_udp(&self, udp: UdpSocket) -> anyhow::Result<()> {
        // Lives for the life of the process (the server's tasks own the socket).
        let server = Server::new(self.server_config(Arc::new(udp))).await.context("starting the TURN server")?;
        std::mem::forget(server);
        Ok(())
    }

    async fn accept_tcp(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((tcp, peer)) => {
                    let _ = tcp.set_nodelay(true);
                    let local = tcp.local_addr().unwrap_or(peer);
                    let relay = self.clone();
                    tokio::spawn(async move { relay.serve_stream(tcp, local, peer).await });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TURN tcp accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Serve TURN on one TCP or (already decrypted) TLS connection until it closes.
    pub async fn serve_stream<S>(&self, stream: S, local: SocketAddr, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let Ok(_permit) = self.streams.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "too many TURN stream connections");
            return;
        };
        let conn = Arc::new(StreamConn::new(stream, local, peer));
        let closed = conn.closed.clone();
        let server = match Server::new(self.server_config(conn)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "TURN stream server failed to start");
                return;
            }
        };
        // The server's read loop closes the conn (and its allocations) when
        // the stream ends or fails.
        closed.cancelled().await;
        let _ = server.close().await;
    }

    #[cfg(test)]
    fn for_test(public_ip: Ipv4Addr, min_port: u16, max_port: u16, secret: &str) -> Self {
        Self::new(Shared {
            realm: "turn.test".into(),
            secret: secret.into(),
            public_ip,
            min_port,
            max_port,
            hub: Mutex::new(HashMap::new()),
            allocations: AtomicUsize::new(0),
            metrics: Arc::new(MetricsRef { allocations: Default::default() }),
            allow_private_peers: true,
        })
    }
}

// ---------------------------------------------------------------- auth

struct RestAuth {
    secret: String,
}

impl AuthHandler for RestAuth {
    fn auth_handle(&self, username: &str, realm: &str, _src: SocketAddr) -> Result<Vec<u8>, turn::Error> {
        let expiry: i64 = username
            .split(':')
            .next()
            .and_then(|e| e.parse().ok())
            .ok_or_else(|| turn::Error::Other("malformed username".into()))?;
        if expiry <= crate::tokens::now() {
            return Err(turn::Error::Other("expired credential".into()));
        }
        let password = crate::ice::credential(&self.secret, username);
        Ok(generate_auth_key(username, realm, &password))
    }
}

// ---------------------------------------------------------------- peers

/// Peers a relay must never talk to (see the module docs).
fn denied_peer(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let private = v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || o[0] == 100 && (o[1] & 0xC0) == 64 // 100.64.0.0/10
                || o[0] == 0;
            (private && !allow_private) || v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() || o[0] >= 240
        }
        // Relays are IPv4 only, so an IPv6 peer is never legitimate.
        IpAddr::V6(_) => true,
    }
}

// ---------------------------------------------------------------- relays

struct RelayGen {
    shared: Arc<Shared>,
}

#[async_trait]
impl RelayAddressGenerator for RelayGen {
    fn validate(&self) -> Result<(), turn::Error> {
        Ok(())
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), turn::Error> {
        let s = &self.shared;
        if !use_ipv4 {
            return Err(turn::Error::Other("only IPv4 relays are offered".into()));
        }
        if s.allocations.fetch_add(1, Ordering::SeqCst) >= MAX_ALLOCATIONS {
            s.allocations.fetch_sub(1, Ordering::SeqCst);
            return Err(turn::Error::Other("relay capacity reached".into()));
        }
        let mut socket = None;
        for attempt in 0..BIND_ATTEMPTS {
            let port = if attempt == 0 && (s.min_port..=s.max_port).contains(&requested_port) {
                requested_port
            } else {
                rand::random::<u16>() % (s.max_port - s.min_port + 1) + s.min_port
            };
            if let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
                socket = Some((sock, port));
                break;
            }
        }
        let Some((sock, port)) = socket else {
            s.allocations.fetch_sub(1, Ordering::SeqCst);
            return Err(turn::Error::Other("no free relay port".into()));
        };
        let (tx, rx) = mpsc::channel(HUB_QUEUE);
        s.hub.lock().unwrap_or_else(|e| e.into_inner()).insert(port, tx);
        s.metrics.allocations.fetch_add(1, Ordering::Relaxed);
        let conn = RelayConn {
            sock,
            port,
            inbox: tokio::sync::Mutex::new(rx),
            shared: s.clone(),
            bucket: Mutex::new(Bucket::new()),
            released: AtomicBool::new(false),
        };
        Ok((Arc::new(conn), SocketAddr::from((s.public_ip, port))))
    }
}

/// Token bucket over bytes; one second of burst.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    const RATE: f64 = MAX_BPS as f64 / 8.0;

    fn new() -> Self {
        Self { tokens: Self::RATE, at: Instant::now() }
    }

    fn take(&mut self, n: usize) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * Self::RATE).min(Self::RATE);
        self.at = now;
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

struct RelayConn {
    sock: UdpSocket,
    port: u16,
    /// Packets from other relays on this server.
    inbox: tokio::sync::Mutex<mpsc::Receiver<HubPacket>>,
    shared: Arc<Shared>,
    bucket: Mutex<Bucket>,
    released: AtomicBool,
}

impl RelayConn {
    fn allow(&self, n: usize) -> bool {
        self.bucket.lock().unwrap_or_else(|e| e.into_inner()).take(n)
    }

    fn is_own_relay(&self, addr: SocketAddr) -> bool {
        addr.ip() == IpAddr::V4(self.shared.public_ip)
            && (self.shared.min_port..=self.shared.max_port).contains(&addr.port())
    }

    fn release(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut hub = self.shared.hub.lock().unwrap_or_else(|e| e.into_inner());
        hub.remove(&self.port);
        drop(hub);
        self.shared.allocations.fetch_sub(1, Ordering::SeqCst);
        self.shared.metrics.allocations.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for RelayConn {
    fn drop(&mut self) {
        self.release();
    }
}

fn unsupported() -> webrtc_util::Error {
    webrtc_util::Error::Other("not supported on a TURN relay".into())
}

#[async_trait]
impl Conn for RelayConn {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Err(unsupported())
    }

    async fn recv(&self, _buf: &mut [u8]) -> webrtc_util::Result<usize> {
        Err(unsupported())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let mut inbox = self.inbox.lock().await;
        loop {
            tokio::select! {
                r = self.sock.recv_from(buf) => {
                    let (n, src) = r?;
                    let own = src.ip() == IpAddr::V4(self.shared.public_ip);
                    if own || denied_peer(src.ip(), self.shared.allow_private_peers) || !self.allow(n) {
                        continue;
                    }
                    return Ok((n, src));
                }
                m = inbox.recv() => {
                    let Some((data, src)) = m else { return Err(webrtc_util::Error::Other("relay closed".into())) };
                    if !self.allow(data.len()) {
                        continue;
                    }
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, src));
                }
            }
        }
    }

    async fn send(&self, _buf: &[u8]) -> webrtc_util::Result<usize> {
        Err(unsupported())
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        // Dropped packets still report success: UDP gives no delivery promise,
        // and an error would tear down the client's allocation.
        if !self.allow(buf.len()) {
            return Ok(buf.len());
        }
        if self.is_own_relay(target) {
            let inbox = self.shared.hub.lock().unwrap_or_else(|e| e.into_inner()).get(&target.port()).cloned();
            if let Some(inbox) = inbox {
                let _ = inbox.try_send((buf.to_vec(), SocketAddr::from((self.shared.public_ip, self.port))));
            }
            return Ok(buf.len());
        }
        if target.ip() == IpAddr::V4(self.shared.public_ip) || denied_peer(target.ip(), self.shared.allow_private_peers)
        {
            return Ok(buf.len());
        }
        Ok(self.sock.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.sock.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.release();
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

// ---------------------------------------------------------------- streams

/// TURN over a byte stream (RFC 5766 §2.1): STUN messages and ChannelData
/// (padded to 4 bytes over streams) framed back to back.
struct StreamConn<S> {
    reader: tokio::sync::Mutex<ReadHalf<S>>,
    writer: tokio::sync::Mutex<WriteHalf<S>>,
    local: SocketAddr,
    peer: SocketAddr,
    closed: CancellationToken,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> StreamConn<S> {
    fn new(stream: S, local: SocketAddr, peer: SocketAddr) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new(r),
            writer: tokio::sync::Mutex::new(w),
            local,
            peer,
            closed: CancellationToken::new(),
        }
    }
}

/// Bytes on the wire for a frame starting with `head`: (payload length to
/// deliver, padding to skip). `None` if it is neither STUN nor ChannelData.
fn frame_len(head: [u8; 4]) -> Option<(usize, usize)> {
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    match head[0] >> 6 {
        // STUN: 20-byte header; the length is already a multiple of 4.
        0b00 => Some((20 + len, 0)),
        // ChannelData: 4-byte header, padded to 4 over streams.
        0b01 => Some((4 + len, (4 - len % 4) % 4)),
        _ => None,
    }
}

fn stream_err(msg: &str) -> webrtc_util::Error {
    webrtc_util::Error::Other(msg.into())
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Conn for StreamConn<S> {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Err(unsupported())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.recv_from(buf).await.map(|(n, _)| n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        loop {
            let read = async {
                let mut head = [0u8; 4];
                reader.read_exact(&mut head).await?;
                let (total, pad) = frame_len(head).ok_or_else(|| stream_err("not a TURN frame"))?;
                if total > MAX_FRAME {
                    return Err(stream_err("frame too large"));
                }
                let mut frame = vec![0u8; total + pad];
                frame[..4].copy_from_slice(&head);
                reader.read_exact(&mut frame[4..]).await?;
                frame.truncate(total);
                Ok::<_, webrtc_util::Error>(frame)
            };
            let frame = match tokio::time::timeout(STREAM_IDLE, read).await {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => {
                    self.closed.cancel();
                    return Err(e);
                }
                Err(_) => {
                    self.closed.cancel();
                    return Err(stream_err("idle"));
                }
            };
            // The server reads into an MTU-sized buffer; bigger frames are skipped.
            if frame.len() > buf.len() {
                continue;
            }
            buf[..frame.len()].copy_from_slice(&frame);
            return Ok((frame.len(), self.peer));
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.send_to(buf, self.peer).await
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> webrtc_util::Result<usize> {
        let pad = if buf.first().is_some_and(|b| b >> 6 == 0b01) { (4 - buf.len() % 4) % 4 } else { 0 };
        let mut writer = self.writer.lock().await;
        let write = async {
            writer.write_all(buf).await?;
            if pad > 0 {
                writer.write_all(&[0u8; 3][..pad]).await?;
            }
            writer.flush().await
        };
        match tokio::time::timeout(STREAM_WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => Ok(buf.len()),
            Ok(Err(e)) => {
                self.closed.cancel();
                Err(e.into())
            }
            Err(_) => {
                self.closed.cancel();
                Err(stream_err("write timed out"))
            }
        }
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.closed.cancel();
        let _ = self.writer.lock().await.shutdown().await;
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turn::client::{Client, ClientConfig};

    const SECRET: &str = "test-secret";
    /// Advertised relay address; any 127/8 address reaches the 0.0.0.0-bound relays.
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    fn creds(valid_for: i64) -> (String, String) {
        let user = format!("{}:abcdefghij:test", crate::tokens::now() + valid_for);
        let pass = crate::ice::credential(SECRET, &user);
        (user, pass)
    }

    async fn udp_server(ports: (u16, u16)) -> (Relay, SocketAddr) {
        let relay = Relay::for_test(PUBLIC, ports.0, ports.1, SECRET);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        relay.serve_udp(udp).await.unwrap();
        (relay, addr)
    }

    async fn client(server: SocketAddr, conn: Arc<dyn Conn + Send + Sync>, (user, pass): (String, String)) -> Client {
        let c = Client::new(ClientConfig {
            stun_serv_addr: server.to_string(),
            turn_serv_addr: server.to_string(),
            username: user,
            password: pass,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn,
            vnet: None,
        })
        .await
        .unwrap();
        c.listen().await.unwrap();
        c
    }

    async fn udp_client(server: SocketAddr, creds: (String, String)) -> Client {
        client(server, Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), creds).await
    }

    /// Relay a datagram to a plain UDP peer and back.
    async fn round_trip(c: &Client) {
        let relay = c.allocate().await.expect("allocate");
        let relay_addr = relay.local_addr().unwrap();
        assert_eq!(relay_addr.ip(), IpAddr::V4(PUBLIC));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay.send_to(b"ping", peer.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from.port(), relay_addr.port());
        peer.send_to(b"pong", SocketAddr::from(([127, 0, 0, 1], relay_addr.port()))).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"pong");
        relay.close().await.unwrap();
    }

    #[tokio::test]
    async fn stun_binding_and_udp_relay() {
        let (_relay, server) = udp_server((51000, 51099)).await;
        let c = udp_client(server, creds(600)).await;
        let mapped = c.send_binding_request().await.unwrap();
        assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        round_trip(&c).await;
        c.close().await.unwrap();
    }

    async fn wait_allocations(relay: &Relay, want: usize) {
        for _ in 0..50 {
            if relay.shared.allocations.load(Ordering::SeqCst) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("allocations: want {want}, have {}", relay.shared.allocations.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tcp_relay_and_allocations_end_with_the_connection() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 51100, 51199, SECRET));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        tokio::spawn(relay.clone().accept_tcp(listener));
        let tcp_client = |server| async move {
            let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
            let local = tcp.local_addr().unwrap();
            let conn = Arc::new(StreamConn::new(tcp, local, server));
            (client(server, conn.clone(), creds(600)).await, conn)
        };

        // Relaying works, and closing the relay (refresh with lifetime 0) frees it.
        let (c, _conn) = tcp_client(server).await;
        round_trip(&c).await;
        wait_allocations(&relay, 0).await;

        // An allocation is freed when its TCP connection goes away.
        let (c2, conn2) = tcp_client(server).await;
        let _held = c2.allocate().await.expect("allocate");
        wait_allocations(&relay, 1).await;
        conn2.close().await.unwrap();
        wait_allocations(&relay, 0).await;
    }

    #[tokio::test]
    async fn relay_to_relay_is_delivered_in_process() {
        let (_relay, server) = udp_server((51200, 51299)).await;
        let a = udp_client(server, creds(600)).await;
        let b = udp_client(server, creds(600)).await;
        let ra = a.allocate().await.unwrap();
        let rb = b.allocate().await.unwrap();
        let (aa, ba) = (ra.local_addr().unwrap(), rb.local_addr().unwrap());
        // Each side permits the other, as ICE does.
        rb.send_to(b"hello-a", aa).await.unwrap();
        ra.send_to(b"hello-b", ba).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), rb.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..n], from), (&b"hello-b"[..], aa));
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), ra.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..n], from), (&b"hello-a"[..], ba));
    }

    #[tokio::test]
    async fn bad_and_expired_credentials_are_refused() {
        let (_relay, server) = udp_server((51300, 51399)).await;
        let (user, _) = creds(600);
        let wrong = udp_client(server, (user, "nope".into())).await;
        assert!(wrong.allocate().await.is_err());
        let expired = udp_client(server, creds(-10)).await;
        assert!(expired.allocate().await.is_err());
        let garbage = udp_client(server, ("someone".into(), "x".into())).await;
        assert!(garbage.allocate().await.is_err());
    }

    #[test]
    fn peer_rules() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "2001:db8::1",
        ] {
            assert!(denied_peer(ip.parse().unwrap(), false), "{ip}");
        }
        for ip in ["8.8.8.8", "203.0.113.9", "100.128.0.1"] {
            assert!(!denied_peer(ip.parse().unwrap(), false), "{ip}");
        }
    }

    #[test]
    fn stream_framing() {
        // STUN binding request header, length 8.
        assert_eq!(frame_len([0x00, 0x01, 0x00, 0x08]), Some((28, 0)));
        // ChannelData 0x4000 with 5 bytes: padded by 3 over streams.
        assert_eq!(frame_len([0x40, 0x00, 0x00, 0x05]), Some((9, 3)));
        assert_eq!(frame_len([0x40, 0x00, 0x00, 0x08]), Some((12, 0)));
        assert_eq!(frame_len([0x80, 0, 0, 0]), None);
        assert_eq!(frame_len([0xC0, 0, 0, 0]), None);
    }
}
