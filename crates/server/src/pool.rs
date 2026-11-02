//! Idle HTTP/1.1 connections to a tunnel's origins, for reuse (audit #10).
//!
//! Each connection is a Yamux stream spliced by the client to a loopback TCP
//! connection, so reuse skips a stream open (a round trip to the sandbox), a
//! local TCP connect, and a handshake. The pool belongs to one
//! [`LiveTunnel`](crate::registry::LiveTunnel) connection, so a replaced or
//! dropped connection takes its pool with it. WebSocket upgrades never use it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use hyper::client::conn::http1::SendRequest;

use crate::util::Body;

/// Idle connections kept per port, and per tunnel connection overall (each
/// holds a Yamux stream and a loopback socket in the sandbox).
const MAX_IDLE_PER_PORT: usize = 16;
const MAX_IDLE_TOTAL: usize = 64;
/// Shorter than Node's default `keepAliveTimeout` (5 s), so the origin rarely
/// closes a connection just as it is reused. When it does, the request was not
/// sent and is retried on a new connection (see `proxy`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(4);

struct Idle {
    sender: SendRequest<Body>,
    since: Instant,
}

#[derive(Default)]
pub struct OriginPool {
    idle: Mutex<HashMap<u16, Vec<Idle>>>,
}

impl OriginPool {
    /// The most recently idle live connection for `port`, if any.
    pub fn checkout(&self, port: u16) -> Option<SendRequest<Body>> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let list = idle.get_mut(&port)?;
        while let Some(c) = list.pop() {
            if c.since.elapsed() < IDLE_TIMEOUT && c.sender.is_ready() {
                return Some(c.sender);
            }
        }
        None
    }

    /// Keep `sender` for reuse (it must be ready for its next request).
    pub fn put(&self, port: u16, sender: SendRequest<Body>) {
        if !sender.is_ready() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let total: usize = idle.values().map(Vec::len).sum();
        let list = idle.entry(port).or_default();
        list.retain(|c| c.since.elapsed() < IDLE_TIMEOUT && !c.sender.is_closed());
        if list.len() < MAX_IDLE_PER_PORT && total < MAX_IDLE_TOTAL {
            list.push(Idle { sender, since: Instant::now() });
        }
    }

    /// Drop every idle connection for `port` (it was unexposed).
    pub fn clear_port(&self, port: u16) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).remove(&port);
    }

    #[cfg(test)]
    pub fn idle_count(&self, port: u16) -> usize {
        self.idle.lock().unwrap().get(&port).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    /// A client connection to an in-memory HTTP/1.1 server that answers "ok".
    async fn conn() -> SendRequest<Body> {
        let (a, b) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let svc = service_fn(|_req| async { Ok::<_, std::convert::Infallible>(http::Response::new(crate::util::full("ok"))) });
            let _ = server_http1::Builder::new().serve_connection(TokioIo::new(b), svc).await;
        });
        let (sender, c) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(a)).await.unwrap();
        tokio::spawn(c);
        sender
    }

    async fn get(sender: &mut SendRequest<Body>) {
        use http_body_util::BodyExt;
        let resp = sender.send_request(http::Request::new(crate::util::empty())).await.unwrap();
        assert_eq!(resp.into_body().collect().await.unwrap().to_bytes(), "ok");
    }

    #[tokio::test]
    async fn reuses_a_ready_connection() {
        let pool = OriginPool::default();
        let mut s = conn().await;
        get(&mut s).await;
        s.ready().await.unwrap();
        pool.put(3000, s);
        assert_eq!(pool.idle_count(3000), 1);
        assert!(pool.checkout(5173).is_none());
        let mut again = pool.checkout(3000).expect("pooled");
        get(&mut again).await;
        assert_eq!(pool.idle_count(3000), 0);
    }

    #[tokio::test]
    async fn caps_and_clears() {
        let pool = OriginPool::default();
        for _ in 0..MAX_IDLE_PER_PORT + 3 {
            let mut s = conn().await;
            s.ready().await.unwrap();
            pool.put(3000, s);
        }
        assert_eq!(pool.idle_count(3000), MAX_IDLE_PER_PORT);
        pool.clear_port(3000);
        assert!(pool.checkout(3000).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_connections_are_not_reused() {
        let pool = OriginPool::default();
        let mut s = conn().await;
        s.ready().await.unwrap();
        pool.put(3000, s);
        assert_eq!(pool.idle_count(3000), 1);
        tokio::time::advance(IDLE_TIMEOUT + Duration::from_millis(10)).await;
        assert!(pool.checkout(3000).is_none());
    }
}
