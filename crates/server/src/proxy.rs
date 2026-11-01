//! Forwarding one visitor request to the sandbox origin over a fresh Yamux
//! stream (HTTP/1.1 toward the origin, no pooling), including WebSocket
//! upgrades and HTTP/2 Extended CONNECT.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use cockpit_tunnel_protocol::{encode_preamble, STREAM_OK, STREAM_REFUSED};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::response::Parts;
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_yamux::StreamHandle;

use crate::db::{HostHeaderMode, TunnelRow};
use crate::headers::{self, ResponseCtx};
use crate::ice;
use crate::inject::{self, Injector};
use crate::metrics::TunnelBytes;
use crate::pages;
use crate::registry::LiveTunnel;
use crate::state::AppState;
use crate::util::{empty, header_str, incoming, text_response, Body, BoxError};

/// Upper bound for opening a stream and reading the client's status byte.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsKind {
    /// HTTP/1.1 `Upgrade: websocket`.
    H1,
    /// HTTP/2 Extended CONNECT (RFC 8441) with `:protocol = websocket`.
    H2,
}

/// Forward `req` to `127.0.0.1:{port}` in the sandbox. The caller has already
/// passed the gate (or the CORS-preflight exception) and checked that `live`
/// declares `port`. `cookie` is the visitor's `Cookie` minus gate cookies;
/// `session_subject` (gate-session hash prefix) is set for gated requests and
/// enables ICE injection.
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    state: &Arc<AppState>,
    tunnel: &TunnelRow,
    live: Arc<LiveTunnel>,
    port: u16,
    mut req: Request<Incoming>,
    cookie: Option<HeaderValue>,
    peer: SocketAddr,
    session_subject: Option<String>,
) -> Response<Body> {
    let cfg = &state.config;
    let ws = websocket_kind(&req);
    if ws.is_none() && *req.method() == Method::CONNECT {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "CONNECT is not supported");
    }
    // Must be taken before the request is consumed.
    let visitor_upgrade = ws.map(|_| hyper::upgrade::on(&mut req));
    let inject_subject = session_subject.filter(|_| {
        tunnel.inject_ice && cfg.webrtc.enabled && *req.method() == Method::GET && is_navigation(req.headers())
    });

    let public_host = state.preview_host(port, &tunnel.id);
    let (parts, body) = req.into_parts();
    let headers = origin_request_headers(parts.headers, state, tunnel, port, &public_host, cookie, peer, ws, inject_subject.is_some());

    let bytes = state.metrics.tunnel_bytes(&tunnel.id);
    let req_body = if ws.is_some() {
        // Upgrade requests carry no body; for Extended CONNECT the stream
        // itself becomes the tunnel after the response.
        drop(body);
        empty()
    } else {
        Counted { inner: incoming(body), bytes: bytes.clone(), outbound: false, _guard: None }.boxed()
    };
    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut out = Request::new(req_body);
    *out.method_mut() = if ws == Some(WsKind::H2) { Method::GET } else { parts.method };
    *out.uri_mut() = path.parse().unwrap_or_else(|_| Uri::from_static("/"));
    *out.version_mut() = Version::HTTP_11;
    *out.headers_mut() = headers;

    let guard = StreamGuard::new(state);
    let stream = match tokio::time::timeout(STREAM_OPEN_TIMEOUT, open_stream(&live, port)).await {
        Ok(Opened::Ready(s)) => s,
        Ok(Opened::Refused) => return pages::app_not_running(port),
        Ok(Opened::Offline) | Err(_) => return pages::offline(),
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(stream)).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(tunnel = %tunnel.id, port, error = %e, "origin handshake failed");
            return pages::bad_gateway();
        }
    };
    let conn_tunnel = tunnel.id.clone();
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(tunnel = %conn_tunnel, error = %e, "origin connection error");
        }
    });

    let mut resp = match sender.send_request(out).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(tunnel = %tunnel.id, port, error = %e, "origin request failed");
            return pages::bad_gateway();
        }
    };

    if let (Some(kind), Some(visitor_upgrade)) = (ws, visitor_upgrade) {
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let origin_upgrade = hyper::upgrade::on(&mut resp);
            let reply = upgrade_response(kind, resp.headers());
            let splice_tunnel = tunnel.id.clone();
            tokio::spawn(async move {
                let _guard = guard;
                let (visitor, origin) = match tokio::try_join!(visitor_upgrade, origin_upgrade) {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!(tunnel = %splice_tunnel, error = %e, "websocket upgrade failed");
                        return;
                    }
                };
                let mut visitor = TokioIo::new(visitor);
                let mut origin = TokioIo::new(origin);
                match tokio::io::copy_bidirectional(&mut visitor, &mut origin).await {
                    Ok((to_origin, to_visitor)) => {
                        bytes.bytes_in.fetch_add(to_origin, Ordering::Relaxed);
                        bytes.bytes_out.fetch_add(to_visitor, Ordering::Relaxed);
                    }
                    Err(e) => tracing::debug!(tunnel = %splice_tunnel, error = %e, "websocket splice ended"),
                }
            });
            return reply;
        }
        // Any 2xx to an Extended CONNECT means "tunnel open" to the browser;
        // an origin that did not upgrade must not produce one.
        if kind == WsKind::H2 && resp.status().is_success() {
            return pages::bad_gateway();
        }
    }

    let (mut parts, body) = resp.into_parts();
    // The visitor connection decides its own version (h1 or h2).
    parts.version = Version::HTTP_11;
    let script = inject_subject
        .filter(|_| injectable(&parts))
        .map(|subject| inject::script(&ice::mint(cfg, &tunnel.id, &subject, cfg.webrtc.browser_ttl_s), &cfg.turn_host));
    let hash = script.as_deref().map(inject::csp_hash);
    let ctx = ResponseCtx { zone: &cfg.preview_zone, tunnel_id: &tunnel.id, frame_ancestors: &cfg.frame_ancestors };
    headers::rewrite_response(&mut parts.headers, &ctx, hash.as_deref());

    let counted = Counted { inner: incoming(body), bytes, outbound: true, _guard: Some(guard) }.boxed();
    let body = match script {
        Some(s) => {
            parts.headers.remove(header::CONTENT_LENGTH);
            // The body differs per response, so the origin's validators do
            // not describe it, and without them the browser never sends a
            // conditional request for this page.
            parts.headers.remove(header::ETAG);
            parts.headers.remove(header::LAST_MODIFIED);
            Injector::new(counted, inject::tag(&s)).boxed()
        }
        None => counted,
    };
    Response::from_parts(parts, body)
}

#[allow(clippy::too_many_arguments)]
fn origin_request_headers(
    mut h: HeaderMap,
    state: &AppState,
    tunnel: &TunnelRow,
    port: u16,
    public_host: &str,
    cookie: Option<HeaderValue>,
    peer: SocketAddr,
    ws: Option<WsKind>,
    inject: bool,
) -> HeaderMap {
    headers::strip_hop_by_hop(&mut h);
    h.remove(header::COOKIE);
    if let Some(c) = cookie {
        h.insert(header::COOKIE, c);
    }
    // hyper already answered any `100-continue` toward the visitor.
    h.remove(header::EXPECT);

    h.remove(header::FORWARDED);
    let spoofable: Vec<HeaderName> = h.keys().filter(|n| n.as_str().starts_with("x-forwarded-")).cloned().collect();
    for name in &spoofable {
        h.remove(name);
    }
    h.remove("x-real-ip");
    h.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    if let Ok(v) = HeaderValue::from_str(public_host) {
        h.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&peer.ip().to_canonical().to_string()) {
        h.insert(HeaderName::from_static("x-forwarded-for"), v);
    }

    let host = match tunnel.host_header {
        HostHeaderMode::Rewrite => format!("localhost:{port}"),
        HostHeaderMode::Preserve => public_host.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&host) {
        h.insert(header::HOST, v);
    }
    if tunnel.host_header == HostHeaderMode::Rewrite {
        headers::rewrite_request_origin(&mut h, &state.config.preview_zone, &tunnel.id);
    }

    if inject {
        // The injector needs uncompressed HTML.
        h.remove(header::ACCEPT_ENCODING);
        // A 304 would revalidate a cached page whose injected script (and
        // credential) is stale and whose CSP hash no longer matches; always
        // fetch the full document.
        h.remove(header::IF_NONE_MATCH);
        h.remove(header::IF_MODIFIED_SINCE);
        h.remove(header::IF_RANGE);
    }

    if let Some(kind) = ws {
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        if kind == WsKind::H2 {
            // RFC 8441 requests have no key; the origin speaks RFC 6455 and needs one.
            h.insert(header::SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
            let key = STANDARD.encode(rand::random::<[u8; 16]>());
            h.insert(header::SEC_WEBSOCKET_KEY, HeaderValue::from_str(&key).expect("base64 is a valid header value"));
        }
    }
    h
}

fn websocket_kind<B>(req: &Request<B>) -> Option<WsKind> {
    if *req.method() == Method::CONNECT {
        return req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .filter(|p| p.as_str().eq_ignore_ascii_case("websocket"))
            .map(|_| WsKind::H2);
    }
    let h1 = req.version() == Version::HTTP_11 || req.version() == Version::HTTP_10;
    let connection_upgrade = req
        .headers()
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    let upgrade_ws = header_str(req.headers().get(header::UPGRADE))
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("websocket")));
    (h1 && *req.method() == Method::GET && connection_upgrade && upgrade_ws).then_some(WsKind::H1)
}

/// Top-level or iframe navigation (`fetch()` and htmx fragments are excluded).
fn is_navigation(headers: &HeaderMap) -> bool {
    header_str(headers.get("sec-fetch-dest"))
        .is_some_and(|d| matches!(d.trim().to_ascii_lowercase().as_str(), "document" | "iframe" | "frame"))
}

/// Non-empty, uncompressed `text/html` with a body.
fn injectable(parts: &Parts) -> bool {
    if parts.status == StatusCode::NO_CONTENT || parts.status == StatusCode::NOT_MODIFIED || parts.status.is_informational() {
        return false;
    }
    let html = header_str(parts.headers.get(header::CONTENT_TYPE)).is_some_and(|ct| {
        ct.split(';').next().unwrap_or_default().trim().eq_ignore_ascii_case("text/html")
    });
    let identity = parts
        .headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|v| v.to_str().is_ok_and(|e| e.split(',').all(|t| t.trim().is_empty() || t.trim().eq_ignore_ascii_case("identity"))));
    let empty = header_str(parts.headers.get(header::CONTENT_LENGTH)).is_some_and(|l| l.trim() == "0");
    html && identity && !empty
}

fn upgrade_response(kind: WsKind, origin: &HeaderMap) -> Response<Body> {
    let mut resp = Response::new(empty());
    *resp.status_mut() = match kind {
        WsKind::H1 => StatusCode::SWITCHING_PROTOCOLS,
        WsKind::H2 => StatusCode::OK,
    };
    let h = resp.headers_mut();
    for name in [header::SEC_WEBSOCKET_PROTOCOL, header::SEC_WEBSOCKET_EXTENSIONS] {
        if let Some(v) = origin.get(&name) {
            h.insert(name, v.clone());
        }
    }
    if kind == WsKind::H1 {
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        // The visitor's key was forwarded unchanged, so the origin's accept matches.
        if let Some(v) = origin.get(header::SEC_WEBSOCKET_ACCEPT) {
            h.insert(header::SEC_WEBSOCKET_ACCEPT, v.clone());
        }
    }
    resp
}

enum Opened {
    Ready(StreamHandle),
    Refused,
    Offline,
}

/// Open a Yamux stream, send the port preamble, and read the client's verdict.
async fn open_stream(live: &LiveTunnel, port: u16) -> Opened {
    let mut control = live.control.clone();
    let Ok(mut stream) = control.open_stream().await else {
        return Opened::Offline;
    };
    if stream.write_all(&encode_preamble(port)).await.is_err() || stream.flush().await.is_err() {
        return Opened::Offline;
    }
    let mut status = [0u8; 1];
    if stream.read_exact(&mut status).await.is_err() {
        return Opened::Offline;
    }
    match status[0] {
        STREAM_OK => Opened::Ready(stream),
        STREAM_REFUSED => Opened::Refused,
        // STREAM_NOT_EXPOSED and anything unknown.
        _ => Opened::Offline,
    }
}

/// Keeps `live_streams` accurate for as long as a request, its response
/// body, or a WebSocket splice is alive.
struct StreamGuard(Arc<AppState>);

impl StreamGuard {
    fn new(state: &Arc<AppState>) -> Self {
        state.metrics.live_streams.fetch_add(1, Ordering::Relaxed);
        Self(state.clone())
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.metrics.live_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts data bytes into the tunnel's metrics; frames pass through as-is.
struct Counted {
    inner: Body,
    bytes: Arc<TunnelBytes>,
    /// Origin → visitor when true.
    outbound: bool,
    _guard: Option<StreamGuard>,
}

impl HttpBody for Counted {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll {
            if let Some(data) = frame.data_ref() {
                let counter = if this.outbound { &this.bytes.bytes_out } else { &this.bytes.bytes_in };
                counter.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(status: StatusCode, headers: &[(&'static str, &'static str)]) -> Parts {
        let mut b = Response::builder().status(status);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn injectable_rules() {
        assert!(injectable(&parts(StatusCode::OK, &[("content-type", "text/html; charset=utf-8")])));
        assert!(!injectable(&parts(StatusCode::OK, &[("content-type", "application/json")])));
        assert!(!injectable(&parts(StatusCode::OK, &[("content-type", "text/html"), ("content-encoding", "gzip")])));
        assert!(!injectable(&parts(StatusCode::NOT_MODIFIED, &[("content-type", "text/html")])));
        assert!(!injectable(&parts(StatusCode::OK, &[("content-type", "text/html"), ("content-length", "0")])));
    }

    #[test]
    fn detects_h1_websocket() {
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();
        assert_eq!(websocket_kind(&req), Some(WsKind::H1));
        let plain = Request::builder().method(Method::GET).body(()).unwrap();
        assert_eq!(websocket_kind(&plain), None);
    }

    #[test]
    fn navigation_dest() {
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-dest", HeaderValue::from_static("iframe"));
        assert!(is_navigation(&h));
        h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
        assert!(!is_navigation(&h));
    }
}
