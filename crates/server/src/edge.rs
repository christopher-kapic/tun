//! Visitor-facing edge for `*.<preview_zone>`.
//!
//! Order: label → `/__access/*` → tunnel lifecycle → `/__login` → gate (with
//! the CORS preflight exception; skipped for public tunnels) → `/__cockpit/*`
//! → live port → proxy. Reserved paths are never forwarded, and the origin is
//! never contacted for a request that fails the gate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http::header::{self, HeaderMap};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body as HttpBody;
use hyper::body::Incoming;

use crate::db::{AccessMode, TunnelLookup, TunnelRow};
use crate::gate;
use crate::headers;
use crate::ice;
use crate::metrics::Metrics;
use crate::pages;
use crate::proxy;
use crate::state::AppState;
use crate::util::{header_str, json_response, text_response, Body};

const ACCESS_PREFIX: &str = "/__access";
const COCKPIT_PREFIX: &str = "/__cockpit";
const LOGIN_PATH: &str = "/__login";
/// TURN username subject for visitors of a public tunnel (no session).
const PUBLIC_SUBJECT: &str = "public";
const ICE_PATH: &str = "/__cockpit/ice";
/// Gate-session hash prefix used as the TURN username subject (coturn log attribution).
const SUBJECT_LEN: usize = 8;
/// The only request headers an unauthenticated preflight carries to the
/// origin. A real preflight has no body and no credentials; anything else a
/// client adds is dropped so the exception cannot carry an ordinary request.
const PREFLIGHT_HEADERS: &[&str] = &[
    "host",
    "origin",
    "referer",
    "user-agent",
    "accept",
    "accept-language",
    "access-control-request-method",
    "access-control-request-headers",
    "access-control-request-private-network",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-dest",
];

/// `label` is the request host minus `.<preview_zone>`, e.g. `3000-ab12cd3efg`.
pub async fn handle(state: Arc<AppState>, peer: SocketAddr, label: &str, req: Request<Incoming>) -> Response<Body> {
    Metrics::inc(&state.metrics.requests);
    let started = Instant::now();
    let method = req.method().clone();
    let path = log_path(req.uri().path());
    let resp = route(&state, peer, label, req).await;
    tracing::info!(
        host = %format_args!("{label}.{}", state.config.preview_zone),
        method = %method,
        path = %path,
        status = resp.status().as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "edge request"
    );
    resp
}

async fn route(state: &Arc<AppState>, peer: SocketAddr, label: &str, req: Request<Incoming>) -> Response<Body> {
    let Some((port, id)) = headers::parse_label(label) else {
        return pages::not_found();
    };
    let path = req.uri().path().to_string();
    let cookies = gate::split_cookies(req.headers());

    // Before the lifecycle check: a link for an unknown, deleted, or expired
    // tunnel gets the same generic 401 as any other bad link (redemption
    // checks the tunnel itself).
    if is_under(&path, ACCESS_PREFIX) {
        let token = path.strip_prefix("/__access/").unwrap_or_default();
        let method_ok = *req.method() == Method::GET || *req.method() == Method::HEAD;
        if !method_ok || token.is_empty() || token.contains('/') {
            return pages::not_found();
        }
        let resp = gate::redeem(state, peer.ip(), id, token, &cookies.values).await;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return resp;
        }
        // A used or expired link still leads somewhere useful when the tunnel
        // has another way in. Unknown and ended tunnels keep the generic 401.
        return match live_access_mode(state, id).await {
            Some(AccessMode::Password) => pages::login(StatusCode::UNAUTHORIZED, "/", None),
            Some(AccessMode::Public) => redirect_root(),
            _ => resp,
        };
    }

    let lookup = match state.tunnel(id).await {
        Ok(l) => l,
        Err(e) => return internal_error(id, e),
    };
    let tunnel = match &*lookup {
        TunnelLookup::Live(t) if !t.is_expired() => t,
        TunnelLookup::Live(_) | TunnelLookup::Tombstoned => return pages::ended(),
        TunnelLookup::Unknown => return pages::not_found(),
    };

    let mode = tunnel.access.mode;
    if path == LOGIN_PATH {
        if mode != AccessMode::Password {
            return pages::not_found();
        }
        return match *req.method() {
            Method::GET | Method::HEAD => {
                let next = req
                    .uri()
                    .query()
                    .and_then(|q| url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "next"))
                    .map(|(_, v)| gate::safe_next(&v))
                    .unwrap_or_else(|| "/".to_string());
                pages::login(StatusCode::OK, &next, None)
            }
            Method::POST => gate::login(state, peer.ip(), tunnel, req.into_body(), &cookies.values).await,
            _ => pages::not_found(),
        };
    }

    let session_hash = match gate::authorize(state, id, &cookies.values).await {
        Ok(s) => s,
        Err(e) => return internal_error(id, e),
    };
    let reserved = is_under(&path, COCKPIT_PREFIX);

    let subject = match session_hash {
        Some(hash) => hash[..SUBJECT_LEN].to_string(),
        None if mode == AccessMode::Public => PUBLIC_SUBJECT.to_string(),
        None => {
            let login_next = (mode == AccessMode::Password && wants_page(&req))
                .then(|| req.uri().path_and_query().map(|p| gate::safe_next(p.as_str())).unwrap_or_default());
            if !reserved && is_same_tunnel_preflight(&req, &state.config.preview_zone, id) {
                // Preflights never carry credentials; forward without any cookie.
                if let Some(req) = preflight_only(req) {
                    return forward_live(state, tunnel, port, req, None, peer, None).await;
                }
            }
            Metrics::inc(&state.metrics.gate_denials);
            if let Some(next) = login_next {
                return pages::login(StatusCode::UNAUTHORIZED, &next, None);
            }
            return pages::unauthorized();
        }
    };

    if reserved {
        let method_ok = *req.method() == Method::GET || *req.method() == Method::HEAD;
        if path == ICE_PATH && method_ok && state.config.webrtc.enabled {
            let ice = ice::mint(&state.config, id, &subject, state.config.webrtc.browser_ttl_s);
            return json_response(StatusCode::OK, &ice);
        }
        return pages::not_found();
    }

    forward_live(state, tunnel, port, req, cookies.forward, peer, Some(subject)).await
}

/// The access mode of a live, unexpired tunnel.
async fn live_access_mode(state: &Arc<AppState>, id: &str) -> Option<AccessMode> {
    match &*state.tunnel(id).await.ok()? {
        TunnelLookup::Live(t) if !t.is_expired() => Some(t.access.mode),
        _ => None,
    }
}

fn redirect_root() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(crate::util::empty())
        .expect("valid response")
}

/// A browser loading a page (top level or in an iframe), as opposed to a
/// fetch, script, or image, which should get a plain 401 rather than a form.
fn wants_page(req: &Request<Incoming>) -> bool {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return false;
    }
    match header_str(req.headers().get("sec-fetch-dest")) {
        Some(dest) => matches!(dest, "document" | "iframe" | "frame"),
        None => header_str(req.headers().get(header::ACCEPT)).is_some_and(|a| a.contains("text/html")),
    }
}

/// Only ports the connected client declared are routable; anything else is
/// "offline" and never reaches the sandbox.
async fn forward_live(
    state: &Arc<AppState>,
    tunnel: &TunnelRow,
    port: u16,
    req: Request<Incoming>,
    cookie: Option<HeaderValue>,
    peer: SocketAddr,
    session_subject: Option<String>,
) -> Response<Body> {
    let Some(live) = state.registry.get(&tunnel.id).filter(|l| l.has_port(port)) else {
        return pages::offline();
    };
    proxy::forward(state, tunnel, live, port, req, cookie, peer, session_subject).await
}

/// CORS preflight from another `{port}-{id}` host of the same tunnel.
fn is_same_tunnel_preflight<B>(req: &Request<B>, zone: &str, tunnel_id: &str) -> bool {
    *req.method() == Method::OPTIONS
        && req.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
        && header_str(req.headers().get(header::ORIGIN))
            .and_then(|o| headers::same_tunnel_origin_port(o, zone, tunnel_id))
            .is_some()
}

/// Reduce a same-tunnel preflight to what a browser preflight carries, or
/// `None` if it has a body (no real preflight does).
fn preflight_only<B: HttpBody>(mut req: Request<B>) -> Option<Request<B>> {
    let declared_body = req.headers().contains_key(header::TRANSFER_ENCODING)
        || header_str(req.headers().get(header::CONTENT_LENGTH)).is_some_and(|l| l.trim() != "0");
    // verify: hyper 1.x `Incoming::is_end_stream()` is true for an h1 request
    // without a body and for an h2 request whose HEADERS frame ended the stream.
    if declared_body || !req.body().is_end_stream() {
        return None;
    }
    let all = std::mem::take(req.headers_mut());
    let mut kept = HeaderMap::new();
    for &name in PREFLIGHT_HEADERS {
        for value in all.get_all(name) {
            kept.append(name, value.clone());
        }
    }
    *req.headers_mut() = kept;
    Some(req)
}

/// `path` is `prefix` itself or below it.
fn is_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Access tokens live in the path; never log them. Long paths are truncated.
fn log_path(path: &str) -> String {
    if is_under(path, ACCESS_PREFIX) {
        return "/__access/[redacted]".to_string();
    }
    path.chars().take(200).collect()
}

fn internal_error(tunnel_id: &str, e: anyhow::Error) -> Response<Body> {
    tracing::error!(tunnel = tunnel_id, error = %e, "edge lookup failed");
    text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_prefixes() {
        assert!(is_under("/__access/ctacc_x", ACCESS_PREFIX));
        assert!(is_under("/__access", ACCESS_PREFIX));
        assert!(!is_under("/__accessible", ACCESS_PREFIX));
        assert!(is_under("/__cockpit/ice", COCKPIT_PREFIX));
    }

    #[test]
    fn redacts_tokens() {
        assert_eq!(log_path("/__access/ctacc_secret"), "/__access/[redacted]");
        assert_eq!(log_path("/a/b"), "/a/b");
    }

    #[test]
    fn preflight_detection() {
        let zone = "previews.example.com";
        let req = |origin: &'static str| {
            Request::builder()
                .method(Method::OPTIONS)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ORIGIN, origin)
                .body(())
                .unwrap()
        };
        assert!(is_same_tunnel_preflight(&req("https://3000-abcdefghij.previews.example.com"), zone, "abcdefghij"));
        assert!(!is_same_tunnel_preflight(&req("https://3000-zzzzzzzzzz.previews.example.com"), zone, "abcdefghij"));
    }

    #[test]
    fn preflight_is_reduced() {
        use bytes::Bytes;
        use http_body_util::{Empty, Full};

        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(header::ORIGIN, "https://3000-abcdefghij.previews.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::AUTHORIZATION, "Bearer x")
            .header("x-custom", "1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let out = preflight_only(req).unwrap();
        assert!(out.headers().contains_key(header::ORIGIN));
        assert!(out.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD));
        assert!(!out.headers().contains_key(header::AUTHORIZATION));
        assert!(!out.headers().contains_key("x-custom"));

        let with_body = Request::builder().method(Method::OPTIONS).body(Full::new(Bytes::from_static(b"x"))).unwrap();
        assert!(preflight_only(with_body).is_none());
    }
}
