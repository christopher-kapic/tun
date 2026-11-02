//! Public listeners: `:443` (SNI `turn_host` → TURN over TLS to the built-in relay, else TLS + HTTP/1.1 and
//! HTTP/2 routed by `Host`) and `:80` (redirect to HTTPS only).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cockpit_tunnel_protocol::CONNECT_PATH;
use http::{header, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::sni::{self, SniPeek};
use crate::state::AppState;
use crate::util::{empty, request_host, text_response, Body, BoxError};
use crate::{api, control, edge, gatehost, pages, tls};

const SNI_PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Lowercased names used for routing, computed once.
struct Hosts {
    api: String,
    tunnel: String,
    turn: String,
    /// `<preview_zone>`: sign-in pages (see `gatehost`).
    zone: String,
    /// `.<preview_zone>`
    zone_suffix: String,
}

impl Hosts {
    fn new(state: &AppState) -> Self {
        let cfg = &state.config;
        Self {
            api: cfg.api_host.to_ascii_lowercase(),
            tunnel: cfg.tunnel_host.to_ascii_lowercase(),
            turn: cfg.turn_host.to_ascii_lowercase(),
            zone: cfg.preview_zone.to_ascii_lowercase(),
            zone_suffix: format!(".{}", cfg.preview_zone.to_ascii_lowercase()),
        }
    }

    fn preview_label<'a>(&self, host: &'a str) -> Option<&'a str> {
        host.strip_suffix(&self.zone_suffix).filter(|l| !l.is_empty())
    }

    fn is_ours(&self, host: &str) -> bool {
        host == self.api || host == self.tunnel || host == self.zone || self.preview_label(host).is_some()
    }
}

pub async fn run_https(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = state.config.listen_https;
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls::server_config(state.certs.clone())));
    let turn_acceptor = TlsAcceptor::from(Arc::new(tls::turn_server_config(state.certs.clone())));
    let hosts = Arc::new(Hosts::new(&state));
    tracing::info!(%addr, "https listener started");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // EMFILE and friends are transient; never take the listener down.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let peer = canonical(peer);
        let state = state.clone();
        let acceptor = acceptor.clone();
        let turn_acceptor = turn_acceptor.clone();
        let hosts = hosts.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_https_conn(state, acceptor, turn_acceptor, hosts, tcp, peer).await {
                tracing::debug!(%peer, error = %e, "https connection ended with error");
            }
        });
    }
}

/// `[::]` listeners report IPv4 peers as `::ffff:a.b.c.d`.
fn canonical(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

async fn serve_https_conn(
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
    turn_acceptor: TlsAcceptor,
    hosts: Arc<Hosts>,
    tcp: TcpStream,
    peer: SocketAddr,
) -> Result<(), BoxError> {
    let _ = tcp.set_nodelay(true);

    let webrtc = &state.config.webrtc;
    if let (true, Some(relay)) = (webrtc.enabled, state.turn.get()) {
        let to_turn = match sni::peek_sni(&tcp, SNI_PEEK_TIMEOUT).await? {
            SniPeek::Sni(name) => name == hosts.turn,
            SniPeek::NoSni => webrtc.passthrough_no_sni,
            SniPeek::NotTls => return Ok(()),
        };
        if to_turn {
            // TURN over TLS: same certificate, no ALPN (TURN clients send none
            // or `stun.turn`, which an h2/http1.1 list would refuse).
            let local = tcp.local_addr()?;
            let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, turn_acceptor.accept(tcp)).await??;
            relay.serve_stream(tls, local, peer).await;
            return Ok(());
        }
    }

    let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await??;

    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let hosts = hosts.clone();
        async move { Ok::<_, Infallible>(route(state, &hosts, peer, req).await) }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
    // RFC 8441 Extended CONNECT carries HTTP/2 WebSockets.
    builder.http2().timer(TokioTimer::new()).enable_connect_protocol();
    builder.serve_connection_with_upgrades(TokioIo::new(tls), svc).await
}

/// Route by `Host`, not SNI: HTTP/2 clients may coalesce connections across
/// names the certificate covers.
async fn route(state: Arc<AppState>, hosts: &Hosts, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let Some(host) = request_host(&req) else {
        return pages::not_found();
    };
    if host == hosts.tunnel && req.uri().path() == CONNECT_PATH {
        return control::handle_connect(state, req).await;
    }
    if host == hosts.zone && gatehost::handles(req.uri().path()) {
        return gatehost::handle(state, peer, req).await;
    }
    if host == hosts.api {
        let mut req = req;
        req.extensions_mut().insert(api::PeerAddr(peer));
        return api::handle(state, req).await;
    }
    if let Some(label) = hosts.preview_label(&host) {
        return edge::handle(state, peer, label, req).await;
    }
    pages::not_found()
}

pub async fn run_http_redirect(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = state.config.listen_http;
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    let hosts = Arc::new(Hosts::new(&state));
    tracing::info!(%addr, "http redirect listener started");

    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let hosts = hosts.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let resp = redirect(&hosts, &req);
                async move { Ok::<_, Infallible>(resp) }
            });
            let result = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(tcp), svc)
                .await;
            if let Err(e) = result {
                tracing::debug!(error = %e, "http connection ended with error");
            }
        });
    }
}

fn redirect<B>(hosts: &Hosts, req: &Request<B>) -> Response<Body> {
    let Some(host) = request_host(req).filter(|h| hosts.is_ours(h)) else {
        return text_response(StatusCode::BAD_REQUEST, "unknown host\n");
    };
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let location = format!("https://{host}{path}");
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty())
        .unwrap_or_else(|_| text_response(StatusCode::BAD_REQUEST, "bad request\n"))
}
