//! Prometheus text metrics on `metrics_listen` (loopback by default).

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::state::AppState;
use crate::util::{full, Body};

#[derive(Default)]
pub struct TunnelBytes {
    /// Visitor → origin.
    pub bytes_in: AtomicU64,
    /// Origin → visitor.
    pub bytes_out: AtomicU64,
}

#[derive(Default)]
pub struct Metrics {
    pub live_streams: AtomicI64,
    pub gate_denials: AtomicU64,
    /// Visitor lookups answered 503 because the lookup slots were full.
    pub lookups_shed: AtomicU64,
    /// Built-in TURN relay gauges.
    pub turn: Arc<crate::turn_relay::MetricsRef>,
    pub access_redemptions: AtomicU64,
    pub access_failures: AtomicU64,
    pub requests: AtomicU64,
    per_tunnel: Mutex<HashMap<String, Arc<TunnelBytes>>>,
}

impl Metrics {
    pub fn tunnel_bytes(&self, tunnel_id: &str) -> Arc<TunnelBytes> {
        self.per_tunnel.lock().expect("metrics lock").entry(tunnel_id.to_string()).or_default().clone()
    }

    pub fn forget_tunnel(&self, tunnel_id: &str) {
        self.per_tunnel.lock().expect("metrics lock").remove(tunnel_id);
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self, state: &AppState) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# TYPE cockpit_tunnels_connected gauge");
        let _ = writeln!(out, "cockpit_tunnels_connected {}", state.registry.len());
        let _ = writeln!(out, "# TYPE cockpit_streams_live gauge");
        let _ = writeln!(out, "cockpit_streams_live {}", self.live_streams.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE cockpit_requests_total counter");
        let _ = writeln!(out, "cockpit_requests_total {}", self.requests.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE cockpit_gate_denials_total counter");
        let _ = writeln!(out, "cockpit_gate_denials_total {}", self.gate_denials.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE cockpit_lookups_shed_total counter");
        let _ = writeln!(out, "cockpit_lookups_shed_total {}", self.lookups_shed.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE cockpit_turn_allocations gauge");
        let _ = writeln!(out, "cockpit_turn_allocations {}", self.turn.allocations.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE cockpit_access_redemptions_total counter");
        let _ = writeln!(out, "cockpit_access_redemptions_total {}", self.access_redemptions.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE cockpit_access_failures_total counter");
        let _ = writeln!(out, "cockpit_access_failures_total {}", self.access_failures.load(Ordering::Relaxed));
        if let Some(not_after) = state.certs.not_after() {
            let _ = writeln!(out, "# TYPE cockpit_cert_not_after_seconds gauge");
            let _ = writeln!(out, "cockpit_cert_not_after_seconds {not_after}");
        }
        let _ = writeln!(out, "# TYPE cockpit_tunnel_bytes_total counter");
        for (id, b) in self.per_tunnel.lock().expect("metrics lock").iter() {
            let _ = writeln!(
                out,
                "cockpit_tunnel_bytes_total{{tunnel=\"{id}\",direction=\"in\"}} {}",
                b.bytes_in.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "cockpit_tunnel_bytes_total{{tunnel=\"{id}\",direction=\"out\"}} {}",
                b.bytes_out.load(Ordering::Relaxed)
            );
        }
        out
    }
}

pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(state.config.metrics_listen).await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |_req| {
                let text = state.metrics.render(&state);
                async move {
                    Ok::<_, Infallible>(
                        http::Response::builder()
                            .header(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body::<Body>(full(text))
                            .expect("valid response"),
                    )
                }
            });
            let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
        });
    }
}
