# Module contracts

Source of truth for behavior: `cockpit-tunnel-plan.md`. This file records the
**Rust interfaces** between modules as implemented in the first pass. The code
has not been compiled yet; see the "first build pass" checklist in `README.md`.

Crate APIs below were checked by reading the sources of the exact versions in
`Cargo.lock` (cached under `~/.cargo/registry`). Items still marked `verify:` in
the code could not be checked offline.

## Protocol crate (`crates/protocol`)

- Wire messages: `ClientMsg { Hello{version, ports}, Expose{id, port}, Unexpose{id, port}, IceRequest{id} }`,
  `ServerMsg { Welcome{tunnel_id, host_template, max_ports, ports, webrtc}, Reply{id, ok, error?, ice?}, Close{reason} }`,
  `CloseReason { Deleted, Expired, Replaced, Shutdown }`, `IceConfig { iceServers, expires_at, ttl_s }`, `IceServer`.
- Constants: `PROTOCOL_VERSION`, `CONNECT_PATH` (`/v1/connect`), token prefixes, `GATE_COOKIE`,
  `PING_INTERVAL` (25s), `STREAM_WINDOW` (256 KiB), `MAX_CONTROL_LINE`, `STREAM_OK/REFUSED/NOT_EXPOSED`,
  `EXIT_REVOKED` (3), `EXIT_REPLACED` (4).
- `yamux_config()`, `encode_preamble(port) -> [u8; 2]`, `decode_preamble`, `read_json_line`, `write_json_line`.
- `ws_bridge::bridge(ws, ping_interval) -> (DuplexStream, JoinHandle<()>)`.

Data streams: the server opens a Yamux stream, writes the 2-byte big-endian
port, the client answers with one status byte, then raw bytes. There are no
preamble flags.

A protocol version mismatch is answered with `Reply { id: 0, ok: false, error }`
and a hang-up (no `CloseReason` fits, and a terminal one would make the client
exit as revoked).

## Server foundation

- `main.rs` — CLI + `mod` list. Calls `commands::{serve, token_rotate, status, backup, cert_renew}` and `setup::run`.
- `config.rs` — `Config` (+ `load`, `save`, `cert_names()`, `preview_host()`, `host_template()`, `db_path()`,
  `cert_dir()`, `acme_account_path()`), `set_mode`, constants `DEFAULT_CONFIG_PATH`, `DEFAULT_DATA_DIR`,
  `SERVICE_USER`, `SERVICE_NAME`.
- `tokens.rs` — `random_token(prefix)`, `random_secret()`, `hash_token`, `hashes_equal`, `random_tunnel_id`,
  `is_valid_tunnel_id`, `random_link_id`, `now()`.
- `util.rs` — `Body` (`BoxBody<Bytes, BoxError>`, `Send + Sync`), `BoxError`, `full`, `empty`, `incoming`,
  `json_response`, `text_response`, `request_host`, `strip_port`, `header_str`, `write_if_changed`,
  `write_atomic`, `chown_recursive`.
- `db.rs` — `Db` (single connection behind `spawn_blocking`) and all queries. `HostHeaderMode`, `TunnelRow`,
  `NewTunnel`, `TunnelPatch`, `NewAccessLink`, `Redemption`, `TunnelLookup`, `DeleteOutcome`, `PurgeStats`.
- `registry.rs` — `Registry`, `LiveTunnel { conn_id, tunnel_id, control, ports, ctrl_tx, cancel, connected_at }`,
  `LiveTunnel::close(reason)`.
- `state.rs` — `AppState { config, db, registry, certs, metrics, access_limiter }`, `AppState::new(config, db, certs)`,
  cached `tunnel()` (→ `Arc<TunnelLookup>`: live row, tombstone, or unknown) and
  `cached_session_grants()` / `load_session_grants()` (one batched query), `invalidate_*` (epoch-guarded, so a
  lookup racing a delete never re-caches stale rows), `delete_tunnel(id, reason)`, `preview_host()`.
- `ice.rs` — `mint(cfg, tunnel_id, subject, ttl_s) -> IceConfig`, `SANDBOX_SUBJECT`.
- `metrics.rs` — `Metrics` counters, `tunnel_bytes(id)`, `forget_tunnel`, `serve(state)`.

## Edge (`edge.rs`, `proxy.rs`, `gate.rs`, `headers.rs`, `inject.rs`, `pages.rs`, `ratelimit.rs`)

```rust
// edge.rs — `label` = lowercased host minus ".<preview_zone>", e.g. "3000-ab12cd3efg".
pub async fn handle(state: Arc<AppState>, peer: SocketAddr, label: &str, req: Request<Incoming>) -> Response<Body>;

// proxy.rs — caller has passed the gate (or the preflight exception) and checked `live` declares `port`.
pub async fn forward(state: &Arc<AppState>, tunnel: &TunnelRow, live: Arc<LiveTunnel>, port: u16,
                     req: Request<Incoming>, cookie: Option<HeaderValue>, peer: SocketAddr,
                     session_subject: Option<String>) -> Response<Body>;

// gate.rs
pub struct GateCookies { pub values: Vec<String>, pub forward: Option<HeaderValue> }
pub fn split_cookies(headers: &HeaderMap) -> GateCookies;
pub async fn authorize(state: &AppState, tunnel_id: &str, values: &[String]) -> anyhow::Result<Option<String>>; // session hash
pub async fn redeem(state: &AppState, peer: IpAddr, tunnel_id: &str, token: &str, cookie_values: &[String]) -> Response<Body>;

// headers.rs
pub fn parse_label(label: &str) -> Option<(u16, &str)>;
pub fn same_tunnel_origin_port(origin: &str, zone: &str, tunnel_id: &str) -> Option<u16>;
pub fn strip_hop_by_hop(headers: &mut HeaderMap);
pub fn rewrite_request_origin(headers: &mut HeaderMap, zone: &str, tunnel_id: &str);
pub struct ResponseCtx<'a> { pub zone: &'a str, pub tunnel_id: &'a str, pub dashboard_origin: &'a str }
pub fn rewrite_response(headers: &mut HeaderMap, ctx: &ResponseCtx<'_>, script_hash: Option<&str>);
pub fn rewrite_csp_value(value: &str, dashboard_origin: &str, script_hash: Option<&str>) -> String;

// inject.rs — hand-rolled streaming injector (no lol_html)
pub fn script(ice: &IceConfig, turn_host: &str) -> String;
pub fn tag(script: &str) -> Bytes;
pub fn csp_hash(script: &str) -> String;
pub struct Injector; impl Injector { pub fn new(inner: Body, tag: Bytes) -> Self }  // impl http_body::Body

// pages.rs — all `Cache-Control: no-store`, nosniff, no-referrer, restrictive CSP
pub fn not_found() / unauthorized() / ended() / offline() / app_not_running(port) / bad_gateway() / rate_limited() -> Response<Body>;

// ratelimit.rs — fixed 60s window; IPv4-mapped → IPv4; IPv6 bucketed per /64; 0 disables
pub struct RateLimiter; impl RateLimiter { pub fn new(per_min: u32) -> Self; pub fn check(&self, ip: IpAddr) -> bool; }
```

Zone host (`<preview_zone>`): `/__access/{port}-{id}/{token}` and `/__login`
(`gatehost.rs`). Sign-in never runs on a preview origin.

Edge order: label → `/__access/*` and `/__login` (redirect to the zone host) →
tunnel lifecycle (404/410) → gate (with the
same-tunnel CORS preflight exception) → `/__cockpit/*` → declared port → proxy.

## TLS / ACME / DNS (`tls.rs`, `sni.rs`, `acme.rs`, `dns/*`)

```rust
// tls.rs
pub struct CertStore;   // manual Debug; implements rustls::server::ResolvesServerCert
impl CertStore {
    pub fn new(cert_dir: PathBuf) -> Arc<Self>;
    pub fn reload(&self) -> anyhow::Result<bool>;   // keyed on fullchain.pem mtime; Ok(true) if swapped
    pub fn not_after(&self) -> Option<i64>;
    pub fn is_loaded(&self) -> bool;
}
pub fn server_config(store: Arc<CertStore>) -> rustls::ServerConfig;   // ALPN h2, http/1.1
pub async fn watch(store: Arc<CertStore>);                             // reload every 60s
pub fn write_cert_files(cert_dir: &Path, fullchain_pem: &str, key_pem: &str, names: &[String]) -> anyhow::Result<()>;
pub enum CertStatus { Missing, NamesChanged, NeedsRenewal, Valid { not_after: i64 } }
pub fn cert_status(cfg: &Config) -> CertStatus;   // renew when < 1/3 of the cert's own lifetime remains

// sni.rs
pub enum SniPeek { Sni(String), NoSni, NotTls }
pub async fn peek_sni(tcp: &TcpStream, timeout: Duration) -> std::io::Result<SniPeek>; // peek only

// acme.rs
pub async fn issue(cfg: &Config) -> anyhow::Result<()>;
pub async fn renew_loop(state: Arc<AppState>);   // first check after 60s, then 12h (1h after a failure)

// dns/mod.rs
pub struct RecordRef { pub name: String, pub rtype: String, pub value: String, pub id: Option<String> }
pub enum Provider { Cloudflare(..), Hetzner(..), DigitalOcean(..), Route53(..) }
impl Provider {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self>;
    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()>; // replaces the whole set
    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef>;
    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()>;
}
pub async fn resolve_public(fqdn: &str, rtype: &str) -> anyhow::Result<Vec<String>>;   // DoH, union of two resolvers
pub async fn wait_for_txt(fqdn: &str, value: &str, timeout: Duration) -> anyhow::Result<()>;
```

`acme-account.json` is `{ "directory": <url>, "credentials": <AccountCredentials> }`
(0600); a directory change registers a new account.

## Setup (`setup/{mod,prompt,os,coturn,firewall,systemd}.rs` + `install.sh`)

```rust
#[derive(clap::Args)] pub struct SetupArgs { pub staging: bool, pub skip_dns: bool, pub skip_self_test: bool }
pub async fn run(config_path: &Path, args: SetupArgs) -> anyhow::Result<()>;
pub use coturn::detect_coturn_user;   // fn() -> Option<String>
```

Prompts return `anyhow::Result<T>` (a closed stdin fails instead of looping).

## API, control plane, listener, commands

```rust
// api.rs — axum router built once (LazyLock), run with tower::ServiceExt::oneshot; body collected into util::full
pub async fn handle(state: Arc<AppState>, req: Request<Incoming>) -> Response<Body>;

// control.rs — token checked before the upgrade (401/410 JSON), then WS → ws_bridge → Yamux server
pub async fn handle_connect(state: Arc<AppState>, req: Request<Incoming>) -> Response<Body>;

// listener.rs
pub async fn run_https(state: Arc<AppState>) -> anyhow::Result<()>;
pub async fn run_http_redirect(state: Arc<AppState>) -> anyhow::Result<()>;

// purge.rs
pub async fn run(state: Arc<AppState>);

// commands.rs
pub async fn serve(config_path: &Path) -> anyhow::Result<()>;
pub async fn token_rotate(config_path: &Path) -> anyhow::Result<()>;
pub async fn status(config_path: &Path) -> anyhow::Result<()>;
pub async fn backup(config_path: &Path, out: &Path) -> anyhow::Result<()>;
pub async fn cert_renew(config_path: &Path, force: bool) -> anyhow::Result<()>;
```

Listener: SNI peek (only when WebRTC is enabled) → `turn_host` (or no SNI, if
`passthrough_no_sni`) is spliced raw to `coturn_tls_addr`; everything else gets
TLS → hyper-util `auto` (h1 + h2, `enable_connect_protocol`,
`serve_connection_with_upgrades`, 30s header read timeout). Routing is by
`Host`, never SNI: `host == tunnel_host && path == CONNECT_PATH` →
`control::handle_connect`; `host == api_host` → `api::handle`; host ends with
`.<preview_zone>` → `edge::handle(label)`; else `pages::not_found()`.

API routes: `GET /healthz`, `GET /v1/openapi.json` (admin), `POST|GET /v1/tunnels`,
`GET|PATCH|DELETE /v1/tunnels/{id}`, `POST /v1/tunnels/{id}/access-links`,
`DELETE /v1/access-links/{id}`, `POST /v1/tunnels/{id}/turn-credentials`.
Creates return `201`. Errors are `{"error":{"code","message"}}`.

## Client (`crates/client`, binary `cockpit-preview`)

Modules: `main` (CLI, single-threaded runtime, ring provider), `paths`, `state`
(`Persisted`, not `Debug`), `ipc` (`Request`, `Response`, `Status`, `ConnState`,
`ensure_daemon`, `call`), `daemon` (`Daemon`, `Link`, `Reply`, `Welcome`, IPC
server, lock file), `session` (dial, backoff, control stream, data streams, ICE
refresh), `ice` (env vars, shell quoting, `GET /ice`), `commands`.

State dir: `$XDG_RUNTIME_DIR/cockpit-preview/` (else `/tmp/cockpit-preview-<uid>/`),
0700, holding `daemon.sock`, `daemon.lock`, `state.json` (0600), `daemon.log`.

## Pinned crate versions (from `Cargo.lock`)

tokio 1, hyper 1.12, hyper-util 0.1.21, http-body-util 0.1.5, axum 0.8.9 (path params `{id}`, native async extractors),
utoipa 5.5, rustls 0.23.46 (ring; provider installed in `main`), tokio-rustls 0.26.6, rustls-pemfile 2.2,
tokio-tungstenite / tungstenite 0.26.2 (`Message::Binary(Bytes)`; `WebSocketConfig` is `#[non_exhaustive]` with
builder setters), tokio-yamux 0.3.20 (`Session::new_server/new_client`, `Session::control(&self)`,
`Control::open_stream(&mut self).await`, `Control::close(&mut self).await`,
`Session: Stream<Item = io::Result<StreamHandle>>`, `StreamHandle: AsyncRead + AsyncWrite + Unpin`,
`Error: Display`), instant-acme 0.7.2 (ring + hyper-rustls defaults), rcgen 0.13.2, rusqlite 0.32 (bundled),
reqwest 0.12.28 (rustls-tls, json), x509-parser 0.16, time 0.3.55 (no `formatting`; `Date: Display`),
hmac 0.12, sha1/sha2 0.10.

tokio-tungstenite is declared with `default-features = false` in the workspace;
the server enables `handshake`, the client `connect` + `rustls-tls-webpki-roots`.
