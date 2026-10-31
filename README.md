# cockpit-tunnel

Preview relay for the app-building harness. A sandbox with no public IP and
only outbound 443 runs `cockpit-preview`, which keeps one WSS connection to a
VPS running `cockpit-tunnel-server`. Visitors open
`https://{port}-{id}.previews.example.com`, pass a cookie gate minted from a
click-time access link, and reach the sandbox port over HTTP/1.1, HTTP/2,
WebSockets, SSE, and (through coturn) WebRTC. Private project.

Behavior is specified in [`cockpit-tunnel-plan.md`](cockpit-tunnel-plan.md);
module interfaces are in [`docs/module-contracts.md`](docs/module-contracts.md).

**Status:** first-pass implementation, written without compiling. Start with
the [first build pass](#first-build-pass) checklist.

## Workspace layout

```text
Cargo.toml                 workspace, shared dependency versions, release profile
install.sh                 curl | sh installer: download, verify, exec `setup`
crates/protocol/           wire messages, constants, Yamux config, WebSocket↔bytes bridge
crates/server/             cockpit-tunnel-server (VPS)
  src/main.rs              CLI: serve | setup | token rotate | status | backup | cert renew
  src/commands.rs          non-interactive subcommands; `serve` wires everything together
  src/listener.rs          :443 (SNI peek → coturn passthrough, else TLS + hyper auto) and :80 redirect
  src/edge.rs proxy.rs     visitor edge: lifecycle, gate, reserved paths, forwarding, WebSockets
  src/gate.rs              gate cookie and /__access/{token}
  src/headers.rs           hop-by-hop, Origin/Location/Set-Cookie/CSP/iframe rewrites
  src/inject.rs            streaming ICE <script> injection + CSP hash
  src/pages.rs ratelimit.rs
  src/api.rs               management API (axum, utoipa OpenAPI)
  src/control.rs           sandbox control plane (/v1/connect → Yamux)
  src/registry.rs state.rs live connections, shared state and caches
  src/db.rs purge.rs       SQLite and the hourly purge
  src/tls.rs sni.rs acme.rs dns/   certificate store, ClientHello peek, DNS-01 issuance, DNS providers
  src/ice.rs metrics.rs    TURN REST credentials, Prometheus text on 127.0.0.1:9464
  src/setup/               interactive wizard (prompts, distro packages, coturn, firewall, systemd)
crates/client/             cockpit-preview (sandbox); see crates/client/README.md
docs/module-contracts.md
```

## Build

Requires Rust 1.85+. The C toolchain is needed for `ring` and the bundled SQLite.

```sh
cargo build --release -p cockpit-tunnel-server
# Bake the default tunnel server into the sandbox client (COCKPIT_TUNNEL_SERVER overrides it at runtime):
COCKPIT_TUNNEL_DEFAULT_SERVER=wss://tunnel.example.com cargo build --release -p cockpit-preview
cargo test --workspace
```

Static Linux binaries (what `install.sh` downloads, and what sandboxes run):

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p cockpit-tunnel-server
cargo build --release --target x86_64-unknown-linux-musl -p cockpit-preview
# aarch64 from x86_64 needs a cross C toolchain, e.g. `cargo zigbuild` or `cross`:
cargo zigbuild --release --target aarch64-unknown-linux-musl -p cockpit-tunnel-server
```

`cockpit-preview` builds on Linux and macOS only (`compile_error!` elsewhere).

## Release and install

1. Publish `cockpit-tunnel-server-<target>` for `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl`, a `SHA256SUMS` file covering them, and
   `SHA256SUMS.minisig` (`minisign -Sm SHA256SUMS`).
2. Before publishing `install.sh`, replace `DOWNLOAD_BASE` and `MINISIGN_PUBKEY`.
   Without a real key the installer refuses to run unless `COCKPIT_ALLOW_UNSIGNED=1`
   (the SHA-256 is still checked).
3. On the VPS (Debian 12+, Ubuntu 22.04+, Fedora 40+, RHEL/Alma/Rocky 9+):

   ```sh
   curl -fsSL https://<private-host>/install.sh | sudo sh            # add `-s -- --staging` to test against LE staging
   ```

   The installer verifies the binary, installs it to `/usr/local/bin`, and
   execs `cockpit-tunnel-server setup </dev/tty`. The wizard asks for domains,
   ACME email, DNS provider (Cloudflare, Hetzner, DigitalOcean, Route53) and
   token, and whether to enable WebRTC; then creates the service user and
   directories, writes `/etc/cockpit-tunnel/config.toml`, creates and verifies
   DNS records, issues the certificate (DNS-01), configures coturn and the
   firewall, installs the systemd unit, self-tests, and prints the admin token
   once. Re-running `setup` changes nothing unless an answer changed.

Admin commands: `cockpit-tunnel-server status`, `token rotate`, `backup <path>`,
`cert renew [--force]` (rotate/renew need root).

## First build pass

Nothing here has been compiled. Suggested order:

0. Delete any existing dev `cockpit-tunnel.db`: the gate schema changed
   (`gate_grants.access_link_id` → `gate_grant_links`) and `CREATE TABLE IF NOT
   EXISTS` will not migrate an old file.
1. `cargo build` **without** `--locked` first: the workspace now declares
   `tokio-tungstenite` with `default-features = false` (server: `handshake`,
   client: `connect` + `rustls-tls-webpki-roots`), so the untracked
   `Cargo.lock` may need to drop packages.
2. `cargo build -p cockpit-tunnel-protocol`, then `-p cockpit-tunnel-server`,
   then `-p cockpit-preview`; then `cargo test --workspace` and
   `cargo clippy --workspace --all-targets`.

### `verify:` notes left in the code

These could not be checked offline:

- [ ] `crates/server/src/dns/hetzner.rs:4` — Hetzner Cloud DNS endpoints and bodies (`api.hetzner.cloud/v1`, RRSets) against the current API reference.
- [ ] `crates/server/src/dns/hetzner.rs:26` — `/zones/{id_or_name}` accepts the zone *name*.
- [ ] `crates/server/src/dns/hetzner.rs:75` — `actions/add_records` creates a missing RRSet (else fall back to `POST /rrsets` on 404).
- [ ] `crates/server/src/dns/hetzner.rs:85` — `actions/remove_records` deletes the RRSet when its last record goes.
- [ ] `crates/server/src/edge.rs:158` — hyper 1.x `Incoming::is_end_stream()` is true for a bodyless h1 request and for an h2 request whose HEADERS frame carried END_STREAM (otherwise real preflights get 401).

### Notes resolved during integration

The implementers' other `verify:` notes were checked against the sources of the
exact locked versions, and the comments were removed:

- tokio-yamux 0.3.20: `StreamHandle` re-exported at the root and `Unpin`; `Session::control(&self)`; `Control::open_stream(&mut self)` and `Control::close(&mut self)` are async; `Session: Stream<Item = io::Result<StreamHandle>>`; `Error: Display`.
- tungstenite 0.26.2: `WebSocketConfig` is `#[non_exhaustive]` with `max_frame_size` / `max_message_size` setters; `derive_accept_key(&[u8])`; `Error::Http(Response<Option<Vec<u8>>>)`; `connect_async_with_config(req, Option<cfg>, disable_nagle)`.
- hyper-util 0.1.21: `Http2Builder::enable_connect_protocol`, `timer` on both builders, `Http1Builder::header_read_timeout`, `serve_connection_with_upgrades`.
- instant-acme 0.7.2: `Order::certificate` re-polls while `Processing`; `Problem { r#type, detail }`; `NewOrder { identifiers: &[..] }`; `Account::create(&NewAccount, url, None) -> (Account, AccountCredentials)`; `refresh() -> &OrderState`; `ChallengeType: PartialEq`; ring is the default backend (no aws-lc).
- rcgen 0.13.2: `csr.der()` → `&CertificateSigningRequestDer`, which derefs to `[u8]`.
- utoipa 5.5: `OpenApi.components: Option<Components>`; `Http::new(HttpAuthScheme)`.
- axum 0.8.9: `Router<()>` is `Sync` (asserted upstream), so a `LazyLock<Router<Arc<AppState>>>` static is fine.
- x509-parser 0.16: `pem::parse_x509_pem`, `Pem::parse_x509`, `X509Name: Display`.
- time 0.3.55: `Date: Display` without the `formatting` feature.
- reqwest 0.12.28: `RequestBuilder::query` (no feature gate), `ClientBuilder::local_address`, `danger_accept_invalid_certs` with `rustls-tls`.
- hyper 1.12: `Incoming: Send + Sync` (asserted upstream), needed for `util::Body`.

### Runtime checks the compiler cannot do

- [ ] systemd `PathChanged=` on `fullchain.pem` fires when `tls::write_cert_files` renames a new file into place (setup's coturn restart unit).
- [ ] The tungstenite client offers no ALPN, so the server's hyper `auto` builder speaks HTTP/1.1 to it and the `101` upgrade path is used.
- [ ] HTTP/2 Extended CONNECT WebSockets through `hyper::upgrade::on` on the visitor side (Chrome/Firefox over h2).
- [ ] `ws_bridge`: pongs are flushed only on the next send; both sides ping every 25s, which is well under the 62.5s dead-peer limit.
- [ ] TURN SNI spike: browsers and libwebrtc/Pion/aiortc send SNI on `turns:` (no-SNI hellos are routed to coturn by default anyway).
- [ ] The rest of the plan's "Tests required before done" list.
