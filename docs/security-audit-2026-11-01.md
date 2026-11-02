# Security and performance audit — 2026-11-01

Auditor: Codex `gpt-6.1-sol` (read-only run against `b225211`), given the threat
model in the prompt: unauthenticated visitors, malicious preview apps, malicious
sandboxes, client-token holders, local users, and password brute force. Every
finding below was checked against the code before acting on it. Fixes landed in
`06afad3` and are deployed to `tunnel.kapic.io`.

## Status

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Preview service workers can intercept `/__login` and `/__access/` on the preview origin | high | **Fixed** — sign-in moved to the zone host (`dfe4071`) |
| 2 | Gate cookie authorizes cross-tunnel WebSockets (and writes) | high | **Fixed** — reproduced before the fix (101/200), 403 after |
| 3 | Argon2 verification has no global bound; slow login bodies | high | **Fixed** — 2 concurrent, 3 s wait then "busy"; 10 s body deadline |
| 4 | No response-header deadline; no per-tunnel stream limit | high | **Fixed** — 120 s header deadline (504); 512 streams per tunnel (503) |
| 5 | Tunnel creation can race client deletion and survive | medium | **Fixed** — client checked inside the same `INSERT` |
| 6 | Merged grant expiry outlives password revocation | medium | **Fixed** — per-source expiry; password change caps at the link's expiry |
| 7 | Blocked control writes prevent teardown | medium | **Fixed** — writes cancellable, 30 s write timeout, bounded writer join |
| 8 | Local `/ice` endpoint serves TURN credentials to any local user | medium | **Fixed** — `Authorization: Bearer $COCKPIT_ICE_TOKEN` required (`dfe4071`) |
| 9 | Enrollment code passed in argv | medium | **Fixed** — `cockpit-preview login` prompts (no echo) or reads stdin |
| 10 | Every request opens a new Yamux stream + loopback connection | medium (perf) | **Fixed** — origin connection pool (`376f0c0`) |
| 11 | WebSocket bridge serializes both directions | medium (perf) | **Fixed** — one pump task per direction (`5de358e`) |
| 12 | Yamux receive backpressure stalls unrelated streams | medium (perf) | **Fixed** — switched to rust-yamux (`6d95dfd`); reproduced live before |
| 13 | Each bridge read allocates and flushes one WebSocket message | medium (perf) | **Fixed** — writer drains the pipe before one flush (`5de358e`) |
| 14 | DB misses queue unbounded work on one connection | medium (perf) | **Fixed** — public tunnels skip lookups; 32 visitor-lookup slots, 2 s wait, then 503 (`376f0c0`) |
| 15 | Missing `expires_at` / `client_id` indexes | medium (perf) | **Fixed** — both indexes; 15 s sweep no longer scans |
| 16 | Rate limiter prunes with a full scan on every check | low (perf) | **Fixed** — prune at most every 10 s; hard cap of 100k addresses (fail closed) |

## Verification

- Unit tests: 63 server + 5 client, including new tests for the origin policy,
  merged-grant revocation, the client-deletion race, and the indexes.
- Live tests against `tunnel.kapic.io` after deploying:
  - origin policy: 12/12 (`gated WS, other tunnel's Origin` → 403; same tunnel,
    other site, and non-browser → 101; public tunnels unaffected);
  - clients end to end: 24/24 (login via stdin, share/link/stop, isolation);
  - access modes in a browser: 16/16; iframes with fetch + WebSocket: 5/5.

## Follow-up (2026-11-02): open items closed

All items were approved as "best long term" and are deployed to `tunnel.kapic.io`.

**#1 — sign-in on the zone host.** Links are now
`https://<zone>/__access/{port}-{id}/{token}` (API field `url`; requests take an
optional `port`), and password tunnels redirect page loads to
`https://<zone>/__login?to={port}-{id}&next=…`. The zone host serves no preview
content, so no preview's service worker can see a token or a password. The form's
CSP allows only the target preview in `form-action` and applies the configured
`frame-ancestors`. Old preview-host `/__access/{token}` and `GET /__login`
redirect to the zone host; `POST` there is gone. Verified live: clients e2e 30/30, browser access modes 16/16 (including sign-in inside a
cross-site iframe), iframes 5/5, origin policy 12/12.

**#8 — `/ice` token.** The daemon keeps a random `ctice_…` token in
`<state dir>/ice-token` (0600, survives restarts). `ice --format env` and
`ice --exec` export `COCKPIT_ICE_URL` and `COCKPIT_ICE_TOKEN`. Verified live:
no token → 401, wrong token → 401, right token → served.

**#10–#14 — throughput.** Measured with the load harness (30 public tunnels,
240 keep-alive connections from a home connection, 30 s; 64 KiB runs: 10
tunnels, 20 connections, 20 s). The metric is the server process's CPU time per
request (`/proc/<pid>/stat`), which is stable across network noise; req/s and
latency are bound by the home link and shown for direction only.

| Step | CPU/req, small | req/s | p50 | CPU/req, 64 KiB | Mbit/s |
|---|---|---|---|---|---|
| Baseline (`ff5f9ba`) | 0.76–0.83 ms | 1,494–1,552 | 140 ms | 3.66 ms | 142 |
| Direct WebSocket adapter (`4df3c21`, reverted) | 0.90–0.92 ms | 1,339–1,363 | 157 ms | — | — |
| Split pump, batched flush (`5de358e`) | 0.77 ms | 1,602 | 131 ms | 3.28 ms | 157 |
| + origin pool (`376f0c0`) | 0.56 ms | 1,962 | 105 ms | 2.23 ms | 226 |
| + rust-yamux (`6d95dfd`) | 0.57–0.60 ms | 1,953–1,983 | 106 ms | 2.58–2.77 ms | 177–216 |

The direct adapter flushed the WebSocket on every Yamux poll and cost more TLS
writes than the pump, so it was replaced. Client daemon CPU per small request fell
from 0.24 ms to 0.09 ms with the pool.

**#12 — head-of-line blocking.** `crates/protocol/tests/yamux_hol.rs` shows one
unread stream freezing the others under tokio-yamux. Live, before the switch: with
one visitor reading a 10 MB response at 1 KB/s, other requests to the same
tunnel timed out (10 s) for about 30 s. After the switch (server first, with old
clients still on tokio-yamux, then both): every request answered in 0.07–0.56 s
during the same slow read. The switch costs nothing measurable on small
requests, but bulk transfers use about 15% more server CPU than with tokio-yamux.
That is still 30% below the baseline. In-process, mux plus bridge moves about
1,600 MiB per CPU-second (`tests/mux_bulk.rs`, ignored by default), so the
difference is probably in how writes reach TLS. That is a possible follow-up.
Under the same 8-stream bulk transfer, tokio-yamux did not finish within 5
minutes.

**Regression after all steps** (new server and clients): clients e2e 30/30,
browser access modes 16/16, iframes with fetch and WebSocket 5/5, origin policy
12/12, unit tests 69 server + 7 client + 8 protocol. Old clients (tokio-yamux)
pass the origin policy suite against the new server.

**Residual.** With rust-yamux each stream may buffer its full 256 KiB window
while its reader is stalled. A tunnel owner who is also its own slow visitor can
hold up to 512 × 256 KiB (128 MiB) of server memory per connected tunnel. This
bound existed before in a different shape. A server-wide memory budget for
stream buffers would cap it; not done.
