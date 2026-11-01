# Security and performance audit — 2026-11-01

Auditor: Codex `gpt-6.1-sol` (read-only run against `b225211`), given the threat
model in the prompt: unauthenticated visitors, malicious preview apps, malicious
sandboxes, client-token holders, local users, and password brute force. Every
finding below was checked against the code before acting on it. Fixes landed in
`06afad3` and are deployed to `tunnel.kapic.io`.

## Status

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Preview service workers can intercept `/__login` and `/__access/` on the preview origin | high | **Open** — design change, see below |
| 2 | Gate cookie authorizes cross-tunnel WebSockets (and writes) | high | **Fixed** — reproduced before the fix (101/200), 403 after |
| 3 | Argon2 verification has no global bound; slow login bodies | high | **Fixed** — 2 concurrent, 3 s wait then "busy"; 10 s body deadline |
| 4 | No response-header deadline; no per-tunnel stream limit | high | **Fixed** — 120 s header deadline (504); 512 streams per tunnel (503) |
| 5 | Tunnel creation can race client deletion and survive | medium | **Fixed** — client checked inside the same `INSERT` |
| 6 | Merged grant expiry outlives password revocation | medium | **Fixed** — per-source expiry; password change caps at the link's expiry |
| 7 | Blocked control writes prevent teardown | medium | **Fixed** — writes cancellable, 30 s write timeout, bounded writer join |
| 8 | Local `/ice` endpoint serves TURN credentials to any local user | medium | **Open** — changes the agent-facing contract, see below |
| 9 | Enrollment code passed in argv | medium | **Fixed** — `cockpit-preview login` prompts (no echo) or reads stdin |
| 10 | Every request opens a new Yamux stream + loopback connection | medium (perf) | **Open** — origin connection pooling |
| 11 | WebSocket bridge serializes both directions | medium (perf) | **Open** — split read/write pumps |
| 12 | Yamux receive backpressure stalls unrelated streams | medium (perf) | **Open** — dependency-level (tokio-yamux 0.3.20) |
| 13 | Each bridge read allocates and flushes one WebSocket message | medium (perf) | **Open** — write batching |
| 14 | DB misses queue unbounded work on one connection | medium (perf) | **Partly fixed** — public tunnels skip session lookups; no bounded DB queue yet |
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

## Open items and recommendations

**#1 — login page on the preview origin (high).** A preview app runs on the
same origin as the login form and access-link redemption, so a service worker
it registers can serve a fake form later. Blocking service workers would break
common dev tooling (e.g. Mock Service Worker), so the right fix is to move
`/__login` and `/__access/` to the server host (`tunnel.kapic.io`), which no
preview controls. The gate cookie is already `Domain=<zone>`, so a cookie set
there covers every preview; the preview would redirect to
`https://<zone>/__login?t=<tunnel>&next=<host+path>` and back. Note that this
only protects against a *different* party's app: a preview app can always show
its own fake login page to its own visitors.

**#8 — `/ice` on loopback (medium).** Any local user on a shared host can read
the sandbox's TURN credential. Sandboxes are normally single-user, so the risk is
low there. Fix by requiring a per-daemon secret in a header (exported as
`COCKPIT_ICE_TOKEN` next to `COCKPIT_ICE_URL`), or by pointing agents at the
0600 ICE file only. Either changes what agents are told, so it needs a decision.

**#10–#13 — per-request cost (~2 ms CPU at ~950 req/s on 2 vCPUs).** In
expected order of payoff: (a) batch WebSocket writes and reuse buffers in
`ws_bridge` (#13) and drive the two directions independently (#11) — the 43%
kernel time in the load test points at many small writes; (b) pool HTTP/1.1
origin connections per tunnel connection and port (#10); (c) replace or patch
the Yamux implementation so one slow stream cannot stall the transport (#12).
Each should be measured with the existing load harness before and after.

**#14 — bounded DB admission.** Invalid-but-plausible cookies still reach SQLite
on gated tunnels. A small negative cache keyed by session hash (seconds) plus a
bounded queue in front of `Db::call` would cap this.
