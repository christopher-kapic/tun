# Onboarding, access modes, and clients

Decisions (2026-10-31):

- Setup asks for **one server hostname**; everything else is derived and confirmed.
- Access modes: **link** (default), **password**, **public**. The tunnel *creator*
  (admin token or client token) picks the mode at creation and can change it.
  The sandbox (tunnel token) cannot.
- Previews stay under the server hostname (`*.tunnel.kapic.io`); no separate domain.
- Per-machine **client tokens**, enrolled with a one-time code.
- Server runs **rootless** (one sudo command at install time).

Target layout for `--host tunnel.kapic.io`:

| Name | Value |
|---|---|
| API + sandbox tunnel | `tunnel.kapic.io` |
| Previews | `*.tunnel.kapic.io` |
| TURN (WebRTC only) | `turn.tunnel.kapic.io` (covered by the wildcard record) |
| DNS zone | auto-detected from the provider token (`kapic.io`) |
| DNS records | `tunnel.kapic.io A`, `*.tunnel.kapic.io A` |

## 1. Setup: one hostname, validate as you go, rootless

- [x] `setup --host <name>`; preview zone = host, api = tunnel = host, turn = `turn.<host>`.
      `--preview-zone`, `--turn-host` override. Show the derived layout and confirm.
- [x] Drop the `base_domain` prompt (field kept only so old configs still parse).
- [x] Cloudflare: verify the token immediately; detect the zone from the zones the token can see.
- [x] Always verify DNS before ACME (also with `--skip-dns`, which now only skips *creating*
      records). Name Cloudflare-proxied answers explicitly ("turn off the orange cloud").
- [x] Secret prompts show the last 4 characters of the kept value.
- [x] Non-interactive: `--yes`, `--email`, `--dns-token-file`, `--frame-ancestors`.
- [x] Self-test timeout names the likely cause (cloud firewall on 80/443).
- [x] Rootless (non-root user) mode:
  - config `~/.config/cockpit-tunnel/config.toml`, data `~/.local/share/cockpit-tunnel`,
    binary `~/.local/bin/cockpit-tunnel-server`, systemd **user** unit.
  - preflight checks `ip_unprivileged_port_start <= 80` and lingering; if missing, print the
    one sudo command (also migrates an existing system install) and stop.
  - no service user, no chown, no host firewall changes; WebRTC refused for now (coturn needs root).
  - `status`, `token rotate`, `cert renew` work without root in this mode.
- [x] Setup installs its own binary to the service path (system: `/usr/local/bin`).

## 1b. Iframes (decided 2026-11-01)

- [x] Gate cookie `SameSite=None; Secure; HttpOnly; Partitioned` so previews authenticate inside
      cross-site iframes (Lax cookies are dropped there). A cookie set inside an iframe belongs to
      that parent site's partition; a direct visit needs its own link.
- [x] Server-wide `frame_ancestors` list replaces `dashboard_origin` (old value migrates).
      Default `*` (any site). A specific list is always enforced: it replaces the app's own
      `frame-ancestors`, or is added as its own CSP policy when the app sends none.
      Per-tunnel overrides can come later without a config migration.
- [x] Browser test matrix (same-site and cross-site iframe, app CSP, WebSocket) green on the
      rootless install (headless Chromium 156, 2026-11-01).

## 2. Access modes

- [x] `access: link | password | public` on `POST/PATCH /v1/tunnels`; stored per tunnel.
- [x] Access links work in every mode; in `password` mode an expired/used link shows the login page.
- [x] `password`: argon2 hash; login form on `/__login` (works in iframes); sets the same gate session.
- [x] `public`: skip the gate; everything else unchanged.
- [x] Tests for each mode, including mode changes on a live tunnel (DB unit tests for revocation
      and migration; 16-check browser run on tunnel.kapic.io, 2026-11-01).

## 3. Clients

- [ ] `client add <name>` → prints `cockpit-preview login '<code>@<host>'`; code single-use, 15 min.
- [ ] `POST /v1/clients/enroll` trades the code for a long-lived `ctcli_` token.
- [ ] `client list` (name, created, last used, tunnel count), `client delete <name>`
      (revokes token, deletes its tunnels, cancels pending codes). Same via admin API.
- [ ] Client tokens can create/list/patch/delete their own tunnels and mint their access links only.
- [ ] `cockpit-preview login`, `cockpit-preview share <port> [--public | --password ...]`.
- [ ] Drop the need for a baked-in server URL (login stores it).
