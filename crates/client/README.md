# cockpit-preview

Sandbox client for cockpit-tunnel. Exposes local ports (HTTP, WebSockets, SSE)
through the tunnel server over one outbound WSS connection, and keeps TURN
credentials fresh for server-side WebRTC peers. Unix only (Linux, macOS).

## Commands

```sh
COCKPIT_TUNNEL_TOKEN=cttun_… cockpit-preview expose 3000   # starts the daemon if needed, adds the port
cockpit-preview expose 8080 5173                            # adds ports to the running daemon
cockpit-preview unexpose 8080
cockpit-preview status                                      # human-readable
cockpit-preview status --json                               # for the agent runtime
cockpit-preview ice --format json|env|file [--fresh]        # current ICE config
cockpit-preview ice --exec -- npm run dev                   # run a command with TURN_*/ICE_* set
cockpit-preview stop                                        # stop the daemon and forget its ports
```

The first command starts one background daemon; later commands talk to it over
a Unix socket. If the daemon dies (crash, OOM kill), the next command restarts
it from the persisted state with the same token and ports.

`expose` with a `COCKPIT_TUNNEL_TOKEN` different from the daemon's switches the
daemon to the new tunnel (ports from the old tunnel are dropped).

`status --json`:

```json
{
  "state": "connected",
  "tunnel_id": "ab12cd3efg",
  "host_template": "{port}-ab12cd3efg.previews.example.com",
  "ports": [{ "port": 3000, "host": "3000-ab12cd3efg.previews.example.com", "connected": true }],
  "last_error": null,
  "ice_file": "/run/cockpit-preview/ice.json"
}
```

`state` is one of `connecting`, `connected`, `revoked` (tunnel deleted or
expired, or token rejected), `replaced` (another client connected with the same
token), `stopped` (no daemon and no tunnel).

## Logged-in machines

Outside a sandbox, a machine can create its own tunnels instead of receiving a
tunnel token:

```sh
cockpit-preview login 'ctenr_…@tunnel.example.com'   # from `cockpit-tunnel-server client add <name>`
cockpit-preview share 3000 [5173 …]                    # link-only; prints a one-time link per port
cockpit-preview share 3000 --public                    # anyone with the URL
COCKPIT_SHARE_PASSWORD=… cockpit-preview share 3000 --password [--username bob]
cockpit-preview share 3000 --link                      # back to links only
cockpit-preview link [--port 3000] [--reusable] [--ttl 1h]
cockpit-preview stop                                   # also deletes the shared tunnel
cockpit-preview logout
```

The login (server and client token) is saved in
`$XDG_CONFIG_HOME/cockpit-preview/login.json` (0600). `share` reuses the tunnel
it made while the daemon still serves it, so one link covers every shared
port. `expose` also uses the logged-in server when `COCKPIT_TUNNEL_SERVER` is unset.

## Environment

| Variable | Meaning |
|---|---|
| `COCKPIT_TUNNEL_TOKEN` | Tunnel token (`cttun_…`). Pass by environment, never argv. |
| `COCKPIT_TUNNEL_SERVER` | Tunnel server, e.g. `wss://tunnel.example.com` (`https://` and bare hosts are accepted). Defaults to `COCKPIT_TUNNEL_DEFAULT_SERVER` baked in at build time. |
| `COCKPIT_ICE_FILE` | ICE file the daemon keeps fresh. Default `/run/cockpit-preview/ice.json` if writable, else `<state dir>/ice.json`. |
| `COCKPIT_ICE_PORT` | Port of `http://127.0.0.1:<port>/ice` (default `47801`). |
| `RUST_LOG` | Log filter (daemon default `info`, commands `warn`). |

State lives in `$XDG_RUNTIME_DIR/cockpit-preview/` (else
`/tmp/cockpit-preview-<uid>/`, mode 0700): `daemon.sock`, `state.json` (0600,
holds the token), `daemon.log`.

`ice --format env` prints `export K='v'` lines for `TURN_URLS`
(comma-separated `turn:`/`turns:` URLs), `TURN_USERNAME`, `TURN_CREDENTIAL`,
`ICE_SERVERS_JSON` (JSON array), `ICE_EXPIRES_AT` (unix seconds), and
`COCKPIT_ICE_FILE`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Error (message on stderr) |
| 3 | Revoked: the tunnel was deleted or expired, or the token was rejected. Create a new tunnel. |
| 4 | Replaced: another client connected with this token. The daemon stopped instead of fighting it. |

The daemon exits with the same codes. A revoked daemon is never restarted until
a different token is supplied; a replaced one is restarted only by an explicit
`expose`.

## Harness usage

`generate_preview(port)` runs in the agent runtime, not in the sandbox:

1. `POST /v1/tunnels` with the admin token (or reuse this sandbox's live tunnel).
2. Run in the sandbox: `COCKPIT_TUNNEL_TOKEN=cttun_… cockpit-preview expose <port>`.
3. Poll `GET /v1/tunnels/{id}` (or `cockpit-preview status --json`) until the port is connected.
4. Export into the agent shell: `COCKPIT_ICE_FILE`, `COCKPIT_ICE_URL=http://127.0.0.1:47801/ice`,
   `COCKPIT_PREVIEW_HOST_TEMPLATE`, and optionally `COCKPIT_ICE_SERVERS` (snapshot from `ice --format json`).
5. On "stop preview": `DELETE /v1/tunnels/{id}`; the daemon exits and `status --json` reports `revoked`.

Server-side WebRTC peers (SFU, aiortc, Pion, voice agents) need TURN over TLS on
443. Restart the dev server with the credential in its environment:

```sh
cockpit-preview ice --exec -- npm run dev
# or
eval "$(cockpit-preview ice --format env)"; npm run dev
```

(`eval "$(…)" npm run dev` on one line does not work: `eval` joins its
arguments into one string.) Values loaded at process start expire with the
credential TTL (24h); long-running peers should re-read `$COCKPIT_ICE_FILE` or
`GET http://127.0.0.1:47801/ice`. Browser code needs nothing: the edge injects
ICE config into preview pages.

**Never write TURN credentials, ICE config, or preview hostnames into source
files or committed `.env` files.** They expire, and the preview host is not a
deployment URL. Read them from the environment or the ICE file at runtime.
