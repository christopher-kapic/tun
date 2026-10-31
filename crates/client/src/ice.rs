//! ICE config helpers and the local `GET /ice` endpoint for sandbox peers.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cockpit_tunnel_protocol::{IceConfig, IceServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::daemon::Daemon;

const MAX_REQUEST_HEAD: usize = 8 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// True when less than 25% of the credential's TTL remains (or it expired).
pub fn needs_refresh(ice: &IceConfig) -> bool {
    let remaining = ice.expires_at.saturating_sub(unix_now());
    remaining == 0 || remaining.saturating_mul(4) < ice.ttl_s
}

/// Variables for `ice --format env` and `ice --exec`.
pub fn env_vars(ice: &IceConfig, ice_file: &str) -> Vec<(&'static str, String)> {
    let turn: Vec<&IceServer> =
        ice.ice_servers.iter().filter(|s| s.username.is_some() && s.credential.is_some()).collect();
    let urls: Vec<&str> = turn
        .iter()
        .flat_map(|s| s.urls.iter())
        .map(String::as_str)
        .filter(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        .collect();
    let mut vars = vec![("TURN_URLS", urls.join(","))];
    if let Some(server) = turn.first() {
        vars.push(("TURN_USERNAME", server.username.clone().unwrap_or_default()));
        vars.push(("TURN_CREDENTIAL", server.credential.clone().unwrap_or_default()));
    }
    vars.push(("ICE_SERVERS_JSON", serde_json::to_string(&ice.ice_servers).unwrap_or_else(|_| "[]".to_string())));
    vars.push(("ICE_EXPIRES_AT", ice.expires_at.to_string()));
    vars.push(("COCKPIT_ICE_FILE", ice_file.to_string()));
    vars
}

/// POSIX single-quoting: safe inside `eval "$(...)"`.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

pub fn format_env(vars: &[(&'static str, String)]) -> String {
    vars.iter().map(|(k, v)| format!("export {k}={}\n", shell_quote(v))).collect()
}

/// Serve the current ICE config at `http://127.0.0.1:<port>/ice`. A taken port
/// only disables this endpoint; the ICE file still works.
pub async fn serve_http(daemon: Arc<Daemon>, port: u16) {
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(l) => l,
        Err(e) => {
            warn!(port, error = %e, "ICE HTTP endpoint disabled");
            return;
        }
    };
    info!(port, "ICE HTTP endpoint listening");
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HTTP_TIMEOUT, answer(&daemon, sock, port)).await {
                        Ok(Err(e)) => debug!(error = %e, "ICE HTTP request failed"),
                        Err(_) => debug!("ICE HTTP request timed out"),
                        Ok(Ok(())) => {}
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "ICE HTTP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn answer(daemon: &Daemon, mut sock: TcpStream, port: u16) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < MAX_REQUEST_HEAD {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&head);
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or_default().split('?').next().unwrap_or_default();

    let (status, body) = if !host_allowed(&head, port) {
        // DNS rebinding guard: a web page must not read credentials via a
        // hostname it controls that resolves to 127.0.0.1.
        ("403 Forbidden", r#"{"error":"forbidden"}"#.to_string())
    } else if method == "GET" && path == "/ice" {
        match daemon.current_ice() {
            Some(ice) => ("200 OK", serde_json::to_string(&ice).unwrap_or_default()),
            None => ("503 Service Unavailable", r#"{"error":"no ICE config yet"}"#.to_string()),
        }
    } else {
        ("404 Not Found", r#"{"error":"not found"}"#.to_string())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(response.as_bytes()).await?;
    sock.shutdown().await
}

fn host_allowed(head: &str, port: u16) -> bool {
    let host = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("host").then(|| value.trim().to_ascii_lowercase())
    });
    match host {
        // HTTP/1.0 clients may omit Host; only a browser can be rebound.
        None => true,
        Some(h) => {
            let with_port = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
            h == "127.0.0.1" || h == "localhost" || with_port.contains(&h)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn env_vars_pick_turn_urls() {
        let ice = IceConfig {
            ice_servers: vec![
                IceServer { urls: vec!["stun:turn.example.com:3478".into()], username: None, credential: None },
                IceServer {
                    urls: vec![
                        "turn:turn.example.com:3478?transport=udp".into(),
                        "turns:turn.example.com:443?transport=tcp".into(),
                    ],
                    username: Some("1:ab:sbx".into()),
                    credential: Some("c".into()),
                },
            ],
            expires_at: 1,
            ttl_s: 86400,
        };
        let vars = env_vars(&ice, "/run/cockpit-preview/ice.json");
        let get = |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("TURN_URLS").as_deref(),
            Some("turn:turn.example.com:3478?transport=udp,turns:turn.example.com:443?transport=tcp")
        );
        assert_eq!(get("TURN_USERNAME").as_deref(), Some("1:ab:sbx"));
        assert_eq!(get("ICE_EXPIRES_AT").as_deref(), Some("1"));
    }

    #[test]
    fn host_check_rejects_rebinding() {
        assert!(host_allowed("GET /ice HTTP/1.1\r\nHost: 127.0.0.1:47801\r\n\r\n", 47801));
        assert!(!host_allowed("GET /ice HTTP/1.1\r\nHost: evil.example:47801\r\n\r\n", 47801));
    }
}
