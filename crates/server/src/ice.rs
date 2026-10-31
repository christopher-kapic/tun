//! Ephemeral TURN credentials (TURN REST API / coturn `use-auth-secret`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cockpit_tunnel_protocol::{IceConfig, IceServer};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::config::Config;
use crate::tokens::now;

/// Subject used for sandbox-side credentials.
pub const SANDBOX_SUBJECT: &str = "sbx";

/// `username = "<expiry>:<tunnel id>:<subject>"`,
/// `credential = base64(HMAC-SHA1(static-auth-secret, username))`.
pub fn mint(cfg: &Config, tunnel_id: &str, subject: &str, ttl_s: u64) -> IceConfig {
    let expires_at = now().max(0) as u64 + ttl_s;
    let username = format!("{expires_at}:{tunnel_id}:{subject}");
    let mut mac = Hmac::<Sha1>::new_from_slice(cfg.webrtc.static_auth_secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(username.as_bytes());
    let credential = STANDARD.encode(mac.finalize().into_bytes());
    let host = &cfg.turn_host;
    let port = cfg.webrtc.stun_port;
    IceConfig {
        ice_servers: vec![
            IceServer { urls: vec![format!("stun:{host}:{port}")], username: None, credential: None },
            IceServer {
                urls: vec![
                    format!("turn:{host}:{port}?transport=udp"),
                    format!("turn:{host}:{port}?transport=tcp"),
                    format!("turns:{host}:443?transport=tcp"),
                ],
                username: Some(username),
                credential: Some(credential),
            },
        ],
        expires_at,
        ttl_s,
    }
}
