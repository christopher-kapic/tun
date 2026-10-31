//! Persisted daemon state and server URL resolution.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::paths::ENV_SERVER;

/// Written on every change so a killed daemon restarts with the same tunnel
/// and ports. Holds the tunnel token, hence 0600 in a 0700 directory.
/// Deliberately not `Debug`, so the token cannot end up in a log line.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Persisted {
    pub server: String,
    pub token: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub revoked: bool,
    /// Another client took over the tunnel; commands do not restart the daemon
    /// on their own, so two sandboxes never fight over one token.
    #[serde(default)]
    pub replaced: bool,
    pub tunnel_id: Option<String>,
    pub host_template: Option<String>,
}

impl Persisted {
    /// A missing or unreadable file is treated as no state.
    pub fn load(path: &Path) -> Option<Self> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read state file");
                return None;
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ignoring corrupt state file");
                None
            }
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic(path, &json, 0o600)
    }
}

/// Write to a sibling temp file and rename over `path`, so readers never see a
/// partial file.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_name = path.file_name().map(OsString::from).unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
        // `mode` only applies on creation; also fix a leftover temp file.
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Server base URL as `wss://host[:port]` (or `ws://` for local testing).
pub fn normalize_server(raw: &str) -> anyhow::Result<String> {
    let s = raw.trim().trim_end_matches('/');
    let url = if let Some(rest) = s.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = s.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if s.starts_with("wss://") || s.starts_with("ws://") {
        s.to_string()
    } else if s.contains("://") {
        bail!("unsupported tunnel server URL scheme: {s}");
    } else {
        format!("wss://{s}")
    };
    if url.ends_with("://") {
        bail!("empty tunnel server URL");
    }
    Ok(url)
}

/// `$COCKPIT_TUNNEL_SERVER`, else the persisted server, else the default baked
/// in at build time via `COCKPIT_TUNNEL_DEFAULT_SERVER`.
pub fn resolve_server(env: Option<&str>, persisted: Option<&str>) -> anyhow::Result<String> {
    let raw = env
        .or(persisted.filter(|s| !s.is_empty()))
        .or(option_env!("COCKPIT_TUNNEL_DEFAULT_SERVER").filter(|s| !s.is_empty()))
        .ok_or_else(|| anyhow!("no tunnel server configured: set {ENV_SERVER}"))?;
    normalize_server(raw)
}
