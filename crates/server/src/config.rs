use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DATA_DIR: &str = "/var/lib/cockpit-tunnel";
pub const SERVICE_USER: &str = "cockpit-tunnel";
pub const SERVICE_NAME: &str = "cockpit-tunnel";

/// `/etc/cockpit-tunnel/config.toml`. Mode 0600, owned by the service user.
/// Contains secrets (TURN secret, DNS token); the admin token is stored only as a hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Unused; kept so configs written by older setups still parse.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_domain: String,
    /// Wildcard preview zone, e.g. `previews.example.com`.
    pub preview_zone: String,
    pub api_host: String,
    pub tunnel_host: String,
    pub turn_host: String,
    /// Older single iframe parent; folded into `frame_ancestors` on load.
    #[serde(default, skip_serializing)]
    pub dashboard_origin: String,
    /// Sites allowed to show previews in an iframe: CSP `frame-ancestors` sources
    /// (`https://app.example.com`, `https://*.example.com`), or `*` for any site.
    /// The preview's own origin is always allowed.
    #[serde(default)]
    pub frame_ancestors: Vec<String>,

    #[serde(default = "default_https")]
    pub listen_https: SocketAddr,
    #[serde(default = "default_http")]
    pub listen_http: SocketAddr,
    #[serde(default = "default_metrics")]
    pub metrics_listen: SocketAddr,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Hex SHA-256 of the admin API token.
    pub admin_token_hash: String,

    #[serde(default)]
    pub public_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub public_ipv6: Option<Ipv6Addr>,

    pub acme: AcmeConfig,
    pub dns: DnsConfig,
    #[serde(default)]
    pub webrtc: WebrtcConfig,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AcmeConfig {
    pub email: String,
    /// Use the Let's Encrypt staging directory.
    #[serde(default)]
    pub staging: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderKind {
    Cloudflare,
    Hetzner,
    Digitalocean,
    Route53,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsConfig {
    pub provider: DnsProviderKind,
    /// DNS zone name managed at the provider, e.g. `example.com`.
    pub zone: String,
    /// Cloudflare / Hetzner / DigitalOcean API token.
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key: Option<String>,
    #[serde(default)]
    pub route53_hosted_zone_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebrtcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub static_auth_secret: String,
    /// Where SNI passthrough for `turn_host` goes.
    #[serde(default = "default_coturn_tls")]
    pub coturn_tls_addr: SocketAddr,
    /// Route TLS ClientHellos without SNI to coturn as well.
    #[serde(default = "default_true")]
    pub passthrough_no_sni: bool,
    #[serde(default = "default_browser_ttl")]
    pub browser_ttl_s: u64,
    #[serde(default = "default_sandbox_ttl")]
    pub sandbox_ttl_s: u64,
    #[serde(default = "default_stun_port")]
    pub stun_port: u16,
    #[serde(default = "default_relay_min")]
    pub relay_min_port: u16,
    #[serde(default = "default_relay_max")]
    pub relay_max_port: u16,
}

impl Default for WebrtcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            static_auth_secret: String::new(),
            coturn_tls_addr: default_coturn_tls(),
            passthrough_no_sni: true,
            browser_ttl_s: default_browser_ttl(),
            sandbox_ttl_s: default_sandbox_ttl(),
            stun_port: default_stun_port(),
            relay_min_port: default_relay_min(),
            relay_max_port: default_relay_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Limits {
    #[serde(default = "default_max_ports")]
    pub default_max_ports: u16,
    #[serde(default = "default_hard_max_ports")]
    pub hard_max_ports: u16,
    /// `/__access/*` attempts per IP per minute.
    #[serde(default = "default_access_rate")]
    pub access_rate_per_min: u32,
    #[serde(default = "default_session_ttl")]
    pub default_session_ttl_s: u64,
    #[serde(default = "default_max_tunnel_ttl")]
    pub max_tunnel_ttl_s: u64,
    #[serde(default = "default_tombstone_retention")]
    pub tombstone_retention_s: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            default_max_ports: default_max_ports(),
            hard_max_ports: default_hard_max_ports(),
            access_rate_per_min: default_access_rate(),
            default_session_ttl_s: default_session_ttl(),
            max_tunnel_ttl_s: default_max_tunnel_ttl(),
            tombstone_retention_s: default_tombstone_retention(),
        }
    }
}

fn default_https() -> SocketAddr {
    "[::]:443".parse().unwrap()
}
fn default_http() -> SocketAddr {
    "[::]:80".parse().unwrap()
}
fn default_metrics() -> SocketAddr {
    "127.0.0.1:9464".parse().unwrap()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}
fn default_coturn_tls() -> SocketAddr {
    "127.0.0.1:5349".parse().unwrap()
}
fn default_true() -> bool {
    true
}
fn default_browser_ttl() -> u64 {
    3600
}
fn default_sandbox_ttl() -> u64 {
    86_400
}
fn default_stun_port() -> u16 {
    3478
}
fn default_relay_min() -> u16 {
    49160
}
fn default_relay_max() -> u16 {
    49999
}
fn default_max_ports() -> u16 {
    8
}
fn default_hard_max_ports() -> u16 {
    32
}
fn default_access_rate() -> u32 {
    30
}
fn default_session_ttl() -> u64 {
    12 * 3600
}
fn default_max_tunnel_ttl() -> u64 {
    30 * 86_400
}
fn default_tombstone_retention() -> u64 {
    30 * 86_400
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        cfg.normalize_frame_ancestors();
        Ok(cfg)
    }

    /// Fold the old `dashboard_origin` into `frame_ancestors`; nothing set means any site.
    pub fn normalize_frame_ancestors(&mut self) {
        if self.frame_ancestors.is_empty() {
            self.frame_ancestors = if self.dashboard_origin.is_empty() {
                vec!["*".to_string()]
            } else {
                vec![self.dashboard_origin.clone()]
            };
        }
        self.dashboard_origin.clear();
    }

    pub fn to_toml(&self) -> anyhow::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Atomic write with mode 0600. Returns `true` if the file content changed.
    pub fn save(&self, path: &Path) -> anyhow::Result<bool> {
        let content = self.to_toml()?;
        crate::util::write_if_changed(path, content.as_bytes(), 0o600)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("cockpit-tunnel.db")
    }

    pub fn cert_dir(&self) -> PathBuf {
        self.data_dir.join("certs")
    }

    pub fn acme_account_path(&self) -> PathBuf {
        self.data_dir.join("acme-account.json")
    }

    /// Every name on the single DNS-01 certificate.
    pub fn cert_names(&self) -> Vec<String> {
        // The zone apex serves sign-in (`gatehost`); usually it is also the API host.
        let mut names = vec![
            format!("*.{}", self.preview_zone),
            self.preview_zone.clone(),
            self.api_host.clone(),
            self.tunnel_host.clone(),
        ];
        if self.webrtc.enabled {
            names.push(self.turn_host.clone());
        }
        names.sort();
        names.dedup();
        names
    }

    /// `{port}-<id>.<zone>` host for a tunnel port.
    pub fn preview_host(&self, port: u16, tunnel_id: &str) -> String {
        format!("{port}-{tunnel_id}.{}", self.preview_zone)
    }

    pub fn host_template(&self, tunnel_id: &str) -> String {
        format!("{{port}}-{tunnel_id}.{}", self.preview_zone)
    }
}

/// Ensure a path has exactly `mode` permissions.
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}
