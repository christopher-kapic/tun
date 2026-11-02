//! coturn from the distro package: install, generated config, group access to
//! the shared certificate, and service management.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::Context;

use super::os::{self, Family, Os};
use crate::config::{Config, SERVICE_USER};
use crate::util::write_if_changed;

const SERVICE: &str = "coturn";
const MARKER: &str = "# Managed by cockpit-tunnel-server setup; changes are overwritten on the next run.";
const APT_CONFIG: &str = "/etc/turnserver.conf";
const DNF_CONFIG: &str = "/etc/coturn/turnserver.conf";
const APT_DEFAULTS: &str = "/etc/default/coturn";

/// Relay targets coturn must refuse: everything non-public, so a TURN
/// credential cannot be used to reach the VM, its metadata service, or a
/// private network. The VM's own public address is appended per host.
const DENIED_PEERS: &[&str] = &[
    "0.0.0.0-0.255.255.255",
    "10.0.0.0-10.255.255.255",
    "100.64.0.0-100.127.255.255",
    "127.0.0.0-127.255.255.255",
    "169.254.0.0-169.254.255.255",
    "172.16.0.0-172.31.255.255",
    "192.168.0.0-192.168.255.255",
    "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::1",
];

/// The account the distro's coturn service runs as (`turnserver` on
/// Debian/Ubuntu, `coturn` on Fedora/RHEL).
pub fn detect_coturn_user() -> Option<String> {
    ["turnserver", "coturn"].into_iter().find(|u| os::succeeds("id", &["-u", *u])).map(str::to_string)
}

fn config_path(family: Family) -> &'static str {
    match family {
        Family::Apt => APT_CONFIG,
        Family::Dnf => DNF_CONFIG,
    }
}

/// Install, configure, and (re)start coturn. Restarts only when the config,
/// the Debian defaults file, or the service user's group membership changed.
pub fn configure(cfg: &Config, os: &mut Os) -> anyhow::Result<()> {
    let public = cfg.public_ipv4.context("WebRTC needs a public IPv4 address")?;
    anyhow::ensure!(!cfg.webrtc.static_auth_secret.is_empty(), "webrtc.static_auth_secret is empty");

    os.ensure_epel()?;
    os.install(&["coturn"])?;
    let user =
        detect_coturn_user().context("coturn is installed but neither a 'turnserver' nor a 'coturn' user exists")?;

    let (listen, private) = listen_address(public);
    let rendered = render(cfg, public, listen, private);
    let path = Path::new(config_path(os.family));
    let mut changed =
        write_if_changed(path, rendered.as_bytes(), 0o640).with_context(|| format!("writing {}", path.display()))?;
    // It holds the static auth secret: readable by coturn, nobody else.
    let owner = format!("root:{user}");
    os::run("chown", &[owner.as_str(), &*path.to_string_lossy()])?;

    if os.family == Family::Apt {
        changed |= enable_apt_defaults()?;
    }

    // Read access to the 0640 cert/key owned by the service user's group.
    let groups = os::output("id", &["-nG", &user])?;
    if !groups.split_whitespace().any(|g| g == SERVICE_USER) {
        os::run("usermod", &["-aG", SERVICE_USER, &user])?;
        changed = true;
    }

    os::run("systemctl", &["enable", SERVICE])?;
    if changed {
        println!("Restarting coturn");
        os::run("systemctl", &["restart", SERVICE])?;
    } else {
        os::run("systemctl", &["start", SERVICE])?;
    }
    Ok(())
}

/// WebRTC was turned off: stop a coturn that this wizard configured. A coturn
/// configured by someone else is left alone.
pub fn disable_if_managed() -> anyhow::Result<()> {
    let managed = [APT_CONFIG, DNF_CONFIG]
        .iter()
        .any(|p| std::fs::read_to_string(p).map(|s| s.starts_with(MARKER)).unwrap_or(false));
    if managed && os::succeeds("systemctl", &["is-enabled", "--quiet", SERVICE]) {
        println!("WebRTC disabled: stopping coturn");
        os::run("systemctl", &["disable", "--now", SERVICE])?;
    }
    Ok(())
}

/// Where coturn listens for UDP/TCP 3478. On hosts behind 1:1 NAT (most
/// clouds) the public address is not on any interface and binding it fails,
/// so coturn listens on the private source address and advertises
/// `external-ip=<public>/<private>`.
fn listen_address(public: Ipv4Addr) -> (Ipv4Addr, Option<Ipv4Addr>) {
    if local_ipv4s().contains(&public) {
        return (public, None);
    }
    match default_route_src() {
        Some(private) if private != public => {
            println!("Public IP {public} is not on a local interface; coturn will listen on {private} (1:1 NAT)");
            (private, Some(private))
        }
        _ => (public, None),
    }
}

fn local_ipv4s() -> Vec<Ipv4Addr> {
    let out = os::output("ip", &["-o", "-4", "addr", "show"]).unwrap_or_default();
    out.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words.find(|w| *w == "inet")?;
            words.next()?.split('/').next()?.parse().ok()
        })
        .collect()
}

fn default_route_src() -> Option<Ipv4Addr> {
    let out = os::output("ip", &["-4", "route", "get", "1.1.1.1"]).ok()?;
    let mut words = out.split_whitespace();
    words.find(|w| *w == "src")?;
    words.next()?.parse().ok()
}

fn render(cfg: &Config, public: Ipv4Addr, listen: Ipv4Addr, private: Option<Ipv4Addr>) -> String {
    let w = &cfg.webrtc;
    let cert_dir = cfg.cert_dir();
    let tls_ip = w.coturn_tls_addr.ip();
    let mut s = String::new();
    let _ = writeln!(s, "{MARKER}");
    let _ = writeln!(s, "listening-port={}", w.stun_port);
    // The TLS listener is reached only through the server's 443 SNI passthrough.
    let _ = writeln!(s, "tls-listening-port={}", w.coturn_tls_addr.port());
    let _ = writeln!(s, "listening-ip={listen}");
    if tls_ip != IpAddr::V4(listen) {
        let _ = writeln!(s, "listening-ip={tls_ip}");
    }
    match private {
        Some(private) => {
            let _ = writeln!(s, "external-ip={public}/{private}");
        }
        None => {
            let _ = writeln!(s, "external-ip={public}");
        }
    }
    let _ = writeln!(s, "realm={}", cfg.turn_host);
    let _ = writeln!(s, "use-auth-secret");
    let _ = writeln!(s, "static-auth-secret={}", w.static_auth_secret);
    let _ = writeln!(s, "cert={}", cert_dir.join("fullchain.pem").display());
    let _ = writeln!(s, "pkey={}", cert_dir.join("privkey.pem").display());
    let _ = writeln!(s, "min-port={}", w.relay_min_port);
    let _ = writeln!(s, "max-port={}", w.relay_max_port);
    let _ = writeln!(s, "no-multicast-peers");
    let _ = writeln!(s, "no-cli");
    let _ = writeln!(s, "no-dtls");
    let _ = writeln!(s, "syslog");
    for peer in DENIED_PEERS {
        let _ = writeln!(s, "denied-peer-ip={peer}");
    }
    let _ = writeln!(s, "denied-peer-ip={public}");
    let _ = writeln!(s, "user-quota=12");
    let _ = writeln!(s, "total-quota=1200");
    let _ = writeln!(s, "max-bps=3000000");
    s
}

/// Debian's init wrapper refuses to start coturn unless this is set.
fn enable_apt_defaults() -> anyhow::Result<bool> {
    let path = Path::new(APT_DEFAULTS);
    let current = std::fs::read_to_string(path).unwrap_or_default();
    let mut found = false;
    let mut out = String::new();
    for line in current.lines() {
        let key = line.trim_start().trim_start_matches('#').trim_start();
        if key.starts_with("TURNSERVER_ENABLED=") {
            if !found {
                out.push_str("TURNSERVER_ENABLED=1\n");
                found = true;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        out.push_str("TURNSERVER_ENABLED=1\n");
    }
    write_if_changed(path, out.as_bytes(), 0o644).with_context(|| format!("writing {APT_DEFAULTS}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        serde_json::from_value(serde_json::json!({
            "base_domain": "example.com",
            "preview_zone": "previews.example.com",
            "api_host": "api.example.com",
            "tunnel_host": "tunnel.example.com",
            "turn_host": "turn.example.com",
            "dashboard_origin": "https://app.example.com",
            "admin_token_hash": "",
            "acme": { "email": "ops@example.com" },
            "dns": { "provider": "cloudflare", "zone": "example.com" },
            "webrtc": { "enabled": true, "static_auth_secret": "s3cret" }
        }))
        .unwrap()
    }

    #[test]
    fn renders_direct_and_nat() {
        let cfg = test_config();
        let public: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let direct = render(&cfg, public, public, None);
        assert!(direct.starts_with(MARKER));
        assert!(direct.contains("listening-ip=203.0.113.7\nlistening-ip=127.0.0.1\n"));
        assert!(direct.contains("external-ip=203.0.113.7\n"));
        assert!(direct.contains("realm=turn.example.com\n"));
        assert!(direct.contains("static-auth-secret=s3cret\n"));
        assert!(direct.contains("cert=/var/lib/cockpit-tunnel/certs/fullchain.pem\n"));
        assert!(direct.contains("min-port=49160\nmax-port=49999\n"));
        assert!(direct.contains("denied-peer-ip=203.0.113.7\n"));

        let private: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let nat = render(&cfg, public, private, Some(private));
        assert!(nat.contains("listening-ip=10.0.0.5\n"));
        assert!(nat.contains("external-ip=203.0.113.7/10.0.0.5\n"));
    }
}
