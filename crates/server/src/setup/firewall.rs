//! Host firewall: ufw or firewalld when active, otherwise a reminder about the
//! cloud provider's firewall.

use super::os;
use crate::config::Config;

/// `(port or range, protocol)`; ranges use `min-max`.
pub fn required_ports(cfg: &Config) -> Vec<(String, &'static str)> {
    let mut ports = vec![("80".to_string(), "tcp"), ("443".to_string(), "tcp")];
    if cfg.webrtc.enabled {
        let w = &cfg.webrtc;
        ports.push((w.stun_port.to_string(), "udp"));
        ports.push((w.stun_port.to_string(), "tcp"));
        ports.push((format!("{}-{}", w.relay_min_port, w.relay_max_port), "udp"));
    }
    ports
}

pub fn configure(cfg: &Config) -> anyhow::Result<()> {
    let ports = required_ports(cfg);
    let listed: Vec<String> = ports.iter().map(|(p, proto)| format!("{p}/{proto}")).collect();

    if ufw_active() {
        println!("Opening {} in ufw", listed.join(", "));
        for (port, proto) in &ports {
            // ufw spells ranges `min:max` and skips rules that already exist.
            let rule = format!("{}/{proto}", port.replace('-', ":"));
            os::output("ufw", &["allow", &rule])?;
        }
    } else if firewalld_running() {
        let mut added = false;
        for spec in &listed {
            let query = format!("--query-port={spec}");
            if !os::succeeds("firewall-cmd", &["--permanent", &query]) {
                os::output("firewall-cmd", &["--permanent", &format!("--add-port={spec}")])?;
                added = true;
            }
        }
        if added {
            println!("Opened {} in firewalld", listed.join(", "));
            os::output("firewall-cmd", &["--reload"])?;
        }
    } else {
        println!(
            "No active ufw/firewalld found. Make sure the cloud provider firewall allows inbound {}.",
            listed.join(", ")
        );
    }
    Ok(())
}

fn ufw_active() -> bool {
    os::output("ufw", &["status"]).map(|s| s.lines().any(|l| l.trim() == "Status: active")).unwrap_or(false)
}

/// Rootless install: the one root command that opens the required ports when
/// a host firewall is running (`ufw status` itself needs root, so the service
/// state decides). `None` when neither ufw nor firewalld runs.
pub fn rootless_command(cfg: &Config) -> Option<String> {
    let ports = required_ports(cfg);
    if os::succeeds("systemctl", &["is-active", "--quiet", "ufw"]) {
        let rules: Vec<String> =
            ports.iter().map(|(p, proto)| format!("ufw allow {}/{proto}", p.replace('-', ":"))).collect();
        return Some(format!("sudo sh -c '{}'", rules.join(" && ")));
    }
    if os::succeeds("systemctl", &["is-active", "--quiet", "firewalld"]) {
        let mut rules: Vec<String> =
            ports.iter().map(|(p, proto)| format!("firewall-cmd --permanent --add-port={p}/{proto}")).collect();
        rules.push("firewall-cmd --reload".into());
        return Some(format!("sudo sh -c '{}'", rules.join(" && ")));
    }
    None
}

fn firewalld_running() -> bool {
    os::output("firewall-cmd", &["--state"]).map(|s| s.trim() == "running").unwrap_or(false)
}
