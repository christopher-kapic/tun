//! Leftovers from installs that used coturn (before the built-in relay in
//! `turn_relay`). A coturn that setup configured holds port 3478, which the
//! built-in relay needs, so it is stopped; a coturn configured by someone else
//! is left alone and reported.

use super::os;

const SERVICE: &str = "coturn";
const MARKER: &str = "# Managed by cockpit-tunnel-server setup; changes are overwritten on the next run.";
const CONFIGS: &[&str] = &["/etc/turnserver.conf", "/etc/coturn/turnserver.conf"];

fn running() -> bool {
    os::succeeds("systemctl", &["is-active", "--quiet", SERVICE])
}

/// Root install: stop and disable a coturn that an older setup configured.
pub fn disable_if_managed() -> anyhow::Result<()> {
    let managed = CONFIGS.iter().any(|p| std::fs::read_to_string(p).map(|s| s.starts_with(MARKER)).unwrap_or(false));
    if managed && (running() || os::succeeds("systemctl", &["is-enabled", "--quiet", SERVICE])) {
        println!("Stopping coturn: the built-in TURN relay replaces it");
        os::run("systemctl", &["disable", "--now", SERVICE])?;
    } else if running() {
        println!("Note: a coturn service is running; with WebRTC enabled it must not use port 3478.");
    }
    Ok(())
}

/// Rootless install: the one-time root command to stop a running coturn
/// (which would hold port 3478), if one is running.
pub fn root_command_to_stop() -> Option<String> {
    running().then(|| format!("systemctl disable --now {SERVICE}"))
}
