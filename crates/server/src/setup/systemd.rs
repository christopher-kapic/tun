//! systemd units for the server and (with WebRTC) the coturn restart on
//! certificate renewal.

use std::path::Path;

use super::os;
use crate::config::{Config, SERVICE_NAME, SERVICE_USER};
use crate::util::write_if_changed;

pub const BINARY_PATH: &str = "/usr/local/bin/cockpit-tunnel-server";
const UNIT_DIR: &str = "/etc/systemd/system";
const CERT_PATH_UNIT: &str = "cockpit-tunnel-cert.path";
const CERT_RELOAD_UNIT: &str = "cockpit-tunnel-cert-reload.service";

fn service_unit(cfg: &Config, config_path: &Path) -> String {
    format!(
        "[Unit]
Description=cockpit-tunnel preview relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
ExecStart={bin} serve --config {config}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={data}
UMask=0027
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
",
        user = SERVICE_USER,
        bin = BINARY_PATH,
        config = config_path.display(),
        data = cfg.data_dir.display(),
    )
}

/// The server itself cannot restart coturn (unprivileged, NoNewPrivileges),
/// so a path unit watches the certificate and does it as root.
fn cert_path_unit(cfg: &Config) -> String {
    format!(
        "[Unit]
Description=Restart coturn when the cockpit-tunnel certificate changes

[Path]
PathChanged={fullchain}
Unit={reload}

[Install]
WantedBy=multi-user.target
",
        fullchain = cfg.cert_dir().join("fullchain.pem").display(),
        reload = CERT_RELOAD_UNIT,
    )
}

fn cert_reload_unit() -> String {
    "[Unit]
Description=Restart coturn to load the renewed cockpit-tunnel certificate

[Service]
Type=oneshot
ExecStart=/bin/systemctl try-restart coturn.service
"
    .to_string()
}

/// Write units, reload systemd if any changed, and make sure the server runs.
/// The server restarts only when its unit or `config.toml` changed.
pub fn install(cfg: &Config, config_path: &Path, config_changed: bool) -> anyhow::Result<()> {
    if !Path::new(BINARY_PATH).exists() {
        println!("Warning: {BINARY_PATH} does not exist; the service will not start until it is installed there.");
    }
    let unit_dir = Path::new(UNIT_DIR);
    let service_file = format!("{SERVICE_NAME}.service");

    let service_changed = write_if_changed(&unit_dir.join(&service_file), service_unit(cfg, config_path).as_bytes(), 0o644)?;
    let mut units_changed = service_changed;

    let path_file = unit_dir.join(CERT_PATH_UNIT);
    let reload_file = unit_dir.join(CERT_RELOAD_UNIT);
    if cfg.webrtc.enabled {
        units_changed |= write_if_changed(&reload_file, cert_reload_unit().as_bytes(), 0o644)?;
        units_changed |= write_if_changed(&path_file, cert_path_unit(cfg).as_bytes(), 0o644)?;
    } else if path_file.exists() || reload_file.exists() {
        // WebRTC was turned off since the last run.
        let _ = os::output("systemctl", &["disable", "--now", CERT_PATH_UNIT]);
        for f in [&path_file, &reload_file] {
            if f.exists() {
                std::fs::remove_file(f)?;
            }
        }
        units_changed = true;
    }

    if units_changed {
        os::run("systemctl", &["daemon-reload"])?;
    }
    if cfg.webrtc.enabled {
        os::run("systemctl", &["enable", "--now", CERT_PATH_UNIT])?;
    }

    let was_active = os::succeeds("systemctl", &["is-active", "--quiet", &service_file]);
    os::run("systemctl", &["enable", &service_file])?;
    if !was_active {
        println!("Starting {service_file}");
        os::run("systemctl", &["start", &service_file])?;
    } else if service_changed || config_changed {
        println!("Restarting {service_file}");
        os::run("systemctl", &["restart", &service_file])?;
    }
    Ok(())
}
