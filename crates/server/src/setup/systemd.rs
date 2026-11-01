//! systemd units for the server and (with WebRTC) the coturn restart on
//! certificate renewal. A system install gets a hardened system unit running
//! as the service user; a rootless install gets a user unit (lingering keeps
//! it running without a login session).

use std::path::Path;

use anyhow::Context;

use crate::config::{Config, SERVICE_NAME, SERVICE_USER};
use crate::mode::Mode;
use crate::util::write_if_changed;

const CERT_PATH_UNIT: &str = "cockpit-tunnel-cert.path";
const CERT_RELOAD_UNIT: &str = "cockpit-tunnel-cert-reload.service";

fn user_service_unit(bin: &Path, config_path: &Path) -> String {
    format!(
        "[Unit]
Description=cockpit-tunnel preview relay

[Service]
Type=simple
ExecStart={bin} serve --config {config}
NoNewPrivileges=true
UMask=0077
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=default.target
",
        bin = bin.display(),
        config = config_path.display(),
    )
}

fn service_unit(cfg: &Config, bin: &Path, config_path: &Path) -> String {
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
        bin = bin.display(),
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

/// Copy the running binary to the service path when it differs (write to a
/// temporary file and rename, so a running server keeps its old inode).
/// Returns `true` if the installed binary changed.
fn install_binary(target: &Path) -> anyhow::Result<bool> {
    let current = std::env::current_exe().context("locating the running binary")?;
    let current = current.canonicalize().unwrap_or(current);
    if target.canonicalize().ok().as_deref() == Some(current.as_path()) {
        return Ok(false);
    }
    let new = std::fs::read(&current).with_context(|| format!("reading {}", current.display()))?;
    if std::fs::read(target).ok().as_deref() == Some(new.as_slice()) {
        return Ok(false);
    }
    let dir = target.parent().context("binary path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = target.with_extension("new");
    std::fs::write(&tmp, &new).with_context(|| format!("writing {}", tmp.display()))?;
    crate::config::set_mode(&tmp, 0o755)?;
    std::fs::rename(&tmp, target).with_context(|| format!("installing {}", target.display()))?;
    println!("Installed {}", target.display());
    Ok(true)
}

/// Install the binary and units, reload systemd if any changed, and make sure
/// the server runs. It restarts only when the binary, unit, or `config.toml` changed.
pub fn install(cfg: &Config, config_path: &Path, config_changed: bool, mode: Mode) -> anyhow::Result<()> {
    let bin = mode.binary_path()?;
    let binary_changed = install_binary(&bin)?;
    let unit_dir = mode.unit_dir()?;
    std::fs::create_dir_all(&unit_dir).with_context(|| format!("creating {}", unit_dir.display()))?;
    let service_file = format!("{SERVICE_NAME}.service");

    let unit = match mode {
        Mode::System => service_unit(cfg, &bin, config_path),
        Mode::User => user_service_unit(&bin, config_path),
    };
    let service_changed = write_if_changed(&unit_dir.join(&service_file), unit.as_bytes(), 0o644)?;
    let mut units_changed = service_changed;

    if mode == Mode::System {
        let path_file = unit_dir.join(CERT_PATH_UNIT);
        let reload_file = unit_dir.join(CERT_RELOAD_UNIT);
        if cfg.webrtc.enabled {
            units_changed |= write_if_changed(&reload_file, cert_reload_unit().as_bytes(), 0o644)?;
            units_changed |= write_if_changed(&path_file, cert_path_unit(cfg).as_bytes(), 0o644)?;
        } else if path_file.exists() || reload_file.exists() {
            // WebRTC was turned off since the last run.
            let _ = mode.systemctl_run(&["disable", "--now", CERT_PATH_UNIT]);
            for f in [&path_file, &reload_file] {
                if f.exists() {
                    std::fs::remove_file(f)?;
                }
            }
            units_changed = true;
        }
    }

    if units_changed {
        mode.systemctl_run(&["daemon-reload"])?;
    }
    if mode == Mode::System && cfg.webrtc.enabled {
        mode.systemctl_run(&["enable", "--now", CERT_PATH_UNIT])?;
    }

    let was_active = mode.systemctl_ok(&["is-active", "--quiet", &service_file]);
    mode.systemctl_run(&["enable", &service_file])?;
    if !was_active {
        println!("Starting {service_file}");
        mode.systemctl_run(&["start", &service_file])?;
    } else if service_changed || config_changed || binary_changed {
        println!("Restarting {service_file}");
        mode.systemctl_run(&["restart", &service_file])?;
    }
    Ok(())
}
