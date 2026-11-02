//! Install mode: a root (system) install or a rootless (user) install.
//!
//! The mode follows the effective user: root manages `/etc`, `/var/lib`, a
//! dedicated service user, and a system unit; anyone else gets XDG paths
//! under their home and a systemd *user* unit. A rootless install needs two
//! one-time root changes (unprivileged ports from 80, lingering), which setup
//! checks and prints as a single command.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Context;

use crate::config::SERVICE_NAME;

pub const SYSTEM_CONFIG_PATH: &str = "/etc/cockpit-tunnel/config.toml";
pub const SYSTEM_DATA_DIR: &str = "/var/lib/cockpit-tunnel";
pub const SYSTEM_BINARY_PATH: &str = "/usr/local/bin/cockpit-tunnel-server";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    System,
    User,
}

impl Mode {
    pub fn current() -> Self {
        if uid() == 0 {
            Self::System
        } else {
            Self::User
        }
    }

    pub fn is_user(self) -> bool {
        self == Self::User
    }

    pub fn config_path(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from(SYSTEM_CONFIG_PATH),
            Self::User => xdg("XDG_CONFIG_HOME", ".config")?.join("cockpit-tunnel/config.toml"),
        })
    }

    pub fn data_dir(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from(SYSTEM_DATA_DIR),
            Self::User => xdg("XDG_DATA_HOME", ".local/share")?.join("cockpit-tunnel"),
        })
    }

    pub fn binary_path(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from(SYSTEM_BINARY_PATH),
            Self::User => home()?.join(".local/bin/cockpit-tunnel-server"),
        })
    }

    pub fn unit_dir(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from("/etc/systemd/system"),
            Self::User => xdg("XDG_CONFIG_HOME", ".config")?.join("systemd/user"),
        })
    }

    /// `systemctl` (or `systemctl --user`) with the environment a user
    /// manager needs even when no login session set it (e.g. a remote runner).
    pub fn systemctl(self) -> Command {
        let mut cmd = Command::new("systemctl");
        if self.is_user() {
            cmd.arg("--user");
            if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
                let runtime = format!("/run/user/{}", uid());
                cmd.env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={runtime}/bus"));
                cmd.env("XDG_RUNTIME_DIR", runtime);
            }
        }
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Run `systemctl`; `Err` carries its stderr.
    pub fn systemctl_run(self, args: &[&str]) -> anyhow::Result<()> {
        let out =
            self.systemctl().args(args).output().with_context(|| format!("running systemctl {}", args.join(" ")))?;
        anyhow::ensure!(
            out.status.success(),
            "systemctl {}{} failed: {}",
            if self.is_user() { "--user " } else { "" },
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    pub fn systemctl_ok(self, args: &[&str]) -> bool {
        self.systemctl().args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    }

    /// `systemctl is-active` prints the state even when it exits non-zero.
    pub fn service_state(self, unit: &str) -> String {
        match self.systemctl().args(["is-active", unit]).output() {
            Ok(out) => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() {
                    "unknown".to_string()
                } else {
                    s
                }
            }
            Err(_) => "unknown (systemctl unavailable)".to_string(),
        }
    }

    /// How to read the service log in this mode.
    pub fn journal_hint(self) -> String {
        match self {
            Self::System => format!("journalctl -u {SERVICE_NAME}"),
            Self::User => format!("journalctl --user -u {SERVICE_NAME}"),
        }
    }
}

pub fn uid() -> u32 {
    std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(u32::MAX)
}

pub fn username() -> anyhow::Result<String> {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() {
            return Ok(u);
        }
    }
    let out = Command::new("id").arg("-un").output().context("running id -un")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn home() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).context("HOME is not set")?;
    Ok(PathBuf::from(home))
}

fn xdg(var: &str, fallback: &str) -> anyhow::Result<PathBuf> {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(v) if PathBuf::from(&v).is_absolute() => Ok(PathBuf::from(v)),
        _ => Ok(home()?.join(fallback)),
    }
}
