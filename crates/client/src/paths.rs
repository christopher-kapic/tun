//! Filesystem locations and environment shared by commands and the daemon.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

pub const ENV_TOKEN: &str = "COCKPIT_TUNNEL_TOKEN";
pub const ENV_SERVER: &str = "COCKPIT_TUNNEL_SERVER";
pub const ENV_ICE_FILE: &str = "COCKPIT_ICE_FILE";
pub const ENV_ICE_PORT: &str = "COCKPIT_ICE_PORT";
pub const DEFAULT_ICE_PORT: u16 = 47801;
const RUN_ICE_DIR: &str = "/run/cockpit-preview";

pub struct Paths {
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub log_file: PathBuf,
    pub lock_file: PathBuf,
}

impl Paths {
    /// Resolve and create (0700) the per-user state directory.
    pub fn resolve() -> anyhow::Result<Self> {
        let dir = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            Some(xdg) if xdg.is_absolute() && xdg.is_dir() => xdg.join("cockpit-preview"),
            _ => PathBuf::from(format!("/tmp/cockpit-preview-{}", uid())),
        };
        ensure_private_dir(&dir)?;
        Ok(Self {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        })
    }
}

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    // Checked after creation so a directory or symlink planted in /tmp by
    // another user is refused rather than trusted.
    let meta = fs::symlink_metadata(dir).with_context(|| format!("inspecting {}", dir.display()))?;
    if !meta.file_type().is_dir() {
        bail!("{} is not a directory; refusing to use it", dir.display());
    }
    if meta.uid() != uid() {
        bail!("{} is owned by uid {}, not {}; refusing to use it", dir.display(), meta.uid(), uid());
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    Ok(())
}

/// `$COCKPIT_ICE_FILE`, else `/run/cockpit-preview/ice.json` when writable,
/// else `<state dir>/ice.json`.
pub fn ice_file(state_dir: &Path) -> PathBuf {
    if let Some(path) = env_nonempty(ENV_ICE_FILE) {
        return PathBuf::from(path);
    }
    let run = Path::new(RUN_ICE_DIR);
    if fs::create_dir_all(run).is_ok() && is_writable(run) {
        return run.join("ice.json");
    }
    state_dir.join("ice.json")
}

fn is_writable(dir: &Path) -> bool {
    let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

pub fn ice_port() -> u16 {
    match env_nonempty(ENV_ICE_PORT) {
        None => DEFAULT_ICE_PORT,
        Some(raw) => raw.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(value = %raw, "invalid {ENV_ICE_PORT}; using {DEFAULT_ICE_PORT}");
            DEFAULT_ICE_PORT
        }),
    }
}
