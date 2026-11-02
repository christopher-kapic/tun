//! Distro detection, package installation, and small process helpers.

use std::process::{Command, Stdio};

use anyhow::{bail, Context};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Apt,
    Dnf,
}

const APT_IDS: &[&str] = &["debian", "ubuntu"];
const DNF_IDS: &[&str] = &["fedora", "rhel", "centos", "rocky", "almalinux"];

#[derive(Debug)]
pub struct Os {
    pub family: Family,
    /// `ID` from `/etc/os-release`, e.g. `ubuntu`, `rocky`.
    pub id: String,
    pub version_id: String,
    apt_updated: bool,
}

impl Os {
    pub fn detect() -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string("/etc/os-release").context("reading /etc/os-release")?;
        Self::from_os_release(&raw)
    }

    fn from_os_release(raw: &str) -> anyhow::Result<Self> {
        let field = |key: &str| -> String {
            raw.lines()
                .filter_map(|l| l.trim().split_once('='))
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.trim().trim_matches(|c: char| c == '"' || c == '\'').to_string())
                .unwrap_or_default()
        };
        let id = field("ID").to_ascii_lowercase();
        let id_like = field("ID_LIKE").to_ascii_lowercase();
        let version_id = field("VERSION_ID");

        // Decided before `id` moves into the result, since the candidates borrow it.
        let family = std::iter::once(id.as_str()).chain(id_like.split_whitespace()).find_map(|candidate| {
            if APT_IDS.contains(&candidate) {
                Some(Family::Apt)
            } else if DNF_IDS.contains(&candidate) {
                Some(Family::Dnf)
            } else {
                None
            }
        });
        match family {
            Some(family) => Ok(Self { family, id, version_id, apt_updated: false }),
            None => bail!(
                "unsupported OS '{id}' (ID_LIKE '{id_like}'); supported: Debian 12+, Ubuntu 22.04+, \
                 Fedora 40+, RHEL/AlmaLinux/Rocky 9+"
            ),
        }
    }

    pub fn is_installed(&self, package: &str) -> bool {
        match self.family {
            Family::Apt => output("dpkg-query", &["-W", "-f=${Status}", package])
                .map(|s| s.contains("install ok installed"))
                .unwrap_or(false),
            Family::Dnf => succeeds("rpm", &["-q", package]),
        }
    }

    /// Install whichever of `packages` are missing. Already-installed packages
    /// cause no package-manager run at all, so re-running setup stays quiet.
    pub fn install(&mut self, packages: &[&str]) -> anyhow::Result<()> {
        let missing: Vec<&str> = packages.iter().copied().filter(|p| !self.is_installed(p)).collect();
        if missing.is_empty() {
            return Ok(());
        }
        println!("Installing {}", missing.join(" "));
        match self.family {
            Family::Apt => {
                if !self.apt_updated {
                    apt_get(&["update"])?;
                    self.apt_updated = true;
                }
                let mut args = vec!["install", "-y"];
                args.extend(&missing);
                apt_get(&args)
            }
            Family::Dnf => {
                let mut args = vec!["install", "-y"];
                args.extend(&missing);
                run("dnf", &args)
            }
        }
    }

    /// coturn lives in EPEL on RHEL-likes (Fedora ships it in the base repos).
    pub fn ensure_epel(&mut self) -> anyhow::Result<()> {
        if self.family != Family::Dnf || self.id == "fedora" || self.is_installed("epel-release") {
            return Ok(());
        }
        if self.id == "rhel" {
            // RHEL proper has no epel-release in its own repos.
            let major = self.version_id.split('.').next().unwrap_or("9");
            let url = format!("https://dl.fedoraproject.org/pub/epel/epel-release-latest-{major}.noarch.rpm");
            println!("Installing EPEL from {url}");
            run("dnf", &["install", "-y", &url])
        } else {
            self.install(&["epel-release"])
        }
    }
}

fn apt_get(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("apt-get")
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .status()
        .context("running apt-get")?;
    anyhow::ensure!(status.success(), "apt-get {} failed ({status})", args.join(" "));
    Ok(())
}

/// Run with inherited stdout/stderr (progress stays visible); fail on non-zero exit.
pub fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status =
        Command::new(program).args(args).stdin(Stdio::null()).status().with_context(|| format!("running {program}"))?;
    anyhow::ensure!(status.success(), "{program} {} failed ({status})", args.join(" "));
    Ok(())
}

/// Run quietly and return stdout; the error carries stderr.
pub fn output(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let out =
        Command::new(program).args(args).stdin(Stdio::null()).output().with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!("{program} {} failed ({}): {}", args.join(" "), out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// True if the command exists and exits 0. Output is discarded.
pub fn succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_distros() {
        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n";
        assert_eq!(Os::from_os_release(ubuntu).unwrap().family, Family::Apt);
        let alma = "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n";
        let os = Os::from_os_release(alma).unwrap();
        assert_eq!(os.family, Family::Dnf);
        assert_eq!(os.id, "almalinux");
        assert_eq!(os.version_id, "9.4");
        let derivative = "ID=pop\nID_LIKE=\"ubuntu debian\"\n";
        assert_eq!(Os::from_os_release(derivative).unwrap().family, Family::Apt);
        assert!(Os::from_os_release("ID=arch\n").is_err());
    }
}
