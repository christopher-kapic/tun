//! Running host commands from setup.

use std::process::{Command, Stdio};

use anyhow::{bail, Context};

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
