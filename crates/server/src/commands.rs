//! Non-interactive subcommands: `serve`, `token rotate`, `status`, `backup`, `cert renew`.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::Context;
use cockpit_tunnel_protocol::{CloseReason, ADMIN_TOKEN_PREFIX};

use crate::config::{Config, SERVICE_NAME, SERVICE_USER};
use crate::db::Db;
use crate::state::AppState;
use crate::tls::{self, CertStatus};
use crate::tokens;
use crate::{acme, listener, metrics, purge, util};

/// Time for `Close { Shutdown }` to reach clients before the process exits.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

pub async fn serve(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    let db = Db::open(&cfg.db_path())?;
    let certs = tls::CertStore::new(cfg.cert_dir());
    certs.reload().with_context(|| {
        format!(
            "no usable certificate in {}; run `cockpit-tunnel-server setup` or `cockpit-tunnel-server cert renew`",
            cfg.cert_dir().display()
        )
    })?;
    let state = AppState::new(cfg, db, certs.clone());
    tracing::info!(not_after = certs.not_after(), "certificate loaded");

    tokio::spawn(tls::watch(certs));
    tokio::spawn(acme::renew_loop(state.clone()));
    tokio::spawn(purge::run(state.clone()));
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(state).await {
                // Metrics are loopback-only diagnostics; serving previews matters more.
                tracing::error!(error = %format!("{e:#}"), "metrics listener failed");
            }
        });
    }

    tokio::select! {
        r = listener::run_https(state.clone()) => r.context("https listener")?,
        r = listener::run_http_redirect(state.clone()) => r.context("http redirect listener")?,
        r = shutdown_signal() => {
            r?;
            tracing::info!(tunnels = state.registry.len(), "shutting down");
            for live in state.registry.all() {
                live.close(CloseReason::Shutdown);
            }
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = term.recv() => {}
    }
    Ok(())
}

pub async fn token_rotate(config_path: &Path) -> anyhow::Result<()> {
    ensure_root("token rotate")?;
    let mut cfg = Config::load(config_path)?;
    let token = tokens::random_token(ADMIN_TOKEN_PREFIX);
    cfg.admin_token_hash = tokens::hash_token(&token);
    cfg.save(config_path)?;
    util::chown_recursive(config_path, SERVICE_USER)?;

    // The server reads the hash at startup; the old token stays valid until it restarts.
    if systemctl(&["try-restart", SERVICE_NAME]) {
        println!("Restarted {SERVICE_NAME} (if it was running); the old token no longer works.");
    } else {
        eprintln!(
            "warning: `systemctl try-restart {SERVICE_NAME}` failed; restart the service so the new token takes effect"
        );
    }

    println!("New admin API token (shown once):");
    println!();
    println!("  {token}");
    println!();
    println!("Harness environment:");
    println!("  COCKPIT_TUNNEL_API=https://{}", cfg.api_host);
    println!("  COCKPIT_TUNNEL_ADMIN_TOKEN={token}");
    Ok(())
}

pub async fn status(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;

    println!("config:      {}", config_path.display());
    println!("api:         https://{}", cfg.api_host);
    println!("tunnel:      wss://{}", cfg.tunnel_host);
    println!("previews:    *.{}", cfg.preview_zone);
    println!("service:     {}", service_state(SERVICE_NAME));
    if cfg.webrtc.enabled {
        println!("coturn:      {} (turn host {})", service_state("coturn"), cfg.turn_host);
    } else {
        println!("webrtc:      disabled");
    }

    println!("certificate: {}", cfg.cert_names().join(", "));
    match tls::cert_status(&cfg) {
        CertStatus::Valid { not_after } => println!("  valid until {}", describe_time(not_after)),
        CertStatus::NeedsRenewal => println!("  due for renewal (the server renews automatically; or `cert renew`)"),
        CertStatus::NamesChanged => println!("  does not cover the configured names; run `cert renew`"),
        CertStatus::Missing => println!("  missing; run `setup` or `cert renew`"),
    }

    let db_path = cfg.db_path();
    if db_path.exists() {
        let db = Db::open(&db_path)?;
        let (tunnels, tombstones, links, sessions) = db.counts().await?;
        drop(db);
        restore_ownership(&cfg)?;
        println!("database:    {}", db_path.display());
        println!("  tunnels {tunnels}, tombstones {tombstones}, access links {links}, gate sessions {sessions}");
    } else {
        println!("database:    {} (not created yet)", db_path.display());
    }
    Ok(())
}

pub async fn backup(config_path: &Path, out: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!out.exists(), "{} already exists; refusing to overwrite", out.display());
    let cfg = Config::load(config_path)?;
    let db_path = cfg.db_path();
    anyhow::ensure!(db_path.exists(), "no database at {}", db_path.display());
    let db = Db::open(&db_path)?;
    db.backup_to(out.to_path_buf()).await?;
    drop(db);
    restore_ownership(&cfg)?;
    // Holds token hashes and session ids; keep it private.
    crate::config::set_mode(out, 0o600)?;
    println!("Wrote {}", out.display());
    Ok(())
}

pub async fn cert_renew(config_path: &Path, force: bool) -> anyhow::Result<()> {
    ensure_root("cert renew")?;
    let cfg = Config::load(config_path)?;
    let status = tls::cert_status(&cfg);
    if let (false, CertStatus::Valid { not_after }) = (force, status) {
        println!("Certificate is valid until {}; nothing to do (use --force to renew anyway).", describe_time(not_after));
        return Ok(());
    }
    println!("Issuing a certificate for {} ...", cfg.cert_names().join(", "));
    acme::issue(&cfg).await?;
    util::chown_recursive(&cfg.data_dir, SERVICE_USER)?;
    println!("Certificate written to {}.", cfg.cert_dir().display());
    println!("A running server loads it within a minute; no restart needed.");
    Ok(())
}

/// Commands that write root-managed files must run as root.
fn ensure_root(what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(is_root(), "`{what}` must run as root (try: sudo cockpit-tunnel-server {what})");
    Ok(())
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}

/// Opening SQLite as root can leave root-owned files (the db, `-wal`, `-shm`)
/// that the service user cannot write; hand the data dir back.
fn restore_ownership(cfg: &Config) -> anyhow::Result<()> {
    if is_root() {
        util::chown_recursive(&cfg.data_dir, SERVICE_USER)?;
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `systemctl is-active` prints the state even when it exits non-zero.
fn service_state(unit: &str) -> String {
    match Command::new("systemctl").args(["is-active", unit]).stdin(Stdio::null()).output() {
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

fn describe_time(unix: i64) -> String {
    let days = (unix - tokens::now()) / 86_400;
    match time::OffsetDateTime::from_unix_timestamp(unix) {
        Ok(t) => format!("{} UTC ({days} days)", t.date()),
        Err(_) => format!("{unix} ({days} days)"),
    }
}
