//! Cleanup. Every 15 seconds, TTL-expired tunnels become tombstones (same
//! cascade and connection close as `DELETE`); this also closes tunnels that
//! `client delete` expired from outside the server process. Hourly, old
//! tombstones, expired links, grants, and sessions are removed.

use std::sync::Arc;
use std::time::Duration;

use cockpit_tunnel_protocol::CloseReason;

use crate::db::DeleteOutcome;
use crate::state::AppState;

const SWEEP_INTERVAL: Duration = Duration::from_secs(15);
const PURGE_INTERVAL: Duration = Duration::from_secs(3600);

pub async fn run(state: Arc<AppState>) {
    let mut last_purge: Option<std::time::Instant> = None;
    loop {
        if let Err(e) = expire_tunnels(&state).await {
            tracing::warn!(error = %format!("{e:#}"), "expiry sweep failed");
        }
        if last_purge.is_none_or(|t| t.elapsed() >= PURGE_INTERVAL) {
            last_purge = Some(std::time::Instant::now());
            if let Err(e) = purge_once(&state).await {
                tracing::warn!(error = %format!("{e:#}"), "purge failed");
            }
        }
        tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

async fn expire_tunnels(state: &AppState) -> anyhow::Result<()> {
    let mut expired = 0usize;
    for id in state.db.expired_tunnel_ids().await? {
        match state.delete_tunnel(&id, CloseReason::Expired).await {
            Ok(DeleteOutcome::Deleted) => expired += 1,
            Ok(_) => {}
            Err(e) => tracing::warn!(tunnel = %id, error = %format!("{e:#}"), "expiring tunnel failed"),
        }
    }
    if expired > 0 {
        tracing::info!(expired_tunnels = expired, "expired tunnels closed");
    }
    Ok(())
}

async fn purge_once(state: &AppState) -> anyhow::Result<()> {
    let retention = i64::try_from(state.config.limits.tombstone_retention_s).unwrap_or(i64::MAX);
    let stats = state.db.purge(retention).await?;
    if stats.tombstones > 0 || stats.access_links > 0 || stats.sessions > 0 || stats.grants > 0 {
        tracing::info!(
            tombstones = stats.tombstones,
            access_links = stats.access_links,
            sessions = stats.sessions,
            grants = stats.grants,
            "purge removed rows"
        );
    }
    if stats.access_links > 0 || stats.sessions > 0 || stats.grants > 0 {
        state.invalidate_sessions();
    }
    Ok(())
}
