//! Hourly cleanup: TTL-expired tunnels become tombstones (same cascade and
//! connection close as `DELETE`), then old tombstones, expired links, grants,
//! and sessions are removed.

use std::sync::Arc;
use std::time::Duration;

use cockpit_tunnel_protocol::CloseReason;

use crate::db::DeleteOutcome;
use crate::state::AppState;

const INTERVAL: Duration = Duration::from_secs(3600);

pub async fn run(state: Arc<AppState>) {
    loop {
        if let Err(e) = purge_once(&state).await {
            tracing::warn!(error = %format!("{e:#}"), "purge failed");
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

async fn purge_once(state: &AppState) -> anyhow::Result<()> {
    let mut expired = 0usize;
    for id in state.db.expired_tunnel_ids().await? {
        match state.delete_tunnel(&id, CloseReason::Expired).await {
            Ok(DeleteOutcome::Deleted) => expired += 1,
            Ok(_) => {}
            Err(e) => tracing::warn!(tunnel = %id, error = %format!("{e:#}"), "expiring tunnel failed"),
        }
    }

    let retention = i64::try_from(state.config.limits.tombstone_retention_s).unwrap_or(i64::MAX);
    let stats = state.db.purge(retention).await?;
    if expired > 0 || stats.tombstones > 0 || stats.access_links > 0 || stats.sessions > 0 || stats.grants > 0 {
        tracing::info!(
            expired_tunnels = expired,
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
