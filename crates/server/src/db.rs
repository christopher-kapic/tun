//! SQLite persistence. All access goes through [`Db::call`], which runs the
//! closure on a blocking thread holding the single connection.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::tokens::now;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tunnels (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT,
    metadata     TEXT,
    max_ports    INTEGER NOT NULL,
    host_header  TEXT NOT NULL,
    inject_ice   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS tombstones (
    id         TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tombstones_deleted_at ON tombstones(deleted_at);
CREATE TABLE IF NOT EXISTS access_links (
    id            TEXT PRIMARY KEY,
    tunnel_id     TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    single_use    INTEGER NOT NULL,
    used_at       INTEGER,
    label         TEXT,
    session_ttl_s INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS access_links_tunnel ON access_links(tunnel_id);
CREATE TABLE IF NOT EXISTS gate_sessions (
    id_hash    TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gate_grants (
    session_hash TEXT NOT NULL REFERENCES gate_sessions(id_hash) ON DELETE CASCADE,
    tunnel_id    TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (session_hash, tunnel_id)
);
CREATE INDEX IF NOT EXISTS gate_grants_tunnel ON gate_grants(tunnel_id);
-- Every link a grant came from, so revoking any of them revokes the grant.
-- Deleting a link cascades here only; the grant itself is removed explicitly
-- by revocation, never by routine link expiry.
CREATE TABLE IF NOT EXISTS gate_grant_links (
    session_hash TEXT NOT NULL,
    tunnel_id    TEXT NOT NULL,
    link_id      TEXT NOT NULL REFERENCES access_links(id) ON DELETE CASCADE,
    PRIMARY KEY (session_hash, tunnel_id, link_id),
    FOREIGN KEY (session_hash, tunnel_id) REFERENCES gate_grants(session_hash, tunnel_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS gate_grant_links_link ON gate_grant_links(link_id);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HostHeaderMode {
    Rewrite,
    Preserve,
}

impl HostHeaderMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rewrite => "rewrite",
            Self::Preserve => "preserve",
        }
    }
    pub fn parse(s: &str) -> Self {
        if s == "preserve" {
            Self::Preserve
        } else {
            Self::Rewrite
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelRow {
    pub id: String,
    pub label: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub max_ports: u16,
    pub host_header: HostHeaderMode,
    pub inject_ice: bool,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: Option<i64>,
}

impl TunnelRow {
    pub fn is_expired(&self) -> bool {
        self.expires_at <= now()
    }
}

#[derive(Debug, Clone)]
pub struct NewTunnel {
    pub id: String,
    pub token_hash: String,
    pub label: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub max_ports: u16,
    pub host_header: HostHeaderMode,
    pub inject_ice: bool,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct TunnelPatch {
    pub expires_at: Option<i64>,
    pub label: Option<String>,
    pub host_header: Option<HostHeaderMode>,
    pub inject_ice: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct NewAccessLink {
    pub id: String,
    pub tunnel_id: String,
    pub token_hash: String,
    pub single_use: bool,
    pub label: Option<String>,
    pub session_ttl_s: i64,
    pub expires_at: i64,
}

/// Outcome of redeeming an access link.
#[derive(Debug, Clone)]
pub enum Redemption {
    /// A fresh gate session holding the new grant (plus the grants of any
    /// live session the browser presented). The caller sets the cookie to
    /// `session_id`, the plaintext; only its hash is stored.
    Granted { session_id: String, expires_at: i64 },
    /// Unknown, expired, revoked, already-used, or for another tunnel.
    Invalid,
}

/// A tunnel id's lifecycle state, resolved in one database call.
#[derive(Debug, Clone)]
pub enum TunnelLookup {
    Live(TunnelRow),
    Tombstoned,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    AlreadyTombstoned,
    NotFound,
}

#[derive(Debug, Clone, Default)]
pub struct PurgeStats {
    pub tombstones: usize,
    pub access_links: usize,
    pub sessions: usize,
    pub grants: usize,
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Run `f` with the connection on a blocking thread.
    pub async fn call<F, R>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut Connection) -> anyhow::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
            f(&mut guard)
        })
        .await?
    }

    // ---------------------------------------------------------------- tunnels

    /// True if `id` is used by a live tunnel or a tombstone (ids are never reused).
    pub async fn id_taken(&self, id: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let n: i64 = c.query_row(
                "SELECT (SELECT COUNT(*) FROM tunnels WHERE id = ?1) + (SELECT COUNT(*) FROM tombstones WHERE id = ?1)",
                params![id],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
        .await
    }

    pub async fn create_tunnel(&self, t: NewTunnel) -> anyhow::Result<TunnelRow> {
        self.call(move |c| {
            let created = now();
            let metadata = t.metadata.as_ref().map(|m| m.to_string());
            c.execute(
                "INSERT INTO tunnels (id, token_hash, label, metadata, max_ports, host_header, inject_ice, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    t.id,
                    t.token_hash,
                    t.label,
                    metadata,
                    t.max_ports,
                    t.host_header.as_str(),
                    t.inject_ice,
                    created,
                    t.expires_at
                ],
            )?;
            Ok(TunnelRow {
                id: t.id,
                label: t.label,
                metadata: t.metadata,
                max_ports: t.max_ports,
                host_header: t.host_header,
                inject_ice: t.inject_ice,
                created_at: created,
                expires_at: t.expires_at,
                last_seen_at: None,
            })
        })
        .await
    }

    pub async fn get_tunnel(&self, id: String) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            Ok(c.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row)
                .optional()?)
        })
        .await
    }

    /// Live row (possibly expired; callers check `is_expired()`), tombstone, or neither.
    pub async fn lookup_tunnel(&self, id: String) -> anyhow::Result<TunnelLookup> {
        self.call(move |c| {
            let row = c
                .query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row)
                .optional()?;
            if let Some(row) = row {
                return Ok(TunnelLookup::Live(row));
            }
            let tomb: i64 = c.query_row("SELECT COUNT(*) FROM tombstones WHERE id = ?1", params![id], |r| r.get(0))?;
            Ok(if tomb > 0 { TunnelLookup::Tombstoned } else { TunnelLookup::Unknown })
        })
        .await
    }

    pub async fn find_tunnel_by_token_hash(&self, hash: String) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            Ok(c.query_row(&format!("{TUNNEL_SELECT} WHERE token_hash = ?1"), params![hash], tunnel_from_row)
                .optional()?)
        })
        .await
    }

    pub async fn list_tunnels(&self) -> anyhow::Result<Vec<TunnelRow>> {
        self.call(|c| {
            let mut stmt = c.prepare(&format!("{TUNNEL_SELECT} ORDER BY created_at DESC"))?;
            let rows = stmt.query_map([], tunnel_from_row)?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    pub async fn update_tunnel(&self, id: String, patch: TunnelPatch) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            let tx = c.transaction()?;
            if let Some(v) = patch.expires_at {
                tx.execute("UPDATE tunnels SET expires_at = ?2 WHERE id = ?1", params![id, v])?;
            }
            if let Some(v) = &patch.label {
                tx.execute("UPDATE tunnels SET label = ?2 WHERE id = ?1", params![id, v])?;
            }
            if let Some(v) = patch.host_header {
                tx.execute("UPDATE tunnels SET host_header = ?2 WHERE id = ?1", params![id, v.as_str()])?;
            }
            if let Some(v) = patch.inject_ice {
                tx.execute("UPDATE tunnels SET inject_ice = ?2 WHERE id = ?1", params![id, v])?;
            }
            let row = tx
                .query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row)
                .optional()?;
            tx.commit()?;
            Ok(row)
        })
        .await
    }

    pub async fn touch_last_seen(&self, id: String) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute("UPDATE tunnels SET last_seen_at = ?2 WHERE id = ?1", params![id, now()])?;
            Ok(())
        })
        .await
    }

    pub async fn is_tombstoned(&self, id: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let n: i64 = c.query_row("SELECT COUNT(*) FROM tombstones WHERE id = ?1", params![id], |r| r.get(0))?;
            Ok(n > 0)
        })
        .await
    }

    /// Hard-delete the tunnel, its token, links, and grants (FK cascades),
    /// delete gate sessions left without grants, insert a tombstone. One transaction.
    pub async fn delete_tunnel(&self, id: String) -> anyhow::Result<DeleteOutcome> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let n = tx.execute("DELETE FROM tunnels WHERE id = ?1", params![id])?;
            if n == 0 {
                let tomb: i64 =
                    tx.query_row("SELECT COUNT(*) FROM tombstones WHERE id = ?1", params![id], |r| r.get(0))?;
                tx.commit()?;
                return Ok(if tomb > 0 { DeleteOutcome::AlreadyTombstoned } else { DeleteOutcome::NotFound });
            }
            tx.execute(
                "INSERT OR REPLACE INTO tombstones (id, deleted_at) VALUES (?1, ?2)",
                params![id, now()],
            )?;
            tx.execute(
                "DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)",
                [],
            )?;
            tx.commit()?;
            Ok(DeleteOutcome::Deleted)
        })
        .await
    }

    /// Ids of tunnels whose TTL has elapsed (the purge job deletes them via the
    /// same path as the API so live connections are closed too).
    pub async fn expired_tunnel_ids(&self) -> anyhow::Result<Vec<String>> {
        self.call(|c| {
            let mut stmt = c.prepare("SELECT id FROM tunnels WHERE expires_at <= ?1")?;
            let ids = stmt.query_map(params![now()], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
            Ok(ids)
        })
        .await
    }

    // ----------------------------------------------------------- access links

    pub async fn create_access_link(&self, l: NewAccessLink) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO access_links (id, tunnel_id, token_hash, single_use, label, session_ttl_s, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![l.id, l.tunnel_id, l.token_hash, l.single_use, l.label, l.session_ttl_s, now(), l.expires_at],
            )?;
            Ok(())
        })
        .await
    }

    /// Revoke a link: delete every grant it contributed to, the link, and
    /// sessions left without grants. Returns `false` if no such link.
    pub async fn delete_access_link(&self, id: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "DELETE FROM gate_grants WHERE EXISTS (
                     SELECT 1 FROM gate_grant_links l
                     WHERE l.link_id = ?1 AND l.session_hash = gate_grants.session_hash
                       AND l.tunnel_id = gate_grants.tunnel_id)",
                params![id],
            )?;
            let n = tx.execute("DELETE FROM access_links WHERE id = ?1", params![id])?;
            tx.execute(
                "DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)",
                [],
            )?;
            tx.commit()?;
            Ok(n > 0)
        })
        .await
    }

    /// Redeem `token_hash` for `tunnel_id`. Always mints a fresh session: a
    /// presented cookie value may have been tossed by preview JS, so the new
    /// grant is never attached to it. The unexpired grants of every live
    /// session in `presented_session_hashes` are copied into the new session
    /// (tossing could already give the browser those), which keeps one cookie
    /// covering every tunnel the visitor holds. Single-use links are consumed
    /// in the same transaction as the grant.
    pub async fn redeem_access_link(
        &self,
        tunnel_id: String,
        token_hash: String,
        presented_session_hashes: Vec<String>,
    ) -> anyhow::Result<Redemption> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let link: Option<(String, bool, Option<i64>, i64, i64)> = tx
                .query_row(
                    "SELECT id, single_use, used_at, session_ttl_s, expires_at FROM access_links
                     WHERE token_hash = ?1 AND tunnel_id = ?2",
                    params![token_hash, tunnel_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((link_id, single_use, used_at, session_ttl_s, link_expires)) = link else {
                return Ok(Redemption::Invalid);
            };
            if link_expires <= t || (single_use && used_at.is_some()) {
                return Ok(Redemption::Invalid);
            }
            let tunnel_expires: Option<i64> = tx
                .query_row("SELECT expires_at FROM tunnels WHERE id = ?1", params![tunnel_id], |r| r.get(0))
                .optional()?;
            if tunnel_expires.is_none_or(|e| e <= t) {
                return Ok(Redemption::Invalid);
            }
            if single_use {
                let n = tx.execute(
                    "UPDATE access_links SET used_at = ?2 WHERE id = ?1 AND used_at IS NULL",
                    params![link_id, t],
                )?;
                if n != 1 {
                    return Ok(Redemption::Invalid);
                }
            }
            // Not capped by the tunnel's expiry: the edge enforces that live,
            // so a later `PATCH` extending the tunnel keeps visitors signed in.
            let grant_expires = t + session_ttl_s;

            let session_id = crate::tokens::random_secret();
            let session_hash = crate::tokens::hash_token(&session_id);
            tx.execute(
                "INSERT INTO gate_sessions (id_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
                params![session_hash, t, grant_expires],
            )?;
            {
                let mut copy_grants = tx.prepare(
                    "INSERT INTO gate_grants (session_hash, tunnel_id, expires_at)
                     SELECT ?1, g.tunnel_id, g.expires_at FROM gate_grants g
                     JOIN gate_sessions s ON s.id_hash = g.session_hash
                     WHERE g.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3
                     ON CONFLICT(session_hash, tunnel_id) DO UPDATE SET
                       expires_at = MAX(gate_grants.expires_at, excluded.expires_at)",
                )?;
                // Provenance follows the copy so revoking the original link
                // also revokes the carried-over grant.
                let mut copy_links = tx.prepare(
                    "INSERT OR IGNORE INTO gate_grant_links (session_hash, tunnel_id, link_id)
                     SELECT ?1, l.tunnel_id, l.link_id FROM gate_grant_links l
                     JOIN gate_grants g ON g.session_hash = l.session_hash AND g.tunnel_id = l.tunnel_id
                     JOIN gate_sessions s ON s.id_hash = l.session_hash
                     WHERE l.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3",
                )?;
                let mut seen: Vec<&String> = Vec::new();
                for h in &presented_session_hashes {
                    if seen.contains(&h) || *h == session_hash {
                        continue;
                    }
                    seen.push(h);
                    copy_grants.execute(params![session_hash, h, t])?;
                    copy_links.execute(params![session_hash, h, t])?;
                }
            }
            tx.execute(
                "INSERT INTO gate_grants (session_hash, tunnel_id, expires_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(session_hash, tunnel_id) DO UPDATE SET
                   expires_at = MAX(gate_grants.expires_at, excluded.expires_at)",
                params![session_hash, tunnel_id, grant_expires],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO gate_grant_links (session_hash, tunnel_id, link_id) VALUES (?1, ?2, ?3)",
                params![session_hash, tunnel_id, link_id],
            )?;
            let expires_at: i64 = tx.query_row(
                "UPDATE gate_sessions SET expires_at =
                   (SELECT MAX(expires_at) FROM gate_grants WHERE session_hash = ?1)
                 WHERE id_hash = ?1 RETURNING expires_at",
                params![session_hash],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(Redemption::Granted { session_id, expires_at })
        })
        .await
    }

    /// Unexpired `(tunnel_id, grant_expires_at)` pairs for each of
    /// `session_hashes` that is a live session with at least one grant, in
    /// one query. Hashes with nothing live are absent from the map.
    pub async fn session_grants(
        &self,
        session_hashes: Vec<String>,
    ) -> anyhow::Result<HashMap<String, Vec<(String, i64)>>> {
        if session_hashes.is_empty() {
            return Ok(HashMap::new());
        }
        self.call(move |c| {
            let placeholders = (0..session_hashes.len()).map(|i| format!("?{}", i + 2)).collect::<Vec<_>>().join(",");
            let mut stmt = c.prepare(&format!(
                "SELECT g.session_hash, g.tunnel_id, g.expires_at FROM gate_grants g
                 JOIN gate_sessions s ON s.id_hash = g.session_hash
                 WHERE g.session_hash IN ({placeholders}) AND s.expires_at > ?1 AND g.expires_at > ?1"
            ))?;
            let mut values = Vec::with_capacity(session_hashes.len() + 1);
            values.push(Value::Integer(now()));
            values.extend(session_hashes.into_iter().map(Value::Text));
            let mut out: HashMap<String, Vec<(String, i64)>> = HashMap::new();
            let mut rows = stmt.query(params_from_iter(values.iter()))?;
            while let Some(r) = rows.next()? {
                out.entry(r.get(0)?).or_default().push((r.get(1)?, r.get(2)?));
            }
            Ok(out)
        })
        .await
    }

    // ------------------------------------------------------------------ purge

    /// Remove tombstones older than `tombstone_retention_s`, expired grants,
    /// expired or grant-less sessions, and expired access links that no live
    /// grant came from. A link outlives its expiry while its grants live, so
    /// revoking it still revokes them and routine expiry never logs anyone out.
    pub async fn purge(&self, tombstone_retention_s: i64) -> anyhow::Result<PurgeStats> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let tombstones =
                tx.execute("DELETE FROM tombstones WHERE deleted_at <= ?1", params![t - tombstone_retention_s])?;
            let grants = tx.execute("DELETE FROM gate_grants WHERE expires_at <= ?1", params![t])?;
            let sessions = tx.execute(
                "DELETE FROM gate_sessions WHERE expires_at <= ?1
                   OR id_hash NOT IN (SELECT session_hash FROM gate_grants)",
                params![t],
            )?;
            let access_links = tx.execute(
                "DELETE FROM access_links WHERE expires_at <= ?1
                   AND NOT EXISTS (SELECT 1 FROM gate_grant_links l WHERE l.link_id = access_links.id)",
                params![t],
            )?;
            tx.commit()?;
            Ok(PurgeStats { tombstones, access_links, sessions, grants })
        })
        .await
    }

    // ----------------------------------------------------------------- admin

    pub async fn backup_to(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute("VACUUM INTO ?1", params![path.to_string_lossy()])?;
            Ok(())
        })
        .await
    }

    /// `(tunnels, tombstones, access_links, gate_sessions)` counts for `status`.
    pub async fn counts(&self) -> anyhow::Result<(i64, i64, i64, i64)> {
        self.call(|c| {
            Ok(c.query_row(
                "SELECT (SELECT COUNT(*) FROM tunnels), (SELECT COUNT(*) FROM tombstones),
                        (SELECT COUNT(*) FROM access_links), (SELECT COUNT(*) FROM gate_sessions)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })
        .await
    }
}

const TUNNEL_SELECT: &str = "SELECT id, label, metadata, max_ports, host_header, inject_ice, created_at, expires_at, last_seen_at FROM tunnels";

fn tunnel_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelRow> {
    let metadata: Option<String> = r.get(2)?;
    let host_header: String = r.get(4)?;
    Ok(TunnelRow {
        id: r.get(0)?,
        label: r.get(1)?,
        metadata: metadata.and_then(|m| serde_json::from_str(&m).ok()),
        max_ports: r.get(3)?,
        host_header: HostHeaderMode::parse(&host_header),
        inject_ice: r.get(5)?,
        created_at: r.get(6)?,
        expires_at: r.get(7)?,
        last_seen_at: r.get(8)?,
    })
}

