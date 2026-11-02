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
    -- When the access this link gave runs out (NULL in older databases: the grant's).
    expires_at   INTEGER,
    PRIMARY KEY (session_hash, tunnel_id, link_id),
    FOREIGN KEY (session_hash, tunnel_id) REFERENCES gate_grants(session_hash, tunnel_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS gate_grant_links_link ON gate_grant_links(link_id);
-- Grants that came from a password login, so changing the password (or
-- leaving password mode) revokes exactly those.
CREATE TABLE IF NOT EXISTS gate_grant_logins (
    session_hash TEXT NOT NULL,
    tunnel_id    TEXT NOT NULL,
    expires_at   INTEGER,
    PRIMARY KEY (session_hash, tunnel_id),
    FOREIGN KEY (session_hash, tunnel_id) REFERENCES gate_grants(session_hash, tunnel_id) ON DELETE CASCADE
);
-- Machines enrolled with `client add` + `cockpit-preview login`.
CREATE TABLE IF NOT EXISTS clients (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
-- One-time enrollment codes; only the hash is stored.
CREATE TABLE IF NOT EXISTS client_enrollments (
    code_hash  TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
"#;

/// Columns added after the first release, as `(table, column, definition)`.
/// `CREATE TABLE IF NOT EXISTS` never alters an existing table.
const COLUMNS_ADDED: &[(&str, &str, &str)] =
    &[("gate_grant_links", "expires_at", "INTEGER"), ("gate_grant_logins", "expires_at", "INTEGER")];

/// Indexes that depend on added columns, created after migration.
const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS tunnels_expires_at ON tunnels(expires_at);
CREATE INDEX IF NOT EXISTS tunnels_client ON tunnels(client_id, expires_at);
";

const TUNNEL_COLUMNS_ADDED: &[(&str, &str)] = &[
    ("access_mode", "TEXT NOT NULL DEFAULT 'link'"),
    ("password_user", "TEXT"),
    ("password_hash", "TEXT"),
    // The client that created the tunnel; NULL for the admin token.
    ("client_id", "TEXT"),
];

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

/// Who may open a tunnel's previews. Access links work in every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Access links only.
    Link,
    /// Access links, or a username and password on the login page.
    Password,
    /// Anyone with the URL; no gate.
    Public,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Password => "password",
            Self::Public => "public",
        }
    }
    /// Unknown values fall back to the strictest mode.
    pub fn parse(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "public" => Self::Public,
            _ => Self::Link,
        }
    }
}

/// A tunnel's access setting as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub mode: AccessMode,
    /// Set in password mode only.
    pub password_user: Option<String>,
    /// PHC-format argon2 hash; set in password mode only.
    pub password_hash: Option<String>,
}

impl Default for Access {
    fn default() -> Self {
        Self { mode: AccessMode::Link, password_user: None, password_hash: None }
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
    pub access: Access,
    /// Creating client's id; `None` for tunnels created with the admin token.
    pub client_id: Option<String>,
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
    pub access: Access,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TunnelPatch {
    pub expires_at: Option<i64>,
    pub label: Option<String>,
    pub host_header: Option<HostHeaderMode>,
    pub inject_ice: Option<bool>,
    /// Replaces the whole access setting.
    pub access: Option<Access>,
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

/// An enrolled machine.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub name: String,
    /// False until the enrollment code has been redeemed.
    pub enrolled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Unexpired tunnels it created.
    pub tunnels: i64,
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
        migrate(&conn)?;
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

    /// `None` if `t.client_id` names a client that no longer exists (deleted
    /// after the request authenticated): checked in the same statement, so a
    /// concurrent `delete_client` cannot leave a live orphan.
    pub async fn create_tunnel(&self, t: NewTunnel) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            let created = now();
            let metadata = t.metadata.as_ref().map(|m| m.to_string());
            let inserted = c.execute(
                "INSERT INTO tunnels (id, token_hash, label, metadata, max_ports, host_header, inject_ice, created_at, expires_at,
                                      access_mode, password_user, password_hash, client_id)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
                 WHERE ?13 IS NULL OR EXISTS (SELECT 1 FROM clients WHERE id = ?13)",
                params![
                    t.id,
                    t.token_hash,
                    t.label,
                    metadata,
                    t.max_ports,
                    t.host_header.as_str(),
                    t.inject_ice,
                    created,
                    t.expires_at,
                    t.access.mode.as_str(),
                    t.access.password_user,
                    t.access.password_hash,
                    t.client_id,
                ],
            )?;
            if inserted == 0 {
                return Ok(None);
            }
            Ok(Some(TunnelRow {
                id: t.id,
                label: t.label,
                metadata: t.metadata,
                max_ports: t.max_ports,
                host_header: t.host_header,
                inject_ice: t.inject_ice,
                created_at: created,
                expires_at: t.expires_at,
                last_seen_at: None,
                access: t.access,
                client_id: t.client_id,
            }))
        })
        .await
    }

    pub async fn get_tunnel(&self, id: String) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            Ok(c.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?)
        })
        .await
    }

    /// Live row (possibly expired; callers check `is_expired()`), tombstone, or neither.
    pub async fn lookup_tunnel(&self, id: String) -> anyhow::Result<TunnelLookup> {
        self.call(move |c| {
            let row =
                c.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?;
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
            if let Some(access) = &patch.access {
                let old_hash: Option<Option<String>> = tx
                    .query_row("SELECT password_hash FROM tunnels WHERE id = ?1", params![id], |r| r.get(0))
                    .optional()?;
                tx.execute(
                    "UPDATE tunnels SET access_mode = ?2, password_user = ?3, password_hash = ?4 WHERE id = ?1",
                    params![id, access.mode.as_str(), access.password_user, access.password_hash],
                )?;
                // A new password (or none) ends every session the old one opened.
                if old_hash.flatten() != access.password_hash {
                    revoke_login_grants(&tx, &id)?;
                }
            }
            let row =
                tx.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?;
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
            tx.execute("INSERT OR REPLACE INTO tombstones (id, deleted_at) VALUES (?1, ?2)", params![id, now()])?;
            tx.execute("DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)", [])?;
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
            tx.execute("DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)", [])?;
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
            let (session_id, session_hash) =
                mint_session(&tx, &tunnel_id, &presented_session_hashes, t, t + session_ttl_s)?;
            tx.execute(
                "INSERT OR IGNORE INTO gate_grant_links (session_hash, tunnel_id, link_id, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![session_hash, tunnel_id, link_id, t + session_ttl_s],
            )?;
            let expires_at = finish_session(&tx, &session_hash)?;
            tx.commit()?;
            Ok(Redemption::Granted { session_id, expires_at })
        })
        .await
    }

    /// A successful password login: a fresh session (carrying the presented
    /// sessions' grants, like a link redemption) with a grant for `tunnel_id`
    /// recorded as login-derived. `None` if the tunnel is gone, expired, or no
    /// longer in password mode with exactly `password_hash` (a concurrent
    /// password change wins over a login checked against the old one).
    pub async fn login_grant(
        &self,
        tunnel_id: String,
        password_hash: String,
        session_ttl_s: i64,
        presented_session_hashes: Vec<String>,
    ) -> anyhow::Result<Option<Redemption>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let current: Option<(i64, String, Option<String>)> = tx
                .query_row(
                    "SELECT expires_at, access_mode, password_hash FROM tunnels WHERE id = ?1",
                    params![tunnel_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match current {
                Some((expires, mode, Some(hash)))
                    if expires > t && AccessMode::parse(&mode) == AccessMode::Password && hash == password_hash => {}
                _ => return Ok(None),
            }
            let (session_id, session_hash) =
                mint_session(&tx, &tunnel_id, &presented_session_hashes, t, t + session_ttl_s)?;
            tx.execute(
                "INSERT OR IGNORE INTO gate_grant_logins (session_hash, tunnel_id, expires_at) VALUES (?1, ?2, ?3)",
                params![session_hash, tunnel_id, t + session_ttl_s],
            )?;
            let expires_at = finish_session(&tx, &session_hash)?;
            tx.commit()?;
            Ok(Some(Redemption::Granted { session_id, expires_at }))
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

    // ---------------------------------------------------------------- clients

    /// New client `name` with a one-time enrollment code (hash stored) valid
    /// until `code_expires_at`. `None` if the name is taken.
    pub async fn create_client(
        &self,
        id: String,
        name: String,
        code_hash: String,
        code_expires_at: i64,
    ) -> anyhow::Result<Option<ClientRow>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let taken: i64 =
                tx.query_row("SELECT COUNT(*) FROM clients WHERE name = ?1", params![name], |r| r.get(0))?;
            if taken > 0 {
                return Ok(None);
            }
            tx.execute("INSERT INTO clients (id, name, created_at) VALUES (?1, ?2, ?3)", params![id, name, t])?;
            tx.execute(
                "INSERT INTO client_enrollments (code_hash, client_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![code_hash, id, t, code_expires_at],
            )?;
            tx.commit()?;
            Ok(Some(ClientRow { name, enrolled: false, created_at: t, last_used_at: None, tunnels: 0 }))
        })
        .await
    }

    /// Redeem an enrollment code: single use, unexpired. Sets the client's token
    /// hash (replacing any earlier token) and returns the client's name.
    pub async fn enroll_client(&self, code_hash: String, token_hash: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let found: Option<(String, String)> = tx
                .query_row(
                    "SELECT e.client_id, c.name FROM client_enrollments e JOIN clients c ON c.id = e.client_id
                     WHERE e.code_hash = ?1 AND e.used_at IS NULL AND e.expires_at > ?2",
                    params![code_hash, t],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((client_id, name)) = found else {
                return Ok(None);
            };
            let n = tx.execute(
                "UPDATE client_enrollments SET used_at = ?2 WHERE code_hash = ?1 AND used_at IS NULL",
                params![code_hash, t],
            )?;
            if n != 1 {
                return Ok(None);
            }
            tx.execute(
                "UPDATE clients SET token_hash = ?2, last_used_at = ?3 WHERE id = ?1",
                params![client_id, token_hash, t],
            )?;
            tx.commit()?;
            Ok(Some(name))
        })
        .await
    }

    /// The client holding `token_hash`, recording use at most once a minute.
    pub async fn client_by_token_hash(&self, token_hash: String) -> anyhow::Result<Option<(String, String)>> {
        self.call(move |c| {
            let t = now();
            let found: Option<(String, String)> = c
                .query_row("SELECT id, name FROM clients WHERE token_hash = ?1", params![token_hash], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            if let Some((id, _)) = &found {
                c.execute(
                    "UPDATE clients SET last_used_at = ?2 WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 60)",
                    params![id, t],
                )?;
            }
            Ok(found)
        })
        .await
    }

    pub async fn list_clients(&self) -> anyhow::Result<Vec<ClientRow>> {
        self.call(|c| {
            let mut stmt = c.prepare(
                "SELECT c.name, c.token_hash IS NOT NULL, c.created_at, c.last_used_at,
                        (SELECT COUNT(*) FROM tunnels t WHERE t.client_id = c.id AND t.expires_at > ?1)
                 FROM clients c ORDER BY c.name",
            )?;
            let rows = stmt
                .query_map(params![now()], |r| {
                    Ok(ClientRow {
                        name: r.get(0)?,
                        enrolled: r.get(1)?,
                        created_at: r.get(2)?,
                        last_used_at: r.get(3)?,
                        tunnels: r.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    /// Delete client `name` (its token and pending codes go with it) and
    /// expire its tunnels so they stop serving at once. Returns the tunnel
    /// ids so a running server can close them right away; otherwise the
    /// expiry sweep does. `None` if there is no such client.
    pub async fn delete_client(&self, name: String) -> anyhow::Result<Option<Vec<String>>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let id: Option<String> =
                tx.query_row("SELECT id FROM clients WHERE name = ?1", params![name], |r| r.get(0)).optional()?;
            let Some(id) = id else {
                return Ok(None);
            };
            let tunnels: Vec<String> = {
                let mut stmt = tx.prepare("SELECT id FROM tunnels WHERE client_id = ?1")?;
                let rows = stmt.query_map(params![id], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
                rows
            };
            tx.execute("UPDATE tunnels SET expires_at = MIN(expires_at, ?2) WHERE client_id = ?1", params![id, t - 1])?;
            tx.execute("DELETE FROM clients WHERE id = ?1", params![id])?;
            tx.commit()?;
            Ok(Some(tunnels))
        })
        .await
    }

    /// The tunnel an access link belongs to.
    pub async fn access_link_tunnel(&self, link_id: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            Ok(c.query_row("SELECT tunnel_id FROM access_links WHERE id = ?1", params![link_id], |r| r.get(0))
                .optional()?)
        })
        .await
    }

    /// Unexpired tunnels created by `client_id`.
    pub async fn list_client_tunnels(&self, client_id: String) -> anyhow::Result<Vec<TunnelRow>> {
        self.call(move |c| {
            let mut stmt = c.prepare(&format!("{TUNNEL_SELECT} WHERE client_id = ?1 ORDER BY created_at DESC"))?;
            let rows = stmt.query_map(params![client_id], tunnel_from_row)?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
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

const TUNNEL_SELECT: &str = "SELECT id, label, metadata, max_ports, host_header, inject_ice, created_at, expires_at, last_seen_at, access_mode, password_user, password_hash, client_id FROM tunnels";

/// Add columns that older databases lack.
fn migrate(conn: &Connection) -> anyhow::Result<()> {
    let columns = TUNNEL_COLUMNS_ADDED.iter().map(|(c, d)| ("tunnels", *c, *d)).chain(COLUMNS_ADDED.iter().copied());
    for (table, column, definition) in columns {
        let have: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        if !have.iter().any(|c| c == column) {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"))?;
        }
    }
    conn.execute_batch(INDEXES)?;
    Ok(())
}

/// Fresh session for a new grant on `tunnel_id`, carrying the unexpired grants
/// (and their provenance) of every live presented session. Returns the
/// plaintext session id and its hash; the caller records the new grant's
/// provenance and then calls [`finish_session`].
fn mint_session(
    tx: &rusqlite::Transaction<'_>,
    tunnel_id: &str,
    presented_session_hashes: &[String],
    t: i64,
    grant_expires: i64,
) -> anyhow::Result<(String, String)> {
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
        // Provenance follows the copy so revoking the original link (or
        // changing the password) also revokes the carried-over grant.
        let mut copy_links = tx.prepare(
            "INSERT OR IGNORE INTO gate_grant_links (session_hash, tunnel_id, link_id, expires_at)
             SELECT ?1, l.tunnel_id, l.link_id, l.expires_at FROM gate_grant_links l
             JOIN gate_grants g ON g.session_hash = l.session_hash AND g.tunnel_id = l.tunnel_id
             JOIN gate_sessions s ON s.id_hash = l.session_hash
             WHERE l.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3",
        )?;
        let mut copy_logins = tx.prepare(
            "INSERT OR IGNORE INTO gate_grant_logins (session_hash, tunnel_id, expires_at)
             SELECT ?1, l.tunnel_id, l.expires_at FROM gate_grant_logins l
             JOIN gate_grants g ON g.session_hash = l.session_hash AND g.tunnel_id = l.tunnel_id
             JOIN gate_sessions s ON s.id_hash = l.session_hash
             WHERE l.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3",
        )?;
        let mut seen: Vec<&String> = Vec::new();
        for h in presented_session_hashes {
            if seen.contains(&h) || *h == session_hash {
                continue;
            }
            seen.push(h);
            copy_grants.execute(params![session_hash, h, t])?;
            copy_links.execute(params![session_hash, h, t])?;
            copy_logins.execute(params![session_hash, h, t])?;
        }
    }
    tx.execute(
        "INSERT INTO gate_grants (session_hash, tunnel_id, expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(session_hash, tunnel_id) DO UPDATE SET
           expires_at = MAX(gate_grants.expires_at, excluded.expires_at)",
        params![session_hash, tunnel_id, grant_expires],
    )?;
    Ok((session_id, session_hash))
}

/// Set the session's expiry to its longest grant; returns it.
fn finish_session(tx: &rusqlite::Transaction<'_>, session_hash: &str) -> anyhow::Result<i64> {
    Ok(tx.query_row(
        "UPDATE gate_sessions SET expires_at =
           (SELECT MAX(expires_at) FROM gate_grants WHERE session_hash = ?1)
         WHERE id_hash = ?1 RETURNING expires_at",
        params![session_hash],
        |r| r.get(0),
    )?)
}

/// End what password logins granted on `tunnel_id`. A grant that a still-live
/// access link also vouches for stays, but only until that link's own
/// expiry (a longer login must not outlive the password); the rest go, then
/// sessions left empty.
fn revoke_login_grants(tx: &rusqlite::Transaction<'_>, tunnel_id: &str) -> anyhow::Result<()> {
    let t = now();
    let has_login = "EXISTS (SELECT 1 FROM gate_grant_logins l
                     WHERE l.session_hash = gate_grants.session_hash AND l.tunnel_id = ?1)";
    let live_link = "FROM gate_grant_links k
                     WHERE k.session_hash = gate_grants.session_hash AND k.tunnel_id = ?1
                       AND (k.expires_at IS NULL OR k.expires_at > ?2)";
    tx.execute(
        &format!("DELETE FROM gate_grants WHERE tunnel_id = ?1 AND {has_login} AND NOT EXISTS (SELECT 1 {live_link})"),
        params![tunnel_id, t],
    )?;
    tx.execute(
        &format!(
            "UPDATE gate_grants SET expires_at = MIN(expires_at,
               (SELECT MAX(COALESCE(k.expires_at, gate_grants.expires_at)) {live_link}))
             WHERE tunnel_id = ?1 AND {has_login}"
        ),
        params![tunnel_id, t],
    )?;
    tx.execute("DELETE FROM gate_grant_logins WHERE tunnel_id = ?1", params![tunnel_id])?;
    tx.execute("DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)", [])?;
    Ok(())
}

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
        access: Access {
            mode: AccessMode::parse(&r.get::<_, String>(9)?),
            password_user: r.get(10)?,
            password_hash: r.get(11)?,
        },
        client_id: r.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("cockpit-tunnel-test-{}.db", crate::tokens::random_tunnel_id()));
        (Db::open(&path).unwrap(), path)
    }

    fn password_access(hash: &str) -> Access {
        Access { mode: AccessMode::Password, password_user: Some("ann".into()), password_hash: Some(hash.into()) }
    }

    async fn has_grant(db: &Db, session_id: &str, tunnel: &str) -> bool {
        let hash = crate::tokens::hash_token(session_id);
        let grants = db.session_grants(vec![hash.clone()]).await.unwrap();
        grants.get(&hash).is_some_and(|g| g.iter().any(|(t, _)| t == tunnel))
    }

    fn granted(r: Option<Redemption>) -> String {
        match r {
            Some(Redemption::Granted { session_id, .. }) => session_id,
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn password_change_revokes_only_login_grants() {
        let (db, path) = temp_db();
        let id = "t1aaaaaaaa".to_string();
        db.create_tunnel(NewTunnel {
            id: id.clone(),
            token_hash: "tok".into(),
            label: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 3600,
            access: password_access("h1"),
            client_id: None,
        })
        .await
        .unwrap();
        db.create_access_link(NewAccessLink {
            id: "al1".into(),
            tunnel_id: id.clone(),
            token_hash: "link".into(),
            single_use: false,
            label: None,
            session_ttl_s: 3600,
            expires_at: now() + 600,
        })
        .await
        .unwrap();

        // Link session; then a login that carries it (both provenances); then a login-only session.
        let s_link = granted(Some(db.redeem_access_link(id.clone(), "link".into(), vec![]).await.unwrap()));
        let s_both = granted(
            db.login_grant(id.clone(), "h1".into(), 3600, vec![crate::tokens::hash_token(&s_link)]).await.unwrap(),
        );
        let s_login = granted(db.login_grant(id.clone(), "h1".into(), 3600, vec![]).await.unwrap());
        assert!(db.login_grant(id.clone(), "wrong".into(), 3600, vec![]).await.unwrap().is_none());
        for s in [&s_link, &s_both, &s_login] {
            assert!(has_grant(&db, s, &id).await);
        }

        // New password: the login-only session is out; link-backed ones stay; the old hash no longer logs in.
        db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
            .await
            .unwrap();
        assert!(!has_grant(&db, &s_login, &id).await);
        assert!(has_grant(&db, &s_both, &id).await);
        assert!(has_grant(&db, &s_link, &id).await);
        assert!(db.login_grant(id.clone(), "h1".into(), 3600, vec![]).await.unwrap().is_none());

        // Same password again changes nothing; leaving password mode revokes new logins and blocks more.
        let s_login2 = granted(db.login_grant(id.clone(), "h2".into(), 3600, vec![]).await.unwrap());
        db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
            .await
            .unwrap();
        assert!(has_grant(&db, &s_login2, &id).await);
        db.update_tunnel(id.clone(), TunnelPatch { access: Some(Access::default()), ..Default::default() })
            .await
            .unwrap();
        assert!(!has_grant(&db, &s_login2, &id).await);
        assert!(has_grant(&db, &s_link, &id).await);
        assert!(db.login_grant(id.clone(), "h2".into(), 3600, vec![]).await.unwrap().is_none());
        let row = db.get_tunnel(id.clone()).await.unwrap().unwrap();
        assert_eq!(row.access, Access::default());

        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn client_enrollment_and_delete() {
        let (db, path) = temp_db();
        assert!(db.create_client("c1".into(), "laptop".into(), "code".into(), now() + 900).await.unwrap().is_some());
        assert!(db.create_client("c2".into(), "laptop".into(), "code2".into(), now() + 900).await.unwrap().is_none());
        assert!(db.create_client("c3".into(), "old".into(), "stale".into(), now() - 1).await.unwrap().is_some());

        assert!(db.enroll_client("wrong".into(), "t".into()).await.unwrap().is_none());
        assert!(db.enroll_client("stale".into(), "t".into()).await.unwrap().is_none(), "expired code");
        assert_eq!(db.enroll_client("code".into(), "tok".into()).await.unwrap().as_deref(), Some("laptop"));
        assert!(db.enroll_client("code".into(), "tok2".into()).await.unwrap().is_none(), "single use");
        assert_eq!(db.client_by_token_hash("tok".into()).await.unwrap().map(|(id, _)| id).as_deref(), Some("c1"));

        let mk = |id: &str, client: Option<&str>| NewTunnel {
            id: id.into(),
            token_hash: format!("tt-{id}"),
            label: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 3600,
            access: Access::default(),
            client_id: client.map(str::to_string),
        };
        db.create_tunnel(mk("own1aaaaaa", Some("c1"))).await.unwrap();
        db.create_tunnel(mk("adm1aaaaaa", None)).await.unwrap();
        assert_eq!(db.list_client_tunnels("c1".into()).await.unwrap().len(), 1);
        let listed = db.list_clients().await.unwrap();
        let laptop = listed.iter().find(|c| c.name == "laptop").unwrap();
        assert!(laptop.enrolled && laptop.tunnels == 1);
        assert!(!listed.iter().find(|c| c.name == "old").unwrap().enrolled);

        assert_eq!(db.delete_client("laptop".into()).await.unwrap(), Some(vec!["own1aaaaaa".to_string()]));
        assert!(db.client_by_token_hash("tok".into()).await.unwrap().is_none());
        assert!(db.get_tunnel("own1aaaaaa".into()).await.unwrap().unwrap().is_expired());
        assert!(!db.get_tunnel("adm1aaaaaa".into()).await.unwrap().unwrap().is_expired());
        assert_eq!(db.expired_tunnel_ids().await.unwrap(), vec!["own1aaaaaa".to_string()]);
        assert!(db.delete_client("laptop".into()).await.unwrap().is_none());

        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn password_change_caps_merged_grant_at_link_expiry() {
        let (db, path) = temp_db();
        let id = "t2aaaaaaaa".to_string();
        db.create_tunnel(NewTunnel {
            id: id.clone(),
            token_hash: "tok2".into(),
            label: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 86_400,
            access: password_access("h1"),
            client_id: None,
        })
        .await
        .unwrap()
        .unwrap();
        db.create_access_link(NewAccessLink {
            id: "short".into(),
            tunnel_id: id.clone(),
            token_hash: "shortlink".into(),
            single_use: false,
            label: None,
            session_ttl_s: 60,
            expires_at: now() + 600,
        })
        .await
        .unwrap();
        let s_link = granted(Some(db.redeem_access_link(id.clone(), "shortlink".into(), vec![]).await.unwrap()));
        let merged = granted(
            db.login_grant(id.clone(), "h1".into(), 7200, vec![crate::tokens::hash_token(&s_link)]).await.unwrap(),
        );
        let hash = crate::tokens::hash_token(&merged);
        let before = db.session_grants(vec![hash.clone()]).await.unwrap()[&hash][0].1;
        assert!(before > now() + 3600, "merged grant carries the login's expiry");

        db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
            .await
            .unwrap();
        let after = db.session_grants(vec![hash.clone()]).await.unwrap()[&hash][0].1;
        assert!(after <= now() + 60, "capped at the link's own expiry, got {}", after - now());

        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn tunnel_for_deleted_client_is_not_created() {
        let (db, path) = temp_db();
        let t = |id: &str, client: &str| NewTunnel {
            id: id.into(),
            token_hash: format!("h-{id}"),
            label: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 600,
            access: Access::default(),
            client_id: Some(client.into()),
        };
        assert!(db.create_tunnel(t("gone1aaaaa", "no-such-client")).await.unwrap().is_none());
        db.create_client("cx".into(), "x".into(), "c".into(), now() + 60).await.unwrap();
        assert!(db.create_tunnel(t("live1aaaaa", "cx")).await.unwrap().is_some());
        db.delete_client("x".into()).await.unwrap();
        assert!(db.create_tunnel(t("late1aaaaa", "cx")).await.unwrap().is_none());
        let indexes: i64 = db
            .call(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('tunnels_expires_at', 'tunnels_client')",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(indexes, 2);
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn migrates_old_tunnels_table() {
        let path = std::env::temp_dir().join(format!("cockpit-tunnel-old-{}.db", crate::tokens::random_tunnel_id()));
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE tunnels (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, label TEXT, metadata TEXT,
                 max_ports INTEGER NOT NULL, host_header TEXT NOT NULL, inject_ice INTEGER NOT NULL,
                 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen_at INTEGER);
                 INSERT INTO tunnels VALUES ('old', 'h', NULL, NULL, 8, 'rewrite', 1, 0, 9999999999, NULL);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let row = tokio::runtime::Runtime::new().unwrap().block_on(db.get_tunnel("old".into())).unwrap().unwrap();
        assert_eq!(row.access.mode, AccessMode::Link);
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
