use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config::Config;

const FULLCHAIN: &str = "fullchain.pem";
const PRIVKEY: &str = "privkey.pem";
const NAMES: &str = "names.json";
const WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// The single DNS-01 certificate, swapped atomically when the files on disk
/// change so renewal never needs a restart.
pub struct CertStore {
    cert_dir: PathBuf,
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// mtime of `fullchain.pem` at the last successful load. It is written
    /// after the key, so a changed mtime means both files are new.
    loaded_mtime: Mutex<Option<SystemTime>>,
    /// Unix seconds; 0 = nothing loaded.
    not_after: AtomicI64,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("cert_dir", &self.cert_dir)
            .field("not_after", &self.not_after())
            .finish_non_exhaustive()
    }
}

impl CertStore {
    pub fn new(cert_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            cert_dir,
            current: RwLock::new(None),
            loaded_mtime: Mutex::new(None),
            not_after: AtomicI64::new(0),
        })
    }

    /// Load `fullchain.pem` + `privkey.pem` if `fullchain.pem` changed since the
    /// last load. Returns `Ok(true)` when a new certificate was swapped in.
    pub fn reload(&self) -> anyhow::Result<bool> {
        let chain_path = self.cert_dir.join(FULLCHAIN);
        let mtime = std::fs::metadata(&chain_path)
            .and_then(|m| m.modified())
            .with_context(|| format!("stat {}", chain_path.display()))?;
        if self.is_loaded() && *self.loaded_mtime.lock().expect("mtime lock") == Some(mtime) {
            return Ok(false);
        }

        let loaded = load_files(&self.cert_dir)?;
        let key = rustls::crypto::ring::sign::any_supported_type(&loaded.key)
            .map_err(|e| anyhow::anyhow!("unsupported private key in {}: {e}", self.cert_dir.display()))?;
        let certified = Arc::new(CertifiedKey::new(loaded.chain, key));

        *self.current.write().expect("cert lock") = Some(certified);
        *self.loaded_mtime.lock().expect("mtime lock") = Some(mtime);
        self.not_after.store(loaded.not_after, Ordering::Relaxed);
        Ok(true)
    }

    pub fn not_after(&self) -> Option<i64> {
        match self.not_after.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.current.read().map(|c| c.is_some()).unwrap_or(false)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // One cert covers every name we serve; routing is by Host, not SNI.
        self.current.read().ok().and_then(|c| c.clone())
    }
}

pub fn server_config(store: Arc<CertStore>) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(store);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// For TURN over TLS: the same certificate, no ALPN.
pub fn turn_server_config(store: Arc<CertStore>) -> rustls::ServerConfig {
    rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(store)
}

/// Pick up renewals written by the renewal task or `cert renew` (another process).
pub async fn watch(store: Arc<CertStore>) {
    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;
        match store.reload() {
            Ok(true) => tracing::info!(not_after = store.not_after(), "certificate reloaded"),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "certificate reload failed"),
        }
    }
}

/// Write a freshly issued certificate. Key first, then chain (the store keys
/// reloads on the chain's mtime), then the name list used by `cert_status`.
/// Files are group-readable by the service group.
pub fn write_cert_files(cert_dir: &Path, fullchain_pem: &str, key_pem: &str, names: &[String]) -> anyhow::Result<()> {
    std::fs::create_dir_all(cert_dir).with_context(|| format!("creating {}", cert_dir.display()))?;
    crate::config::set_mode(cert_dir, 0o750)?;
    crate::util::write_atomic(&cert_dir.join(PRIVKEY), key_pem.as_bytes(), 0o640)?;
    crate::util::write_atomic(&cert_dir.join(FULLCHAIN), fullchain_pem.as_bytes(), 0o640)?;
    let names_json = serde_json::to_vec_pretty(names)?;
    crate::util::write_atomic(&cert_dir.join(NAMES), &names_json, 0o640)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Missing,
    NamesChanged,
    NeedsRenewal,
    Valid { not_after: i64 },
}

/// Whether the certificate on disk is usable for `cfg` as-is.
///
/// Renews once a third of the lifetime remains, derived from the cert itself
/// (no hardcoded 90 days). ARI is not used: instant-acme 0.7 does not expose it.
pub fn cert_status(cfg: &Config) -> CertStatus {
    let dir = cfg.cert_dir();
    let loaded = match load_files(&dir) {
        Ok(l) => l,
        Err(_) => return CertStatus::Missing,
    };
    if rustls::crypto::ring::sign::any_supported_type(&loaded.key).is_err() {
        return CertStatus::Missing;
    }

    let on_disk: Option<Vec<String>> =
        std::fs::read(dir.join(NAMES)).ok().and_then(|raw| serde_json::from_slice(&raw).ok());
    let mut on_disk = match on_disk {
        Some(n) => n,
        None => return CertStatus::NamesChanged,
    };
    on_disk.sort();
    on_disk.dedup();
    if on_disk != cfg.cert_names() {
        return CertStatus::NamesChanged;
    }

    let lifetime = (loaded.not_after - loaded.not_before).max(0);
    let remaining = loaded.not_after - crate::tokens::now();
    if remaining < lifetime / 3 {
        CertStatus::NeedsRenewal
    } else {
        CertStatus::Valid { not_after: loaded.not_after }
    }
}

struct LoadedFiles {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    not_before: i64,
    not_after: i64,
}

fn load_files(dir: &Path) -> anyhow::Result<LoadedFiles> {
    let chain_path = dir.join(FULLCHAIN);
    let key_path = dir.join(PRIVKEY);

    let chain_pem = std::fs::read(&chain_path).with_context(|| format!("reading {}", chain_path.display()))?;
    let chain = rustls_pemfile::certs(&mut chain_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", chain_path.display()))?;
    anyhow::ensure!(!chain.is_empty(), "{} contains no certificates", chain_path.display());

    let key_pem = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .with_context(|| format!("parsing {}", key_path.display()))?
        .with_context(|| format!("{} contains no private key", key_path.display()))?;

    let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0])
        .map_err(|e| anyhow::anyhow!("parsing leaf certificate in {}: {e}", chain_path.display()))?;
    let validity = leaf.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();

    Ok(LoadedFiles { chain, key, not_before, not_after })
}
