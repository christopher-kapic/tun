//! Let's Encrypt DNS-01 issuance for the single certificate, and the renewal task.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderStatus,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::dns::{self, RecordRef};
use crate::state::AppState;
use crate::tls::{self, CertStatus};

const TXT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(300);
const ORDER_TIMEOUT: Duration = Duration::from_secs(300);
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);

/// `acme-account.json`: the credentials plus the directory they belong to, so
/// toggling `acme.staging` doesn't reuse an account from the other directory.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}

/// Run a full DNS-01 order for `cfg.cert_names()` and write the result to
/// `cfg.cert_dir()`. Challenge TXT records are always removed afterwards.
pub async fn issue(cfg: &Config) -> anyhow::Result<()> {
    let provider = dns::Provider::from_config(cfg)?;
    let mut created = Vec::new();
    let result = run_order(cfg, &provider, &mut created).await;
    for rec in &created {
        if let Err(e) = provider.delete(rec).await {
            tracing::warn!(error = %format!("{e:#}"), name = %rec.name, "failed to remove ACME challenge record");
        }
    }
    result
}

async fn run_order(cfg: &Config, provider: &dns::Provider, created: &mut Vec<RecordRef>) -> anyhow::Result<()> {
    let names = cfg.cert_names();
    let account = load_or_create_account(cfg).await?;

    let identifiers: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = account
        .new_order(&NewOrder { identifiers: &identifiers })
        .await
        .context("creating ACME order")?;
    tracing::info!(names = ?names, "ACME order created");

    let authorizations = order.authorizations().await.context("fetching ACME authorizations")?;
    let mut pending = Vec::new();
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            // Already validated recently (e.g. a retried order); nothing to do.
            AuthorizationStatus::Valid => continue,
            ref other => bail!("ACME authorization for {:?} is {other:?}", authz.identifier),
        }
        #[allow(unreachable_patterns)]
        let domain = match &authz.identifier {
            Identifier::Dns(d) => d.clone(),
            other => bail!("unsupported ACME identifier {other:?}"),
        };
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .with_context(|| format!("no dns-01 challenge offered for {domain}"))?;
        // Wildcard authorizations already carry the base name; strip defensively.
        let txt_name = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        let value = order.key_authorization(challenge).dns_value();
        // Create, never replace: two authorizations could share a TXT name.
        let rec = provider.create_txt(&txt_name, &value).await?;
        created.push(rec);
        pending.push((txt_name, value, challenge.url.clone()));
    }

    // Public resolvers are only a propagation hint; Let's Encrypt queries the
    // authoritative servers itself, so a slow resolver should not fail issuance.
    let waits = pending
        .iter()
        .map(|(name, value, _)| dns::wait_for_txt(name, value, TXT_PROPAGATION_TIMEOUT));
    for (res, (name, _, _)) in futures_util::future::join_all(waits).await.into_iter().zip(&pending) {
        if let Err(e) = res {
            tracing::warn!(error = %format!("{e:#}"), %name, "continuing without public-resolver confirmation");
        }
    }

    for (_, _, url) in &pending {
        order.set_challenge_ready(url).await.context("marking ACME challenge ready")?;
    }

    wait_until_ready(&mut order).await?;

    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(names.clone())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key)?;
    let csr_der: &[u8] = csr.der();
    order.finalize(csr_der).await.context("finalizing ACME order")?;

    let chain = wait_for_certificate(&mut order).await?;
    tls::write_cert_files(&cfg.cert_dir(), &chain, &key.serialize_pem(), &names)?;
    tracing::info!(names = ?names, "certificate issued");
    Ok(())
}

async fn load_or_create_account(cfg: &Config) -> anyhow::Result<Account> {
    let directory = if cfg.acme.staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let path = cfg.acme_account_path();

    if let Ok(raw) = std::fs::read(&path) {
        match serde_json::from_slice::<StoredAccount>(&raw) {
            Ok(stored) if stored.directory == directory => {
                return Account::from_credentials(stored.credentials)
                    .await
                    .context("loading ACME account");
            }
            Ok(_) => tracing::info!("ACME directory changed; registering a new account"),
            Err(e) => tracing::warn!(error = %e, path = %path.display(), "unreadable ACME account file; registering a new account"),
        }
    }

    let contact = format!("mailto:{}", cfg.acme.email);
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[contact.as_str()],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        directory,
        None,
    )
    .await
    .context("registering ACME account")?;

    let stored = StoredAccount { directory: directory.to_string(), credentials };
    crate::util::write_atomic(&path, &serde_json::to_vec(&stored)?, 0o600)?;
    Ok(account)
}

/// Exponential backoff 1s → 15s, bounded by `ORDER_TIMEOUT`.
struct Backoff {
    delay: Duration,
    deadline: tokio::time::Instant,
}

impl Backoff {
    fn new() -> Self {
        Self { delay: Duration::from_secs(1), deadline: tokio::time::Instant::now() + ORDER_TIMEOUT }
    }

    async fn wait(&mut self, what: &str) -> anyhow::Result<()> {
        if tokio::time::Instant::now() + self.delay > self.deadline {
            bail!("timed out waiting for {what}");
        }
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(Duration::from_secs(15));
        Ok(())
    }
}

async fn wait_until_ready(order: &mut Order) -> anyhow::Result<()> {
    let mut backoff = Backoff::new();
    loop {
        let status = &order.refresh().await.context("polling ACME order")?.status;
        // Valid before finalize cannot happen for a fresh order; let finalize report it.
        if matches!(status, OrderStatus::Ready | OrderStatus::Valid) {
            return Ok(());
        }
        if matches!(status, OrderStatus::Invalid) {
            bail!("ACME order invalid: {}", challenge_errors(order).await);
        }
        backoff.wait("ACME challenge validation").await?;
    }
}

async fn wait_for_certificate(order: &mut Order) -> anyhow::Result<String> {
    let mut backoff = Backoff::new();
    loop {
        // certificate() refreshes the order while it is Processing.
        if let Some(chain) = order.certificate().await.context("downloading certificate")? {
            return Ok(chain);
        }
        if order.state().status == OrderStatus::Invalid {
            bail!("ACME order became invalid after finalize");
        }
        backoff.wait("certificate issuance").await?;
    }
}

/// Best-effort summary of why an order failed, for the log.
async fn challenge_errors(order: &mut Order) -> String {
    let authorizations = match order.authorizations().await {
        Ok(a) => a,
        Err(e) => return format!("(could not fetch authorizations: {e})"),
    };
    let mut out = Vec::new();
    for authz in authorizations {
        for ch in authz.challenges {
            if let Some(err) = ch.error {
                out.push(format!(
                    "{:?}: {}",
                    authz.identifier,
                    err.detail.as_deref().or(err.r#type.as_deref()).unwrap_or("unknown error")
                ));
            }
        }
    }
    if out.is_empty() {
        "no challenge error reported".to_string()
    } else {
        out.join("; ")
    }
}

/// Background renewal: first check shortly after start, then every 12 hours
/// (hourly while failing). Issuance writes the files; reloading here (and the
/// 60s watcher) swaps the cert in. coturn picks it up via setup's systemd path unit.
pub async fn renew_loop(state: Arc<AppState>) {
    tokio::time::sleep(FIRST_CHECK_DELAY).await;
    loop {
        let next = match renew_if_needed(&state).await {
            Ok(()) => CHECK_INTERVAL,
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "certificate renewal failed; retrying in 1h");
                RETRY_AFTER_FAILURE
            }
        };
        tokio::time::sleep(next).await;
    }
}

async fn renew_if_needed(state: &AppState) -> anyhow::Result<()> {
    let status = tls::cert_status(&state.config);
    if let CertStatus::Valid { .. } = status {
        return Ok(());
    }
    tracing::info!(?status, "certificate needs (re)issuance");
    issue(&state.config).await?;
    if state.certs.reload()? {
        tracing::info!(not_after = state.certs.not_after(), "renewed certificate loaded");
    }
    Ok(())
}
