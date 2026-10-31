//! DNS provider adapters (record management for setup and ACME DNS-01) and
//! public-resolver checks over DoH.

mod cloudflare;
mod digitalocean;
mod hetzner;
mod route53;

use std::time::Duration;

use anyhow::{bail, Context};
use serde::Deserialize;

use crate::config::{Config, DnsProviderKind};

/// TTL for every record we create: short so re-running setup after an IP
/// change converges quickly, and challenge records vanish fast.
pub(crate) const TTL: u32 = 120;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = concat!("cockpit-tunnel/", env!("CARGO_PKG_VERSION"));
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const RESOLVERS: [&str; 2] = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];

/// A record we created, enough to delete exactly that record later.
#[derive(Debug, Clone)]
pub struct RecordRef {
    /// Fully qualified name, no trailing dot.
    pub name: String,
    pub rtype: String,
    /// Unquoted value (TXT quoting is the adapter's concern).
    pub value: String,
    /// Provider record id, where the provider has per-record ids.
    pub id: Option<String>,
}

pub enum Provider {
    Cloudflare(cloudflare::Cloudflare),
    Hetzner(hetzner::Hetzner),
    DigitalOcean(digitalocean::DigitalOcean),
    Route53(route53::Route53),
}

impl Provider {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let dns = &cfg.dns;
        let zone = normalize(&dns.zone);
        anyhow::ensure!(!zone.is_empty(), "dns.zone is empty");
        let http = http_client()?;
        let token = || -> anyhow::Result<String> {
            dns.api_token
                .clone()
                .filter(|t| !t.is_empty())
                .context("dns.api_token is required for this DNS provider")
        };
        Ok(match dns.provider {
            DnsProviderKind::Cloudflare => Self::Cloudflare(cloudflare::Cloudflare::new(http, token()?, zone)),
            DnsProviderKind::Hetzner => Self::Hetzner(hetzner::Hetzner::new(http, token()?, zone)),
            DnsProviderKind::Digitalocean => {
                Self::DigitalOcean(digitalocean::DigitalOcean::new(http, token()?, zone))
            }
            DnsProviderKind::Route53 => {
                let key_id = dns
                    .aws_access_key_id
                    .clone()
                    .filter(|s| !s.is_empty())
                    .context("dns.aws_access_key_id is required for Route53")?;
                let secret = dns
                    .aws_secret_access_key
                    .clone()
                    .filter(|s| !s.is_empty())
                    .context("dns.aws_secret_access_key is required for Route53")?;
                let zone_id = dns
                    .route53_hosted_zone_id
                    .clone()
                    .filter(|s| !s.is_empty())
                    .context("dns.route53_hosted_zone_id is required for Route53")?;
                Self::Route53(route53::Route53::new(http, key_id, secret, zone_id, zone))
            }
        })
    }

    /// Make `fqdn`/`rtype` resolve to exactly `value` (A/AAAA), TTL 120, never
    /// behind a CDN proxy.
    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        let fqdn = normalize(fqdn);
        let rtype = rtype.to_ascii_uppercase();
        let result = match self {
            Self::Cloudflare(p) => p.upsert(&fqdn, &rtype, value).await,
            Self::Hetzner(p) => p.upsert(&fqdn, &rtype, value).await,
            Self::DigitalOcean(p) => p.upsert(&fqdn, &rtype, value).await,
            Self::Route53(p) => p.upsert(&fqdn, &rtype, value).await,
        };
        result.with_context(|| format!("setting {rtype} record for {fqdn}"))
    }

    /// Add a TXT record alongside any existing ones at `fqdn` (create, not
    /// replace, so concurrent challenges for one name can coexist).
    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef> {
        let fqdn = normalize(fqdn);
        let result = match self {
            Self::Cloudflare(p) => p.create_txt(&fqdn, value).await,
            Self::Hetzner(p) => p.create_txt(&fqdn, value).await,
            Self::DigitalOcean(p) => p.create_txt(&fqdn, value).await,
            Self::Route53(p) => p.create_txt(&fqdn, value).await,
        };
        result.with_context(|| format!("creating TXT record for {fqdn}"))
    }

    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()> {
        let result = match self {
            Self::Cloudflare(p) => p.delete(rec).await,
            Self::Hetzner(p) => p.delete(rec).await,
            Self::DigitalOcean(p) => p.delete(rec).await,
            Self::Route53(p) => p.delete(rec).await,
        };
        result.with_context(|| format!("deleting {} record for {}", rec.rtype, rec.name))
    }
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()?)
}

/// Lowercase, no trailing dot.
fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `fqdn` relative to `zone`: `"@"` for the apex, else the leading labels.
pub(crate) fn relative_name(fqdn: &str, zone: &str) -> anyhow::Result<String> {
    if fqdn == zone {
        return Ok("@".to_string());
    }
    match fqdn.strip_suffix(zone).and_then(|p| p.strip_suffix('.')) {
        Some(rel) if !rel.is_empty() => Ok(rel.to_string()),
        _ => bail!("{fqdn} is not inside DNS zone {zone}"),
    }
}

pub(crate) fn quote_txt(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Fail on a non-2xx response, including (truncated) body text. Provider error
/// bodies never echo our credentials.
pub(crate) async fn ensure_success(resp: reqwest::Response, what: &str) -> anyhow::Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    bail!("{what}: HTTP {status}: {}", truncate(&body, 600))
}

pub(crate) fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
}

fn rtype_code(rtype: &str) -> anyhow::Result<u16> {
    Ok(match rtype.to_ascii_uppercase().as_str() {
        "A" => 1,
        "CNAME" => 5,
        "TXT" => 16,
        "AAAA" => 28,
        other => bail!("unsupported record type {other}"),
    })
}

async fn query_resolver(
    client: &reqwest::Client,
    resolver: &str,
    fqdn: &str,
    rtype: &str,
) -> anyhow::Result<Vec<String>> {
    let code = rtype_code(rtype)?;
    let resp = client
        .get(resolver)
        .query(&[("name", fqdn), ("type", rtype)])
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await
        .with_context(|| format!("querying {resolver}"))?;
    let resp = ensure_success(resp, resolver).await?;
    let parsed: DohResponse = resp.json().await.with_context(|| format!("parsing {resolver} response"))?;
    // 0 = NOERROR, 3 = NXDOMAIN (no records yet); anything else is a resolver failure.
    match parsed.status {
        0 | 3 => {}
        rcode => bail!("{resolver} returned DNS rcode {rcode} for {fqdn}"),
    }
    Ok(parsed
        .answer
        .into_iter()
        .filter(|a| a.rtype == code)
        .map(|a| if code == 16 { unquote_txt(&a.data) } else { a.data.trim_end_matches('.').to_string() })
        .collect())
}

/// DoH renders TXT rdata as one or more quoted strings (`"a" "b"`); join them.
fn unquote_txt(data: &str) -> String {
    let data = data.trim();
    if !data.starts_with('"') {
        return data.to_string();
    }
    let mut out = String::new();
    let mut in_str = false;
    let mut chars = data.chars();
    while let Some(c) = chars.next() {
        match (in_str, c) {
            (false, '"') => in_str = true,
            (true, '"') => in_str = false,
            (true, '\\') => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            (true, c) => out.push(c),
            (false, _) => {}
        }
    }
    out
}

/// Records of `rtype` at `fqdn` as seen by Cloudflare and Google public DNS
/// (union). Fails only if both resolvers fail.
pub async fn resolve_public(fqdn: &str, rtype: &str) -> anyhow::Result<Vec<String>> {
    let client = http_client()?;
    let fqdn = normalize(fqdn);
    let (a, b) = futures_util::future::join(
        query_resolver(&client, RESOLVERS[0], &fqdn, rtype),
        query_resolver(&client, RESOLVERS[1], &fqdn, rtype),
    )
    .await;
    let mut out = match (a, b) {
        (Err(e), Err(_)) => return Err(e),
        (a, b) => {
            let mut v = a.unwrap_or_default();
            v.extend(b.unwrap_or_default());
            v
        }
    };
    out.sort();
    out.dedup();
    Ok(out)
}

/// Poll until both public resolvers return `value` among the TXT records at
/// `fqdn`, or `timeout` elapses.
pub async fn wait_for_txt(fqdn: &str, value: &str, timeout: Duration) -> anyhow::Result<()> {
    let client = http_client()?;
    let fqdn = normalize(fqdn);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Query only after a delay: an early NXDOMAIN gets negatively cached
        // by the resolver and would hide the record for the SOA minimum TTL.
        tokio::time::sleep(POLL_INTERVAL).await;
        let mut seen = 0;
        for resolver in RESOLVERS {
            match query_resolver(&client, resolver, &fqdn, "TXT").await {
                Ok(values) if values.iter().any(|v| v == value) => seen += 1,
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %format!("{e:#}"), resolver, "TXT lookup failed"),
            }
        }
        if seen == RESOLVERS.len() {
            return Ok(());
        }
        if tokio::time::Instant::now() + POLL_INTERVAL > deadline {
            bail!("TXT record for {fqdn} not visible on public resolvers after {}s", timeout.as_secs());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_names() {
        assert_eq!(relative_name("example.com", "example.com").unwrap(), "@");
        assert_eq!(relative_name("api.example.com", "example.com").unwrap(), "api");
        assert_eq!(relative_name("*.previews.example.com", "example.com").unwrap(), "*.previews");
        assert!(relative_name("api.badexample.com", "example.com").is_err());
        assert!(relative_name("other.org", "example.com").is_err());
    }

    #[test]
    fn txt_unquoting() {
        assert_eq!(unquote_txt("\"abc\""), "abc");
        assert_eq!(unquote_txt("\"ab\" \"cd\""), "abcd");
        assert_eq!(unquote_txt("\"a\\\"b\""), "a\"b");
        assert_eq!(unquote_txt("plain"), "plain");
    }

    #[test]
    fn txt_quoting() {
        assert_eq!(quote_txt("abc"), "\"abc\"");
        assert_eq!(quote_txt("a\"b"), "\"a\\\"b\"");
    }
}
