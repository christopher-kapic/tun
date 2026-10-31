use anyhow::{bail, Context};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::OnceCell;

use super::{truncate, RecordRef, TTL};

const API: &str = "https://api.cloudflare.com/client/v4";

pub struct Cloudflare {
    http: reqwest::Client,
    token: String,
    zone: String,
    zone_id: OnceCell<String>,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
}

impl Cloudflare {
    pub fn new(http: reqwest::Client, token: String, zone: String) -> Self {
        Self { http, token, zone, zone_id: OnceCell::new() }
    }

    async fn call<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder, what: &str) -> anyhow::Result<T> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("Cloudflare {what}"))?;
        let status = resp.status();
        let body = resp.text().await.with_context(|| format!("Cloudflare {what}"))?;
        let env: Envelope<T> = match serde_json::from_str(&body) {
            Ok(env) => env,
            Err(_) => bail!("Cloudflare {what}: HTTP {status}: {}", truncate(&body, 600)),
        };
        if !status.is_success() || !env.success {
            let errors: Vec<String> = env.errors.iter().map(|e| format!("{} ({})", e.message, e.code)).collect();
            bail!("Cloudflare {what}: HTTP {status}: {}", errors.join("; "));
        }
        env.result.with_context(|| format!("Cloudflare {what}: response has no result"))
    }

    async fn zone_id(&self) -> anyhow::Result<&str> {
        let id = self.zone_id.get_or_try_init(|| self.lookup_zone_id()).await?;
        Ok(id.as_str())
    }

    async fn lookup_zone_id(&self) -> anyhow::Result<String> {
        let zones: Vec<Zone> = self
            .call(self.http.get(format!("{API}/zones")).query(&[("name", self.zone.as_str())]), "zone lookup")
            .await?;
        match zones.into_iter().next() {
            Some(z) => Ok(z.id),
            None => bail!("Cloudflare zone {} not found (check the token's zone permissions)", self.zone),
        }
    }

    async fn find(&self, zone_id: &str, fqdn: &str, rtype: &str) -> anyhow::Result<Vec<DnsRecord>> {
        self.call(
            self.http
                .get(format!("{API}/zones/{zone_id}/dns_records"))
                .query(&[("type", rtype), ("name", fqdn), ("per_page", "100")]),
            "record lookup",
        )
        .await
    }

    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        let zone_id = self.zone_id().await?;
        // Never proxied: TLS must terminate on this server, not Cloudflare's CDN.
        let body = json!({ "type": rtype, "name": fqdn, "content": value, "ttl": TTL, "proxied": false });
        let existing = self.find(zone_id, fqdn, rtype).await?;
        let mut existing = existing.into_iter();
        match existing.next() {
            Some(rec) => {
                let _: serde_json::Value = self
                    .call(
                        self.http.put(format!("{API}/zones/{zone_id}/dns_records/{}", rec.id)).json(&body),
                        "record update",
                    )
                    .await?;
            }
            None => {
                let _: serde_json::Value = self
                    .call(self.http.post(format!("{API}/zones/{zone_id}/dns_records")).json(&body), "record create")
                    .await?;
            }
        }
        // Stale addresses (e.g. after an IP change) must not keep resolving.
        for extra in existing {
            self.delete_id(zone_id, &extra.id).await?;
        }
        Ok(())
    }

    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef> {
        let zone_id = self.zone_id().await?;
        let body = json!({ "type": "TXT", "name": fqdn, "content": value, "ttl": TTL });
        let rec: DnsRecord = self
            .call(self.http.post(format!("{API}/zones/{zone_id}/dns_records")).json(&body), "TXT create")
            .await?;
        Ok(RecordRef { name: fqdn.to_string(), rtype: "TXT".into(), value: value.to_string(), id: Some(rec.id) })
    }

    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()> {
        let zone_id = self.zone_id().await?;
        match &rec.id {
            Some(id) => self.delete_id(zone_id, id).await,
            None => bail!("Cloudflare record reference has no id"),
        }
    }

    async fn delete_id(&self, zone_id: &str, id: &str) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .call(self.http.delete(format!("{API}/zones/{zone_id}/dns_records/{id}")), "record delete")
            .await?;
        Ok(())
    }
}
