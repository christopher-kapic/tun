//! Hetzner Cloud DNS (api.hetzner.cloud/v1), which replaced the legacy
//! dns.hetzner.com API in 2025. Records are managed as RRSets addressed by
//! relative name + type.
// verify: endpoints, bodies, and the add_records/remove_records semantics
// below against https://docs.hetzner.cloud/reference/cloud#dns before release.

use anyhow::Context;
use serde_json::json;

use super::{ensure_success, quote_txt, relative_name, RecordRef, TTL};

const API: &str = "https://api.hetzner.cloud/v1";

pub struct Hetzner {
    http: reqwest::Client,
    token: String,
    zone: String,
}

impl Hetzner {
    pub fn new(http: reqwest::Client, token: String, zone: String) -> Self {
        Self { http, token, zone }
    }

    /// Zones are addressable by name in the path, so no id lookup is needed.
    // verify: `/zones/{id_or_name}` accepts the zone name.
    fn rrset_url(&self, name: &str, rtype: &str) -> String {
        format!("{API}/zones/{}/rrsets/{name}/{rtype}", self.zone)
    }

    async fn send(&self, req: reqwest::RequestBuilder, what: &str) -> anyhow::Result<reqwest::Response> {
        let resp = req.bearer_auth(&self.token).send().await.with_context(|| format!("Hetzner {what}"))?;
        ensure_success(resp, &format!("Hetzner {what}")).await
    }

    fn value_for(rtype: &str, value: &str) -> String {
        if rtype == "TXT" {
            quote_txt(value)
        } else {
            value.to_string()
        }
    }

    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        let name = relative_name(fqdn, &self.zone)?;
        let records = json!([{ "value": Self::value_for(rtype, value) }]);
        let existing = self
            .http
            .get(self.rrset_url(&name, rtype))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("Hetzner RRSet lookup")?;
        if existing.status() == reqwest::StatusCode::NOT_FOUND {
            let body = json!({ "name": name, "type": rtype, "ttl": TTL, "records": records });
            self.send(self.http.post(format!("{API}/zones/{}/rrsets", self.zone)).json(&body), "RRSet create").await?;
        } else {
            ensure_success(existing, "Hetzner RRSet lookup").await?;
            // Replaces every record in the set, dropping stale addresses.
            let url = format!("{}/actions/set_records", self.rrset_url(&name, rtype));
            self.send(self.http.post(url).json(&json!({ "records": records })), "RRSet set_records").await?;
        }
        Ok(())
    }

    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef> {
        let name = relative_name(fqdn, &self.zone)?;
        // add_records creates the RRSet when absent and keeps any other values.
        // verify: add_records creates a missing RRSet (else fall back to POST /rrsets on 404).
        let url = format!("{}/actions/add_records", self.rrset_url(&name, "TXT"));
        let body = json!({ "ttl": TTL, "records": [{ "value": quote_txt(value) }] });
        self.send(self.http.post(url).json(&body), "TXT add_records").await?;
        Ok(RecordRef { name: fqdn.to_string(), rtype: "TXT".into(), value: value.to_string(), id: None })
    }

    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()> {
        let name = relative_name(&rec.name, &self.zone)?;
        // Remove only our value; the RRSet goes away once empty.
        // verify: remove_records deletes the RRSet when its last record is removed.
        let url = format!("{}/actions/remove_records", self.rrset_url(&name, &rec.rtype));
        let body = json!({ "records": [{ "value": Self::value_for(&rec.rtype, &rec.value) }] });
        self.send(self.http.post(url).json(&body), "remove_records").await?;
        Ok(())
    }
}
