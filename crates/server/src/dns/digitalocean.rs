use anyhow::Context;
use serde::Deserialize;
use serde_json::json;

use super::{ensure_success, relative_name, RecordRef, TTL};

const API: &str = "https://api.digitalocean.com/v2";

pub struct DigitalOcean {
    http: reqwest::Client,
    token: String,
    zone: String,
}

#[derive(Deserialize)]
struct RecordList {
    #[serde(default)]
    domain_records: Vec<Record>,
}

#[derive(Deserialize)]
struct RecordOne {
    domain_record: Record,
}

#[derive(Deserialize)]
struct Record {
    id: u64,
}

impl DigitalOcean {
    pub fn new(http: reqwest::Client, token: String, zone: String) -> Self {
        Self { http, token, zone }
    }

    async fn send(&self, req: reqwest::RequestBuilder, what: &str) -> anyhow::Result<reqwest::Response> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("DigitalOcean {what}"))?;
        ensure_success(resp, &format!("DigitalOcean {what}")).await
    }

    fn records_url(&self) -> String {
        format!("{API}/domains/{}/records", self.zone)
    }

    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        let name = relative_name(fqdn, &self.zone)?;
        // The `name` filter takes the fully qualified name; bodies use the relative one.
        let list: RecordList = self
            .send(
                self.http.get(self.records_url()).query(&[("type", rtype), ("name", fqdn), ("per_page", "200")]),
                "record lookup",
            )
            .await?
            .json()
            .await
            .context("DigitalOcean record lookup: parsing response")?;
        let body = json!({ "type": rtype, "name": name, "data": value, "ttl": TTL });
        let mut existing = list.domain_records.into_iter();
        match existing.next() {
            Some(rec) => {
                self.send(self.http.put(format!("{}/{}", self.records_url(), rec.id)).json(&body), "record update")
                    .await?;
            }
            None => {
                self.send(self.http.post(self.records_url()).json(&body), "record create").await?;
            }
        }
        // Stale addresses (e.g. after an IP change) must not keep resolving.
        for extra in existing {
            self.delete_id(extra.id).await?;
        }
        Ok(())
    }

    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef> {
        let name = relative_name(fqdn, &self.zone)?;
        let body = json!({ "type": "TXT", "name": name, "data": value, "ttl": TTL });
        let created: RecordOne = self
            .send(self.http.post(self.records_url()).json(&body), "TXT create")
            .await?
            .json()
            .await
            .context("DigitalOcean TXT create: parsing response")?;
        Ok(RecordRef {
            name: fqdn.to_string(),
            rtype: "TXT".into(),
            value: value.to_string(),
            id: Some(created.domain_record.id.to_string()),
        })
    }

    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()> {
        let id: u64 = rec
            .id
            .as_deref()
            .context("DigitalOcean record reference has no id")?
            .parse()
            .context("DigitalOcean record id is not numeric")?;
        self.delete_id(id).await
    }

    async fn delete_id(&self, id: u64) -> anyhow::Result<()> {
        self.send(self.http.delete(format!("{}/{id}", self.records_url())), "record delete").await?;
        Ok(())
    }
}
