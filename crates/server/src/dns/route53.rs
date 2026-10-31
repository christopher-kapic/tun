//! Route53 via `ChangeResourceRecordSets`, signed with a hand-rolled AWS
//! SigV4 (avoids pulling in the AWS SDK for one call).

use anyhow::Context;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::{ensure_success, quote_txt, RecordRef, TTL};

const HOST: &str = "route53.amazonaws.com";
// Route53 is a global service signed in us-east-1.
const REGION: &str = "us-east-1";
const SERVICE: &str = "route53";

pub struct Route53 {
    http: reqwest::Client,
    access_key_id: String,
    secret_access_key: String,
    hosted_zone_id: String,
    zone: String,
}

impl Route53 {
    pub fn new(
        http: reqwest::Client,
        access_key_id: String,
        secret_access_key: String,
        hosted_zone_id: String,
        zone: String,
    ) -> Self {
        // Accept both "Z123" and the "/hostedzone/Z123" form the console shows.
        let hosted_zone_id = hosted_zone_id.trim().trim_start_matches("/hostedzone/").to_string();
        Self { http, access_key_id, secret_access_key, hosted_zone_id, zone }
    }

    fn check_in_zone(&self, fqdn: &str) -> anyhow::Result<()> {
        super::relative_name(fqdn, &self.zone).map(|_| ())
    }

    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        self.check_in_zone(fqdn)?;
        self.change("UPSERT", fqdn, rtype, &wire_value(rtype, value)).await
    }

    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef> {
        self.check_in_zone(fqdn)?;
        // UPSERT so a TXT left behind by an interrupted run doesn't block issuance.
        self.change("UPSERT", fqdn, "TXT", &quote_txt(value)).await?;
        Ok(RecordRef { name: fqdn.to_string(), rtype: "TXT".into(), value: value.to_string(), id: None })
    }

    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()> {
        // DELETE must match the record set exactly (value and TTL).
        self.change("DELETE", &rec.name, &rec.rtype, &wire_value(&rec.rtype, &rec.value)).await
    }

    async fn change(&self, action: &str, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        let body = change_batch_xml(action, fqdn, rtype, value);
        let path = format!("/2013-04-01/hostedzone/{}/rrset/", self.hosted_zone_id);
        let now = time::OffsetDateTime::now_utc();
        let (amz_date, date) = amz_dates(now);
        let authorization = sign(
            &self.access_key_id,
            &self.secret_access_key,
            &path,
            &amz_date,
            &date,
            body.as_bytes(),
        );

        let resp = self
            .http
            .post(format!("https://{HOST}{path}"))
            .header("x-amz-date", &amz_date)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, "text/xml")
            .body(body)
            .send()
            .await
            .with_context(|| format!("Route53 {action} {rtype}"))?;
        ensure_success(resp, &format!("Route53 {action} {rtype}")).await?;
        Ok(())
    }
}

fn wire_value(rtype: &str, value: &str) -> String {
    if rtype == "TXT" {
        quote_txt(value)
    } else {
        value.to_string()
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn change_batch_xml(action: &str, fqdn: &str, rtype: &str, value: &str) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">"#,
            "<ChangeBatch><Changes><Change><Action>{action}</Action><ResourceRecordSet>",
            "<Name>{name}.</Name><Type>{rtype}</Type><TTL>{ttl}</TTL>",
            "<ResourceRecords><ResourceRecord><Value>{value}</Value></ResourceRecord></ResourceRecords>",
            "</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"
        ),
        action = action,
        name = xml_escape(fqdn),
        rtype = rtype,
        ttl = TTL,
        value = xml_escape(value),
    )
}

/// (`YYYYMMDDTHHMMSSZ`, `YYYYMMDD`).
fn amz_dates(t: time::OffsetDateTime) -> (String, String) {
    let date = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
    let amz = format!("{date}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second());
    (amz, date)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SigV4 `Authorization` header for `POST <path>` with headers host + x-amz-date.
fn sign(access_key_id: &str, secret: &str, path: &str, amz_date: &str, date: &str, body: &[u8]) -> String {
    let signed_headers = "host;x-amz-date";
    let canonical_request = format!(
        "POST\n{path}\n\nhost:{HOST}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{}",
        sha256_hex(body)
    );
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical_request.as_bytes()));

    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!("AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_derivation_matches_aws_example() {
        // AWS SigV4 docs example: secret wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
        // 20120215 / us-east-1 / iam.
        let k_date = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20120215");
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"iam");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(hex::encode(k_signing), "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d");
    }

    #[test]
    fn date_format() {
        let t = time::OffsetDateTime::from_unix_timestamp(1_329_264_000 + 3_723).unwrap();
        assert_eq!(amz_dates(t), ("20120215T010203Z".to_string(), "20120215".to_string()));
    }

    #[test]
    fn txt_xml_is_quoted_and_escaped() {
        let xml = change_batch_xml("UPSERT", "_acme-challenge.api.example.com", "TXT", &quote_txt("abc"));
        assert!(xml.contains("<Name>_acme-challenge.api.example.com.</Name>"));
        assert!(xml.contains("<Value>&quot;abc&quot;</Value>"));
    }
}
