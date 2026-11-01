//! `cockpit-preview login`: the machine's client token and server, plus a
//! small management-API client for `share`, `link`, and `stop`.
//!
//! Saved at `$XDG_CONFIG_HOME/cockpit-preview/login.json` (else
//! `~/.config/...`), mode 0600 in a 0700 directory. Deliberately not `Debug`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::write_atomic;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize)]
pub struct Login {
    /// Client name on the server.
    pub name: String,
    /// `https://<api host>`
    pub api: String,
    /// `wss://<tunnel host>`
    pub server: String,
    /// `ctcli_…`
    pub token: String,
}

pub fn path() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("cockpit-preview").join("login.json"))
}

impl Login {
    pub fn load() -> anyhow::Result<Option<Self>> {
        let p = path()?;
        match std::fs::read(&p) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", p.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    pub fn require() -> anyhow::Result<Self> {
        Self::load()?.context("not logged in: ask the server admin for a login command (`cockpit-tunnel-server client add <name>`) and run it here")
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let p = path()?;
        if let Some(dir) = p.parent() {
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
            }
        }
        write_atomic(&p, &serde_json::to_vec_pretty(self)?, 0o600).with_context(|| format!("writing {}", p.display()))
    }
}

fn http() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("cockpit-preview/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Body of an API response, or its `error.message` as the error.
async fn decode<T: DeserializeOwned>(resp: reqwest::Response, what: &str) -> anyhow::Result<T> {
    let status = resp.status();
    let text = resp.text().await.with_context(|| what.to_string())?;
    if status == reqwest::StatusCode::UNAUTHORIZED && what != "login" {
        bail!(
            "the server no longer accepts this machine's login (the client was deleted or logged in elsewhere); \
             ask the admin for a new `cockpit-preview login` command"
        );
    }
    if !status.is_success() {
        let message = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| text.chars().take(300).collect());
        bail!("{what}: HTTP {}: {message}", status.as_u16());
    }
    if text.trim().is_empty() {
        return Ok(serde_json::from_value(Value::Null)?);
    }
    serde_json::from_str(&text).with_context(|| format!("{what}: unexpected response"))
}

/// `<code>@<host>` from `client add`.
pub fn parse_login_arg(arg: &str) -> anyhow::Result<(String, String)> {
    let arg = arg.trim().trim_matches('\'').trim_matches('"');
    let Some((code, host)) = arg.rsplit_once('@') else {
        bail!("expected <code>@<host>, as printed by `cockpit-tunnel-server client add`");
    };
    let host = host.trim().trim_start_matches("https://").trim_end_matches('/');
    if !code.starts_with(cockpit_tunnel_protocol::ENROLL_CODE_PREFIX) || host.is_empty() || host.contains('/') {
        bail!("expected <code>@<host>, as printed by `cockpit-tunnel-server client add`");
    }
    Ok((code.to_string(), host.to_string()))
}

#[derive(Deserialize)]
struct Enrolled {
    name: String,
    token: String,
    api: String,
    server: String,
}

pub async fn enroll(code: &str, host: &str) -> anyhow::Result<Login> {
    let resp = http()?
        .post(format!("https://{host}/v1/clients/enroll"))
        .json(&json!({ "code": code }))
        .send()
        .await
        .with_context(|| format!("contacting https://{host}"))?;
    let e: Enrolled = decode(resp, "login").await?;
    Ok(Login { name: e.name, api: e.api, server: e.server, token: e.token })
}

/// Management API calls made with this machine's client token.
pub struct Api<'a> {
    login: &'a Login,
    http: reqwest::Client,
}

#[derive(Deserialize)]
pub struct Created {
    pub id: String,
    pub tunnel_token: String,
}

#[derive(Deserialize)]
pub struct TunnelInfo {
    pub expired: bool,
    pub access: AccessInfo,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct AccessInfo {
    pub mode: String,
    #[serde(default)]
    pub username: Option<String>,
}

impl<'a> Api<'a> {
    pub fn new(login: &'a Login) -> anyhow::Result<Self> {
        Ok(Self { login, http: http()? })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http.request(method, format!("{}{path}", self.login.api)).bearer_auth(&self.login.token)
    }

    pub async fn create_tunnel(&self, label: &str, ttl_s: u64, access: &Value) -> anyhow::Result<Created> {
        let body = json!({ "label": label, "ttl_s": ttl_s, "access": access });
        decode(self.req(reqwest::Method::POST, "/v1/tunnels").json(&body).send().await?, "creating tunnel").await
    }

    /// `None` if the tunnel is gone (deleted, or not this client's).
    pub async fn tunnel(&self, id: &str) -> anyhow::Result<Option<TunnelInfo>> {
        let resp = self.req(reqwest::Method::GET, &format!("/v1/tunnels/{id}")).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status() == reqwest::StatusCode::CONFLICT {
            return Ok(None);
        }
        decode(resp, "reading tunnel").await.map(Some)
    }

    pub async fn set_access(&self, id: &str, access: &Value) -> anyhow::Result<()> {
        let resp = self.req(reqwest::Method::PATCH, &format!("/v1/tunnels/{id}")).json(&json!({ "access": access })).send().await?;
        decode::<Value>(resp, "changing access").await.map(|_| ())
    }

    /// Path (`/__access/…`) of a new access link.
    pub async fn access_link(&self, id: &str, ttl_s: u64, single_use: bool) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct Link {
            url_path: String,
        }
        let body = json!({ "ttl_s": ttl_s, "single_use": single_use });
        let resp = self.req(reqwest::Method::POST, &format!("/v1/tunnels/{id}/access-links")).json(&body).send().await?;
        decode::<Link>(resp, "creating access link").await.map(|l| l.url_path)
    }

    pub async fn delete_tunnel(&self, id: &str) -> anyhow::Result<()> {
        let resp = self.req(reqwest::Method::DELETE, &format!("/v1/tunnels/{id}")).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        decode::<Value>(resp, "deleting tunnel").await.map(|_| ())
    }
}

/// `90`, `30m`, `8h`, `2d` → seconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("'{s}' is not a duration like 90s, 30m, 8h, or 2d"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_arg() {
        assert_eq!(
            parse_login_arg("'ctenr_abc@tunnel.example.com'").unwrap(),
            ("ctenr_abc".to_string(), "tunnel.example.com".to_string())
        );
        assert!(parse_login_arg("ctenr_abc").is_err());
        assert!(parse_login_arg("other_abc@host").is_err());
        assert!(parse_login_arg("ctenr_abc@host/path").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("8h").unwrap(), 28_800);
        assert_eq!(parse_duration("2d").unwrap(), 172_800);
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
