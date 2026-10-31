//! `cockpit-tunnel-server setup`: the interactive install/reconfigure wizard.
//!
//! Every step is idempotent. Existing config values are the prompt defaults,
//! secrets are never regenerated, files are only rewritten when their content
//! changes, and services only restart when their config changed, so re-running
//! with the same answers changes nothing.

mod coturn;
mod firewall;
mod os;
mod prompt;
mod systemd;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use cockpit_tunnel_protocol::ADMIN_TOKEN_PREFIX;

use crate::config::{Config, DnsProviderKind, SERVICE_USER};
use crate::{acme, dns, tls, tokens, util};

#[allow(unused_imports)] // part of the module contract; no caller outside setup yet
pub use coturn::detect_coturn_user;

#[derive(clap::Args, Debug)]
pub struct SetupArgs {
    /// Use the Let's Encrypt staging directory (untrusted certs, generous rate limits).
    #[arg(long)]
    pub staging: bool,
    /// Do not create or verify DNS records (they must already point here).
    #[arg(long)]
    pub skip_dns: bool,
    /// Skip the HTTPS checks against the running service.
    #[arg(long)]
    pub skip_self_test: bool,
}

const DNS_POLL: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(30);

const PROVIDERS: [(DnsProviderKind, &str); 4] = [
    (DnsProviderKind::Cloudflare, "cloudflare"),
    (DnsProviderKind::Hetzner, "hetzner"),
    (DnsProviderKind::Digitalocean, "digitalocean"),
    (DnsProviderKind::Route53, "route53"),
];

pub async fn run(config_path: &Path, args: SetupArgs) -> anyhow::Result<()> {
    ensure_root()?;
    let os = os::Os::detect()?;

    let existing = if config_path.exists() {
        Some(Config::load(config_path)?)
    } else {
        None
    };
    if existing.is_some() {
        println!("Reconfiguring from {} (Enter keeps each current value).", config_path.display());
    }
    let mut cfg = ask_config(existing.as_ref(), &args)?;

    // Set only once the config holding its hash is on disk, so a failure
    // after that point still shows the token instead of losing it.
    let mut new_token: Option<String> = None;
    let result = configure(config_path, existing.as_ref(), &mut cfg, &args, os, &mut new_token).await;
    if let Err(e) = result {
        if let Some(token) = &new_token {
            eprintln!("\nSetup failed, but a new admin token was already saved. Keep it:");
            print_token_box(&cfg, token);
        }
        return Err(e);
    }
    finish(&cfg, new_token.as_deref());
    Ok(())
}

async fn configure(
    config_path: &Path,
    existing: Option<&Config>,
    cfg: &mut Config,
    args: &SetupArgs,
    mut os: os::Os,
    new_token: &mut Option<String>,
) -> anyhow::Result<()> {
    step("Detecting public IP addresses");
    let (v4, v6) = detect_public_ips(existing).await?;
    cfg.public_ipv4 = Some(v4);
    cfg.public_ipv6 = v6;
    if v6.is_none() && existing.and_then(|c| c.public_ipv6).is_some() {
        println!("Note: no IPv6 detected any more; remove stale AAAA records at the DNS provider by hand.");
    }

    // Before DNS so the answers are persisted even if DNS verification times out.
    step("Creating the service user and directories");
    ensure_service_user(cfg)?;
    ensure_dirs(cfg, config_path)?;

    step("Generating secrets");
    let token = generate_secrets(cfg);
    let config_changed = cfg.save(config_path)?;
    chown(config_path, &format!("{SERVICE_USER}:{SERVICE_USER}"))?;
    *new_token = token;
    println!("{} {}", if config_changed { "Wrote" } else { "Unchanged:" }, config_path.display());

    if args.skip_dns {
        println!("Skipping DNS (--skip-dns)");
    } else {
        step("Configuring DNS");
        configure_dns(cfg).await?;
    }

    step("Certificate");
    ensure_certificate(cfg).await?;
    util::chown_recursive(&cfg.data_dir, SERVICE_USER)?;

    if cfg.webrtc.enabled {
        step("coturn");
        coturn::configure(cfg, &mut os)?;
    } else {
        coturn::disable_if_managed()?;
    }

    step("Firewall");
    firewall::configure(cfg)?;

    step("systemd");
    systemd::install(cfg, config_path, config_changed)?;

    if args.skip_self_test {
        println!("Skipping self-test (--skip-self-test)");
    } else {
        step("Self-test");
        self_test(cfg).await?;
    }
    Ok(())
}

fn step(title: &str) {
    println!("\n==> {title}");
}

fn ensure_root() -> anyhow::Result<()> {
    let uid = os::output("id", &["-u"]).context("checking the current user")?;
    anyhow::ensure!(uid.trim() == "0", "setup must run as root (try: sudo cockpit-tunnel-server setup)");
    Ok(())
}

/// A config with only defaults, so `config.rs` stays the single source of
/// default values.
fn fresh_config() -> anyhow::Result<Config> {
    Ok(serde_json::from_value(serde_json::json!({
        "base_domain": "",
        "preview_zone": "",
        "api_host": "",
        "tunnel_host": "",
        "turn_host": "",
        "dashboard_origin": "",
        "admin_token_hash": "",
        "acme": { "email": "" },
        "dns": { "provider": "cloudflare", "zone": "" },
    }))?)
}

fn ask_config(existing: Option<&Config>, args: &SetupArgs) -> anyhow::Result<Config> {
    let mut cfg = match existing {
        Some(c) => c.clone(),
        None => fresh_config()?,
    };

    let base = prompt::ask_with("Base domain (e.g. example.com)", &cfg.base_domain, parse_host)?;
    // Derived names follow the base domain unless it is unchanged.
    let same_base = existing.is_some_and(|c| c.base_domain == base);
    let default_for = |current: &str, derived: String| if same_base { current.to_string() } else { derived };

    let zone_default = default_for(&cfg.preview_zone, format!("previews.{base}"));
    cfg.preview_zone = prompt::ask_with("Preview zone", &zone_default, parse_host)?;
    let api_default = default_for(&cfg.api_host, format!("api.{base}"));
    cfg.api_host = prompt::ask_with("Management API host", &api_default, parse_host)?;
    let tunnel_default = default_for(&cfg.tunnel_host, format!("tunnel.{base}"));
    cfg.tunnel_host = prompt::ask_with("Sandbox tunnel host", &tunnel_default, parse_host)?;
    let turn_default = default_for(&cfg.turn_host, format!("turn.{base}"));
    cfg.turn_host = prompt::ask_with("TURN host", &turn_default, parse_host)?;
    let origin_default = default_for(&cfg.dashboard_origin, format!("https://app.{base}"));
    cfg.dashboard_origin = prompt::ask_with("Harness dashboard origin (iframe parent)", &origin_default, parse_origin)?;
    cfg.base_domain = base.clone();

    cfg.acme.email = prompt::ask_with("ACME contact email", &cfg.acme.email, parse_email)?;
    cfg.acme.staging = args.staging;

    let names: Vec<&str> = PROVIDERS.iter().map(|(_, n)| *n).collect();
    let current = PROVIDERS.iter().position(|(k, _)| *k == cfg.dns.provider).unwrap_or(0);
    let provider = PROVIDERS[prompt::ask_choice("DNS provider", &names, current)?].0;
    let zone_default = default_for(&cfg.dns.zone, base.clone());
    cfg.dns.zone = prompt::ask_with("DNS zone managed at the provider", &zone_default, parse_host)?;

    // Credentials of a different provider are dropped, not carried over.
    if existing.map(|c| c.dns.provider) != Some(provider) {
        cfg.dns.api_token = None;
        cfg.dns.aws_access_key_id = None;
        cfg.dns.aws_secret_access_key = None;
        cfg.dns.route53_hosted_zone_id = None;
    }
    cfg.dns.provider = provider;
    match provider {
        DnsProviderKind::Route53 => {
            let key_id = cfg.dns.aws_access_key_id.clone().unwrap_or_default();
            cfg.dns.aws_access_key_id = Some(prompt::ask_with("AWS access key id", &key_id, non_empty)?);
            cfg.dns.aws_secret_access_key = Some(prompt::ask_secret(
                "AWS secret access key",
                cfg.dns.aws_secret_access_key.as_deref(),
            )?);
            let zone_id = cfg.dns.route53_hosted_zone_id.clone().unwrap_or_default();
            cfg.dns.route53_hosted_zone_id = Some(prompt::ask_with("Route53 hosted zone id", &zone_id, non_empty)?);
            cfg.dns.api_token = None;
        }
        _ => {
            let hint = match provider {
                DnsProviderKind::Cloudflare => "Cloudflare API token (Zone:DNS:Edit on this zone)",
                DnsProviderKind::Hetzner => "Hetzner DNS API token",
                _ => "DigitalOcean API token (domain read/write)",
            };
            cfg.dns.api_token = Some(prompt::ask_secret(hint, cfg.dns.api_token.as_deref())?);
            cfg.dns.aws_access_key_id = None;
            cfg.dns.aws_secret_access_key = None;
            cfg.dns.route53_hosted_zone_id = None;
        }
    }

    cfg.webrtc.enabled = prompt::ask_bool("Enable WebRTC (coturn TURN relay)?", cfg.webrtc.enabled)?;

    check_names(&cfg)?;
    Ok(cfg)
}

/// Every record setup creates must live inside the provider zone.
fn check_names(cfg: &Config) -> anyhow::Result<()> {
    let zone = &cfg.dns.zone;
    let inside = |host: &str| host == zone.as_str() || host.ends_with(&format!(".{zone}"));
    let mut hosts = vec![&cfg.preview_zone, &cfg.api_host, &cfg.tunnel_host];
    if cfg.webrtc.enabled {
        hosts.push(&cfg.turn_host);
    }
    for host in hosts {
        anyhow::ensure!(inside(host.as_str()), "{host} is not inside the DNS zone {zone}");
    }
    if !inside(cfg.base_domain.as_str()) && !zone.ends_with(&format!(".{}", cfg.base_domain)) {
        println!("Warning: DNS zone {zone} and base domain {} are unrelated.", cfg.base_domain);
    }
    Ok(())
}

fn parse_host(input: &str) -> Result<String, String> {
    let host = input.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if host.len() > 253 || !host.contains('.') || !host.split('.').all(valid_label) {
        return Err(format!("'{input}' is not a valid DNS name"));
    }
    Ok(host)
}

fn parse_origin(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| "the origin must start with https://".to_string())?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(p) = port {
        p.parse::<u16>().map_err(|_| format!("bad port in '{input}'"))?;
    }
    let host = parse_host(host).map_err(|_| format!("'{input}' is not https://<host>[:port] (no path)"))?;
    Ok(match port {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    })
}

fn parse_email(input: &str) -> Result<String, String> {
    let email = input.trim();
    match email.split_once('@') {
        Some((local, domain)) if !local.is_empty() && domain.contains('.') && !email.contains(' ') => {
            Ok(email.to_string())
        }
        _ => Err(format!("'{input}' is not an email address")),
    }
}

fn non_empty(input: &str) -> Result<String, String> {
    let v = input.trim();
    if v.is_empty() {
        Err("a value is required".to_string())
    } else {
        Ok(v.to_string())
    }
}

async fn detect_public_ips(existing: Option<&Config>) -> anyhow::Result<(Ipv4Addr, Option<Ipv6Addr>)> {
    let v4 = match fetch_ip("https://api.ipify.org", IpAddr::V4(Ipv4Addr::UNSPECIFIED)).await {
        Ok(IpAddr::V4(ip)) => ip,
        other => {
            if let Err(e) = &other {
                println!("Could not detect the public IPv4 address: {e:#}");
            }
            let default = existing.and_then(|c| c.public_ipv4).map(|ip| ip.to_string()).unwrap_or_default();
            prompt::ask_with("Public IPv4 address of this VM", &default, |s| {
                s.trim().parse::<Ipv4Addr>().map_err(|_| format!("'{s}' is not an IPv4 address"))
            })?
        }
    };
    let v6 = match fetch_ip("https://api6.ipify.org", IpAddr::V6(Ipv6Addr::UNSPECIFIED)).await {
        Ok(IpAddr::V6(ip)) => Some(ip),
        _ => None,
    };
    println!("Public IPv4: {v4}");
    match v6 {
        Some(ip) => println!("Public IPv6: {ip}"),
        None => println!("Public IPv6: none"),
    }
    Ok((v4, v6))
}

/// Bind the request to one address family so the echo service sees that family.
async fn fetch_ip(url: &str, local: IpAddr) -> anyhow::Result<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .local_address(local)
        .build()?;
    let text = client.get(url).send().await?.error_for_status()?.text().await?;
    Ok(text.trim().parse()?)
}

fn ensure_service_user(cfg: &Config) -> anyhow::Result<()> {
    if os::succeeds("id", &["-u", SERVICE_USER]) {
        return Ok(());
    }
    println!("Creating system user {SERVICE_USER}");
    let home = cfg.data_dir.to_string_lossy();
    let mut args = vec![
        "--system",
        "--home-dir",
        &*home,
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
    ];
    if os::succeeds("getent", &["group", SERVICE_USER]) {
        args.extend(["--gid", SERVICE_USER]);
    } else {
        args.push("--user-group");
    }
    args.push(SERVICE_USER);
    os::run("useradd", &args)
}

fn ensure_dirs(cfg: &Config, config_path: &Path) -> anyhow::Result<()> {
    // `chown -R` runs on the data dir as root; refuse anything that is not
    // obviously dedicated to this service.
    let data = &cfg.data_dir;
    anyhow::ensure!(
        data.is_absolute() && data.file_name().is_some_and(|n| n.to_string_lossy().contains("cockpit")),
        "data_dir {} must be an absolute path to a dedicated cockpit-tunnel directory",
        data.display()
    );
    std::fs::create_dir_all(data).with_context(|| format!("creating {}", data.display()))?;
    crate::config::set_mode(data, 0o750)?;
    chown(data, &format!("{SERVICE_USER}:{SERVICE_USER}"))?;

    // Only a dedicated config directory gets its mode/owner managed (never `/etc`).
    let etc = config_path.parent().context("config path has no parent directory")?;
    std::fs::create_dir_all(etc).with_context(|| format!("creating {}", etc.display()))?;
    if etc.file_name().is_some_and(|n| n.to_string_lossy().contains("cockpit")) {
        crate::config::set_mode(etc, 0o750)?;
        chown(etc, &format!("root:{SERVICE_USER}"))?;
    }
    Ok(())
}

fn chown(path: &Path, owner: &str) -> anyhow::Result<()> {
    let path = path.to_string_lossy();
    os::run("chown", &[owner, &*path])
}

/// Fill in missing secrets; returns the plaintext admin token if one was minted.
fn generate_secrets(cfg: &mut Config) -> Option<String> {
    let mut minted = None;
    if cfg.admin_token_hash.is_empty() {
        let token = tokens::random_token(ADMIN_TOKEN_PREFIX);
        cfg.admin_token_hash = tokens::hash_token(&token);
        minted = Some(token);
        println!("Generated a new admin API token (shown at the end)");
    }
    if cfg.webrtc.enabled && cfg.webrtc.static_auth_secret.is_empty() {
        cfg.webrtc.static_auth_secret = tokens::random_secret();
        println!("Generated the coturn static-auth-secret");
    }
    minted
}

fn record_hosts(cfg: &Config) -> Vec<String> {
    let mut hosts = vec![format!("*.{}", cfg.preview_zone), cfg.api_host.clone(), cfg.tunnel_host.clone()];
    if cfg.webrtc.enabled {
        hosts.push(cfg.turn_host.clone());
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

async fn configure_dns(cfg: &Config) -> anyhow::Result<()> {
    let provider = dns::Provider::from_config(cfg)?;
    let v4 = cfg.public_ipv4.context("no public IPv4 address")?;
    for host in record_hosts(cfg) {
        println!("  {host} A {v4}");
        provider.upsert(&host, "A", &v4.to_string()).await?;
        if let Some(v6) = cfg.public_ipv6 {
            println!("  {host} AAAA {v6}");
            provider.upsert(&host, "AAAA", &v6.to_string()).await?;
        }
    }
    verify_dns(cfg, v4).await
}

/// Wait until public resolvers return this VM for the API host and a fresh
/// (never-queried, so never negatively cached) wildcard name.
async fn verify_dns(cfg: &Config, v4: Ipv4Addr) -> anyhow::Result<()> {
    let probe = format!("1-{}.{}", tokens::random_tunnel_id(), cfg.preview_zone);
    let mut checks: Vec<(String, &str, IpAddr)> = Vec::new();
    for name in [cfg.api_host.clone(), probe] {
        checks.push((name.clone(), "A", IpAddr::V4(v4)));
        if let Some(v6) = cfg.public_ipv6 {
            checks.push((name, "AAAA", IpAddr::V6(v6)));
        }
    }

    println!("Waiting for public DNS (polling every {}s, up to {} min)", DNS_POLL.as_secs(), DNS_TIMEOUT.as_secs() / 60);
    let deadline = Instant::now() + DNS_TIMEOUT;
    loop {
        let mut pending = Vec::new();
        for (name, rtype, want) in &checks {
            let seen = match dns::resolve_public(name, rtype).await {
                Ok(values) => values,
                Err(e) => vec![format!("lookup error: {e:#}")],
            };
            if !seen.iter().any(|v| v.parse::<IpAddr>().ok() == Some(*want)) {
                pending.push((name, rtype, want, seen));
            }
        }
        if pending.is_empty() {
            println!("DNS resolves to this VM");
            return Ok(());
        }
        if Instant::now() >= deadline {
            eprintln!("DNS did not converge:");
            for (name, rtype, want, seen) in &pending {
                let seen = if seen.is_empty() { "nothing".to_string() } else { seen.join(", ") };
                eprintln!("  {name} {rtype}: expected {want}, saw {seen}");
            }
            bail!("DNS records do not resolve to this VM; fix them (or wait) and re-run setup");
        }
        tokio::time::sleep(DNS_POLL).await;
    }
}

async fn ensure_certificate(cfg: &Config) -> anyhow::Result<()> {
    let status = tls::cert_status(cfg);
    // A staging leftover is "valid" by dates and names but untrusted.
    let staging_leftover = !cfg.acme.staging && cert_is_staging(cfg);
    match status {
        tls::CertStatus::Valid { not_after } if !staging_leftover => {
            println!("Certificate is valid until {} (unix {not_after}); not reissuing", format_unix(not_after));
            return Ok(());
        }
        _ if staging_leftover => println!("Replacing the Let's Encrypt staging certificate with a production one"),
        other => println!("Certificate status: {other:?}; issuing via DNS-01 for {}", cfg.cert_names().join(", ")),
    }
    acme::issue(cfg).await.context("issuing the certificate")?;
    println!("Certificate issued");
    Ok(())
}

/// Let's Encrypt staging intermediates are named "(STAGING) ...".
fn cert_is_staging(cfg: &Config) -> bool {
    let Ok(pem) = std::fs::read(cfg.cert_dir().join("fullchain.pem")) else {
        return false;
    };
    match x509_parser::pem::parse_x509_pem(&pem) {
        Ok((_, block)) => block
            .parse_x509()
            .map(|cert| cert.issuer().to_string().contains("STAGING"))
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn format_unix(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .map(|t| format!("{} {:02}:{:02} UTC", t.date(), t.hour(), t.minute()))
        .unwrap_or_else(|_| secs.to_string())
}

async fn self_test(cfg: &Config) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(cfg.acme.staging)
        .build()?;
    let health = format!("https://{}/healthz", cfg.api_host);
    expect_status(&client, &health, 200).await?;
    // Unknown tunnel id → 404 proves the wildcard cert and preview routing.
    let probe = format!("https://1-{}.{}/", tokens::random_tunnel_id(), cfg.preview_zone);
    expect_status(&client, &probe, 404).await?;
    println!("Self-test passed");
    Ok(())
}

/// Retries for a short while: the service may have just (re)started.
async fn expect_status(client: &reqwest::Client, url: &str, want: u16) -> anyhow::Result<()> {
    let deadline = Instant::now() + SELF_TEST_TIMEOUT;
    loop {
        let outcome = match client.get(url).send().await {
            Ok(resp) if resp.status().as_u16() == want => {
                println!("  GET {url} -> {want}");
                return Ok(());
            }
            Ok(resp) => format!("HTTP {}", resp.status()),
            Err(e) => format!("{:#}", anyhow::Error::from(e)),
        };
        if Instant::now() >= deadline {
            bail!(
                "self-test GET {url}: expected HTTP {want}, got {outcome} \
                 (check `journalctl -u cockpit-tunnel`; re-run with --skip-self-test to bypass)"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn print_token_box(cfg: &Config, token: &str) {
    let lines = [
        "Admin API token (shown once; only its hash is stored):".to_string(),
        String::new(),
        format!("COCKPIT_TUNNEL_API=https://{}", cfg.api_host),
        format!("COCKPIT_TUNNEL_ADMIN_TOKEN={token}"),
    ];
    let width = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let rule = "-".repeat(width + 2);
    println!("+{rule}+");
    for line in &lines {
        println!("| {line:<width$} |");
    }
    println!("+{rule}+");
}

fn finish(cfg: &Config, new_token: Option<&str>) {
    println!("\nSetup complete.\n");
    match new_token {
        Some(token) => {
            print_token_box(cfg, token);
            println!("Put these in the harness backend environment. They will not be shown again.");
        }
        None => {
            println!("The existing admin token was kept. Harness backend environment:");
            println!("  COCKPIT_TUNNEL_API=https://{}", cfg.api_host);
            println!("  COCKPIT_TUNNEL_ADMIN_TOKEN=<existing token>  (lost it? run `cockpit-tunnel-server token rotate`)");
        }
    }
    println!("\nSandbox server URL (baked into cockpit-preview, or set in the sandbox):");
    println!("  COCKPIT_TUNNEL_SERVER=wss://{}", cfg.tunnel_host);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parsing() {
        assert_eq!(parse_host(" Example.COM. ").unwrap(), "example.com");
        assert!(parse_host("localhost").is_err());
        assert!(parse_host("-bad.example.com").is_err());
        assert!(parse_host("a_b.example.com").is_err());
    }

    #[test]
    fn origin_parsing() {
        assert_eq!(parse_origin("https://App.example.com/").unwrap(), "https://app.example.com");
        assert_eq!(parse_origin("https://app.example.com:8443").unwrap(), "https://app.example.com:8443");
        assert!(parse_origin("http://app.example.com").is_err());
        assert!(parse_origin("https://app.example.com/path").is_err());
    }

    #[test]
    fn fresh_config_has_defaults() {
        let cfg = fresh_config().unwrap();
        assert_eq!(cfg.data_dir, Path::new(crate::config::DEFAULT_DATA_DIR));
        assert!(!cfg.webrtc.enabled);
    }

    #[test]
    fn secrets_are_not_regenerated() {
        let mut cfg = fresh_config().unwrap();
        cfg.webrtc.enabled = true;
        let token = generate_secrets(&mut cfg).unwrap();
        assert!(token.starts_with(ADMIN_TOKEN_PREFIX));
        assert_eq!(cfg.admin_token_hash, tokens::hash_token(&token));
        let (hash, secret) = (cfg.admin_token_hash.clone(), cfg.webrtc.static_auth_secret.clone());
        assert!(generate_secrets(&mut cfg).is_none());
        assert_eq!(cfg.admin_token_hash, hash);
        assert_eq!(cfg.webrtc.static_auth_secret, secret);
    }

    #[test]
    fn record_hosts_dedupe() {
        let mut cfg = fresh_config().unwrap();
        cfg.preview_zone = "previews.example.com".into();
        cfg.api_host = "edge.example.com".into();
        cfg.tunnel_host = "edge.example.com".into();
        cfg.turn_host = "turn.example.com".into();
        assert_eq!(record_hosts(&cfg), vec!["*.previews.example.com", "edge.example.com"]);
        cfg.webrtc.enabled = true;
        assert_eq!(record_hosts(&cfg).len(), 3);
    }
}
