//! `cockpit-tunnel-server setup`: the install/reconfigure wizard.
//!
//! One question matters: the server hostname. The API, the sandbox tunnel,
//! and `*.<host>` previews all live on it (TURN on `turn.<host>`), so two DNS
//! records cover everything. Every input is checked as soon as it is given
//! (DNS token, zone, records) so mistakes fail early with a reason.
//!
//! Every step is idempotent. Existing config values are the defaults,
//! secrets are never regenerated, files are only rewritten when their content
//! changes, and services only restart when something changed, so re-running
//! with the same answers changes nothing.
//!
//! Run as root for a system install; as any other user for a rootless one
//! (see `crate::mode`).

mod coturn;
mod firewall;
mod os;
mod prompt;
mod systemd;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use cockpit_tunnel_protocol::ADMIN_TOKEN_PREFIX;

use crate::config::{Config, DnsProviderKind, SERVICE_NAME, SERVICE_USER};
use crate::mode::{self, Mode};
use crate::{acme, dns, tls, tokens, util};

#[allow(unused_imports)] // part of the module contract; no caller outside setup yet
pub use coturn::detect_coturn_user;

#[derive(clap::Args, Debug, Default)]
pub struct SetupArgs {
    /// Server hostname, e.g. tunnel.example.com. The API and sandbox tunnel use it,
    /// previews are *.<host>, TURN is turn.<host>.
    #[arg(long)]
    pub host: Option<String>,
    /// Override the preview zone (default: the server hostname).
    #[arg(long)]
    pub preview_zone: Option<String>,
    /// Override the TURN hostname (default: turn.<host>).
    #[arg(long)]
    pub turn_host: Option<String>,
    /// ACME (Let's Encrypt) contact email.
    #[arg(long)]
    pub email: Option<String>,
    /// DNS provider: cloudflare, hetzner, digitalocean, or route53.
    #[arg(long)]
    pub dns_provider: Option<String>,
    /// DNS zone at the provider (detected automatically for Cloudflare).
    #[arg(long)]
    pub dns_zone: Option<String>,
    /// File holding the DNS provider API token (keeps it out of argv and shell history).
    #[arg(long)]
    pub dns_token_file: Option<PathBuf>,
    /// Sites allowed to show previews in an iframe, comma-separated:
    /// https://app.example.com,https://*.example.com — or * for any site (the default).
    #[arg(long)]
    pub frame_ancestors: Option<String>,
    /// Enable WebRTC (coturn TURN relay): true or false.
    #[arg(long)]
    pub webrtc: Option<bool>,
    /// Never prompt: use flags and current values, fail if something required is missing.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Use the Let's Encrypt staging directory (untrusted certs, generous rate limits).
    #[arg(long)]
    pub staging: bool,
    /// Do not create DNS records (they must already point here; they are still verified).
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
    let mode = Mode::current();
    let os = os::Os::detect()?;
    if mode.is_user() {
        println!("Rootless install for user {} (run with sudo for a system install).", mode::username()?);
        user_preflight(&args)?;
    }

    let existing = if config_path.exists() { Some(Config::load(config_path)?) } else { None };
    if existing.is_some() {
        println!("Reconfiguring from {} (Enter keeps each current value).", config_path.display());
    }
    let ask = Ask { yes: args.yes };
    let mut cfg = ask_config(&ask, existing.as_ref(), &args, mode).await?;

    // Set only once the config holding its hash is on disk, so a failure
    // after that point still shows the token instead of losing it.
    let mut new_token: Option<String> = None;
    let result = configure(config_path, existing.as_ref(), &mut cfg, &args, mode, os, &mut new_token).await;
    if let Err(e) = result {
        if let Some(token) = &new_token {
            eprintln!("\nSetup failed, but a new admin token was already saved. Keep it:");
            print_token_box(&cfg, token);
        }
        return Err(e);
    }
    finish(&cfg, mode, new_token.as_deref());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn configure(
    config_path: &Path,
    existing: Option<&Config>,
    cfg: &mut Config,
    args: &SetupArgs,
    mode: Mode,
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

    step("Checking DNS provider access");
    let provider = dns::Provider::from_config(cfg)?;
    provider
        .check_write(&cfg.tunnel_host)
        .await
        .context("the DNS token cannot create records in this zone (it needs DNS edit permission)")?;
    println!("Token can edit records in {}", cfg.dns.zone);

    // Before DNS so the answers are persisted even if DNS verification times out.
    step("Creating directories");
    if mode == Mode::System {
        ensure_service_user(cfg)?;
    }
    ensure_dirs(cfg, config_path, mode)?;

    step("Generating secrets");
    let token = generate_secrets(cfg);
    let config_changed = cfg.save(config_path)?;
    if mode == Mode::System {
        chown(config_path, &format!("{SERVICE_USER}:{SERVICE_USER}"))?;
    }
    *new_token = token;
    println!("{} {}", if config_changed { "Wrote" } else { "Unchanged:" }, config_path.display());

    if args.skip_dns {
        println!("Not creating DNS records (--skip-dns)");
    } else {
        step("Configuring DNS");
        configure_dns(cfg, &provider).await?;
    }
    verify_dns(cfg, v4, v6).await?;

    step("Certificate");
    ensure_certificate(cfg).await?;
    if mode == Mode::System {
        util::chown_recursive(&cfg.data_dir, SERVICE_USER)?;
    }

    if cfg.webrtc.enabled {
        step("coturn");
        coturn::configure(cfg, &mut os)?;
    } else if mode == Mode::System {
        coturn::disable_if_managed()?;
    }

    step("Firewall");
    if mode == Mode::System {
        firewall::configure(cfg)?;
    } else {
        println!("Rootless install: not touching the host firewall. Inbound TCP 80 and 443 must be open");
        println!("(host firewall and any cloud provider firewall).");
    }

    step("Service");
    systemd::install(cfg, config_path, config_changed, mode)?;

    if args.skip_self_test {
        println!("Skipping self-test (--skip-self-test)");
    } else {
        step("Self-test");
        self_test(cfg, mode).await?;
    }
    Ok(())
}

fn step(title: &str) {
    println!("\n==> {title}");
}

/// A rootless server needs two root-owned settings. Check both (and whether a
/// root install is still around) and print one command that fixes everything.
fn user_preflight(args: &SetupArgs) -> anyhow::Result<()> {
    let user = mode::username()?;
    let port_start = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1024);
    let ports_ok = port_start <= 80;
    let linger_ok = Path::new("/var/lib/systemd/linger").join(&user).exists();
    let system_install = Path::new(mode::SYSTEM_CONFIG_PATH).parent().is_some_and(Path::exists);

    if args.webrtc == Some(true) {
        bail!("WebRTC needs coturn, which needs a root install for now (run setup with sudo)");
    }
    if ports_ok && linger_ok && !system_install {
        return Ok(());
    }

    let config = Mode::User.config_path()?;
    let data = Mode::User.data_dir()?;
    let config_dir = config.parent().context("config path has no parent")?.display().to_string();
    let data = data.display().to_string();
    let mut lines: Vec<String> = Vec::new();
    if !ports_ok {
        lines.push(
            "echo net.ipv4.ip_unprivileged_port_start=80 > /etc/sysctl.d/60-cockpit-tunnel.conf && sysctl -q --system"
                .to_string(),
        );
    }
    if !linger_ok {
        lines.push(format!("loginctl enable-linger {user}"));
    }
    if system_install {
        // Move the root install's config, certificate, and database to this user.
        lines.push(format!("(systemctl disable --now {SERVICE_NAME}.service 2>/dev/null || true)"));
        lines.push(format!("runuser -u {user} -- mkdir -p {config_dir} {data}"));
        lines.push(format!("cp -a {}/. {data}/", mode::SYSTEM_DATA_DIR));
        lines.push(format!("cp {} {}", mode::SYSTEM_CONFIG_PATH, config.display()));
        lines.push(format!("chown -R {user}:{user} {config_dir} {data}"));
        lines.push(format!(
            "mv /etc/cockpit-tunnel /etc/cockpit-tunnel.migrated && mv {} {}.migrated",
            mode::SYSTEM_DATA_DIR,
            mode::SYSTEM_DATA_DIR
        ));
        lines.push(format!("rm -f /etc/systemd/system/{SERVICE_NAME}.service && systemctl daemon-reload"));
    }

    eprintln!("A rootless install needs a one-time change as root:");
    if !ports_ok {
        eprintln!("  - allow unprivileged programs to use ports 80 and up (now {port_start})");
    }
    if !linger_ok {
        eprintln!("  - keep {user}'s services running after logout (lingering)");
    }
    if system_install {
        eprintln!("  - move the existing root install (config, certificate, database) to {user}");
    }
    // One line joined with `&&`: it survives copy/paste and runners that fold newlines,
    // and stops at the first failing step.
    eprintln!("\nRun this once, then run setup again:\n");
    eprintln!("sudo sh -c '{}'", lines.join(" && "));
    bail!("one-time root setup needed (see above)")
}

/// A config with only defaults, so `config.rs` stays the single source of
/// default values.
fn fresh_config() -> anyhow::Result<Config> {
    Ok(serde_json::from_value(serde_json::json!({
        "preview_zone": "",
        "api_host": "",
        "tunnel_host": "",
        "turn_host": "",
        "admin_token_hash": "",
        "acme": { "email": "" },
        "dns": { "provider": "cloudflare", "zone": "" },
    }))?)
}

/// Answers come from a flag, else a prompt, else (with `--yes`) the default.
struct Ask {
    yes: bool,
}

impl Ask {
    fn text<T>(
        &self,
        flag: Option<&str>,
        flag_name: &str,
        question: &str,
        default: &str,
        parse: impl Fn(&str) -> Result<T, String>,
    ) -> anyhow::Result<T> {
        if let Some(v) = flag {
            return parse(v).map_err(|e| anyhow::anyhow!("--{flag_name}: {e}"));
        }
        if self.yes {
            anyhow::ensure!(!default.is_empty(), "--{flag_name} is required with --yes");
            return parse(default).map_err(|e| anyhow::anyhow!("current {flag_name}: {e}"));
        }
        prompt::ask_with(question, default, parse)
    }

    fn bool(&self, flag: Option<bool>, question: &str, default: bool) -> anyhow::Result<bool> {
        match flag {
            Some(v) => Ok(v),
            None if self.yes => Ok(default),
            None => prompt::ask_bool(question, default),
        }
    }

    fn confirm(&self, question: &str) -> anyhow::Result<bool> {
        if self.yes {
            Ok(true)
        } else {
            prompt::ask_bool(question, true)
        }
    }

    fn secret(
        &self,
        file: Option<&Path>,
        flag_name: &str,
        question: &str,
        current: Option<&str>,
    ) -> anyhow::Result<String> {
        if let Some(path) = file {
            let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let v = raw.trim().to_string();
            anyhow::ensure!(!v.is_empty(), "{} is empty", path.display());
            return Ok(v);
        }
        if self.yes {
            return current
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .with_context(|| format!("--{flag_name} is required with --yes"));
        }
        prompt::ask_secret(question, current)
    }
}

async fn ask_config(ask: &Ask, existing: Option<&Config>, args: &SetupArgs, mode: Mode) -> anyhow::Result<Config> {
    let mut cfg = match existing {
        Some(c) => c.clone(),
        None => fresh_config()?,
    };
    cfg.base_domain.clear();
    if mode.is_user() {
        // A migrated root config still points at /var/lib.
        cfg.data_dir = mode.data_dir()?;
    }

    // 1. The server hostname; the rest of the layout follows from it.
    let host = ask.text(
        args.host.as_deref(),
        "host",
        "Server hostname (API, sandbox tunnel, and *.<host> previews), e.g. tunnel.example.com",
        &cfg.tunnel_host,
        parse_host,
    )?;
    let preview_zone = match &args.preview_zone {
        Some(z) => parse_host(z).map_err(|e| anyhow::anyhow!("--preview-zone: {e}"))?,
        None => host.clone(),
    };
    let turn_host = match &args.turn_host {
        Some(t) => parse_host(t).map_err(|e| anyhow::anyhow!("--turn-host: {e}"))?,
        None => format!("turn.{host}"),
    };
    let before = existing.map(layout);
    cfg.api_host = host.clone();
    cfg.tunnel_host = host.clone();
    cfg.preview_zone = preview_zone;
    cfg.turn_host = turn_host;

    // 2. Who may frame previews.
    cfg.normalize_frame_ancestors();
    let current = cfg.frame_ancestors.join(",");
    cfg.frame_ancestors = ask.text(
        args.frame_ancestors.as_deref(),
        "frame-ancestors",
        "Sites that may show previews in an iframe (comma-separated, e.g. https://app.example.com,https://*.example.com; * for any)",
        &current,
        parse_frame_ancestors,
    )?;

    // 3. Let's Encrypt contact.
    cfg.acme.email = ask.text(args.email.as_deref(), "email", "ACME contact email", &cfg.acme.email, parse_email)?;
    cfg.acme.staging = args.staging;

    // 4. DNS provider, credentials, and zone (checked right away).
    let current = PROVIDERS.iter().position(|(k, _)| *k == cfg.dns.provider).unwrap_or(0);
    let provider = match args.dns_provider.as_deref() {
        Some(name) => PROVIDERS
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name.trim()))
            .map(|(k, _)| *k)
            .with_context(|| format!("--dns-provider: unknown provider '{name}'"))?,
        None if ask.yes => PROVIDERS[current].0,
        None => {
            let names: Vec<&str> = PROVIDERS.iter().map(|(_, n)| *n).collect();
            PROVIDERS[prompt::ask_choice("DNS provider", &names, current)?].0
        }
    };
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
            cfg.dns.aws_access_key_id =
                Some(ask.text(None, "aws-access-key-id (config)", "AWS access key id", &key_id, non_empty)?);
            cfg.dns.aws_secret_access_key = Some(ask.secret(
                args.dns_token_file.as_deref(),
                "dns-token-file",
                "AWS secret access key",
                cfg.dns.aws_secret_access_key.as_deref(),
            )?);
            let zone_id = cfg.dns.route53_hosted_zone_id.clone().unwrap_or_default();
            cfg.dns.route53_hosted_zone_id = Some(ask.text(
                None,
                "route53-hosted-zone-id (config)",
                "Route53 hosted zone id",
                &zone_id,
                non_empty,
            )?);
            cfg.dns.api_token = None;
        }
        _ => {
            let hint = match provider {
                DnsProviderKind::Cloudflare => {
                    "Cloudflare API token (\"Edit zone DNS\" template, limited to this zone)"
                }
                DnsProviderKind::Hetzner => "Hetzner DNS API token",
                _ => "DigitalOcean API token (domain read/write)",
            };
            cfg.dns.api_token = Some(ask.secret(
                args.dns_token_file.as_deref(),
                "dns-token-file",
                hint,
                cfg.dns.api_token.as_deref(),
            )?);
            cfg.dns.aws_access_key_id = None;
            cfg.dns.aws_secret_access_key = None;
            cfg.dns.route53_hosted_zone_id = None;
        }
    }
    cfg.dns.zone = choose_zone(ask, &cfg, args).await?;

    // 5. WebRTC.
    if mode.is_user() {
        if cfg.webrtc.enabled {
            println!("WebRTC turned off: coturn needs a root install for now.");
        }
        cfg.webrtc.enabled = false;
    } else {
        cfg.webrtc.enabled = ask.bool(args.webrtc, "Enable WebRTC (coturn TURN relay)?", cfg.webrtc.enabled)?;
    }

    check_names(&cfg)?;
    print_layout(&cfg, before.as_ref());
    anyhow::ensure!(ask.confirm("Continue with this layout?")?, "stopped; nothing was changed");
    Ok(cfg)
}

/// Cloudflare: the zones the token can see decide (the token is checked here).
/// Other providers: ask, defaulting to the host's parent domain.
async fn choose_zone(ask: &Ask, cfg: &Config, args: &SetupArgs) -> anyhow::Result<String> {
    let host = cfg.tunnel_host.as_str();
    if cfg.dns.provider == DnsProviderKind::Cloudflare {
        let token = cfg.dns.api_token.as_deref().unwrap_or_default();
        let zones = dns::cloudflare_zones(token).await.context("checking the Cloudflare token")?;
        let zone = match &args.dns_zone {
            Some(z) => parse_host(z).map_err(|e| anyhow::anyhow!("--dns-zone: {e}"))?,
            None => match dns::pick_zone(host, &zones) {
                Some(z) => z,
                None if zones.is_empty() => {
                    bail!("the Cloudflare token cannot see any zone; give it access to the zone that holds {host}")
                }
                None => bail!(
                    "{host} is not in any zone this Cloudflare token can see ({}); give it access to the right zone",
                    zones.join(", ")
                ),
            },
        };
        anyhow::ensure!(
            zones.contains(&zone),
            "the Cloudflare token cannot see zone {zone} (it sees: {})",
            if zones.is_empty() { "nothing".to_string() } else { zones.join(", ") }
        );
        println!("Cloudflare token OK; DNS zone {zone}");
        return Ok(zone);
    }
    let guess = if !cfg.dns.zone.is_empty() && (host == cfg.dns.zone || host.ends_with(&format!(".{}", cfg.dns.zone))) {
        cfg.dns.zone.clone()
    } else {
        parent_domain(host)
    };
    ask.text(args.dns_zone.as_deref(), "dns-zone", "DNS zone managed at the provider", &guess, parse_host)
}

/// `a.b.example.com` → `example.com` (a guess; public suffixes like co.uk need the flag).
fn parent_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

type Layout = Vec<(&'static str, String)>;

fn layout(cfg: &Config) -> Layout {
    let mut rows = vec![
        ("API", format!("https://{}", cfg.api_host)),
        ("Sandbox tunnel", format!("wss://{}", cfg.tunnel_host)),
        ("Previews", format!("https://{{port}}-{{id}}.{}", cfg.preview_zone)),
    ];
    if cfg.webrtc.enabled {
        rows.push(("TURN", cfg.turn_host.clone()));
    }
    rows.push(("DNS zone", format!("{} ({:?})", cfg.dns.zone, cfg.dns.provider).to_lowercase()));
    let parents = if cfg.frame_ancestors.iter().any(|s| s == "*") {
        "any site".to_string()
    } else {
        cfg.frame_ancestors.join(", ")
    };
    rows.push(("Iframe parents", parents));
    rows
}

fn print_layout(cfg: &Config, before: Option<&Layout>) {
    println!("\nLayout:");
    for (name, value) in layout(cfg) {
        let old = before.and_then(|b| b.iter().find(|(n, _)| *n == name)).map(|(_, v)| v);
        match old {
            Some(old) if *old != value => println!("  {name:<15} {value}   (was {old})"),
            _ => println!("  {name:<15} {value}"),
        }
    }
    println!("\nDNS records (each pointing at this server; setup creates them unless --skip-dns):");
    for host in record_hosts(cfg) {
        println!("  {host}");
    }
    println!();
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
    Ok(())
}

/// `*`, or a comma-separated list of `https://host[:port]` origins whose host
/// may start with a `*.` wildcard label (CSP source syntax).
fn parse_frame_ancestors(input: &str) -> Result<Vec<String>, String> {
    let items: Vec<&str> = input.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if items.is_empty() || items == ["*"] {
        return Ok(vec!["*".to_string()]);
    }
    let mut out = Vec::new();
    for item in items {
        if item == "*" {
            return Err("use * alone (any site) or list specific sites".to_string());
        }
        let parsed = match item.strip_prefix("https://*.") {
            Some(rest) => parse_origin(&format!("https://{rest}")).map(|o| o.replacen("https://", "https://*.", 1)),
            None => parse_origin(item),
        }?;
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
    Ok(out)
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
    let rest = trimmed.strip_prefix("https://").ok_or_else(|| "the origin must start with https://".to_string())?;
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
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).local_address(local).build()?;
    let text = client.get(url).send().await?.error_for_status()?.text().await?;
    Ok(text.trim().parse()?)
}

fn ensure_service_user(cfg: &Config) -> anyhow::Result<()> {
    if os::succeeds("id", &["-u", SERVICE_USER]) {
        return Ok(());
    }
    println!("Creating system user {SERVICE_USER}");
    let home = cfg.data_dir.to_string_lossy();
    let mut args = vec!["--system", "--home-dir", &*home, "--no-create-home", "--shell", "/usr/sbin/nologin"];
    if os::succeeds("getent", &["group", SERVICE_USER]) {
        args.extend(["--gid", SERVICE_USER]);
    } else {
        args.push("--user-group");
    }
    args.push(SERVICE_USER);
    os::run("useradd", &args)
}

fn ensure_dirs(cfg: &Config, config_path: &Path, mode: Mode) -> anyhow::Result<()> {
    // `chown -R` runs on the data dir as root; refuse anything that is not
    // obviously dedicated to this service.
    let data = &cfg.data_dir;
    anyhow::ensure!(
        data.is_absolute() && data.file_name().is_some_and(|n| n.to_string_lossy().contains("cockpit")),
        "data_dir {} must be an absolute path to a dedicated cockpit-tunnel directory",
        data.display()
    );
    std::fs::create_dir_all(data).with_context(|| format!("creating {}", data.display()))?;
    let etc = config_path.parent().context("config path has no parent directory")?;
    std::fs::create_dir_all(etc).with_context(|| format!("creating {}", etc.display()))?;
    let dedicated = etc.file_name().is_some_and(|n| n.to_string_lossy().contains("cockpit"));

    if mode.is_user() {
        crate::config::set_mode(data, 0o700)?;
        if dedicated {
            crate::config::set_mode(etc, 0o700)?;
        }
        return Ok(());
    }
    crate::config::set_mode(data, 0o750)?;
    chown(data, &format!("{SERVICE_USER}:{SERVICE_USER}"))?;
    // Only a dedicated config directory gets its mode/owner managed (never `/etc`).
    if dedicated {
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

async fn configure_dns(cfg: &Config, provider: &dns::Provider) -> anyhow::Result<()> {
    let v4 = cfg.public_ipv4.context("no public IPv4 address")?;
    for host in record_hosts(cfg) {
        println!("  {host} A {v4}");
        provider.upsert(&host, "A", &v4.to_string()).await?;
        if let Some(v6) = cfg.public_ipv6 {
            println!("  {host} AAAA {v6}");
            provider.upsert(&host, "AAAA", &v6.to_string()).await?;
        }
    }
    Ok(())
}

/// Wait until public resolvers return this VM for the server host and a fresh
/// (never-queried, so never negatively cached) preview name. Runs even with
/// `--skip-dns`: issuing a certificate for names that point elsewhere fails later
/// with a far less useful error.
async fn verify_dns(cfg: &Config, v4: Ipv4Addr, v6: Option<Ipv6Addr>) -> anyhow::Result<()> {
    step("Verifying DNS");
    let probe = format!("1-{}.{}", tokens::random_tunnel_id(), cfg.preview_zone);
    let mut names = vec![cfg.api_host.clone(), cfg.tunnel_host.clone(), probe];
    names.dedup();
    let mut checks: Vec<(String, &str, IpAddr)> = Vec::new();
    for name in names {
        checks.push((name.clone(), "A", IpAddr::V4(v4)));
        if let Some(v6) = v6 {
            checks.push((name, "AAAA", IpAddr::V6(v6)));
        }
    }

    println!(
        "Waiting for public DNS (polling every {}s, up to {} min)",
        DNS_POLL.as_secs(),
        DNS_TIMEOUT.as_secs() / 60
    );
    let deadline = Instant::now() + DNS_TIMEOUT;
    let mut warned_proxy = false;
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
        let proxied: Vec<&String> = pending
            .iter()
            .filter(|(_, _, _, seen)| seen.iter().any(|v| v.parse().is_ok_and(is_cloudflare_proxy)))
            .map(|(name, ..)| *name)
            .collect();
        if !proxied.is_empty() && !warned_proxy {
            warned_proxy = true;
            eprintln!(
                "{} resolve to Cloudflare's proxy, not this server. Set those records to \"DNS only\" \
                 (grey cloud) in Cloudflare; TLS must end on this server.",
                proxied.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
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

/// Cloudflare's published proxy ranges (an orange-cloud record answers with these).
fn is_cloudflare_proxy(ip: IpAddr) -> bool {
    const V4: [(u32, u32); 7] = [
        (0x6810_0000, 13), // 104.16.0.0/13
        (0x6818_0000, 14), // 104.24.0.0/14
        (0xAC40_0000, 13), // 172.64.0.0/13
        (0xA29E_0000, 15), // 162.158.0.0/15
        (0xBC72_6000, 20), // 188.114.96.0/20
        (0xC629_8000, 17), // 198.41.128.0/17
        (0x6715_F400, 22), // 103.21.244.0/22
    ];
    match ip {
        IpAddr::V4(v4) => {
            let n = u32::from(v4);
            V4.iter().any(|(net, len)| n >> (32 - len) == net >> (32 - len))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0x2606 && s[1] == 0x4700) || (s[0] == 0x2a06 && s[1] & 0xfe00 == 0x9800)
        }
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
        Ok((_, block)) => block.parse_x509().map(|cert| cert.issuer().to_string().contains("STAGING")).unwrap_or(false),
        Err(_) => false,
    }
}

fn format_unix(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .map(|t| format!("{} {:02}:{:02} UTC", t.date(), t.hour(), t.minute()))
        .unwrap_or_else(|_| secs.to_string())
}

async fn self_test(cfg: &Config, mode: Mode) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(cfg.acme.staging)
        .build()?;
    let health = format!("https://{}/healthz", cfg.api_host);
    // A protected /healthz is a 404 without its token, which still proves TLS and routing.
    let want = if cfg.health_token_hash.is_some() { 404 } else { 200 };
    expect_status(&client, &health, want, mode).await?;
    // Unknown tunnel id → 404 proves the wildcard cert and preview routing.
    let probe = format!("https://1-{}.{}/", tokens::random_tunnel_id(), cfg.preview_zone);
    expect_status(&client, &probe, 404, mode).await?;
    println!("Self-test passed");
    Ok(())
}

/// Retries for a short while: the service may have just (re)started.
async fn expect_status(client: &reqwest::Client, url: &str, want: u16, mode: Mode) -> anyhow::Result<()> {
    let deadline = Instant::now() + SELF_TEST_TIMEOUT;
    loop {
        let (outcome, timed_out) = match client.get(url).send().await {
            Ok(resp) if resp.status().as_u16() == want => {
                println!("  GET {url} -> {want}");
                return Ok(());
            }
            Ok(resp) => (format!("HTTP {}", resp.status()), false),
            Err(e) => (format!("{:#}", anyhow::Error::from(e)), true),
        };
        if Instant::now() >= deadline {
            let hint = if timed_out && mode.service_state(&format!("{SERVICE_NAME}.service")) == "active" {
                "the service is running, so a firewall is probably dropping inbound 443 \
                 (check the cloud provider's firewall)"
                    .to_string()
            } else {
                format!("check `{}`", mode.journal_hint())
            };
            bail!(
                "self-test GET {url}: expected HTTP {want}, got {outcome}; {hint} \
                 (re-run with --skip-self-test to bypass)"
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

fn finish(cfg: &Config, mode: Mode, new_token: Option<&str>) {
    println!("\nSetup complete.\n");
    println!("  API             https://{}", cfg.api_host);
    println!("  Sandbox server  COCKPIT_TUNNEL_SERVER=wss://{}", cfg.tunnel_host);
    println!("  Previews        https://{{port}}-{{id}}.{}", cfg.preview_zone);
    println!("  Logs            {}", mode.journal_hint());
    println!();
    match new_token {
        Some(token) => {
            print_token_box(cfg, token);
            println!("Put these in the harness backend environment. They will not be shown again.");
        }
        None => {
            println!("The existing admin token was kept. Harness backend environment:");
            println!("  COCKPIT_TUNNEL_API=https://{}", cfg.api_host);
            println!(
                "  COCKPIT_TUNNEL_ADMIN_TOKEN=<existing token>  (lost it? run `cockpit-tunnel-server token rotate`)"
            );
        }
    }
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
        assert_eq!(parse_frame_ancestors("*").unwrap(), vec!["*"]);
        assert_eq!(parse_frame_ancestors("").unwrap(), vec!["*"]);
        assert_eq!(
            parse_frame_ancestors("https://App.example.com/, https://*.Example.com").unwrap(),
            vec!["https://app.example.com", "https://*.example.com"]
        );
        assert!(parse_frame_ancestors("*, https://a.example.com").is_err());
        assert!(parse_frame_ancestors("http://a.example.com").is_err());
    }

    #[test]
    fn fresh_config_has_defaults() {
        let cfg = fresh_config().unwrap();
        assert_eq!(cfg.data_dir, Path::new(crate::config::DEFAULT_DATA_DIR));
        assert!(!cfg.webrtc.enabled);
        assert!(cfg.frame_ancestors.is_empty());
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
        cfg.preview_zone = "tunnel.example.com".into();
        cfg.api_host = "tunnel.example.com".into();
        cfg.tunnel_host = "tunnel.example.com".into();
        cfg.turn_host = "turn.tunnel.example.com".into();
        assert_eq!(record_hosts(&cfg), vec!["*.tunnel.example.com", "tunnel.example.com"]);
        cfg.webrtc.enabled = true;
        assert_eq!(record_hosts(&cfg).len(), 3);
    }

    #[test]
    fn parent_domain_guess() {
        assert_eq!(parent_domain("tunnel.kapic.io"), "kapic.io");
        assert_eq!(parent_domain("a.b.kapic.io"), "kapic.io");
        assert_eq!(parent_domain("kapic.io"), "kapic.io");
    }

    #[test]
    fn cloudflare_proxy_ranges() {
        assert!(is_cloudflare_proxy("104.21.93.176".parse().unwrap()));
        assert!(is_cloudflare_proxy("172.67.213.73".parse().unwrap()));
        assert!(is_cloudflare_proxy("2606:4700:3030::ac43:d549".parse().unwrap()));
        assert!(!is_cloudflare_proxy("66.42.124.183".parse().unwrap()));
    }
}
