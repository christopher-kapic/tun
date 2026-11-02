mod acme;
mod api;
mod clients;
mod commands;
mod config;
mod control;
mod db;
mod dns;
mod edge;
mod gate;
mod gatehost;
mod headers;
mod ice;
mod inject;
mod listener;
mod metrics;
mod mode;
mod pages;
mod password;
mod pool;
mod proxy;
mod purge;
mod ratelimit;
mod registry;
mod setup;
mod sni;
mod state;
mod tls;
mod tokens;
mod turn_relay;
mod util;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cockpit-tunnel-server", version, about = "Preview relay for sandboxed apps")]
struct Cli {
    /// Config file (default: /etc/cockpit-tunnel/config.toml as root,
    /// ~/.config/cockpit-tunnel/config.toml otherwise).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (used by the systemd unit).
    Serve,
    /// Install or reconfigure (as root: system install; as another user: rootless install).
    Setup(setup::SetupArgs),
    /// Admin token management.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Protect /healthz with an optional token (for uptime monitors).
    HealthToken {
        #[command(subcommand)]
        cmd: HealthTokenCmd,
    },
    /// Show service, database, and certificate status.
    Status,
    /// Write a consistent SQLite backup (`VACUUM INTO`).
    Backup { path: PathBuf },
    /// Replace the database with a backup: checks it, stops the service, keeps
    /// the current database as `<db>.before-restore-<time>`, starts again.
    Restore { path: PathBuf },
    /// Certificate management.
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
    /// Machines that may create tunnels with their own token (`cockpit-preview login`).
    Client {
        #[command(subcommand)]
        cmd: ClientCmd,
    },
}

#[derive(Subcommand)]
enum ClientCmd {
    /// Register a machine and print the one-time login command to run on it.
    Add { name: String },
    /// List machines, when they were last used, and their open tunnels.
    List,
    /// Remove a machine: its token stops working and its tunnels close.
    Delete { name: String },
}

#[derive(Subcommand)]
enum HealthTokenCmd {
    /// Require a token for /healthz: generate one, print it once, restart.
    Set,
    /// Make /healthz open again.
    Clear,
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Generate a new admin API token, print it once, restart the service.
    Rotate,
}

#[derive(Subcommand)]
enum CertCmd {
    /// Renew the certificate if due (or always with --force).
    Renew {
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = match cli.config {
        Some(p) => p,
        None => mode::Mode::current().config_path()?,
    };
    match cli.cmd {
        Cmd::Serve => commands::serve(&config).await,
        Cmd::Setup(args) => setup::run(&config, args).await,
        Cmd::Token { cmd: TokenCmd::Rotate } => commands::token_rotate(&config).await,
        Cmd::HealthToken { cmd } => commands::health_token(&config, matches!(cmd, HealthTokenCmd::Set)).await,
        Cmd::Status => commands::status(&config).await,
        Cmd::Backup { path } => commands::backup(&config, &path).await,
        Cmd::Restore { path } => commands::restore(&config, &path).await,
        Cmd::Cert { cmd: CertCmd::Renew { force } } => commands::cert_renew(&config, force).await,
        Cmd::Client { cmd: ClientCmd::Add { name } } => commands::client_add(&config, &name).await,
        Cmd::Client { cmd: ClientCmd::List } => commands::client_list(&config).await,
        Cmd::Client { cmd: ClientCmd::Delete { name } } => commands::client_delete(&config, &name).await,
    }
}
