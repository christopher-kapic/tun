mod acme;
mod api;
mod commands;
mod config;
mod control;
mod db;
mod dns;
mod edge;
mod gate;
mod headers;
mod ice;
mod inject;
mod listener;
mod metrics;
mod pages;
mod proxy;
mod purge;
mod ratelimit;
mod registry;
mod setup;
mod sni;
mod state;
mod tls;
mod tokens;
mod util;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cockpit-tunnel-server", version, about = "Preview relay for sandboxed apps")]
struct Cli {
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (used by the systemd unit).
    Serve,
    /// Interactive install/reconfigure wizard (run as root).
    Setup(setup::SetupArgs),
    /// Admin token management.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Show service, database, and certificate status.
    Status,
    /// Write a consistent SQLite backup (`VACUUM INTO`).
    Backup { path: PathBuf },
    /// Certificate management.
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
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
    match cli.cmd {
        Cmd::Serve => commands::serve(&cli.config).await,
        Cmd::Setup(args) => setup::run(&cli.config, args).await,
        Cmd::Token { cmd: TokenCmd::Rotate } => commands::token_rotate(&cli.config).await,
        Cmd::Status => commands::status(&cli.config).await,
        Cmd::Backup { path } => commands::backup(&cli.config, &path).await,
        Cmd::Cert { cmd: CertCmd::Renew { force } } => commands::cert_renew(&cli.config, force).await,
    }
}
