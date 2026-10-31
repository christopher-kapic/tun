//! `cockpit-preview`: the sandbox side of cockpit-tunnel.
//!
//! Commands talk to one background daemon over a Unix socket. The daemon owns
//! the single control connection to the tunnel server and splices
//! server-opened streams to loopback ports.

#[cfg(not(unix))]
compile_error!("cockpit-preview supports only Unix targets (Linux and macOS)");

mod commands;
mod daemon;
mod ice;
mod ipc;
mod paths;
mod session;
mod state;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cockpit-preview", version, about = "Expose sandbox ports through cockpit-tunnel")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Expose local ports (starts the daemon if needed). Token from COCKPIT_TUNNEL_TOKEN.
    Expose {
        #[arg(required = true, num_args = 1.., value_parser = clap::value_parser!(u16).range(1..))]
        ports: Vec<u16>,
    },
    /// Stop exposing a port.
    Unexpose {
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
    },
    /// Show tunnel and per-port status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Print the current ICE (STUN/TURN) config, or run a command with it in the environment.
    Ice {
        #[arg(long, value_enum, default_value_t = IceFormat::Json)]
        format: IceFormat,
        /// Ask the server for a new credential even if the cached one is fresh.
        #[arg(long)]
        fresh: bool,
        /// Exec the command after `--` with TURN_* / ICE_* variables set.
        #[arg(long, requires = "command")]
        exec: bool,
        #[arg(last = true, requires = "exec", value_name = "CMD")]
        command: Vec<String>,
    },
    /// Stop the daemon and forget exposed ports.
    Stop,
    #[command(hide = true)]
    Daemon,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum IceFormat {
    /// `export K='v'` lines for `eval "$(...)"`.
    Env,
    /// The ICE config JSON.
    Json,
    /// The path of the ICE file the daemon keeps fresh.
    File,
}

fn main() {
    let cli = Cli::parse();
    let is_daemon = matches!(cli.cmd, Cmd::Daemon);
    init_tracing(is_daemon);
    // Fails only if a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cockpit-preview: starting runtime: {e}");
            std::process::exit(1);
        }
    };
    let code = match runtime.block_on(run(cli.cmd)) {
        Ok(code) => code,
        Err(e) => {
            if is_daemon {
                tracing::error!("{e:#}");
            } else {
                eprintln!("cockpit-preview: {e:#}");
            }
            1
        }
    };
    std::process::exit(code);
}

async fn run(cmd: Cmd) -> anyhow::Result<i32> {
    match cmd {
        Cmd::Expose { ports } => commands::expose(ports).await,
        Cmd::Unexpose { port } => commands::unexpose(port).await,
        Cmd::Status { json } => commands::status(json).await,
        Cmd::Ice { format, fresh, exec: _, command } => commands::ice(format, fresh, command).await,
        Cmd::Stop => commands::stop().await,
        Cmd::Daemon => daemon::run().await.map(|()| 0),
    }
}

fn init_tracing(daemon: bool) {
    let default = if daemon { "info" } else { "warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr);
    if daemon {
        builder.init();
    } else {
        builder.without_time().init();
    }
}
