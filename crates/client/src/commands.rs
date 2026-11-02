//! User-facing subcommands. Each talks to the daemon over IPC.

use std::io;
use std::os::unix::process::CommandExt;
use std::time::Duration;

use anyhow::bail;
use tokio::net::UnixStream;

use crate::ice;
use crate::ipc::{call, ensure_daemon, ConnState, Reach, Request, Response, Status};
use crate::paths::{env_nonempty, Paths, ENV_SERVER, ENV_TOKEN};
use crate::state::Persisted;
use crate::IceFormat;

/// Covers the daemon's per-port server round trips plus its connect wait.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) enum Answer {
    Response(Response),
    /// Already reported; exit with this code.
    Exit(i32),
    Stopped,
}

pub(crate) async fn ask(req: Request, takeover: bool, json: bool) -> anyhow::Result<Answer> {
    let paths = Paths::resolve()?;
    let (token, server) = match &req {
        Request::Expose { token, server, .. } => (token.as_deref(), server.as_deref()),
        _ => (None, None),
    };
    match ensure_daemon(&paths, takeover, token, server).await? {
        Reach::Running(stream) => match call(stream, &req, REQUEST_TIMEOUT).await? {
            Some(Response::Error { message }) => bail!("{message}"),
            Some(resp) => Ok(Answer::Response(resp)),
            None => daemon_gone(&paths, json).map(Answer::Exit),
        },
        Reach::Terminal(p, state) => Ok(Answer::Exit(report_terminal(&p, state, json))),
        Reach::Stopped => Ok(Answer::Stopped),
    }
}

fn report_terminal(p: &Persisted, state: ConnState, json: bool) -> i32 {
    let status = Status::from_persisted(p, state);
    status.print(json);
    status.exit_code()
}

/// The daemon hung up mid-request: it exited, usually on revocation.
fn daemon_gone(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    match Persisted::load(&paths.state_file) {
        Some(p) if p.revoked => Ok(report_terminal(&p, ConnState::Revoked, json)),
        Some(p) if p.replaced => Ok(report_terminal(&p, ConnState::Replaced, json)),
        _ => bail!("daemon exited unexpectedly; see {}", paths.log_file.display()),
    }
}

fn expect_status(resp: Response) -> anyhow::Result<Status> {
    match resp {
        Response::Status { status } => Ok(status),
        _ => bail!("unexpected daemon response"),
    }
}

pub async fn expose(ports: Vec<u16>) -> anyhow::Result<i32> {
    // The server: $COCKPIT_TUNNEL_SERVER, else the one this machine logged in to
    // (the daemon falls back to its saved server, then the build-time default).
    let server = env_nonempty(ENV_SERVER).or_else(|| crate::login::Login::load().ok().flatten().map(|l| l.server));
    let req = Request::Expose { ports, token: env_nonempty(ENV_TOKEN), server };
    match ask(req, true, false).await? {
        Answer::Response(resp) => {
            let status = expect_status(resp)?;
            status.print(false);
            Ok(status.exit_code())
        }
        Answer::Exit(code) => Ok(code),
        Answer::Stopped => bail!("no tunnel token: set {ENV_TOKEN}"),
    }
}

pub async fn unexpose(port: u16) -> anyhow::Result<i32> {
    match ask(Request::Unexpose { port }, false, false).await? {
        Answer::Response(resp) => {
            let status = expect_status(resp)?;
            status.print(false);
            Ok(status.exit_code())
        }
        Answer::Exit(code) => Ok(code),
        Answer::Stopped => bail!("cockpit-preview is not running"),
    }
}

pub async fn status(json: bool) -> anyhow::Result<i32> {
    let status = match ask(Request::Status, false, json).await? {
        Answer::Response(resp) => expect_status(resp)?,
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => Status::stopped(),
    };
    status.print(json);
    Ok(status.exit_code())
}

pub async fn ice(format: IceFormat, fresh: bool, exec: Vec<String>) -> anyhow::Result<i32> {
    let (config, ice_file, endpoint) = match ask(Request::Ice { fresh }, false, false).await? {
        Answer::Response(Response::Ice { ice, ice_file, ice_url, ice_token }) => {
            (ice, ice_file, ice_url.zip(ice_token))
        }
        Answer::Response(_) => bail!("unexpected daemon response"),
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => bail!("cockpit-preview is not running; run `cockpit-preview expose <PORT>` first"),
    };
    let mut vars = ice::env_vars(&config, &ice_file);
    if let Some((url, token)) = endpoint {
        vars.push(("COCKPIT_ICE_URL", url));
        vars.push(("COCKPIT_ICE_TOKEN", token));
    }
    if let Some((program, args)) = exec.split_first() {
        // Replaces this process, so the command keeps the caller's stdio and exit status.
        let err = std::process::Command::new(program).args(args).envs(vars).exec();
        bail!("exec {program}: {err}");
    }
    match format {
        IceFormat::Env => print!("{}", ice::format_env(&vars)),
        IceFormat::Json => println!("{}", serde_json::to_string_pretty(&config)?),
        IceFormat::File => println!("{ice_file}"),
    }
    Ok(0)
}

pub async fn stop() -> anyhow::Result<i32> {
    let paths = Paths::resolve()?;
    // A tunnel `share` created is deleted on the server, not just disconnected.
    crate::share::delete_shared(&paths).await;
    if let Ok(stream) = UnixStream::connect(&paths.socket).await {
        // The daemon replies, deletes its state, and exits.
        if let Some(Response::Error { message }) = call(stream, &Request::Stop, REQUEST_TIMEOUT).await? {
            bail!("{message}");
        }
    }
    // No daemon (or it already exited): make sure nothing restarts it from state.
    match std::fs::remove_file(&paths.state_file) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => bail!("removing {}: {e}", paths.state_file.display()),
    }
    println!("stopped");
    Ok(0)
}
