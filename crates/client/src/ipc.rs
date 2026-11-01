//! Command ↔ daemon IPC: newline-delimited JSON over `<state dir>/daemon.sock`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::time::Duration;

use anyhow::{bail, Context};
use cockpit_tunnel_protocol::{read_json_line, write_json_line, IceConfig, EXIT_REPLACED, EXIT_REVOKED};
use serde::{Deserialize, Serialize};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::time::Instant;

use crate::paths::{env_nonempty, Paths, ENV_ICE_FILE, ENV_SERVER, ENV_TOKEN};
use crate::state::{resolve_server, Persisted};

const SPAWN_WAIT: Duration = Duration::from_secs(5);
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Expose {
        ports: Vec<u16>,
        /// The command's `COCKPIT_TUNNEL_TOKEN`; a different token switches tunnels.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
    },
    Unexpose {
        port: u16,
    },
    Status,
    Ice {
        fresh: bool,
    },
    Stop,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status { status: Status },
    Ice {
        ice: IceConfig,
        ice_file: String,
        /// `http://127.0.0.1:<port>/ice` and the bearer token it requires.
        #[serde(default)]
        ice_url: Option<String>,
        #[serde(default)]
        ice_token: Option<String>,
    },
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Connecting,
    Connected,
    /// Token rejected (401/410) or tunnel deleted/expired. Terminal.
    Revoked,
    /// Another client connected with the same token. Terminal for this daemon.
    Replaced,
    /// No daemon and no persisted tunnel.
    Stopped,
}

impl ConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnState::Connecting => "connecting",
            ConnState::Connected => "connected",
            ConnState::Revoked => "revoked",
            ConnState::Replaced => "replaced",
            ConnState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: ConnState,
    pub tunnel_id: Option<String>,
    pub host_template: Option<String>,
    pub ports: Vec<PortStatus>,
    pub last_error: Option<String>,
    pub ice_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStatus {
    pub port: u16,
    pub host: Option<String>,
    pub connected: bool,
}

pub fn host_for(template: &str, port: u16) -> String {
    template.replace("{port}", &port.to_string())
}

impl Status {
    pub fn stopped() -> Self {
        Self {
            state: ConnState::Stopped,
            tunnel_id: None,
            host_template: None,
            ports: Vec::new(),
            last_error: None,
            ice_file: None,
        }
    }

    /// Status of a tunnel whose daemon is gone (revoked or replaced).
    pub fn from_persisted(p: &Persisted, state: ConnState) -> Self {
        Self {
            state,
            tunnel_id: p.tunnel_id.clone(),
            host_template: p.host_template.clone(),
            ports: p
                .ports
                .iter()
                .map(|&port| PortStatus {
                    port,
                    host: p.host_template.as_deref().map(|t| host_for(t, port)),
                    connected: false,
                })
                .collect(),
            last_error: None,
            ice_file: None,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.state {
            ConnState::Revoked => EXIT_REVOKED,
            ConnState::Replaced => EXIT_REPLACED,
            _ => 0,
        }
    }

    pub fn print(&self, json: bool) {
        if json {
            match serde_json::to_string_pretty(self) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("cockpit-preview: encoding status: {e}"),
            }
            return;
        }
        println!("state: {}", self.state.as_str());
        if let Some(id) = &self.tunnel_id {
            println!("tunnel: {id}");
        }
        if self.ports.is_empty() {
            println!("ports: none");
        } else {
            println!("ports:");
            for p in &self.ports {
                let url = p.host.as_deref().map_or_else(|| "(host pending)".to_string(), |h| format!("https://{h}"));
                let conn = if p.connected { "connected" } else { "not connected" };
                println!("  {} -> {url} ({conn})", p.port);
            }
        }
        if let Some(e) = &self.last_error {
            println!("last error: {e}");
        }
        if let Some(f) = &self.ice_file {
            println!("ice file: {f}");
        }
        match self.state {
            ConnState::Revoked => {
                eprintln!("the tunnel was deleted, expired, or its token rejected; create a new tunnel")
            }
            ConnState::Replaced => eprintln!("another client connected with this tunnel token; this daemon stopped"),
            _ => {}
        }
    }
}

pub enum Reach {
    Running(UnixStream),
    /// The daemon is gone for a terminal reason and must not be restarted.
    Terminal(Persisted, ConnState),
    /// No daemon, no persisted tunnel, no token.
    Stopped,
}

/// Connect to the daemon, starting it if needed. `takeover` lets an explicit
/// `expose` restart a daemon that was replaced by another client.
/// `token`/`server` are what the request will carry (`expose` takes them from
/// the environment, `share` from its login); a token there counts as one to start with.
pub async fn ensure_daemon(
    paths: &Paths,
    takeover: bool,
    token: Option<&str>,
    server: Option<&str>,
) -> anyhow::Result<Reach> {
    if let Ok(stream) = UnixStream::connect(&paths.socket).await {
        return Ok(Reach::Running(stream));
    }
    let state = Persisted::load(&paths.state_file);
    let env_token = token.map(str::to_string).or_else(|| env_nonempty(ENV_TOKEN));
    let new_token = |p: &Persisted| env_token.as_deref().is_some_and(|t| t != p.token);
    if let Some(p) = &state {
        if p.revoked && !new_token(p) {
            return Ok(Reach::Terminal(p.clone(), ConnState::Revoked));
        }
        if p.replaced && !takeover && !new_token(p) {
            return Ok(Reach::Terminal(p.clone(), ConnState::Replaced));
        }
    }
    let has_token = env_token.is_some() || state.as_ref().is_some_and(|p| !p.token.is_empty());
    if !has_token {
        return Ok(Reach::Stopped);
    }
    // Fail here rather than in the detached daemon, where the error would only reach the log.
    let persisted_server = state.as_ref().filter(|p| !new_token(*p)).map(|p| p.server.as_str());
    let server = server.map(str::to_string).or_else(|| env_nonempty(ENV_SERVER));
    resolve_server(server.as_deref(), persisted_server)?;

    // The daemon itself removes a stale socket, under its lock file, so a
    // concurrently starting daemon's fresh socket is never deleted here.
    let mut child = spawn_daemon(paths, env_token.as_deref(), server.as_deref())?;
    let deadline = Instant::now() + SPAWN_WAIT;
    loop {
        if let Ok(stream) = UnixStream::connect(&paths.socket).await {
            return Ok(Reach::Running(stream));
        }
        // Exit 0 means another daemon won the lock; keep waiting for its socket.
        if let Some(status) = child.try_wait().context("waiting for daemon")? {
            if !status.success() {
                if let Some(p) = Persisted::load(&paths.state_file).filter(|p| p.revoked) {
                    return Ok(Reach::Terminal(p, ConnState::Revoked));
                }
                bail!("daemon exited ({status}); see {}", paths.log_file.display());
            }
        }
        if Instant::now() >= deadline {
            bail!("daemon did not start within {}s; see {}", SPAWN_WAIT.as_secs(), paths.log_file.display());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn spawn_daemon(paths: &Paths, token: Option<&str>, server: Option<&str>) -> anyhow::Result<Child> {
    let exe = std::env::current_exe().context("locating the cockpit-preview executable")?;
    let log = open_log(paths)?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("duplicating log handle")?)
        .stderr(log);
    // COCKPIT_TUNNEL_TOKEN / _SERVER reach the daemon through its environment,
    // never argv (argv is visible in `ps`): inherited for `expose`, set here for
    // `share`, whose token comes from the API. Only a relative ICE file path
    // needs fixing up because the daemon runs from `/`.
    if let Some(t) = token {
        cmd.env(ENV_TOKEN, t);
    }
    if let Some(s) = server {
        cmd.env(ENV_SERVER, s);
    }
    if let Some(file) = env_nonempty(ENV_ICE_FILE) {
        if let Ok(abs) = std::path::absolute(&file) {
            cmd.env(ENV_ICE_FILE, abs);
        }
    }
    // SAFETY: setsid is async-signal-safe and touches no Rust state.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().context("starting the cockpit-preview daemon")
}

fn open_log(paths: &Paths) -> anyhow::Result<File> {
    if fs::metadata(&paths.log_file).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
        let _ = fs::remove_file(&paths.log_file);
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&paths.log_file)
        .with_context(|| format!("opening {}", paths.log_file.display()))
}

/// Send one request. `Ok(None)` means the daemon closed the connection
/// without answering (it exited, e.g. on revocation).
pub async fn call(stream: UnixStream, req: &Request, timeout: Duration) -> anyhow::Result<Option<Response>> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    match write_json_line(&mut wr, req).await {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(None),
        Err(e) => return Err(e).context("sending request to daemon"),
    }
    let mut buf = String::new();
    match tokio::time::timeout(timeout, read_json_line::<_, Response>(&mut rd, &mut buf)).await {
        Err(_) => bail!("daemon did not answer within {}s", timeout.as_secs()),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => Ok(None),
        Ok(r) => r.context("reading daemon response"),
    }
}
