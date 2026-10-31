//! The background daemon: persisted state, the IPC socket, and the shared
//! state the tunnel session (`session.rs`) and ICE endpoint (`ice.rs`) use.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use cockpit_tunnel_protocol::{read_json_line, write_json_line, ClientMsg, IceConfig, EXIT_REPLACED, EXIT_REVOKED};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tracing::{info, warn};

use crate::ice;
use crate::ipc::{host_for, ConnState, PortStatus, Request, Response, Status};
use crate::paths::{self, env_nonempty, Paths, ENV_SERVER, ENV_TOKEN};
use crate::session;
use crate::state::{normalize_server, resolve_server, write_atomic, Persisted};

/// Wait for a server reply on the control stream.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `expose`/`ice` wait for an in-progress connection before answering.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

pub struct Reply {
    pub ok: bool,
    pub error: Option<String>,
    pub ice: Option<IceConfig>,
}

pub type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Reply>>>>;

/// Handle to the live control stream of one connection.
#[derive(Clone)]
pub struct Link {
    pub ctrl_tx: mpsc::Sender<ClientMsg>,
    pub pending: Pending,
    pub webrtc: bool,
    /// Connection generation; stale links never touch newer state.
    pub generation: u64,
}

pub struct Welcome {
    pub tunnel_id: String,
    pub host_template: String,
    pub max_ports: u16,
    pub ports: Vec<u16>,
}

struct Inner {
    persisted: Persisted,
    /// Ports the server has acknowledged on the current connection.
    accepted: BTreeSet<u16>,
    last_error: Option<String>,
    link: Option<Link>,
    ice: Option<IceConfig>,
    /// Bumped when the target tunnel changes, so the old connection's late
    /// results are discarded.
    generation: u64,
}

pub struct Daemon {
    pub paths: Paths,
    pub ice_file: PathBuf,
    inner: Mutex<Inner>,
    conn: watch::Sender<ConnState>,
    /// Signalled when the token or server changes: drop the connection now.
    pub reconnect: Notify,
    next_id: AtomicU64,
}

pub fn lock_poisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Daemon {
    fn new(paths: Paths, ice_file: PathBuf, persisted: Persisted) -> Self {
        Self {
            paths,
            ice_file,
            inner: Mutex::new(Inner {
                persisted,
                accepted: BTreeSet::new(),
                last_error: None,
                link: None,
                ice: None,
                generation: 0,
            }),
            conn: watch::channel(ConnState::Connecting).0,
            reconnect: Notify::new(),
            next_id: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        lock_poisoned(&self.inner)
    }

    fn save(&self, inner: &Inner) {
        if let Err(e) = inner.persisted.save(&self.paths.state_file) {
            warn!(path = %self.paths.state_file.display(), error = %e, "cannot write state file");
        }
    }

    pub fn conn_state(&self) -> ConnState {
        *self.conn.borrow()
    }

    pub fn set_conn(&self, state: ConnState) {
        self.conn.send_replace(state);
    }

    async fn wait_connected(&self, within: Duration) {
        let mut rx = self.conn.subscribe();
        let _ = tokio::time::timeout(within, rx.wait_for(|s| *s == ConnState::Connected)).await;
    }

    /// `(server, token, generation)` for the next connection attempt.
    pub fn target(&self) -> (String, String, u64) {
        let g = self.lock();
        (g.persisted.server.clone(), g.persisted.token.clone(), g.generation)
    }

    pub fn ports(&self) -> Vec<u16> {
        self.lock().persisted.ports.clone()
    }

    pub fn is_exposed(&self, port: u16) -> bool {
        self.lock().persisted.ports.contains(&port)
    }

    pub fn set_last_error(&self, error: String) {
        self.lock().last_error = Some(error);
    }

    /// Install a freshly welcomed connection. Returns the ports persisted
    /// during the handshake (not in `hello`) that still need declaring, or
    /// `None` if the target changed meanwhile.
    pub fn connected(&self, link: Link, welcome: Welcome, hello: &[u16]) -> Option<Vec<u16>> {
        let mut g = self.lock();
        if g.generation != link.generation {
            return None;
        }
        let accepted: BTreeSet<u16> = welcome
            .ports
            .iter()
            .copied()
            .filter(|p| hello.contains(p) && g.persisted.ports.contains(p))
            .collect();
        // The server keeps a prefix when over max_ports; drop the rest locally.
        let dropped: Vec<u16> = hello.iter().copied().filter(|p| !welcome.ports.contains(p)).collect();
        g.persisted.ports.retain(|p| !dropped.contains(p));
        let missing = g.persisted.ports.iter().copied().filter(|p| !hello.contains(p)).collect();
        g.last_error = (!dropped.is_empty())
            .then(|| format!("server allows at most {} ports; not exposed: {dropped:?}", welcome.max_ports));
        g.persisted.tunnel_id = Some(welcome.tunnel_id);
        g.persisted.host_template = Some(welcome.host_template);
        g.accepted = accepted;
        g.link = Some(link);
        self.save(&g);
        drop(g);
        self.set_conn(ConnState::Connected);
        Some(missing)
    }

    /// Forget the connection of `generation` (no-op if already superseded).
    pub fn disconnected(&self, generation: u64) {
        let mut g = self.lock();
        if g.generation == generation {
            g.link = None;
            g.accepted.clear();
            drop(g);
            self.set_conn(ConnState::Connecting);
        }
    }

    /// Record a terminal outcome and exit. Revoked: 401/410 or tunnel
    /// deleted/expired. Replaced: another client holds the tunnel.
    pub fn terminate(&self, state: ConnState, why: &str) -> ! {
        {
            let mut g = self.lock();
            match state {
                ConnState::Revoked => g.persisted.revoked = true,
                ConnState::Replaced => g.persisted.replaced = true,
                _ => {}
            }
            g.link = None;
            g.accepted.clear();
            g.ice = None;
            g.last_error = Some(why.to_string());
            self.save(&g);
        }
        self.set_conn(state);
        if state == ConnState::Revoked {
            let _ = fs::remove_file(&self.ice_file);
        }
        let _ = fs::remove_file(&self.paths.socket);
        warn!("{why}; daemon exiting");
        std::process::exit(if state == ConnState::Revoked { EXIT_REVOKED } else { EXIT_REPLACED });
    }

    /// Send one request on the control stream and wait for its `Reply`.
    pub async fn call(&self, link: &Link, msg: impl FnOnce(u64) -> ClientMsg) -> anyhow::Result<Reply> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock_poisoned(&link.pending).insert(id, tx);
        if link.ctrl_tx.send(msg(id)).await.is_err() {
            lock_poisoned(&link.pending).remove(&id);
            bail!("not connected to the tunnel server");
        }
        let reply = match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => bail!("connection to the tunnel server was lost"),
            Err(_) => {
                lock_poisoned(&link.pending).remove(&id);
                bail!("tunnel server did not reply within {}s", CALL_TIMEOUT.as_secs());
            }
        };
        if !reply.ok {
            bail!("{}", reply.error.unwrap_or_else(|| "rejected by the tunnel server".to_string()));
        }
        Ok(reply)
    }

    /// Declare one port on a live connection.
    pub async fn declare(&self, link: &Link, port: u16) -> anyhow::Result<()> {
        self.call(link, |id| ClientMsg::Expose { id, port }).await?;
        let mut g = self.lock();
        if g.generation == link.generation && g.persisted.ports.contains(&port) {
            g.accepted.insert(port);
        }
        Ok(())
    }

    pub fn drop_port(&self, port: u16) {
        let mut g = self.lock();
        g.persisted.ports.retain(|p| *p != port);
        g.accepted.remove(&port);
        self.save(&g);
    }

    pub fn status(&self) -> Status {
        let state = self.conn_state();
        let g = self.lock();
        let template = g.persisted.host_template.clone();
        Status {
            state,
            tunnel_id: g.persisted.tunnel_id.clone(),
            ports: g
                .persisted
                .ports
                .iter()
                .map(|&port| PortStatus {
                    port,
                    host: template.as_deref().map(|t| host_for(t, port)),
                    connected: state == ConnState::Connected && g.accepted.contains(&port),
                })
                .collect(),
            host_template: template,
            last_error: g.last_error.clone(),
            ice_file: Some(self.ice_file.display().to_string()),
        }
    }

    /// Switch tunnels when a command brings a different token (clears ports
    /// and the revoked flag), or reconnect when the server URL changes.
    fn retarget(&self, token: Option<String>, server: Option<String>) -> anyhow::Result<()> {
        let server = server.map(|s| normalize_server(&s)).transpose()?;
        let mut g = self.lock();
        let mut changed = false;
        if let Some(token) = token.filter(|t| *t != g.persisted.token) {
            info!("tunnel token changed; switching tunnels");
            let server = g.persisted.server.clone();
            g.persisted = Persisted { server, token, ..Persisted::default() };
            g.ice = None;
            g.last_error = None;
            changed = true;
        }
        if let Some(server) = server.filter(|s| *s != g.persisted.server) {
            info!(server = %server, "tunnel server changed; reconnecting");
            g.persisted.server = server;
            changed = true;
        }
        if changed {
            g.generation += 1;
            g.link = None;
            g.accepted.clear();
            self.save(&g);
            drop(g);
            self.set_conn(ConnState::Connecting);
            self.reconnect.notify_one();
        }
        Ok(())
    }

    async fn expose(&self, ports: Vec<u16>, token: Option<String>, server: Option<String>) -> anyhow::Result<Status> {
        self.retarget(token, server)?;
        for port in ports {
            let link = {
                let mut g = self.lock();
                if g.persisted.ports.contains(&port) {
                    continue;
                }
                g.persisted.ports.push(port);
                g.persisted.ports.sort_unstable();
                self.save(&g);
                g.link.clone()
            };
            // Disconnected: persisted only; the next Hello declares it.
            let Some(link) = link else { continue };
            if let Err(e) = self.declare(&link, port).await {
                self.drop_port(port);
                return Err(e.context(format!("exposing port {port}")));
            }
        }
        if self.conn_state() != ConnState::Connected {
            self.wait_connected(CONNECT_WAIT).await;
        }
        Ok(self.status())
    }

    async fn unexpose(&self, port: u16) -> anyhow::Result<Status> {
        let link = {
            let mut g = self.lock();
            if !g.persisted.ports.contains(&port) {
                bail!("port {port} is not exposed");
            }
            g.persisted.ports.retain(|p| *p != port);
            g.accepted.remove(&port);
            self.save(&g);
            g.link.clone()
        };
        // Local removal already stops routing (`is_exposed`); the server
        // message only updates its view.
        if let Some(link) = link {
            if let Err(e) = self.call(&link, |id| ClientMsg::Unexpose { id, port }).await {
                warn!(port, error = %format!("{e:#}"), "server did not acknowledge unexpose");
            }
        }
        Ok(self.status())
    }

    pub fn current_ice(&self) -> Option<IceConfig> {
        let now = ice::unix_now();
        self.lock().ice.clone().filter(|i| i.expires_at > now)
    }

    pub fn ice_needs_refresh(&self) -> bool {
        let cached = self.lock().ice.clone();
        cached.as_ref().is_none_or(ice::needs_refresh)
    }

    /// Fetch a new credential and rewrite the ICE file.
    pub async fn refresh_ice(&self, link: &Link) -> anyhow::Result<IceConfig> {
        let reply = self.call(link, |id| ClientMsg::IceRequest { id }).await?;
        let config = reply.ice.ok_or_else(|| anyhow!("tunnel server sent no ICE config"))?;
        {
            let mut g = self.lock();
            if g.generation != link.generation {
                bail!("tunnel changed while fetching ICE config");
            }
            g.ice = Some(config.clone());
        }
        let json = serde_json::to_vec_pretty(&config)?;
        write_atomic(&self.ice_file, &json, 0o600).with_context(|| format!("writing {}", self.ice_file.display()))?;
        Ok(config)
    }

    async fn ice(&self, fresh: bool) -> anyhow::Result<IceConfig> {
        if !fresh {
            let cached = self.lock().ice.clone();
            if let Some(config) = cached.filter(|i| !ice::needs_refresh(i)) {
                return Ok(config);
            }
        }
        if self.conn_state() != ConnState::Connected {
            self.wait_connected(CONNECT_WAIT).await;
        }
        let link = self.lock().link.clone();
        match link {
            Some(link) if link.webrtc => self.refresh_ice(&link).await,
            Some(_) => bail!("this tunnel server does not offer TURN/WebRTC"),
            None => match self.current_ice() {
                Some(config) if !fresh => Ok(config),
                _ => bail!("not connected to the tunnel server"),
            },
        }
    }

    async fn handle(&self, req: Request) -> Response {
        let result = match req {
            Request::Expose { ports, token, server } => {
                self.expose(ports, token, server).await.map(|status| Response::Status { status })
            }
            Request::Unexpose { port } => self.unexpose(port).await.map(|status| Response::Status { status }),
            Request::Status | Request::Stop => Ok(Response::Status { status: self.status() }),
            Request::Ice { fresh } => self.ice(fresh).await.map(|ice| Response::Ice {
                ice,
                ice_file: self.ice_file.display().to_string(),
            }),
        };
        result.unwrap_or_else(|e| Response::Error { message: format!("{e:#}") })
    }

    /// `stop`: forget the tunnel locally so no later command resurrects it.
    fn stop(&self) -> ! {
        let _ = fs::remove_file(&self.paths.state_file);
        let _ = fs::remove_file(&self.ice_file);
        let _ = fs::remove_file(&self.paths.socket);
        info!("stop requested; daemon exiting");
        std::process::exit(0);
    }
}

/// Entry point of the hidden `daemon` subcommand.
pub async fn run() -> anyhow::Result<()> {
    let paths = Paths::resolve()?;
    let Some(_lock) = lock_daemon(&paths)? else {
        info!("another daemon holds the lock; exiting");
        return Ok(());
    };

    let mut persisted = Persisted::load(&paths.state_file).unwrap_or_default();
    if let Some(token) = env_nonempty(ENV_TOKEN).filter(|t| *t != persisted.token) {
        // A different token is a different tunnel: start clean.
        persisted = Persisted { token, ..Persisted::default() };
    }
    if persisted.token.is_empty() {
        bail!("no tunnel token: set {ENV_TOKEN}");
    }
    if persisted.revoked {
        warn!("tunnel was revoked; not reconnecting");
        std::process::exit(EXIT_REVOKED);
    }
    // Being started at all means a command chose to take the tunnel back.
    persisted.replaced = false;
    persisted.server = resolve_server(env_nonempty(ENV_SERVER).as_deref(), Some(persisted.server.as_str()))?;
    persisted.save(&paths.state_file).context("writing state file")?;

    match fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing stale {}", paths.socket.display())),
    }
    let listener =
        UnixListener::bind(&paths.socket).with_context(|| format!("binding {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

    let ice_file = paths::ice_file(&paths.dir);
    let ice_port = paths::ice_port();
    info!(
        server = %persisted.server,
        ports = ?persisted.ports,
        ice_file = %ice_file.display(),
        "daemon starting"
    );
    let daemon = Arc::new(Daemon::new(paths, ice_file, persisted));
    tokio::spawn(accept_ipc(daemon.clone(), listener));
    tokio::spawn(ice::serve_http(daemon.clone(), ice_port));
    tokio::spawn(exit_on_signal(daemon.clone()));
    session::run(daemon).await;
    Ok(())
}

/// One daemon per state dir; held for the process lifetime.
fn lock_daemon(paths: &Paths) -> anyhow::Result<Option<File>> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&paths.lock_file)
        .with_context(|| format!("opening {}", paths.lock_file.display()))?;
    // SAFETY: the fd is valid for the lifetime of `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(err).context("locking daemon lock file")
    }
}

async fn accept_ipc(daemon: Arc<Daemon>, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(serve_ipc(daemon.clone(), stream));
            }
            Err(e) => {
                warn!(error = %e, "ipc accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn serve_ipc(daemon: Arc<Daemon>, stream: UnixStream) {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let mut buf = String::new();
    loop {
        let req = match read_json_line::<_, Request>(&mut rd, &mut buf).await {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(e) => {
                // Not logged: a malformed request may carry the token.
                let message = format!("bad request: {e}");
                let _ = write_json_line(&mut wr, &Response::Error { message }).await;
                return;
            }
        };
        let stop = matches!(req, Request::Stop);
        let resp = daemon.handle(req).await;
        if write_json_line(&mut wr, &resp).await.is_err() {
            return;
        }
        if stop {
            daemon.stop();
        }
    }
}

/// SIGTERM/SIGINT: exit but keep the state file, so the next command restarts
/// the daemon with the same ports.
async fn exit_on_signal(daemon: Arc<Daemon>) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
        warn!("cannot install signal handlers");
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    info!("signal received; daemon exiting");
    let _ = fs::remove_file(&daemon.paths.socket);
    std::process::exit(0);
}
