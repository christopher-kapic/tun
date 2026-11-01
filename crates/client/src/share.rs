//! `login`, `logout`, `share`, and `link`: create and expose tunnels from a
//! machine that logged in with `cockpit-preview login`, without an admin token.
//!
//! `share` reuses the tunnel it created earlier while the daemon still runs
//! it, so `share 3000` then `share 5173` serve both ports from one tunnel (one
//! link covers both). `stop` deletes a tunnel that `share` created.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::commands::{ask, Answer};
use crate::ipc::{host_for, Request, Response, Status};
use crate::login::{enroll, parse_login_arg, Api, Login};
use crate::paths::{env_nonempty, Paths};
use crate::state::{write_atomic, Persisted};

pub const ENV_SHARE_PASSWORD: &str = "COCKPIT_SHARE_PASSWORD";
/// How long a link printed by `share` (and `link` by default) works.
pub const LINK_TTL_S: u64 = 10 * 60;
const CONNECT_WAIT: Duration = Duration::from_secs(15);

/// The tunnel `share` created, so later `share`/`link`/`stop` find it.
#[derive(Serialize, Deserialize)]
struct Shared {
    tunnel_id: String,
    api: String,
}

fn shared_path(paths: &Paths) -> PathBuf {
    paths.dir.join("share.json")
}

fn load_shared(paths: &Paths) -> Option<Shared> {
    std::fs::read(shared_path(paths)).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn forget_shared(paths: &Paths) {
    let _ = std::fs::remove_file(shared_path(paths));
}

pub async fn login(arg: Option<&str>) -> anyhow::Result<i32> {
    let arg = match arg.filter(|a| *a != "-") {
        Some(a) => a.to_string(),
        None => read_secret_line("Login code (from `cockpit-tunnel-server client add`): ")?,
    };
    let (code, host) = parse_login_arg(&arg)?;
    let login = enroll(&code, &host).await?;
    login.save()?;
    println!("Logged in to {} as {}.", login.api, login.name);
    println!("Share a local port with: cockpit-preview share <PORT>");
    Ok(0)
}

pub fn logout() -> anyhow::Result<i32> {
    let p = crate::login::path()?;
    match std::fs::remove_file(&p) {
        Ok(()) => println!("Logged out (removed {}). Ask the server admin to `client delete` this machine to revoke its token.", p.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("Not logged in."),
        Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
    }
    Ok(0)
}

/// Requested access for `share`; `None` fields mean "not given".
pub struct ShareAccess {
    pub public: bool,
    pub password: bool,
    pub link: bool,
    pub username: Option<String>,
}

impl ShareAccess {
    fn explicit(&self) -> bool {
        self.public || self.password || self.link
    }

    fn to_json(&self) -> anyhow::Result<Value> {
        Ok(if self.public {
            json!({ "mode": "public" })
        } else if self.password {
            let username = self.username.clone().unwrap_or_else(|| "preview".to_string());
            json!({ "mode": "password", "username": username, "password": read_password()? })
        } else {
            json!({ "mode": "link" })
        })
    }
}

/// `$COCKPIT_SHARE_PASSWORD`, else a prompt on the terminal (not echoed).
fn read_password() -> anyhow::Result<String> {
    if let Some(p) = env_nonempty(ENV_SHARE_PASSWORD) {
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        bail!("set {ENV_SHARE_PASSWORD} (no terminal to prompt for the password)");
    }
    read_secret_line("Password for visitors (8+ characters): ")
}

/// One line from stdin: prompted without echo on a terminal, read as-is from a pipe.
fn read_secret_line(prompt: &str) -> anyhow::Result<String> {
    let tty = std::io::stdin().is_terminal();
    let mut echo_off = false;
    if tty {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        echo_off = std::process::Command::new("stty").arg("-echo").status().is_ok_and(|s| s.success());
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if echo_off {
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
    }
    read?;
    let line = line.trim().to_string();
    if line.is_empty() {
        bail!("nothing entered");
    }
    Ok(line)
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "machine".to_string())
}

pub async fn share(ports: Vec<u16>, access: ShareAccess, ttl_s: u64, label: Option<String>) -> anyhow::Result<i32> {
    let login = Login::require()?;
    let api = Api::new(&login)?;
    let paths = Paths::resolve()?;

    // Reuse the tunnel an earlier `share` made, while the daemon still serves it.
    let running = Persisted::load(&paths.state_file).and_then(|p| p.tunnel_id);
    let mut reuse = None;
    if let Some(s) = load_shared(&paths).filter(|s| s.api == login.api && running.as_deref() == Some(&s.tunnel_id)) {
        if let Some(info) = api.tunnel(&s.tunnel_id).await?.filter(|i| !i.expired) {
            reuse = Some((s.tunnel_id, info.access.mode));
        }
    }

    let (tunnel_id, token, mode) = match reuse {
        Some((id, current_mode)) => {
            let mode = if access.explicit() {
                let wanted = access.to_json()?;
                api.set_access(&id, &wanted).await?;
                wanted["mode"].as_str().unwrap_or("link").to_string()
            } else {
                current_mode
            };
            (id, None, mode)
        }
        None => {
            let wanted = access.to_json()?;
            let label = label.unwrap_or_else(|| format!("share-{}", hostname()));
            let created = api.create_tunnel(&label, ttl_s, &wanted).await?;
            let shared = Shared { tunnel_id: created.id.clone(), api: login.api.clone() };
            write_atomic(&shared_path(&paths), &serde_json::to_vec(&shared)?, 0o600)?;
            let mode = wanted["mode"].as_str().unwrap_or("link").to_string();
            (created.id, Some(created.tunnel_token), mode)
        }
    };

    let req = Request::Expose { ports: ports.clone(), token, server: Some(login.server.clone()) };
    let mut status = match ask(req, true, false).await? {
        Answer::Response(Response::Status { status }) => status,
        Answer::Response(_) => bail!("unexpected daemon response"),
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => bail!("the daemon did not start"),
    };
    status = wait_connected(status, &ports).await;

    let username = match mode.as_str() {
        "password" => api.tunnel(&tunnel_id).await?.and_then(|i| i.access.username),
        _ => None,
    };
    for port in &ports {
        let host = port_host(&status, *port);
        let connected = status.ports.iter().any(|p| p.port == *port && p.connected);
        let note = if connected { "" } else { "  (not connected yet; check `cockpit-preview status`)" };
        match mode.as_str() {
            "public" => println!("{port}  https://{host}/  (public){note}"),
            "password" => println!(
                "{port}  https://{host}/  (username {}, password as set){note}",
                username.as_deref().unwrap_or("?")
            ),
            _ => {
                let url = api.access_link(&tunnel_id, *port, LINK_TTL_S, true).await?;
                println!("{port}  {url}  (works once, within {} min){note}", LINK_TTL_S / 60);
            }
        }
    }
    if mode == "link" {
        println!("More links: cockpit-preview link [--port PORT] [--reusable]");
    }
    println!("Stop sharing: cockpit-preview stop");
    Ok(0)
}

fn port_host(status: &Status, port: u16) -> String {
    status
        .ports
        .iter()
        .find(|p| p.port == port)
        .and_then(|p| p.host.clone())
        .or_else(|| status.host_template.as_deref().map(|t| host_for(t, port)))
        .unwrap_or_else(|| format!("{port}-?"))
}

/// Poll the daemon until `ports` are connected (or give up after a while).
async fn wait_connected(mut status: Status, ports: &[u16]) -> Status {
    let deadline = Instant::now() + CONNECT_WAIT;
    let all = |s: &Status| ports.iter().all(|port| s.ports.iter().any(|p| p.port == *port && p.connected));
    while !all(&status) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(300)).await;
        match ask(Request::Status, false, false).await {
            Ok(Answer::Response(Response::Status { status: s })) => status = s,
            _ => break,
        }
    }
    status
}

pub async fn link(port: Option<u16>, reusable: bool, ttl_s: u64) -> anyhow::Result<i32> {
    let login = Login::require()?;
    let paths = Paths::resolve()?;
    let Some(shared) = load_shared(&paths).filter(|s| s.api == login.api) else {
        bail!("nothing shared from this machine; run `cockpit-preview share <PORT>` first");
    };
    let status = match ask(Request::Status, false, false).await? {
        Answer::Response(Response::Status { status }) => status,
        _ => bail!("cockpit-preview is not running; run `cockpit-preview share <PORT>`"),
    };
    let port = match port.or_else(|| status.ports.first().map(|p| p.port)) {
        Some(p) => p,
        None => bail!("no ports are shared"),
    };
    let api = Api::new(&login)?;
    let url = api.access_link(&shared.tunnel_id, port, ttl_s, !reusable).await?;
    let uses = if reusable { "any number of times" } else { "once" };
    println!("{url}  (works {uses}, for {} min)", ttl_s / 60);
    Ok(0)
}

/// For `stop`: delete the tunnel `share` created, if any.
pub async fn delete_shared(paths: &Paths) {
    let Some(shared) = load_shared(paths) else {
        return;
    };
    match Login::load() {
        Ok(Some(login)) if login.api == shared.api => match Api::new(&login) {
            Ok(api) => {
                if let Err(e) = api.delete_tunnel(&shared.tunnel_id).await {
                    eprintln!("cockpit-preview: deleting shared tunnel {}: {e:#}", shared.tunnel_id);
                    return;
                }
            }
            Err(e) => eprintln!("cockpit-preview: {e:#}"),
        },
        _ => {}
    }
    forget_shared(paths);
}
