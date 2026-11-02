use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use serde::Serialize;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Response/request body used throughout the server.
pub type Body = http_body_util::combinators::BoxBody<Bytes, BoxError>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub fn incoming(body: Incoming) -> Body {
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}

pub fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full(body))
        .expect("valid response")
}

pub fn text_response(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full(text))
        .expect("valid response")
}

/// Lowercased request host without port, from `Host` (HTTP/1.1) or the URI
/// authority (HTTP/2).
pub fn request_host<B>(req: &Request<B>) -> Option<String> {
    let raw = req
        .uri()
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).map(|s| s.to_string()))?;
    Some(strip_port(&raw).to_ascii_lowercase())
}

pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map(|i| &host[..=i]).unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

pub fn header_str(value: Option<&HeaderValue>) -> Option<&str> {
    value.and_then(|v| v.to_str().ok())
}

/// Atomically write `content` with `mode` if it differs from what is on disk.
/// Returns `true` when the file was (re)written.
pub fn write_if_changed(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<bool> {
    if let Ok(existing) = std::fs::read(path) {
        if existing == content {
            crate::config::set_mode(path, mode)?;
            return Ok(false);
        }
    }
    write_atomic(path, content, mode)?;
    Ok(true)
}

/// Write to `<path>.tmp` with `mode`, fsync, then rename over `path`.
/// The temp file is created fresh with `mode` from the start (some targets,
/// like the config, hold secrets in directories others may traverse), and
/// a leftover or pre-planted file or symlink at that name is never reused.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        // `mode` above is filtered by the umask; set it exactly.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Recursively chown a path to `user:group` via `chown -R` (setup/CLI only, runs as root).
pub fn chown_recursive(path: &Path, owner: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("chown").arg("-R").arg(format!("{owner}:{owner}")).arg(path).status()?;
    anyhow::ensure!(status.success(), "chown -R {owner} {} failed", path.display());
    Ok(())
}
