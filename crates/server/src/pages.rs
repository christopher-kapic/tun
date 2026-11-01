//! Small, unbranded status pages served by the edge.

use http::header::{self, HeaderName};
use http::{Response, StatusCode};

use crate::util::{full, Body};

fn page(status: StatusCode, title: &str, message: &str, retry_after: Option<u32>) -> Response<Body> {
    // A meta refresh lets the offline pages recover on their own once the
    // sandbox (re)connects, including inside the harness iframe.
    let refresh = match retry_after {
        Some(s) if status.is_server_error() => format!(r#"<meta http-equiv="refresh" content="{s}">"#),
        _ => String::new(),
    };
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">{refresh}<title>{title}</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;color:#1f1f1f;background:#fafafa}}main{{max-width:30rem;padding:1.5rem;text-align:center}}h1{{margin:0 0 .5rem;font-size:1.25rem}}p{{margin:0;color:#5f5f5f}}@media (prefers-color-scheme:dark){{body{{color:#ececec;background:#161616}}p{{color:#a8a8a8}}}}</style></head>
<body><main><h1>{title}</h1><p>{message}</p></main></body></html>
"#
    );
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-robots-tag"), "noindex")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'");
    if let Some(s) = retry_after {
        builder = builder.header(header::RETRY_AFTER, s.to_string());
    }
    builder.body(full(html)).expect("valid response")
}

/// Minimal HTML escaping for text and attribute values.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Login form for a password-protected preview. Posts to `/__login` on the
/// same host, so it also works inside an iframe. `next` is where to go after
/// signing in (already sanitized by the caller).
pub fn login(status: StatusCode, next: &str, error: Option<&str>) -> Response<Body> {
    let error = error.map(|e| format!(r#"<p class="err" role="alert">{}</p>"#, escape(e))).unwrap_or_default();
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Sign in</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;color:#1f1f1f;background:#fafafa}}main{{width:100%;max-width:20rem;padding:1.5rem;box-sizing:border-box}}h1{{margin:0 0 1rem;font-size:1.25rem}}label{{display:block;margin:.75rem 0 .25rem;font-size:.875rem;color:#5f5f5f}}input{{width:100%;box-sizing:border-box;padding:.5rem .625rem;font:inherit;border:1px solid #c8c8c8;border-radius:6px;background:#fff;color:inherit}}button{{margin-top:1rem;width:100%;padding:.55rem;font:inherit;font-weight:600;border:0;border-radius:6px;background:#1f1f1f;color:#fff;cursor:pointer}}.err{{margin:0 0 .5rem;color:#b3261e;font-size:.875rem}}@media (prefers-color-scheme:dark){{body{{color:#ececec;background:#161616}}label{{color:#a8a8a8}}input{{background:#232323;border-color:#3a3a3a}}button{{background:#ececec;color:#161616}}.err{{color:#f2b8b5}}}}</style></head>
<body><main><h1>Sign in to view this preview</h1>{error}
<form method="post" action="/__login"><input type="hidden" name="next" value="{next}">
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form></main></body></html>
"#,
        next = escape(next),
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-robots-tag"), "noindex")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        .body(full(html))
        .expect("valid response")
}

pub fn not_found() -> Response<Body> {
    page(StatusCode::NOT_FOUND, "Not found", "There is no preview at this address.", None)
}

/// Deliberately generic: never says whether a link was unknown, used, or expired.
pub fn unauthorized() -> Response<Body> {
    page(
        StatusCode::UNAUTHORIZED,
        "Access required",
        "Open this preview from the link you were given.",
        None,
    )
}

pub fn ended() -> Response<Body> {
    page(StatusCode::GONE, "Preview ended", "This preview has been stopped or has expired.", None)
}

pub fn offline() -> Response<Body> {
    page(
        StatusCode::BAD_GATEWAY,
        "Preview offline",
        "The preview is not connected right now. This page retries every few seconds.",
        Some(5),
    )
}

pub fn app_not_running(port: u16) -> Response<Body> {
    let message = format!("Nothing is listening on port {port} in the sandbox yet. This page retries every few seconds.");
    page(StatusCode::BAD_GATEWAY, "App not running", &message, Some(5))
}

pub fn bad_gateway() -> Response<Body> {
    page(
        StatusCode::BAD_GATEWAY,
        "Bad gateway",
        "The app closed the connection without a valid response.",
        None,
    )
}

pub fn rate_limited() -> Response<Body> {
    page(StatusCode::TOO_MANY_REQUESTS, "Too many attempts", "Wait a minute and try again.", Some(60))
}
