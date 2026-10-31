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
