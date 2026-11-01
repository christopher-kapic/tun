//! Visitor gate: the parent-domain session cookie, access-link redemption,
//! and password login. Redemption and login run on the zone host (see
//! `gatehost`), never on a preview origin a preview app could control.

use std::net::IpAddr;

use cockpit_tunnel_protocol::{ACCESS_TOKEN_PREFIX, GATE_COOKIE};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Response, StatusCode};

use crate::db::Redemption;
use crate::metrics::Metrics;
use crate::pages;
use crate::state::AppState;
use crate::tokens::{hash_token, now};
use crate::util::{empty, text_response, Body};



/// Distinct plausible gate-cookie values considered per request. Preview JS
/// can toss extra same-named cookies (longer paths are sent first), so this
/// must exceed what a browser will store for one site (Chrome keeps 180 per
/// domain) or tossed values could push the real session out. All values are
/// looked up in one query, so the bound only limits query size.
const MAX_GATE_VALUES: usize = 256;

pub struct GateCookies {
    /// Every gate-cookie value the browser sent, in order.
    pub values: Vec<String>,
    /// All other cookies, as one `Cookie` header for the origin.
    pub forward: Option<HeaderValue>,
}

/// Split gate cookies from the rest. HTTP/2 clients may send several
/// `Cookie` headers; all of them are considered and merged.
pub fn split_cookies(headers: &HeaderMap) -> GateCookies {
    let mut values = Vec::new();
    let mut kept: Vec<u8> = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        for pair in value.as_bytes().split(|&b| b == b';') {
            let pair = pair.trim_ascii();
            if pair.is_empty() {
                continue;
            }
            let (name, val) = match pair.iter().position(|&b| b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &pair[pair.len()..]),
            };
            if name.trim_ascii().eq_ignore_ascii_case(GATE_COOKIE.as_bytes()) {
                if let Ok(v) = std::str::from_utf8(val.trim_ascii()) {
                    values.push(v.to_string());
                }
                continue;
            }
            if !kept.is_empty() {
                kept.extend_from_slice(b"; ");
            }
            kept.extend_from_slice(pair);
        }
    }
    let forward = if kept.is_empty() { None } else { HeaderValue::from_bytes(&kept).ok() };
    GateCookies { values, forward }
}

/// Session ids are 43-char base64url; anything else cannot be a session and
/// is not worth a database lookup.
fn plausible(value: &str) -> bool {
    (16..=128).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Hashes of the distinct plausible cookie values, in order, capped.
fn session_hashes(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values.iter().filter(|v| plausible(v)) {
        if out.len() >= MAX_GATE_VALUES {
            break;
        }
        let hash = hash_token(value);
        if !out.contains(&hash) {
            out.push(hash);
        }
    }
    out
}

/// Hash of a presented session that grants `tunnel_id`. Any valid value
/// suffices, so tossed cookies cannot lock a visitor out. Cached sessions are
/// checked first; the rest are looked up together in one query.
pub async fn authorize(state: &AppState, tunnel_id: &str, values: &[String]) -> anyhow::Result<Option<String>> {
    let hashes = session_hashes(values);
    if hashes.is_empty() {
        return Ok(None);
    }
    let t = now();
    let grants_tunnel = |grants: &[(String, i64)]| grants.iter().any(|(id, expires_at)| id == tunnel_id && *expires_at > t);
    let (hits, misses) = state.cached_session_grants(&hashes);
    if let Some((hash, _)) = hits.into_iter().find(|(_, g)| grants_tunnel(g.as_slice())) {
        return Ok(Some(hash));
    }
    let loaded = state.load_session_grants(misses).await?;
    Ok(loaded.into_iter().find(|(_, g)| grants_tunnel(g.as_slice())).map(|(hash, _)| hash))
}

/// Access-link redemption: validate, mint a fresh session carrying the new
/// grant and those of any valid presented session, set the cookie, and
/// redirect to `location` so the token never appears in a later URL.
pub async fn redeem(
    state: &AppState,
    peer: IpAddr,
    tunnel_id: &str,
    token: &str,
    cookie_values: &[String],
    location: &str,
) -> Response<Body> {
    if !state.access_limiter.check(peer) {
        return pages::rate_limited();
    }
    if !token.starts_with(ACCESS_TOKEN_PREFIX) || token.len() > 256 {
        Metrics::inc(&state.metrics.access_failures);
        return pages::unauthorized();
    }
    let outcome = match state
        .db
        .redeem_access_link(tunnel_id.to_string(), hash_token(token), session_hashes(cookie_values))
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(tunnel = tunnel_id, error = %e, "access link redemption failed");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let (session_id, expires_at) = match outcome {
        Redemption::Invalid => {
            Metrics::inc(&state.metrics.access_failures);
            return pages::unauthorized();
        }
        Redemption::Granted { session_id, expires_at } => (session_id, expires_at),
    };
    Metrics::inc(&state.metrics.access_redemptions);

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::SET_COOKIE, gate_cookie(&state.config.preview_zone, &session_id, expires_at - now()))
        .body(empty())
        .expect("valid response")
}

/// Largest login form body accepted.
const LOGIN_BODY_LIMIT: usize = 8 * 1024;
/// A login body must arrive within this long (slow bodies cannot pile up).
const LOGIN_BODY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The fields of a submitted login form.
pub struct LoginForm {
    pub to: String,
    pub username: String,
    pub password: String,
    pub next: String,
}

/// Read a login form body, bounded in size and time. `Err` is the page to show.
pub async fn read_login_form(body: hyper::body::Incoming) -> Result<LoginForm, (StatusCode, &'static str)> {
    use http_body_util::BodyExt;
    let raw = match tokio::time::timeout(LOGIN_BODY_DEADLINE, http_body_util::Limited::new(body, LOGIN_BODY_LIMIT).collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(_)) => return Err((StatusCode::PAYLOAD_TOO_LARGE, "The form was too large.")),
        Err(_) => return Err((StatusCode::REQUEST_TIMEOUT, "The form took too long to arrive.")),
    };
    let mut form = LoginForm { to: String::new(), username: String::new(), password: String::new(), next: String::new() };
    for (k, v) in url::form_urlencoded::parse(&raw) {
        match &*k {
            "to" => form.to = v.into_owned(),
            "username" => form.username = v.into_owned(),
            "password" => form.password = v.into_owned(),
            "next" => form.next = v.into_owned(),
            _ => {}
        }
    }
    form.next = safe_next(&form.next);
    Ok(form)
}

/// How a password login ended.
pub enum LoginOutcome {
    /// Signed in: the `Set-Cookie` value to send.
    Granted(String),
    /// Show the form again with this status and message.
    Retry(StatusCode, &'static str),
    RateLimited,
    /// The tunnel is not (or no longer) password-protected.
    NotPassword,
    Internal,
}

/// Check a submitted username and password against a password-mode tunnel
/// and mint a session exactly like a link redemption. Attempts share the
/// access-link rate limit.
pub async fn login(
    state: &AppState,
    peer: IpAddr,
    tunnel: &crate::db::TunnelRow,
    form: LoginForm,
    cookie_values: &[String],
) -> LoginOutcome {
    if !state.access_limiter.check(peer) {
        return LoginOutcome::RateLimited;
    }
    let (Some(user), Some(hash)) = (tunnel.access.password_user.clone(), tunnel.access.password_hash.clone()) else {
        return LoginOutcome::NotPassword;
    };
    match crate::password::verify(user, hash.clone(), form.username, form.password).await {
        crate::password::Verdict::Match => {}
        crate::password::Verdict::NoMatch => {
            Metrics::inc(&state.metrics.access_failures);
            return LoginOutcome::Retry(StatusCode::UNAUTHORIZED, "Wrong username or password.");
        }
        crate::password::Verdict::Busy => {
            return LoginOutcome::Retry(StatusCode::SERVICE_UNAVAILABLE, "The server is busy. Try again in a moment.");
        }
    }

    let ttl = state.config.limits.default_session_ttl_s as i64;
    let granted = state.db.login_grant(tunnel.id.clone(), hash, ttl, session_hashes(cookie_values)).await;
    let (session_id, expires_at) = match granted {
        Ok(Some(Redemption::Granted { session_id, expires_at })) => (session_id, expires_at),
        // The password or mode changed while we were checking.
        Ok(_) => return LoginOutcome::Retry(StatusCode::UNAUTHORIZED, "Wrong username or password."),
        Err(e) => {
            tracing::error!(tunnel = %tunnel.id, error = %e, "password login failed");
            return LoginOutcome::Internal;
        }
    };
    Metrics::inc(&state.metrics.access_redemptions);
    tracing::info!(tunnel = %tunnel.id, "password login");
    LoginOutcome::Granted(gate_cookie(&state.config.preview_zone, &session_id, expires_at - now()))
}

/// Same-host path to continue to after signing in; anything else becomes `/`.
pub fn safe_next(next: &str) -> String {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.starts_with("/__")
        && next.len() <= 2048
        && !next.chars().any(|c| c.is_control() || c == '\\');
    if ok {
        next.to_string()
    } else {
        "/".to_string()
    }
}

fn gate_cookie(zone: &str, value: &str, max_age: i64) -> String {
    format!(
        "{GATE_COOKIE}={value}; Domain={zone}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age={}",
        max_age.max(0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_gate_cookies_across_headers() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("a=1; __Secure-cockpit-gate=one"));
        h.append(header::COOKIE, HeaderValue::from_static("__Secure-cockpit-gate=two; b=2"));
        let c = split_cookies(&h);
        assert_eq!(c.values, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(c.forward.unwrap(), "a=1; b=2");
    }

    #[test]
    fn only_gate_cookie_forwards_nothing() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("__Secure-cockpit-gate=one"));
        assert!(split_cookies(&h).forward.is_none());
    }

    #[test]
    fn session_hashes_filter_dedupe_and_cap() {
        let real = "A".repeat(43);
        let values = vec!["garbage!".to_string(), real.clone(), "short".to_string(), real.clone()];
        assert_eq!(session_hashes(&values), vec![hash_token(&real)]);

        let many: Vec<String> = (0..MAX_GATE_VALUES + 10).map(|i| format!("{i:0>43}")).collect();
        assert_eq!(session_hashes(&many).len(), MAX_GATE_VALUES);
    }

    #[test]
    fn next_is_same_host_path_only() {
        assert_eq!(safe_next("/app?x=1"), "/app?x=1");
        for bad in ["", "https://evil.example", "//evil.example", "/\\evil.example", "/__access/x", "/a\\b", "app"] {
            assert_eq!(safe_next(bad), "/", "{bad}");
        }
    }

    #[test]
    fn cookie_attributes() {
        let c = gate_cookie("previews.example.com", "abc", 60);
        assert_eq!(
            c,
            "__Secure-cockpit-gate=abc; Domain=previews.example.com; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=60"
        );
    }
}
