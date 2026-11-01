//! Visitor gate: the parent-domain session cookie and `/__access/{token}`.

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

/// `/__access/{token}`: validate, mint a fresh session carrying the new grant
/// and those of any valid presented session, set the cookie, and redirect to
/// `/` so the token never appears in a later URL.
pub async fn redeem(
    state: &AppState,
    peer: IpAddr,
    tunnel_id: &str,
    token: &str,
    cookie_values: &[String],
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
        .header(header::LOCATION, "/")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::SET_COOKIE, gate_cookie(&state.config.preview_zone, &session_id, expires_at - now()))
        .body(empty())
        .expect("valid response")
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
    fn cookie_attributes() {
        let c = gate_cookie("previews.example.com", "abc", 60);
        assert_eq!(
            c,
            "__Secure-cockpit-gate=abc; Domain=previews.example.com; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=60"
        );
    }
}
