//! Header rewriting between visitors and origins, and preview-host parsing.

use cockpit_tunnel_protocol::GATE_COOKIE;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};

use crate::tokens::is_valid_tunnel_id;
use crate::util::header_str;

/// Connection-specific headers (RFC 9110 §7.6.1 plus legacy ones). HTTP/2
/// responses must not carry any of them (hyper rejects them).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Parse a preview label `"{port}-{id}"`. Ports are canonical decimal
/// (no leading zeros) so every port has exactly one host name.
pub fn parse_label(label: &str) -> Option<(u16, &str)> {
    let (p, id) = label.split_once('-')?;
    if p.is_empty() || p.len() > 5 || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = p.parse().ok()?;
    is_valid_tunnel_id(id).then_some((port, id))
}

/// If `origin` is `https://{p}-{tunnel_id}.{zone}` (same tunnel, any port),
/// return `p`.
pub fn same_tunnel_origin_port(origin: &str, zone: &str, tunnel_id: &str) -> Option<u16> {
    let rest = strip_prefix_ci(origin, "https://")?;
    let host = rest.strip_suffix(":443").unwrap_or(rest).to_ascii_lowercase();
    let label = host.strip_suffix(zone)?.strip_suffix('.')?;
    let (port, id) = parse_label(label)?;
    (id == tunnel_id).then_some(port)
}

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in &named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// `host_header = rewrite`: make same-tunnel `Origin`/`Referer` look like the
/// app's own local origin so dev-server origin checks pass.
pub fn rewrite_request_origin(headers: &mut HeaderMap, zone: &str, tunnel_id: &str) {
    for name in [header::ORIGIN, header::REFERER] {
        let mapped = header_str(headers.get(&name)).and_then(|v| public_to_local(v, zone, tunnel_id));
        if let Some(v) = mapped.and_then(|m| HeaderValue::from_str(&m).ok()) {
            headers.insert(name, v);
        }
    }
}

fn public_to_local(url: &str, zone: &str, tunnel_id: &str) -> Option<String> {
    let rest = strip_prefix_ci(url, "https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let port = same_tunnel_origin_port(&format!("https://{authority}"), zone, tunnel_id)?;
    Some(format!("http://localhost:{port}{tail}"))
}

pub struct ResponseCtx<'a> {
    pub zone: &'a str,
    pub tunnel_id: &'a str,
    /// Allowed iframe parents (`*` = any site); see `Config::frame_ancestors`.
    pub frame_ancestors: &'a [String],
}

/// Rewrite origin response headers for the visitor. `script_hash` is the
/// base64 SHA-256 of an injected inline script, if one is being injected.
pub fn rewrite_response(headers: &mut HeaderMap, ctx: &ResponseCtx<'_>, script_hash: Option<&str>) {
    strip_hop_by_hop(headers);
    rewrite_set_cookies(headers);

    for name in [header::LOCATION, header::ACCESS_CONTROL_ALLOW_ORIGIN] {
        let mapped = header_str(headers.get(&name)).and_then(|v| local_to_public(v, ctx));
        if let Some(v) = mapped.and_then(|m| HeaderValue::from_str(&m).ok()) {
            headers.insert(name, v);
        }
    }

    headers.remove(header::X_FRAME_OPTIONS);
    rewrite_csp_headers(headers, ctx.frame_ancestors, script_hash);

    let corp = HeaderName::from_static("cross-origin-resource-policy");
    if header_str(headers.get(&corp)).is_some_and(|v| v.trim().eq_ignore_ascii_case("same-origin")) {
        headers.insert(corp, HeaderValue::from_static("same-site"));
    }

    rewrite_clear_site_data(headers);
}

/// `Clear-Site-Data: "cookies"` (or `"*"`) clears cookies for the whole
/// registrable domain: the gate cookie and the harness app's session. Keep
/// only the directives scoped to this origin (cache, storage, ...).
fn rewrite_clear_site_data(headers: &mut HeaderMap) {
    let name = HeaderName::from_static("clear-site-data");
    if !headers.contains_key(&name) {
        return;
    }
    let kept: Vec<String> = headers
        .get_all(&name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|d| {
            let bare = d.trim_matches('"');
            !d.is_empty() && !bare.eq_ignore_ascii_case("cookies") && bare != "*"
        })
        .map(str::to_string)
        .collect();
    headers.remove(&name);
    if kept.is_empty() {
        return;
    }
    if let Ok(v) = HeaderValue::from_str(&kept.join(", ")) {
        headers.insert(name, v);
    }
}

/// Keep multiple `Set-Cookie`s, drop any `Domain` attribute (cookies become
/// host-only on the public name), and drop cookies that shadow the gate cookie.
fn rewrite_set_cookies(headers: &mut HeaderMap) {
    if !headers.contains_key(header::SET_COOKIE) {
        return;
    }
    let cookies: Vec<HeaderValue> = headers.get_all(header::SET_COOKIE).iter().filter_map(rewrite_set_cookie).collect();
    headers.remove(header::SET_COOKIE);
    for c in cookies {
        headers.append(header::SET_COOKIE, c);
    }
}

/// `None` drops the cookie. Works on bytes: cookie values may contain obs-text.
fn rewrite_set_cookie(value: &HeaderValue) -> Option<HeaderValue> {
    let mut parts = value.as_bytes().split(|&b| b == b';');
    let first = parts.next().unwrap_or_default();
    if attr_name(first).eq_ignore_ascii_case(GATE_COOKIE.as_bytes()) {
        return None;
    }
    let attrs: Vec<&[u8]> = parts.collect();
    if !attrs.iter().any(|a| attr_name(a).eq_ignore_ascii_case(b"domain")) {
        return Some(value.clone());
    }
    let mut out = first.to_vec();
    for a in attrs.iter().filter(|a| !attr_name(a).eq_ignore_ascii_case(b"domain")) {
        out.push(b';');
        out.extend_from_slice(a);
    }
    HeaderValue::from_bytes(&out).ok()
}

fn attr_name(part: &[u8]) -> &[u8] {
    part.split(|&b| b == b'=').next().unwrap_or_default().trim_ascii()
}

/// Map an origin-side absolute URL to the public one:
/// `http(s)://(localhost|127.0.0.1|[::1]):{p}/…` → `https://{p}-{id}.{zone}/…`,
/// and `http://` links to this tunnel's preview hosts → `https://`.
fn local_to_public(url: &str, ctx: &ResponseCtx<'_>) -> Option<String> {
    let (https, rest) = match strip_prefix_ci(url, "http://") {
        Some(r) => (false, r),
        None => (true, strip_prefix_ci(url, "https://")?),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return None;
    }
    let (host, port) = split_host_port(authority);
    let host = host.to_ascii_lowercase();
    if matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
        let p: u16 = port?.parse().ok().filter(|p| *p != 0)?;
        return Some(format!("https://{p}-{}.{}{tail}", ctx.tunnel_id, ctx.zone));
    }
    if https || port.is_some_and(|p| p != "80") {
        return None;
    }
    let label = host.strip_suffix(ctx.zone)?.strip_suffix('.')?;
    let (_, id) = parse_label(label)?;
    (id == ctx.tunnel_id).then(|| format!("https://{host}{tail}"))
}

fn split_host_port(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(i) => (&authority[..=i], authority[i + 1..].strip_prefix(':')),
            None => (authority, None),
        };
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let n = prefix.len();
    (s.len() >= n && s.as_bytes()[..n].eq_ignore_ascii_case(prefix.as_bytes())).then(|| &s[n..])
}

// ------------------------------------------------------------------- CSP

/// Rewrite every enforced CSP header. `Content-Security-Policy-Report-Only`
/// is left alone: it never blocks anything.
fn rewrite_csp_headers(headers: &mut HeaderMap, frame_ancestors: &[String], script_hash: Option<&str>) {
    let mut app_sets_framing = false;
    if headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        let values: Vec<HeaderValue> = headers.get_all(header::CONTENT_SECURITY_POLICY).iter().cloned().collect();
        headers.remove(header::CONTENT_SECURITY_POLICY);
        for v in values {
            let rewritten = v.to_str().ok().and_then(|s| {
                let (out, framing) = rewrite_csp(s, frame_ancestors, script_hash);
                app_sets_framing |= framing;
                HeaderValue::from_str(&out).ok()
            });
            headers.append(header::CONTENT_SECURITY_POLICY, rewritten.unwrap_or(v));
        }
    }
    // A restricted parent list is enforced even when the app says nothing about
    // framing: a separate policy only adds this one restriction.
    if !app_sets_framing && !allows_any_parent(frame_ancestors) {
        if let Ok(v) = HeaderValue::from_str(&format!("frame-ancestors {}", frame_sources(frame_ancestors).join(" "))) {
            headers.append(header::CONTENT_SECURITY_POLICY, v);
        }
    }
}

fn allows_any_parent(frame_ancestors: &[String]) -> bool {
    frame_ancestors.is_empty() || frame_ancestors.iter().any(|s| s == "*")
}

/// `'self'` plus the configured parents (or just `*`).
fn frame_sources(frame_ancestors: &[String]) -> Vec<String> {
    if allows_any_parent(frame_ancestors) {
        return vec!["*".to_string()];
    }
    let mut out = vec!["'self'".to_string()];
    for s in frame_ancestors {
        if !has(&out, s) {
            out.push(s.clone());
        }
    }
    out
}

/// One header value may hold several comma-separated policies; each is
/// enforced independently, so each is rewritten independently.
#[cfg(test)]
fn rewrite_csp_value(value: &str, frame_ancestors: &[String], script_hash: Option<&str>) -> String {
    rewrite_csp(value, frame_ancestors, script_hash).0
}

/// Also reports whether any policy had a `frame-ancestors` directive.
fn rewrite_csp(value: &str, frame_ancestors: &[String], script_hash: Option<&str>) -> (String, bool) {
    let mut framing = false;
    let out = value
        .split(',')
        .map(|p| {
            let (policy, f) = rewrite_policy(p.trim(), frame_ancestors, script_hash);
            framing |= f;
            policy
        })
        .collect::<Vec<_>>()
        .join(", ");
    (out, framing)
}

type Directive = (String, Vec<String>);

fn rewrite_policy(policy: &str, frame_ancestors: &[String], script_hash: Option<&str>) -> (String, bool) {
    let mut dirs: Vec<Directive> = policy
        .split(';')
        .filter_map(|d| {
            let mut toks = d.split_ascii_whitespace();
            let name = toks.next()?.to_ascii_lowercase();
            Some((name, toks.map(str::to_string).collect()))
        })
        .collect();

    let mut changed = false;
    let framing = first(&dirs, "frame-ancestors");
    if let Some(i) = framing {
        // The configured parents replace the app's own list: a dev server's
        // `'self'`/`'none'` would otherwise block every harness iframe.
        dirs[i].1 = frame_sources(frame_ancestors);
        changed = true;
    }
    if let Some(hash) = script_hash {
        changed |= add_script_hash(&mut dirs, hash);
    }
    if !changed {
        return (policy.to_string(), false);
    }
    let out = dirs
        .iter()
        .map(|(n, s)| if s.is_empty() { n.clone() } else { format!("{n} {}", s.join(" ")) })
        .collect::<Vec<_>>()
        .join("; ");
    (out, framing.is_some())
}

/// Browsers honour only the first occurrence of a directive.
fn first(dirs: &[Directive], name: &str) -> Option<usize> {
    dirs.iter().position(|(n, _)| n == name)
}

fn has(src: &[String], token: &str) -> bool {
    src.iter().any(|s| s.eq_ignore_ascii_case(token))
}

/// CSP3 "allows all inline behavior": `'unsafe-inline'` without any nonce,
/// hash, or `'strict-dynamic'`. Adding a hash to such a list would switch
/// `'unsafe-inline'` off for the app's other inline scripts.
fn allows_all_inline(src: &[String]) -> bool {
    let lower = |s: &String| s.to_ascii_lowercase();
    has(src, "'unsafe-inline'")
        && !src.iter().map(lower).any(|s| {
            s.starts_with("'nonce-")
                || s.starts_with("'sha256-")
                || s.starts_with("'sha384-")
                || s.starts_with("'sha512-")
                || s == "'strict-dynamic'"
        })
}

/// Permit exactly the injected script. Returns whether the policy changed.
fn add_script_hash(dirs: &mut Vec<Directive>, hash: &str) -> bool {
    let source = format!("'sha256-{hash}'");
    let targets: Vec<usize> = ["script-src", "script-src-elem"].iter().filter_map(|n| first(dirs, n)).collect();

    if targets.is_empty() {
        let Some(d) = first(dirs, "default-src") else {
            return false;
        };
        if allows_all_inline(&dirs[d].1) {
            return false;
        }
        // Scripts fall back to default-src; an explicit copy plus the hash
        // keeps every other script restriction identical.
        let mut copy: Vec<String> = dirs[d].1.iter().filter(|s| !s.eq_ignore_ascii_case("'none'")).cloned().collect();
        copy.push(source);
        dirs.push(("script-src".to_string(), copy));
        return true;
    }

    let mut changed = false;
    for i in targets {
        let src = &mut dirs[i].1;
        if allows_all_inline(src) || has(src, &source) {
            continue;
        }
        // `'none'` is only meaningful alone; with the hash it means "only this script".
        src.retain(|s| !s.eq_ignore_ascii_case("'none'"));
        src.push(source.clone());
        changed = true;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    static APP_LIST: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| vec!["https://app.example.com".to_string()]);
    static ANY_LIST: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| vec!["*".to_string()]);

    fn csp_after(app_csp: Option<&str>, parents: &[String]) -> Vec<String> {
        let mut h = HeaderMap::new();
        if let Some(v) = app_csp {
            h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(v).unwrap());
        }
        rewrite_csp_headers(&mut h, parents, None);
        h.get_all(header::CONTENT_SECURITY_POLICY).iter().map(|v| v.to_str().unwrap().to_string()).collect()
    }

    #[test]
    fn any_parent_replaces_app_framing_and_adds_nothing() {
        assert_eq!(
            csp_after(Some("default-src 'self'; frame-ancestors 'self'"), &ANY_LIST),
            vec!["default-src 'self'; frame-ancestors *"]
        );
        assert!(csp_after(None, &ANY_LIST).is_empty());
        assert!(csp_after(None, &[]).is_empty());
    }

    #[test]
    fn restricted_parents_are_enforced_without_app_csp() {
        assert_eq!(csp_after(None, &APP_LIST), vec!["frame-ancestors 'self' https://app.example.com"]);
        // An app policy without framing keeps its own header; the restriction is a second policy.
        assert_eq!(
            csp_after(Some("script-src 'self'"), &APP_LIST),
            vec!["script-src 'self'", "frame-ancestors 'self' https://app.example.com"]
        );
        // An app policy with framing is rewritten in place, not duplicated.
        assert_eq!(csp_after(Some("frame-ancestors 'none'"), &APP_LIST), vec!["frame-ancestors 'self' https://app.example.com"]);
    }

    const ZONE: &str = "previews.example.com";
    const ID: &str = "abcdefghij";

    fn ctx() -> ResponseCtx<'static> {
        ResponseCtx { zone: ZONE, tunnel_id: ID, frame_ancestors: &APP_LIST }
    }

    #[test]
    fn labels() {
        assert_eq!(parse_label("3000-abcdefghij"), Some((3000, "abcdefghij")));
        assert_eq!(parse_label("03000-abcdefghij"), None);
        assert_eq!(parse_label("0-abcdefghij"), None);
        assert_eq!(parse_label("70000-abcdefghij"), None);
        assert_eq!(parse_label("3000-ABCDEFGHIJ"), None);
        assert_eq!(parse_label("abcdefghij"), None);
    }

    #[test]
    fn same_tunnel_origin() {
        assert_eq!(same_tunnel_origin_port("https://8080-abcdefghij.previews.example.com", ZONE, ID), Some(8080));
        assert_eq!(same_tunnel_origin_port("https://8080-abcdefghij.previews.example.com:443", ZONE, ID), Some(8080));
        assert_eq!(same_tunnel_origin_port("https://8080-zzzzzzzzzz.previews.example.com", ZONE, ID), None);
        assert_eq!(same_tunnel_origin_port("http://8080-abcdefghij.previews.example.com", ZONE, ID), None);
        assert_eq!(same_tunnel_origin_port("https://8080-abcdefghij.evil.com", ZONE, ID), None);
    }

    #[test]
    fn request_origin_rewrite() {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, HeaderValue::from_static("https://5173-abcdefghij.previews.example.com"));
        h.insert(header::REFERER, HeaderValue::from_static("https://3000-abcdefghij.previews.example.com/a?b"));
        rewrite_request_origin(&mut h, ZONE, ID);
        assert_eq!(h[header::ORIGIN], "http://localhost:5173");
        assert_eq!(h[header::REFERER], "http://localhost:3000/a?b");
    }

    #[test]
    fn location_rewrite() {
        let c = ctx();
        assert_eq!(
            local_to_public("http://localhost:3000/login", &c).as_deref(),
            Some("https://3000-abcdefghij.previews.example.com/login")
        );
        assert_eq!(
            local_to_public("http://[::1]:8080", &c).as_deref(),
            Some("https://8080-abcdefghij.previews.example.com")
        );
        assert_eq!(
            local_to_public("http://3000-abcdefghij.previews.example.com/x", &c).as_deref(),
            Some("https://3000-abcdefghij.previews.example.com/x")
        );
        assert_eq!(local_to_public("https://example.org/", &c), None);
        assert_eq!(local_to_public("/relative", &c), None);
    }

    #[test]
    fn set_cookie_rewrite() {
        let mut h = HeaderMap::new();
        h.append(header::SET_COOKIE, HeaderValue::from_static("x=1; Domain=.example.com; Path=/"));
        h.append(header::SET_COOKIE, HeaderValue::from_static("session=abc; HttpOnly"));
        h.append(header::SET_COOKIE, HeaderValue::from_static("__Secure-cockpit-gate=evil; Path=/"));
        rewrite_response(&mut h, &ctx(), None);
        let v: Vec<_> = h.get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert_eq!(v, vec!["x=1; Path=/".to_string(), "session=abc; HttpOnly".to_string()]);
    }

    #[test]
    fn clear_site_data_keeps_origin_scoped_directives() {
        let mut h = HeaderMap::new();
        h.insert("clear-site-data", HeaderValue::from_static("\"cache\", \"cookies\", \"storage\""));
        rewrite_response(&mut h, &ctx(), None);
        assert_eq!(h["clear-site-data"], "\"cache\", \"storage\"");

        let mut h = HeaderMap::new();
        h.insert("clear-site-data", HeaderValue::from_static("\"*\""));
        rewrite_response(&mut h, &ctx(), None);
        assert!(!h.contains_key("clear-site-data"));
    }

    #[test]
    fn frame_ancestors_merge() {
        let out = rewrite_csp_value("default-src 'self'; frame-ancestors 'none'", &APP_LIST, None);
        assert_eq!(out, "default-src 'self'; frame-ancestors 'self' https://app.example.com");
    }

    #[test]
    fn script_hash_added() {
        let out = rewrite_csp_value("script-src 'self'", &ANY_LIST, Some("AAA="));
        assert_eq!(out, "script-src 'self' 'sha256-AAA='");
        let out = rewrite_csp_value("default-src 'self' 'none'", &ANY_LIST, Some("AAA="));
        assert_eq!(out, "default-src 'self' 'none'; script-src 'self' 'sha256-AAA='");
    }

    #[test]
    fn unsafe_inline_untouched() {
        let p = "script-src 'self' 'unsafe-inline'";
        assert_eq!(rewrite_csp_value(p, &ANY_LIST, Some("AAA=")), p);
        let out = rewrite_csp_value("script-src 'unsafe-inline' 'nonce-xyz'", &ANY_LIST, Some("AAA="));
        assert_eq!(out, "script-src 'unsafe-inline' 'nonce-xyz' 'sha256-AAA='");
    }

    #[test]
    fn multiple_policies() {
        let out = rewrite_csp_value("script-src 'self', img-src *", &ANY_LIST, Some("AAA="));
        assert_eq!(out, "script-src 'self' 'sha256-AAA=', img-src *");
    }
}
