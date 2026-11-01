//! Management API on `api_host`: bearer admin token, JSON, OpenAPI via utoipa.
//!
//! The axum router is built once; each request runs it through
//! `tower::ServiceExt::oneshot` with the shared state attached.

use std::sync::{Arc, LazyLock};

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Path, Request as AxumRequest, State};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use cockpit_tunnel_protocol::{
    CloseReason, IceServer, ACCESS_TOKEN_PREFIX, ADMIN_TOKEN_PREFIX, CLIENT_TOKEN_PREFIX, ENROLL_CODE_PREFIX, TUNNEL_TOKEN_PREFIX,
};
use http::request::Parts;
use http::{header, HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::clients;
use crate::db::{Access, AccessMode, ClientRow, DeleteOutcome, HostHeaderMode, NewAccessLink, NewTunnel, TunnelPatch, TunnelRow};
use crate::password;
use crate::ice;
use crate::state::AppState;
use crate::tokens::{self, now};
use crate::util::{full, json_response, Body};

const MIN_TUNNEL_TTL_S: u64 = 60;
const MIN_LINK_TTL_S: u64 = 30;
const MIN_ICE_TTL_S: u64 = 60;
const MAX_LABEL_LEN: usize = 200;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const ID_ATTEMPTS: usize = 16;
/// TURN username subject for credentials minted through the API.
const API_SUBJECT: &str = "api";

static ROUTER: LazyLock<Router<Arc<AppState>>> = LazyLock::new(build_router);

pub async fn handle(state: Arc<AppState>, req: Request<Incoming>) -> Response<Body> {
    let router: Router = ROUTER.clone().with_state(state);
    let resp = match router.oneshot(req.map(axum::body::Body::new)).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    };
    // axum's body is `!Sync` and `util::Body` requires `Sync`. API responses
    // are small JSON documents, so collecting them is cheaper than a wrapper.
    let (parts, body) = resp.into_parts();
    match body.collect().await {
        Ok(collected) => Response::from_parts(parts, full(collected.to_bytes())),
        Err(e) => {
            tracing::error!(error = %e, "collecting api response failed");
            let body = ErrorBody {
                error: ErrorDetail { code: "internal".into(), message: "internal server error".into() },
            };
            json_response(StatusCode::INTERNAL_SERVER_ERROR, &body)
        }
    }
}

fn build_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/openapi.json", get(openapi_json))
        .route("/v1/tunnels", post(create_tunnel).get(list_tunnels))
        .route("/v1/tunnels/{id}", get(get_tunnel).patch(patch_tunnel).delete(delete_tunnel))
        .route("/v1/tunnels/{id}/access-links", post(create_access_link))
        .route("/v1/access-links/{id}", delete(delete_access_link))
        .route("/v1/tunnels/{id}/turn-credentials", post(turn_credentials))
        .route("/v1/clients", post(create_client).get(list_clients))
        .route("/v1/clients/enroll", post(enroll_client))
        .route("/v1/clients/{name}", delete(delete_client))
        .fallback(fallback)
}

// ------------------------------------------------------------------ errors

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorDetail {
    /// Machine-readable code, e.g. `not_found`, `tunnel_expired`, `validation`.
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid token")
    }

    fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", format!("{what} not found"))
    }

    fn expired() -> Self {
        Self::new(StatusCode::CONFLICT, "tunnel_expired", "tunnel has expired or was deleted")
    }

    fn validation(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "validation", message)
    }

    fn internal(e: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{e:#}"), "api request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal server error")
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> AxumResponse {
        let body = ErrorBody { error: ErrorDetail { code: self.code.to_string(), message: self.message } };
        let mut resp = (self.status, Json(body)).into_response();
        resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

type ApiResult<T> = Result<T, ApiError>;

// -------------------------------------------------------------- extractors

/// Proof that the request carried the admin token.
pub struct Admin;

/// Who is calling a tunnel endpoint: the admin token (every tunnel) or an
/// enrolled client's token (only tunnels that client created).
#[derive(Debug, Clone)]
pub enum Caller {
    Admin,
    Client { id: String, name: String },
}

impl Caller {
    fn client_id(&self) -> Option<&str> {
        match self {
            Self::Admin => None,
            Self::Client { id, .. } => Some(id),
        }
    }

    fn may_use(&self, row: &TunnelRow) -> bool {
        match self {
            Self::Admin => true,
            Self::Client { id, .. } => row.client_id.as_deref() == Some(id.as_str()),
        }
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or_else(ApiError::unauthorized)?;
        if token.starts_with(ADMIN_TOKEN_PREFIX) {
            return if tokens::hashes_equal(&tokens::hash_token(token), &state.config.admin_token_hash) {
                Ok(Self::Admin)
            } else {
                Err(ApiError::unauthorized())
            };
        }
        if token.starts_with(CLIENT_TOKEN_PREFIX) && token.len() <= 256 {
            if let Some((id, name)) = state.db.client_by_token_hash(tokens::hash_token(token)).await? {
                return Ok(Self::Client { id, name });
            }
        }
        Err(ApiError::unauthorized())
    }
}

/// Peer address of the API request (set by the listener).
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub std::net::SocketAddr);

impl FromRequestParts<Arc<AppState>> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).filter(|t| t.starts_with(ADMIN_TOKEN_PREFIX)).ok_or_else(ApiError::unauthorized)?;
        if tokens::hashes_equal(&tokens::hash_token(token), &state.config.admin_token_hash) {
            Ok(Admin)
        } else {
            Err(ApiError::unauthorized())
        }
    }
}

/// `Json<T>` whose rejections use the API error shape (422).
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: AxumRequest, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rejection) => Err(json_rejection(rejection)),
        }
    }
}

fn json_rejection(rejection: JsonRejection) -> ApiError {
    ApiError::validation(rejection.body_text())
}

/// Parse an optional JSON body: empty means `T::default()`.
fn optional_json<T: DeserializeOwned + Default>(body: &Bytes) -> ApiResult<T> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|e| ApiError::validation(format!("invalid JSON body: {e}")))
}

// ----------------------------------------------------------------- schemas

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTunnelRequest {
    #[serde(default)]
    pub label: Option<String>,
    /// Lifetime in seconds (60 ..= server max).
    pub ttl_s: u64,
    /// Ports the sandbox may expose (default 8).
    #[serde(default)]
    pub max_ports: Option<u16>,
    #[serde(default)]
    pub host_header: Option<HostHeaderMode>,
    /// Inject TURN config into preview HTML (default true).
    #[serde(default)]
    pub inject_ice: Option<bool>,
    /// Opaque JSON stored with the tunnel.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
    /// Who may open previews (default: access links only).
    #[serde(default)]
    pub access: Option<AccessRequest>,
}

/// Access setting. Access links work in every mode.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    /// `link`: access links only. `password`: links, or the username and
    /// password on the preview's login page. `public`: anyone with the URL.
    pub mode: AccessMode,
    /// Password mode only (1..=64 characters). On PATCH, omitted keeps the current one.
    #[serde(default)]
    pub username: Option<String>,
    /// Password mode only (8..=256 characters); never returned. On PATCH,
    /// omitted keeps the current one. A new password signs out everyone who
    /// logged in with the old one.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccessView {
    pub mode: AccessMode,
    /// Set in password mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateTunnelResponse {
    pub id: String,
    /// Returned once; only its hash is stored.
    pub tunnel_token: String,
    /// e.g. `{port}-ab12cd3efg.previews.example.com`
    pub host_template: String,
    /// Unix seconds.
    pub expires_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchTunnelRequest {
    /// New lifetime from now, in seconds.
    #[serde(default)]
    pub ttl_s: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub host_header: Option<HostHeaderMode>,
    #[serde(default)]
    pub inject_ice: Option<bool>,
    /// Replace the access setting.
    #[serde(default)]
    pub access: Option<AccessRequest>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PortView {
    pub port: u16,
    pub host: String,
    pub connected: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TunnelView {
    pub id: String,
    pub label: Option<String>,
    pub access: AccessView,
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
    /// A control connection is live.
    pub connected: bool,
    /// Unix seconds when the live control connection was established.
    pub connected_since: Option<i64>,
    /// TTL elapsed; the purge job will tombstone it.
    pub expired: bool,
    /// Ports declared on the live connection (empty while disconnected).
    pub ports: Vec<PortView>,
    pub host_template: String,
    pub max_ports: u16,
    pub host_header: HostHeaderMode,
    pub inject_ice: bool,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TunnelList {
    pub tunnels: Vec<TunnelView>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAccessLinkRequest {
    /// Link lifetime in seconds (30 ..= tunnel remaining lifetime).
    pub ttl_s: u64,
    /// Default true.
    #[serde(default)]
    pub single_use: Option<bool>,
    #[serde(default)]
    pub label: Option<String>,
    /// Gate session lifetime (default 12h), capped by the tunnel's expiry.
    #[serde(default)]
    pub session_ttl_s: Option<u64>,
    /// Port whose preview the link opens. Default: the lowest connected port
    /// at mint time, else the lowest connected port when the link is opened.
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccessLinkResponse {
    pub id: String,
    /// The link to hand out: `https://<zone>/__access/{port}-{id}/ctacc_…`.
    /// It signs the visitor in on the zone host (which no preview controls)
    /// and redirects to the preview.
    pub url: String,
    /// Legacy: `/__access/ctacc_…` on any `{port}-{id}` host of the tunnel,
    /// which redirects to the zone host. Prefer `url`.
    pub url_path: String,
    pub expires_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnCredentialsRequest {
    /// Default: the browser TTL (1h); max: the sandbox TTL (24h).
    #[serde(default)]
    pub ttl_s: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TurnCredentialsResponse {
    #[serde(rename = "iceServers")]
    #[schema(value_type = Vec<Object>)]
    pub ice_servers: Vec<IceServer>,
    pub expires_at: u64,
    pub ttl_s: u64,
}

#[derive(OpenApi)]
#[openapi(
    info(title = "cockpit-tunnel management API"),
    paths(
        healthz,
        create_tunnel,
        list_tunnels,
        get_tunnel,
        patch_tunnel,
        delete_tunnel,
        create_access_link,
        delete_access_link,
        turn_credentials,
        create_client,
        list_clients,
        delete_client,
        enroll_client,
    ),
    components(schemas(
        ErrorBody,
        ErrorDetail,
        CreateTunnelRequest,
        CreateTunnelResponse,
        AccessRequest,
        AccessView,
        AccessMode,
        CreateClientRequest,
        CreateClientResponse,
        ClientView,
        ClientList,
        EnrollRequest,
        EnrollResponse,
        PatchTunnelRequest,
        PortView,
        TunnelView,
        TunnelList,
        CreateAccessLinkRequest,
        AccessLinkResponse,
        TurnCredentialsRequest,
        TurnCredentialsResponse,
        HostHeaderMode,
    )),
    modifiers(&BearerAuth),
    security(("admin" = []))
)]
struct ApiDoc;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme("admin", SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)));
    }
}

// ---------------------------------------------------------------- handlers

#[utoipa::path(get, path = "/healthz", security(()), responses((status = 200, description = "Alive", body = String)))]
async fn healthz() -> &'static str {
    "ok"
}

async fn openapi_json(_admin: Admin) -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

async fn fallback() -> ApiError {
    ApiError::not_found("route")
}

#[utoipa::path(
    post,
    path = "/v1/tunnels",
    request_body = CreateTunnelRequest,
    responses(
        (status = 201, description = "Tunnel created", body = CreateTunnelResponse),
        (status = 401, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn create_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    ApiJson(req): ApiJson<CreateTunnelRequest>,
) -> ApiResult<(StatusCode, Json<CreateTunnelResponse>)> {
    let limits = &state.config.limits;
    validate_tunnel_ttl(req.ttl_s, limits.max_tunnel_ttl_s)?;
    let max_ports = req.max_ports.unwrap_or(limits.default_max_ports);
    if !(1..=limits.hard_max_ports).contains(&max_ports) {
        return Err(ApiError::validation(format!("max_ports must be within 1..={}", limits.hard_max_ports)));
    }
    validate_label(req.label.as_deref())?;
    if let Some(m) = &req.metadata {
        if m.to_string().len() > MAX_METADATA_BYTES {
            return Err(ApiError::validation(format!("metadata must be at most {MAX_METADATA_BYTES} bytes")));
        }
    }

    let access = match req.access {
        Some(a) => build_access(a, None).await?,
        None => Access::default(),
    };
    let mode = access.mode;

    let id = fresh_tunnel_id(&state).await?;
    let token = tokens::random_token(TUNNEL_TOKEN_PREFIX);
    let row = state
        .db
        .create_tunnel(NewTunnel {
            id,
            token_hash: tokens::hash_token(&token),
            label: req.label,
            metadata: req.metadata,
            max_ports,
            host_header: req.host_header.unwrap_or(HostHeaderMode::Rewrite),
            inject_ice: req.inject_ice.unwrap_or(true),
            expires_at: now() + req.ttl_s as i64,
            access,
            client_id: caller.client_id().map(str::to_string),
        })
        .await?
        // The client was deleted while this request was in flight.
        .ok_or_else(ApiError::unauthorized)?;
    // A cached negative lookup for this id (e.g. a probe) must not hide the new tunnel.
    state.invalidate_tunnel(&row.id);
    let by = match &caller {
        Caller::Admin => "admin",
        Caller::Client { name, .. } => name.as_str(),
    };
    tracing::info!(tunnel = %row.id, by, max_ports, access = mode.as_str(), expires_at = row.expires_at, "tunnel created");

    Ok((
        StatusCode::CREATED,
        Json(CreateTunnelResponse {
            host_template: state.config.host_template(&row.id),
            id: row.id,
            tunnel_token: token,
            expires_at: row.expires_at,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/v1/tunnels",
    responses((status = 200, body = TunnelList), (status = 401, body = ErrorBody))
)]
async fn list_tunnels(State(state): State<Arc<AppState>>, caller: Caller) -> ApiResult<Json<TunnelList>> {
    let rows = match caller.client_id() {
        None => state.db.list_tunnels().await?,
        Some(id) => state.db.list_client_tunnels(id.to_string()).await?,
    };
    let tunnels = rows.iter().map(|row| tunnel_view(&state, row)).collect();
    Ok(Json(TunnelList { tunnels }))
}

#[utoipa::path(
    get,
    path = "/v1/tunnels/{id}",
    params(("id" = String, Path, description = "Tunnel id")),
    responses((status = 200, body = TunnelView), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody))
)]
async fn get_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Json<TunnelView>> {
    let row = find_tunnel(&state, &caller, &id).await?;
    Ok(Json(tunnel_view(&state, &row)))
}

#[utoipa::path(
    patch,
    path = "/v1/tunnels/{id}",
    params(("id" = String, Path, description = "Tunnel id")),
    request_body = PatchTunnelRequest,
    responses(
        (status = 200, body = TunnelView),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn patch_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<PatchTunnelRequest>,
) -> ApiResult<Json<TunnelView>> {
    if let Some(ttl) = req.ttl_s {
        validate_tunnel_ttl(ttl, state.config.limits.max_tunnel_ttl_s)?;
    }
    validate_label(req.label.as_deref())?;
    // Expiry is revocation: an expired tunnel cannot be revived by extending it.
    let current = active_tunnel(&state, &caller, &id).await?;
    let access = match req.access {
        Some(a) => Some(build_access(a, Some(&current.access)).await?),
        None => None,
    };
    let access_changed = access.as_ref().is_some_and(|a| *a != current.access);

    let patch = TunnelPatch {
        expires_at: req.ttl_s.map(|ttl| now() + ttl as i64),
        label: req.label,
        host_header: req.host_header,
        inject_ice: req.inject_ice,
        access,
    };
    let row = state.db.update_tunnel(id.clone(), patch).await?;
    state.invalidate_tunnel(&id);
    if access_changed {
        // A password change may have revoked sessions.
        state.invalidate_sessions();
        tracing::info!(tunnel = %id, access = row.as_ref().map(|r| r.access.mode.as_str()), "tunnel access changed");
    }
    let row = row.ok_or_else(|| ApiError::not_found("tunnel"))?;
    Ok(Json(tunnel_view(&state, &row)))
}

#[utoipa::path(
    delete,
    path = "/v1/tunnels/{id}",
    params(("id" = String, Path, description = "Tunnel id")),
    responses(
        (status = 204, description = "Deleted (or already deleted)"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
async fn delete_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !tokens::is_valid_tunnel_id(&id) {
        return Err(ApiError::not_found("tunnel"));
    }
    if matches!(caller, Caller::Client { .. }) {
        // Clients may delete only their own live rows (tombstones have no owner).
        find_tunnel(&state, &caller, &id).await?;
    }
    match state.delete_tunnel(&id, CloseReason::Deleted).await? {
        DeleteOutcome::Deleted => {
            tracing::info!(tunnel = %id, "tunnel deleted");
            Ok(StatusCode::NO_CONTENT)
        }
        DeleteOutcome::AlreadyTombstoned => Ok(StatusCode::NO_CONTENT),
        DeleteOutcome::NotFound => Err(ApiError::not_found("tunnel")),
    }
}

#[utoipa::path(
    post,
    path = "/v1/tunnels/{id}/access-links",
    params(("id" = String, Path, description = "Tunnel id")),
    request_body = CreateAccessLinkRequest,
    responses(
        (status = 201, body = AccessLinkResponse),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn create_access_link(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<CreateAccessLinkRequest>,
) -> ApiResult<(StatusCode, Json<AccessLinkResponse>)> {
    let tunnel = active_tunnel(&state, &caller, &id).await?;
    let t = now();
    let remaining = (tunnel.expires_at - t).max(0) as u64;
    if req.ttl_s < MIN_LINK_TTL_S || req.ttl_s > remaining {
        return Err(ApiError::validation(format!(
            "ttl_s must be within {MIN_LINK_TTL_S}..={remaining} (the tunnel's remaining lifetime)"
        )));
    }
    let session_ttl_s = match req.session_ttl_s {
        Some(0) => return Err(ApiError::validation("session_ttl_s must be positive")),
        Some(s) => s,
        None => state.config.limits.default_session_ttl_s,
    }
    .min(remaining);
    validate_label(req.label.as_deref())?;
    if req.port == Some(0) {
        return Err(ApiError::validation("port must be 1..=65535"));
    }
    let port = req.port.or_else(|| state.registry.get(&tunnel.id).and_then(|l| l.ports().first().copied()));

    let link_id = tokens::random_link_id();
    let token = tokens::random_token(ACCESS_TOKEN_PREFIX);
    let expires_at = t + req.ttl_s as i64;
    let single_use = req.single_use.unwrap_or(true);
    state
        .db
        .create_access_link(NewAccessLink {
            id: link_id.clone(),
            tunnel_id: tunnel.id.clone(),
            token_hash: tokens::hash_token(&token),
            single_use,
            label: req.label,
            session_ttl_s: session_ttl_s as i64,
            expires_at,
        })
        .await?;
    tracing::info!(tunnel = %tunnel.id, link = %link_id, single_use, expires_at, "access link created");

    Ok((
        StatusCode::CREATED,
        Json(AccessLinkResponse {
            id: link_id,
            url: crate::gatehost::access_url(&state.config.preview_zone, &tunnel.id, port, &token),
            url_path: format!("/__access/{token}"),
            expires_at,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/v1/access-links/{id}",
    params(("id" = String, Path, description = "Access link id")),
    responses(
        (status = 204, description = "Revoked, along with the gate sessions it created"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
async fn delete_access_link(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if matches!(caller, Caller::Client { .. }) {
        let tunnel = state.db.access_link_tunnel(id.clone()).await?.ok_or_else(|| ApiError::not_found("access link"))?;
        if find_tunnel(&state, &caller, &tunnel).await.is_err() {
            return Err(ApiError::not_found("access link"));
        }
    }
    if !state.db.delete_access_link(id.clone()).await? {
        return Err(ApiError::not_found("access link"));
    }
    state.invalidate_sessions();
    tracing::info!(link = %id, "access link revoked");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/tunnels/{id}/turn-credentials",
    params(("id" = String, Path, description = "Tunnel id")),
    request_body(content = TurnCredentialsRequest, description = "Optional; empty body uses the defaults"),
    responses(
        (status = 200, body = TurnCredentialsResponse),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody, description = "Tunnel expired, or WebRTC disabled"),
        (status = 422, body = ErrorBody),
    )
)]
async fn turn_credentials(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<TurnCredentialsResponse>> {
    let req: TurnCredentialsRequest = optional_json(&body)?;
    let webrtc = &state.config.webrtc;
    if !webrtc.enabled {
        return Err(ApiError::new(StatusCode::CONFLICT, "webrtc_disabled", "WebRTC is not enabled on this server"));
    }
    let ttl_s = req.ttl_s.unwrap_or(webrtc.browser_ttl_s);
    if !(MIN_ICE_TTL_S..=webrtc.sandbox_ttl_s).contains(&ttl_s) {
        return Err(ApiError::validation(format!("ttl_s must be within {MIN_ICE_TTL_S}..={}", webrtc.sandbox_ttl_s)));
    }
    let tunnel = active_tunnel(&state, &caller, &id).await?;
    let ice = ice::mint(&state.config, &tunnel.id, API_SUBJECT, ttl_s);
    Ok(Json(TurnCredentialsResponse { ice_servers: ice.ice_servers, expires_at: ice.expires_at, ttl_s: ice.ttl_s }))
}

// ----------------------------------------------------------------- helpers

fn validate_tunnel_ttl(ttl_s: u64, max: u64) -> ApiResult<()> {
    if (MIN_TUNNEL_TTL_S..=max).contains(&ttl_s) {
        Ok(())
    } else {
        Err(ApiError::validation(format!("ttl_s must be within {MIN_TUNNEL_TTL_S}..={max}")))
    }
}

fn validate_label(label: Option<&str>) -> ApiResult<()> {
    match label {
        Some(l) if l.chars().count() > MAX_LABEL_LEN => {
            Err(ApiError::validation(format!("label must be at most {MAX_LABEL_LEN} characters")))
        }
        _ => Ok(()),
    }
}

// ----------------------------------------------------------------- clients

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateClientRequest {
    /// 1..=64 characters: letters, digits, `.`, `_`, `-`.
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateClientResponse {
    pub name: String,
    /// `<code>@<host>`: paste at the `cockpit-preview login` prompt on the
    /// client machine. Works once, until `expires_at`.
    pub login_code: String,
    /// The same as a single command (puts the code in process listings and history).
    pub login_command: String,
    /// Unix seconds.
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientView {
    pub name: String,
    /// The login code has been used.
    pub enrolled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Unexpired tunnels this client created.
    pub tunnels: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientList {
    pub clients: Vec<ClientView>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    /// `ctenr_…` code from `client add`.
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EnrollResponse {
    pub name: String,
    /// Long-lived client token (`ctcli_…`), shown once.
    pub token: String,
    /// `https://<api host>`
    pub api: String,
    /// `wss://<tunnel host>`
    pub server: String,
}

impl From<ClientRow> for ClientView {
    fn from(c: ClientRow) -> Self {
        Self { name: c.name, enrolled: c.enrolled, created_at: c.created_at, last_used_at: c.last_used_at, tunnels: c.tunnels }
    }
}

#[utoipa::path(
    post,
    path = "/v1/clients",
    request_body = CreateClientRequest,
    responses((status = 201, body = CreateClientResponse), (status = 401, body = ErrorBody), (status = 409, body = ErrorBody), (status = 422, body = ErrorBody))
)]
async fn create_client(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    ApiJson(req): ApiJson<CreateClientRequest>,
) -> ApiResult<(StatusCode, Json<CreateClientResponse>)> {
    match clients::add(&state.db, &state.config, &req.name).await {
        Ok(e) => Ok((StatusCode::CREATED, Json(CreateClientResponse { name: e.name, login_code: e.login_code, login_command: e.login_command, expires_at: e.expires_at }))),
        Err(clients::AddError::Invalid(m)) => Err(ApiError::validation(m)),
        Err(clients::AddError::Taken) => {
            Err(ApiError::new(StatusCode::CONFLICT, "client_exists", "a client with this name exists; delete it first"))
        }
        Err(clients::AddError::Other(e)) => Err(e.into()),
    }
}

#[utoipa::path(get, path = "/v1/clients", responses((status = 200, body = ClientList), (status = 401, body = ErrorBody)))]
async fn list_clients(State(state): State<Arc<AppState>>, _admin: Admin) -> ApiResult<Json<ClientList>> {
    let clients = state.db.list_clients().await?.into_iter().map(ClientView::from).collect();
    Ok(Json(ClientList { clients }))
}

#[utoipa::path(
    delete,
    path = "/v1/clients/{name}",
    params(("name" = String, Path, description = "Client name")),
    responses((status = 204, description = "Deleted; its token stops working and its tunnels close"), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody))
)]
async fn delete_client(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let tunnels = state.db.delete_client(name.clone()).await?.ok_or_else(|| ApiError::not_found("client"))?;
    for id in &tunnels {
        state.delete_tunnel(id, CloseReason::Deleted).await?;
    }
    tracing::info!(client = %name, tunnels = tunnels.len(), "client deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Unauthenticated: the one-time code is the credential. Shares the
/// access-link rate limit per IP.
#[utoipa::path(
    post,
    path = "/v1/clients/enroll",
    security(()),
    request_body = EnrollRequest,
    responses((status = 200, body = EnrollResponse), (status = 401, body = ErrorBody), (status = 429, body = ErrorBody))
)]
async fn enroll_client(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(req): ApiJson<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    if let Some(axum::Extension(PeerAddr(addr))) = peer {
        if !state.access_limiter.check(addr.ip()) {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
        }
    }
    let code = req.code.trim();
    if !code.starts_with(ENROLL_CODE_PREFIX) || code.len() > 256 {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_code", "invalid, used, or expired login code"));
    }
    let token = tokens::random_token(CLIENT_TOKEN_PREFIX);
    match state.db.enroll_client(tokens::hash_token(code), tokens::hash_token(&token)).await? {
        Some(name) => {
            tracing::info!(client = %name, "client enrolled");
            Ok(Json(EnrollResponse {
                name,
                token,
                api: format!("https://{}", state.config.api_host),
                server: format!("wss://{}", state.config.tunnel_host),
            }))
        }
        None => Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_code", "invalid, used, or expired login code")),
    }
}

/// Validate an access request; hashes a new password. `current` is the stored
/// setting on PATCH, which supplies an omitted username or password.
async fn build_access(req: AccessRequest, current: Option<&Access>) -> ApiResult<Access> {
    if req.mode != AccessMode::Password {
        if req.username.is_some() || req.password.is_some() {
            return Err(ApiError::validation("username and password apply only to access mode \"password\""));
        }
        return Ok(Access { mode: req.mode, password_user: None, password_hash: None });
    }
    let current = current.filter(|c| c.mode == AccessMode::Password);
    let username = match req.username.or_else(|| current.and_then(|c| c.password_user.clone())) {
        Some(u) => u,
        None => return Err(ApiError::validation("access.username is required for password mode")),
    };
    let len = username.chars().count();
    if !(1..=password::MAX_USERNAME_LEN).contains(&len) || username.chars().any(char::is_control) {
        return Err(ApiError::validation(format!(
            "access.username must be 1..={} characters without control characters",
            password::MAX_USERNAME_LEN
        )));
    }
    let password_hash = match req.password {
        Some(p) => {
            let len = p.chars().count();
            if !(password::MIN_PASSWORD_LEN..=password::MAX_PASSWORD_LEN).contains(&len) {
                return Err(ApiError::validation(format!(
                    "access.password must be {}..={} characters",
                    password::MIN_PASSWORD_LEN,
                    password::MAX_PASSWORD_LEN
                )));
            }
            password::hash(p).await?
        }
        None => match current.and_then(|c| c.password_hash.clone()) {
            Some(h) => h,
            None => return Err(ApiError::validation("access.password is required for password mode")),
        },
    };
    Ok(Access { mode: AccessMode::Password, password_user: Some(username), password_hash: Some(password_hash) })
}

/// Ids are never reused: retry while the id belongs to a tunnel or a tombstone.
async fn fresh_tunnel_id(state: &AppState) -> ApiResult<String> {
    for _ in 0..ID_ATTEMPTS {
        let id = tokens::random_tunnel_id();
        if !state.db.id_taken(id.clone()).await? {
            return Ok(id);
        }
    }
    Err(ApiError::internal(anyhow::anyhow!("could not allocate an unused tunnel id")))
}

/// Tunnel row (expired or not) straight from the database; 404 if unknown or tombstoned.
/// A tunnel the caller may use; another client's tunnel is "not found".
async fn find_tunnel(state: &AppState, caller: &Caller, id: &str) -> ApiResult<TunnelRow> {
    if !tokens::is_valid_tunnel_id(id) {
        return Err(ApiError::not_found("tunnel"));
    }
    match state.db.get_tunnel(id.to_string()).await? {
        Some(row) if caller.may_use(&row) => Ok(row),
        _ => Err(ApiError::not_found("tunnel")),
    }
}

/// Unexpired tunnel; 409 if expired or tombstoned, 404 if never existed.
async fn active_tunnel(state: &AppState, caller: &Caller, id: &str) -> ApiResult<TunnelRow> {
    match find_tunnel(state, caller, id).await {
        Ok(row) if row.is_expired() => Err(ApiError::expired()),
        Ok(row) => Ok(row),
        // Tombstones carry no owner, so only the admin learns that an id ended.
        Err(e) if e.status == StatusCode::NOT_FOUND && tokens::is_valid_tunnel_id(id) && matches!(caller, Caller::Admin) => {
            if state.db.is_tombstoned(id.to_string()).await? {
                Err(ApiError::expired())
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

fn tunnel_view(state: &AppState, row: &TunnelRow) -> TunnelView {
    let live = state.registry.get(&row.id);
    let ports = live
        .as_ref()
        .map(|l| {
            l.ports()
                .into_iter()
                .map(|port| PortView { port, host: state.preview_host(port, &row.id), connected: true })
                .collect()
        })
        .unwrap_or_default();
    TunnelView {
        id: row.id.clone(),
        label: row.label.clone(),
        access: AccessView { mode: row.access.mode, username: row.access.password_user.clone() },
        metadata: row.metadata.clone(),
        connected: live.is_some(),
        connected_since: live.as_ref().map(|l| l.connected_at),
        expired: row.is_expired(),
        ports,
        host_template: state.config.host_template(&row.id),
        max_ports: row.max_ports,
        host_header: row.host_header,
        inject_ice: row.inject_ice,
        created_at: row.created_at,
        expires_at: row.expires_at,
        last_seen_at: row.last_seen_at,
    }
}
