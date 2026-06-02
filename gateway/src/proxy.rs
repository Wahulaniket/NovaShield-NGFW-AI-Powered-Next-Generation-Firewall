use crate::{
    ai_client::{self, AiDecision, AiRequest},
    security::{self, GuardFailure},
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use shared::{
    ApiError, BalanceResponse, BlacklistUpdateRequest, HealthResponse, LiveEvent, LoginRequest,
    LoginResponse, RequestDecision, RequestLogEntry, SecurityEvent, SecurityRule, Severity,
    TransferRequest, TransferResponse,
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/balance", get(balance))
        .route("/api/transfer", post(transfer))
        .route("/api/admin/health", get(health))
        .route("/api/admin/snapshot", get(snapshot))
        .route("/api/admin/logs", get(logs))
        .route("/api/admin/metrics", get(metrics))
        .route("/api/admin/blacklist/add", post(add_blacklist_ip))
        .route("/api/admin/blacklist/remove", post(remove_blacklist_ip))
        .route("/ws/live", any(ws))
        .with_state(state)
}

struct RequestContext {
    request_id: String,
    method: String,
    path: String,
    ip: String,
    started_at: Instant,
}

impl RequestContext {
    fn new(method: &str, path: String, ip: String) -> Self {
        Self {
            request_id: Uuid::now_v7().to_string(),
            method: method.to_string(),
            path,
            ip,
            started_at: Instant::now(),
        }
    }

    async fn log(&self, state: &AppState, status: StatusCode, decision: RequestDecision) {
        let entry = RequestLogEntry {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            request_id: self.request_id.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            ip: self.ip.clone(),
            status: status.as_u16(),
            decision,
            latency_ms: self.started_at.elapsed().as_millis() as u64,
        };

        // Persist to Redis in background
        if let Some(ref redis) = state.redis {
            let redis = redis.clone();
            let entry_clone = entry.clone();
            tokio::spawn(async move {
                redis.push_log(&entry_clone).await;
            });
        }

        state.observability.record_request(entry).await;
    }
}

/// Run AI engine check on the request. Returns `Some(Response)` if blocked.
async fn ai_check(
    state: &AppState,
    ctx: &RequestContext,
    user_agent: &str,
) -> Option<Response> {
    let config = state.current_config();
    if !config.ai_enabled {
        return None;
    }

    let ai_request = AiRequest {
        ip: ctx.ip.clone(),
        path: ctx.path.clone(),
        method: ctx.method.clone(),
        user_agent: user_agent.to_string(),
    };

    let decision = ai_client::check(
        &state.http_client,
        &config.ai_engine_url,
        config.ai_timeout_ms,
        &ai_request,
    )
    .await;

    match decision {
        AiDecision::Block => {
            state
                .observability
                .record_security(SecurityEvent {
                    id: Uuid::now_v7(),
                    timestamp: Utc::now(),
                    ip: ctx.ip.clone(),
                    path: ctx.path.clone(),
                    rule: SecurityRule::AiEngine,
                    severity: Severity::Critical,
                    message: "request blocked by AI engine threat classification".to_string(),
                })
                .await;

            ctx.log(state, StatusCode::FORBIDDEN, RequestDecision::AiBlocked)
                .await;

            Some(json_response(
                StatusCode::FORBIDDEN,
                &ApiError::new(
                    "AI_BLOCKED",
                    "traffic classified as malicious by AI engine",
                ),
            ))
        }
        AiDecision::Allow | AiDecision::Fallback => None,
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let ip = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    let ctx = RequestContext::new("POST", path.clone(), ip.clone());
    let config = state.current_config();
    let body = serde_json::to_string(&payload).unwrap_or_default();
    let inspected_body = security::truncate_for_inspection(&body, config.max_inspection_body_bytes);

    if let Some(rejection) =
        security::inspect_common(&state, &ip, "login", &path, Some(&inspected_body))
    {
        return reject(&state, &ctx, rejection).await;
    }

    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip, &path) {
        return reject(&state, &ctx, rejection).await;
    }

    // AI enforcement
    let user_agent = security::extract_user_agent(&headers);
    if let Some(blocked) = ai_check(&state, &ctx, &user_agent).await {
        return blocked;
    }

    let url = format!("{}/login", config.backend_base_url.trim_end_matches('/'));
    let response = state
        .http_client
        .post(url)
        .header("x-request-id", &ctx.request_id)
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(response) => match proxy_json::<LoginResponse>(response).await {
            Ok((status, payload)) => {
                let decision = if status.is_success() {
                    RequestDecision::Allowed
                } else {
                    RequestDecision::UpstreamError
                };
                ctx.log(&state, status, decision).await;
                json_response(status, &payload)
            }
            Err((status, error)) => {
                ctx.log(&state, status, RequestDecision::UpstreamError)
                    .await;
                json_response(status, &error)
            }
        },
        Err(error) => {
            warn!(request_id = %ctx.request_id, %error, "login upstream call failed");
            state
                .observability
                .record_security(shared::SecurityEvent {
                    id: Uuid::now_v7(),
                    timestamp: Utc::now(),
                    ip,
                    path,
                    rule: SecurityRule::Upstream,
                    severity: Severity::Warn,
                    message: format!("upstream login call failed: {error}"),
                })
                .await;
            ctx.log(
                &state,
                StatusCode::BAD_GATEWAY,
                RequestDecision::UpstreamError,
            )
            .await;
            json_response(
                StatusCode::BAD_GATEWAY,
                &ApiError::new("UPSTREAM_ERROR", "failed to reach backend"),
            )
        }
    }
}

async fn balance(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let ip = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    let ctx = RequestContext::new("GET", path.clone(), ip.clone());

    if let Some(rejection) = security::inspect_common(&state, &ip, "balance", &path, None) {
        return reject(&state, &ctx, rejection).await;
    }

    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip, &path) {
        return reject(&state, &ctx, rejection).await;
    }

    let claims = match security::verify_jwt(&headers, &state, &ip, &path) {
        Ok(claims) => claims,
        Err(rejection) => return reject(&state, &ctx, rejection).await,
    };

    // AI enforcement
    let user_agent = security::extract_user_agent(&headers);
    if let Some(blocked) = ai_check(&state, &ctx, &user_agent).await {
        return blocked;
    }

    let config = state.current_config();
    let url = format!(
        "{}/balance{}",
        config.backend_base_url.trim_end_matches('/'),
        query_suffix(&uri)
    );
    let mut request = state
        .http_client
        .get(url)
        .header("x-request-id", &ctx.request_id);
    if let Some(value) = headers.get(header::AUTHORIZATION).cloned() {
        request = request.header(header::AUTHORIZATION, value);
    }
    let response = request.send().await;

    match response {
        Ok(response) => match proxy_json::<BalanceResponse>(response).await {
            Ok((status, payload)) => {
                info!(request_id = %ctx.request_id, subject = %claims.sub, "balance request proxied");
                let decision = if status.is_success() {
                    RequestDecision::Allowed
                } else {
                    RequestDecision::UpstreamError
                };
                ctx.log(&state, status, decision).await;
                json_response(status, &payload)
            }
            Err((status, error)) => {
                ctx.log(&state, status, RequestDecision::UpstreamError)
                    .await;
                json_response(status, &error)
            }
        },
        Err(error) => {
            warn!(request_id = %ctx.request_id, %error, "balance upstream call failed");
            ctx.log(
                &state,
                StatusCode::BAD_GATEWAY,
                RequestDecision::UpstreamError,
            )
            .await;
            json_response(
                StatusCode::BAD_GATEWAY,
                &ApiError::new("UPSTREAM_ERROR", "failed to reach backend"),
            )
        }
    }
}

async fn transfer(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Json(payload): Json<TransferRequest>,
) -> Response {
    let ip = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    let ctx = RequestContext::new("POST", path.clone(), ip.clone());
    let config = state.current_config();
    let body = serde_json::to_string(&payload).unwrap_or_default();
    let inspected_body = security::truncate_for_inspection(&body, config.max_inspection_body_bytes);

    if let Some(rejection) =
        security::inspect_common(&state, &ip, "transfer", &path, Some(&inspected_body))
    {
        return reject(&state, &ctx, rejection).await;
    }

    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip, &path) {
        return reject(&state, &ctx, rejection).await;
    }

    let claims = match security::verify_jwt(&headers, &state, &ip, &path) {
        Ok(claims) => claims,
        Err(rejection) => return reject(&state, &ctx, rejection).await,
    };

    // AI enforcement
    let user_agent = security::extract_user_agent(&headers);
    if let Some(blocked) = ai_check(&state, &ctx, &user_agent).await {
        return blocked;
    }

    let url = format!("{}/transfer", config.backend_base_url.trim_end_matches('/'));
    let mut request = state
        .http_client
        .post(url)
        .header("x-request-id", &ctx.request_id);
    if let Some(value) = headers.get(header::AUTHORIZATION).cloned() {
        request = request.header(header::AUTHORIZATION, value);
    }
    let response = request.json(&payload).send().await;

    match response {
        Ok(response) => match proxy_json::<TransferResponse>(response).await {
            Ok((status, payload)) => {
                info!(request_id = %ctx.request_id, subject = %claims.sub, "transfer request proxied");
                let decision = if status.is_success() {
                    RequestDecision::Allowed
                } else {
                    RequestDecision::UpstreamError
                };
                ctx.log(&state, status, decision).await;
                json_response(status, &payload)
            }
            Err((status, error)) => {
                ctx.log(&state, status, RequestDecision::UpstreamError)
                    .await;
                json_response(status, &error)
            }
        },
        Err(error) => {
            warn!(request_id = %ctx.request_id, %error, "transfer upstream call failed");
            ctx.log(
                &state,
                StatusCode::BAD_GATEWAY,
                RequestDecision::UpstreamError,
            )
            .await;
            json_response(
                StatusCode::BAD_GATEWAY,
                &ApiError::new("UPSTREAM_ERROR", "failed to reach backend"),
            )
        }
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let config = state.current_config();
    json_response(
        StatusCode::OK,
        &HealthResponse {
            service: "gateway".to_string(),
            status: "ok".to_string(),
            tls_enabled: config.tls.enabled,
        },
    )
}

async fn snapshot(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let ip = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    if let Some(rejection) = security::inspect_common(&state, &ip, "admin", &path, None) {
        return reject_admin(&state, rejection).await;
    }
    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip, &path) {
        return reject_admin(&state, rejection).await;
    }
    if let Err(rejection) = security::verify_admin_jwt(&headers, &state, &ip, &path) {
        return reject_admin(&state, rejection).await;
    }

    let snapshot = state.observability.snapshot(state.blacklisted_ips()).await;
    json_response(StatusCode::OK, &snapshot)
}

async fn logs(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let ip = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    if let Some(rejection) = security::inspect_common(&state, &ip, "admin", &path, None) {
        return reject_admin(&state, rejection).await;
    }
    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip, &path) {
        return reject_admin(&state, rejection).await;
    }
    if let Err(rejection) = security::verify_admin_jwt(&headers, &state, &ip, &path) {
        return reject_admin(&state, rejection).await;
    }

    let snapshot = state.observability.snapshot(state.blacklisted_ips()).await;
    json_response(StatusCode::OK, &snapshot.recent_logs)
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let ip = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    if let Some(rejection) = security::inspect_common(&state, &ip, "admin", &path, None) {
        return reject_admin(&state, rejection).await;
    }
    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip, &path) {
        return reject_admin(&state, rejection).await;
    }
    if let Err(rejection) = security::verify_admin_jwt(&headers, &state, &ip, &path) {
        return reject_admin(&state, rejection).await;
    }

    match state.observability.render_prometheus() {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            body,
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to render prometheus metrics");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &ApiError::new("METRICS_ERROR", "failed to render metrics"),
            )
        }
    }
}

async fn add_blacklist_ip(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Json(payload): Json<BlacklistUpdateRequest>,
) -> Response {
    let ip_client = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    if let Some(rejection) = security::inspect_common(&state, &ip_client, "admin", &path, None) {
        return reject_admin(&state, rejection).await;
    }
    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip_client, &path) {
        return reject_admin(&state, rejection).await;
    }
    if let Err(rejection) = security::verify_admin_jwt(&headers, &state, &ip_client, &path) {
        return reject_admin(&state, rejection).await;
    }

    let ip = payload.ip.trim();
    if ip.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &ApiError::new("INVALID_IP", "ip is required"),
        );
    }

    let reason = payload
        .reason
        .unwrap_or_else(|| "manually added to blacklist".to_string());
    state.blacklist_ip(ip.to_string(), reason.clone());

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "status": "ok",
            "ip": ip,
            "reason": reason
        }),
    )
}

async fn remove_blacklist_ip(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Json(payload): Json<BlacklistUpdateRequest>,
) -> Response {
    let ip_client = security::client_ip(&headers, addr);
    let path = path_with_query(&uri);
    if let Some(rejection) = security::inspect_common(&state, &ip_client, "admin", &path, None) {
        return reject_admin(&state, rejection).await;
    }
    if let Some(rejection) = security::inspect_headers(&state, &headers, &ip_client, &path) {
        return reject_admin(&state, rejection).await;
    }
    if let Err(rejection) = security::verify_admin_jwt(&headers, &state, &ip_client, &path) {
        return reject_admin(&state, rejection).await;
    }

    let ip = payload.ip.trim();
    if ip.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &ApiError::new("INVALID_IP", "ip is required"),
        );
    }

    if state.remove_blacklisted_ip(ip) {
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "status": "removed",
                "ip": ip
            }),
        )
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            &ApiError::new("NOT_FOUND", "ip was not present in blacklist"),
        )
    }
}

async fn ws(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    ws.on_upgrade(move |socket| websocket_session(socket, state))
}

async fn websocket_session(socket: WebSocket, state: Arc<AppState>) {
    state.observability.websocket_connected();
    let config = state.current_config();
    let mut tick = interval(Duration::from_secs(
        config.websocket_ping_interval_secs.max(5),
    ));
    let mut feed = state.observability.subscribe();
    let (mut sender, mut receiver) = socket.split();

    let snapshot = state.observability.snapshot(state.blacklisted_ips()).await;
    if sender
        .send(Message::Text(
            serde_json::to_string(&LiveEvent::Snapshot { snapshot })
                .unwrap_or_else(|_| "{}".to_string())
                .into(),
        ))
        .await
        .is_err()
    {
        state.observability.websocket_disconnected();
        return;
    }

    loop {
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        warn!(%error, "dashboard websocket receive failed");
                        break;
                    }
                }
            }
            event = feed.recv() => {
                match event {
                    Ok(event) => {
                        let payload = match serde_json::to_string(&event) {
                            Ok(payload) => payload,
                            Err(error) => {
                                warn!(%error, "failed to serialize live event");
                                continue;
                            }
                        };
                        if sender.send(Message::Text(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ = tick.tick() => {
                if sender.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }

    state.observability.websocket_disconnected();
}

async fn reject(state: &AppState, ctx: &RequestContext, rejection: GuardFailure) -> Response {
    if let Some(event) = rejection.security_event {
        if should_promote_to_blacklist(&event.rule) {
            state.blacklist_ip(event.ip.clone(), event.message.clone());
        }
        state.observability.record_security(event).await;
    }
    ctx.log(state, rejection.status, rejection.decision).await;
    let mut response = json_response(rejection.status, &rejection.error);
    if let Some(rate_limit) = rejection.rate_limit {
        for (name, value) in rate_limit.header_pairs() {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

/// Reject for admin endpoints — records security events and applies blacklist
/// promotion, but does not log a full request entry (no RequestContext).
async fn reject_admin(state: &AppState, rejection: GuardFailure) -> Response {
    if let Some(event) = rejection.security_event {
        if should_promote_to_blacklist(&event.rule) {
            state.blacklist_ip(event.ip.clone(), event.message.clone());
        }
        state.observability.record_security(event).await;
    }
    let mut response = json_response(rejection.status, &rejection.error);
    if let Some(rate_limit) = rejection.rate_limit {
        for (name, value) in rate_limit.header_pairs() {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn should_promote_to_blacklist(rule: &SecurityRule) -> bool {
    matches!(
        rule,
        SecurityRule::WafSqli
            | SecurityRule::WafXss
            | SecurityRule::WafTraversal
            | SecurityRule::WafCommandInjection
            | SecurityRule::WafNullByte
            | SecurityRule::WafCrlf
            | SecurityRule::WafSsrf
    )
}

async fn proxy_json<T>(
    response: reqwest::Response,
) -> Result<(StatusCode, T), (StatusCode, ApiError)>
where
    T: serde::de::DeserializeOwned,
{
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let body = response.text().await.map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            ApiError::new(
                "UPSTREAM_READ_ERROR",
                format!("failed to read backend response: {error}"),
            ),
        )
    })?;

    if status.is_success() {
        serde_json::from_str::<T>(&body)
            .map(|parsed| (status, parsed))
            .map_err(|error| {
                (
                    StatusCode::BAD_GATEWAY,
                    ApiError::new(
                        "UPSTREAM_DECODE_ERROR",
                        format!("failed to decode backend success payload: {error}"),
                    ),
                )
            })
    } else {
        let error = serde_json::from_str::<ApiError>(&body).unwrap_or_else(|_| {
            ApiError::new(
                "UPSTREAM_ERROR",
                format!("backend returned {}: {}", status.as_u16(), body),
            )
        });
        Err((status, error))
    }
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let mut response = Json(body).into_response();
    *response.status_mut() = status;
    response
}

fn path_with_query(uri: &Uri) -> String {
    match uri.query() {
        Some(query) => format!("{}?{query}", uri.path()),
        None => uri.path().to_string(),
    }
}

fn query_suffix(uri: &Uri) -> String {
    uri.query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default()
}
