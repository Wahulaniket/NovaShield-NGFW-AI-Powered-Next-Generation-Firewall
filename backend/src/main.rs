mod config;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use config::BackendConfig;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use shared::{
    ApiError, BalanceResponse, Claims, HealthResponse, LoginRequest, LoginResponse,
    TransferRequest, TransferResponse,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

/// Admin usernames that receive the "admin" role in JWT claims.
const ADMIN_USERS: &[&str] = &["admin", "root", "superadmin"];

#[derive(Clone)]
struct BackendState {
    config: BackendConfig,
    balances: Arc<RwLock<HashMap<String, f64>>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "backend=info,tower_http=info,axum=info".to_string()),
        )
        .json()
        .init();

    let config_path = std::env::var("NOVA_CONFIG_PATH")
        .unwrap_or_else(|_| "config/backend.json".to_string());
    let config = BackendConfig::load(&config_path)?;
    let state = BackendState {
        config: config.clone(),
        balances: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/login", post(login))
        .route("/balance", get(balance))
        .route("/transfer", post(transfer))
        .with_state(state);

    let addr: SocketAddr = config.listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, issuer = %config.issuer, "backend listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(_state): State<BackendState>) -> Response {
    json_response(
        StatusCode::OK,
        &HealthResponse {
            service: "backend".to_string(),
            status: "ok".to_string(),
            tls_enabled: false,
        },
    )
}

async fn login(State(state): State<BackendState>, Json(payload): Json<LoginRequest>) -> Response {
    if payload.username.trim().is_empty() || payload.password.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ApiError::new("INVALID_LOGIN", "username and password are required"),
        );
    }

    let username = payload.username.trim().to_lowercase();
    let account_id = format!("acct-{}", username);
    {
        let mut balances = state.balances.write().await;
        balances.entry(account_id.clone()).or_insert(50_000.0);
    }

    // Assign role based on username
    let role = if ADMIN_USERS.contains(&username.as_str()) {
        "admin".to_string()
    } else {
        "customer".to_string()
    };

    let now = Utc::now();
    let claims = Claims {
        sub: account_id.clone(),
        role,
        iat: now.timestamp() as usize,
        exp: (now + Duration::seconds(state.config.token_ttl_secs as i64)).timestamp() as usize,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::new(
                    "TOKEN_ISSUE_FAILED",
                    format!("failed to create token: {error}"),
                ),
            );
        }
    };

    json_response(
        StatusCode::OK,
        &LoginResponse {
            token,
            message: "login successful".to_string(),
            account_id,
        },
    )
}

async fn balance(State(state): State<BackendState>, headers: HeaderMap) -> Response {
    let claims = match authorize(&headers, &state.config.jwt_secret) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    let balance = {
        let balances = state.balances.read().await;
        *balances.get(&claims.sub).unwrap_or(&50_000.0)
    };

    json_response(
        StatusCode::OK,
        &BalanceResponse {
            account_id: claims.sub,
            balance,
            currency: "INR".to_string(),
        },
    )
}

async fn transfer(
    State(state): State<BackendState>,
    headers: HeaderMap,
    Json(payload): Json<TransferRequest>,
) -> Response {
    let claims = match authorize(&headers, &state.config.jwt_secret) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    if payload.amount <= 0.0 {
        return error_response(
            StatusCode::BAD_REQUEST,
            ApiError::new("INVALID_AMOUNT", "transfer amount must be positive"),
        );
    }

    let remaining_balance = {
        let mut balances = state.balances.write().await;
        let balance = balances.entry(claims.sub.clone()).or_insert(50_000.0);
        if *balance < payload.amount {
            return error_response(
                StatusCode::BAD_REQUEST,
                ApiError::new("INSUFFICIENT_FUNDS", "insufficient balance for transfer"),
            );
        }
        *balance -= payload.amount;
        *balance
    };

    json_response(
        StatusCode::OK,
        &TransferResponse {
            transaction_id: format!("txn-{}", Uuid::now_v7()),
            status: format!("queued to {}", payload.to_account),
            remaining_balance,
        },
    )
}

fn authorize(headers: &HeaderMap, secret: &str) -> Result<Claims, Response> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            ApiError::new("UNAUTHORIZED", "missing bearer token"),
        ));
    };

    let Ok(raw) = value.to_str() else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            ApiError::new("UNAUTHORIZED", "invalid authorization header"),
        ));
    };

    let Some(token) = raw.strip_prefix("Bearer ") else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            ApiError::new("UNAUTHORIZED", "invalid bearer token"),
        ));
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            ApiError::new("UNAUTHORIZED", "token verification failed"),
        )
    })
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let mut response = Json(body).into_response();
    *response.status_mut() = status;
    response
}

fn error_response(status: StatusCode, error: ApiError) -> Response {
    json_response(status, &error)
}
