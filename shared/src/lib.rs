use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub message: String,
    pub account_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub account_id: String,
    pub balance: f64,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub to_account: String,
    pub amount: f64,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResponse {
    pub transaction_id: String,
    pub status: String,
    pub remaining_balance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub service: String,
    pub status: String,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestDecision {
    Allowed,
    Blocked,
    RateLimited,
    AuthFailed,
    UpstreamError,
    AiBlocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub ip: String,
    pub status: u16,
    pub decision: RequestDecision,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityRule {
    Blacklist,
    WafSqli,
    WafXss,
    WafTraversal,
    WafCommandInjection,
    WafNullByte,
    WafCrlf,
    WafSsrf,
    Jwt,
    RateLimit,
    Upstream,
    System,
    AiEngine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub path: String,
    pub rule: SecurityRule,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistedIpEntry {
    pub ip: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistUpdateRequest {
    pub ip: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemNotice {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub level: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficCounters {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub rate_limited_requests: u64,
    pub auth_failures: u64,
    pub upstream_errors: u64,
    pub active_websockets: u64,
    pub ai_blocked_requests: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub generated_at: DateTime<Utc>,
    pub counters: TrafficCounters,
    pub blacklisted_ips: Vec<BlacklistedIpEntry>,
    pub recent_logs: Vec<RequestLogEntry>,
    pub recent_security_events: Vec<SecurityEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LiveEvent {
    Snapshot { snapshot: DashboardSnapshot },
    RequestLog { entry: RequestLogEntry },
    SecurityEvent { entry: SecurityEvent },
    SystemNotice { notice: SystemNotice },
}
