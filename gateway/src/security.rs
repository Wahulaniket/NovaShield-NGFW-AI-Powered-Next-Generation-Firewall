use crate::{
    auth,
    config::RateLimits,
    state::{AppState, RateWindow},
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::Utc;
use dashmap::mapref::entry::Entry;
use regex::Regex;
use shared::{ApiError, Claims, RequestDecision, SecurityEvent, SecurityRule, Severity};
use percent_encoding::percent_decode_str;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GuardFailure {
    pub status: StatusCode,
    pub decision: RequestDecision,
    pub error: ApiError,
    pub security_event: Option<SecurityEvent>,
    pub rate_limit: Option<RateLimitMetadata>,
}

#[derive(Debug, Clone)]
pub struct RateLimitMetadata {
    pub limit: u32,
    pub remaining: u32,
    pub retry_after_secs: u64,
}

impl RateLimitMetadata {
    pub fn header_pairs(&self) -> [(&'static str, HeaderValue); 3] {
        [
            (
                "retry-after",
                HeaderValue::from_str(&self.retry_after_secs.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("60")),
            ),
            (
                "x-ratelimit-limit",
                HeaderValue::from_str(&self.limit.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("0")),
            ),
            (
                "x-ratelimit-remaining",
                HeaderValue::from_str(&self.remaining.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("0")),
            ),
        ]
    }
}

struct WafRule {
    regex: Regex,
    code: &'static str,
    rule: SecurityRule,
    message: &'static str,
}

pub struct WafEngine {
    rules: Vec<WafRule>,
}

impl WafEngine {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            rules: vec![
                WafRule {
                    regex: Regex::new(r#"(?i)(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+"#)?,
                    code: "WAF_SQLI",
                    rule: SecurityRule::WafSqli,
                    message: "possible SQL injection pattern detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)union\s+select|drop\s+table|sleep\s*\(|(?:^|[';)\s])--(?:\s|$)")?,
                    code: "WAF_SQLI",
                    rule: SecurityRule::WafSqli,
                    message: "dangerous SQL keyword sequence detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)<script|onerror=|onload=|javascript:")?,
                    code: "WAF_XSS",
                    rule: SecurityRule::WafXss,
                    message: "cross-site scripting payload detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)\.\./|/etc/passwd|boot\.ini")?,
                    code: "WAF_TRAVERSAL",
                    rule: SecurityRule::WafTraversal,
                    message: "path traversal payload detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)(\|\s*(cat|sh|bash))|(;|&&)\s*(cat|curl|wget)")?,
                    code: "WAF_COMMAND",
                    rule: SecurityRule::WafCommandInjection,
                    message: "command injection payload detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)%00|\x00")?,
                    code: "WAF_NULLBYTE",
                    rule: SecurityRule::WafNullByte,
                    message: "null byte injection detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)%0d%0a")?,
                    code: "WAF_CRLF",
                    rule: SecurityRule::WafCrlf,
                    message: "CRLF injection detected",
                },
                WafRule {
                    regex: Regex::new(r"(?i)169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data")?,
                    code: "WAF_SSRF",
                    rule: SecurityRule::WafSsrf,
                    message: "potential SSRF pattern detected",
                },
            ],
        })
    }

    pub fn inspect(&self, input: &str) -> Option<(&'static str, SecurityRule, &'static str)> {
        // Check original input
        for rule in &self.rules {
            if rule.regex.is_match(input) {
                return Some((rule.code, rule.rule.clone(), rule.message));
            }
        }

        // Check percent-decoded input to catch encoding-based WAF evasion
        let decoded = percent_decode_str(input).decode_utf8_lossy();
        if decoded.as_ref() != input {
            for rule in &self.rules {
                if rule.regex.is_match(decoded.as_ref()) {
                    return Some((rule.code, rule.rule.clone(), rule.message));
                }
            }

            // Check double-decoded to catch double-encoding bypass (%253C -> %3C -> <)
            let double_decoded = percent_decode_str(decoded.as_ref()).decode_utf8_lossy();
            if double_decoded.as_ref() != decoded.as_ref() {
                for rule in &self.rules {
                    if rule.regex.is_match(double_decoded.as_ref()) {
                        return Some((rule.code, rule.rule.clone(), rule.message));
                    }
                }
            }
        }

        None
    }
}

pub fn client_ip(headers: &HeaderMap, remote_addr: SocketAddr) -> String {
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return ip.to_string();
    }

    if let Some(ip) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return ip.to_string();
    }

    remote_addr.ip().to_string()
}

pub fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

pub fn inspect_common(
    state: &AppState,
    ip: &str,
    route_key: &str,
    path: &str,
    request_body: Option<&str>,
) -> Option<GuardFailure> {
    if state.blacklist.contains_key(ip) {
        let reason = state
            .blacklist
            .get(ip)
            .map(|entry| entry.value().clone())
            .unwrap_or_else(|| "blacklisted".to_string());
        return Some(GuardFailure {
            status: StatusCode::FORBIDDEN,
            decision: RequestDecision::Blocked,
            error: ApiError::new(
                "BLOCKED_IP",
                format!("request rejected because IP is blacklisted: {reason}"),
            ),
            security_event: Some(build_event(
                ip,
                path,
                SecurityRule::Blacklist,
                Severity::Critical,
                &format!("request rejected by IP blacklist: {reason}"),
            )),
            rate_limit: None,
        });
    }

    if let Some((code, rule, message)) = state.waf.inspect(path) {
        return Some(GuardFailure {
            status: StatusCode::FORBIDDEN,
            decision: RequestDecision::Blocked,
            error: ApiError::new(code, message),
            security_event: Some(build_event(ip, path, rule, Severity::Critical, message)),
            rate_limit: None,
        });
    }

    if let Some(body) = request_body {
        if let Some((code, rule, message)) = state.waf.inspect(body) {
            return Some(GuardFailure {
                status: StatusCode::FORBIDDEN,
                decision: RequestDecision::Blocked,
                error: ApiError::new(code, message),
                security_event: Some(build_event(ip, path, rule, Severity::Critical, message)),
                rate_limit: None,
            });
        }
    }

    if let Some(metadata) = check_rate_limit(state, ip, route_key) {
        let message = format!(
            "{route_key} limit {} requests per 60 seconds exceeded for IP {ip}; retry in {} seconds",
            metadata.limit, metadata.retry_after_secs
        );
        return Some(GuardFailure {
            status: StatusCode::TOO_MANY_REQUESTS,
            decision: RequestDecision::RateLimited,
            error: ApiError::new("RATE_LIMITED", message.clone()),
            security_event: Some(build_event(
                ip,
                path,
                SecurityRule::RateLimit,
                Severity::Warn,
                &message,
            )),
            rate_limit: Some(metadata),
        });
    }

    None
}

pub fn verify_jwt(
    headers: &HeaderMap,
    state: &AppState,
    ip: &str,
    path: &str,
) -> Result<Claims, GuardFailure> {
    let config = state.current_config();
    auth::authorize(headers, &config.jwt_secret).map_err(|error| GuardFailure {
        status: StatusCode::UNAUTHORIZED,
        decision: RequestDecision::AuthFailed,
        error,
        security_event: Some(build_event(
            ip,
            path,
            SecurityRule::Jwt,
            Severity::Warn,
            "request rejected by JWT validation",
        )),
        rate_limit: None,
    })
}

/// Verify JWT and enforce admin role. Returns `GuardFailure` with 403 if user
/// is authenticated but lacks the `admin` role.
pub fn verify_admin_jwt(
    headers: &HeaderMap,
    state: &AppState,
    ip: &str,
    path: &str,
) -> Result<Claims, GuardFailure> {
    let claims = verify_jwt(headers, state, ip, path)?;

    if claims.role != "admin" {
        return Err(GuardFailure {
            status: StatusCode::FORBIDDEN,
            decision: RequestDecision::AuthFailed,
            error: ApiError::new(
                "FORBIDDEN",
                "admin role required to access this endpoint",
            ),
            security_event: Some(build_event(
                ip,
                path,
                SecurityRule::Jwt,
                Severity::Warn,
                &format!("non-admin user '{}' attempted admin endpoint access", claims.sub),
            )),
            rate_limit: None,
        });
    }

    Ok(claims)
}

fn check_rate_limit(state: &AppState, ip: &str, route_key: &str) -> Option<RateLimitMetadata> {
    let config = state.current_config();
    let limit = limit_for_route(route_key, &config.rate_limits);
    let key = format!("{ip}:{route_key}");
    let now = Instant::now();
    let window = Duration::from_secs(60);

    match state.rate_store.entry(key) {
        Entry::Occupied(mut entry) => {
            let rate_state = entry.get_mut();
            if now.duration_since(rate_state.window_started) >= window {
                rate_state.window_started = now;
                rate_state.hits = 1;
                None
            } else if rate_state.hits >= limit {
                let elapsed = now.duration_since(rate_state.window_started);
                let retry_after_secs = window.saturating_sub(elapsed).as_secs().max(1);
                Some(RateLimitMetadata {
                    limit,
                    remaining: 0,
                    retry_after_secs,
                })
            } else {
                rate_state.hits += 1;
                None
            }
        }
        Entry::Vacant(entry) => {
            entry.insert(RateWindow {
                window_started: now,
                hits: 1,
            });
            None
        }
    }
}

fn limit_for_route(route_key: &str, limits: &RateLimits) -> u32 {
    match route_key {
        "login" => limits.login_per_minute,
        "transfer" => limits.transfer_per_minute,
        "balance" => limits.balance_per_minute,
        _ => limits.default_per_minute,
    }
}

fn build_event(
    ip: &str,
    path: &str,
    rule: SecurityRule,
    severity: Severity,
    message: &str,
) -> SecurityEvent {
    SecurityEvent {
        id: Uuid::now_v7(),
        timestamp: Utc::now(),
        ip: ip.to_string(),
        path: path.to_string(),
        rule,
        severity,
        message: message.to_string(),
    }
}

pub fn truncate_for_inspection(body: &str, limit: usize) -> String {
    body.chars().take(limit).collect()
}

/// Inspect selected request headers for WAF rule violations.
///
/// Attackers may inject payloads into headers like User-Agent, Referer,
/// Cookie, or Origin to bypass WAF inspection that only examines the URL
/// path and body.
pub fn inspect_headers(
    state: &AppState,
    headers: &HeaderMap,
    ip: &str,
    path: &str,
) -> Option<GuardFailure> {
    const INSPECTABLE: &[&str] = &["user-agent", "referer", "cookie", "origin"];
    for name in INSPECTABLE {
        if let Some(value) = headers.get(*name).and_then(|v| v.to_str().ok()) {
            if let Some((code, rule, message)) = state.waf.inspect(value) {
                return Some(GuardFailure {
                    status: StatusCode::FORBIDDEN,
                    decision: RequestDecision::Blocked,
                    error: ApiError::new(code, format!("{message} (in header: {name})")),
                    security_event: Some(build_event(
                        ip,
                        path,
                        rule,
                        Severity::Critical,
                        &format!("{message} in header {name}"),
                    )),
                    rate_limit: None,
                });
            }
        }
    }
    None
}
