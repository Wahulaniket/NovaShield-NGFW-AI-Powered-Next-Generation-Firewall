use anyhow::Context;
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub tls_listen_addr: String,
    pub backend_base_url: String,
    pub request_timeout_ms: u64,
    pub dashboard_history_limit: usize,
    pub max_inspection_body_bytes: usize,
    pub websocket_ping_interval_secs: u64,
    pub jwt_secret: String,
    pub tls: TlsConfig,
    pub rate_limits: RateLimits,
    pub blacklist: Vec<BlacklistConfigEntry>,
    pub upstream: UpstreamPoolConfig,
    #[serde(default = "default_ai_engine_url")]
    pub ai_engine_url: String,
    #[serde(default = "default_ai_timeout_ms")]
    pub ai_timeout_ms: u64,
    #[serde(default = "default_ai_enabled")]
    pub ai_enabled: bool,
    #[serde(default)]
    pub redis_url: String,
}

fn default_ai_engine_url() -> String {
    "http://127.0.0.1:8000".to_string()
}

fn default_ai_timeout_ms() -> u64 {
    500
}

fn default_ai_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlacklistConfigEntry {
    pub ip: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimits {
    pub default_per_minute: u32,
    pub login_per_minute: u32,
    pub transfer_per_minute: u32,
    pub balance_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamPoolConfig {
    pub max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
}

impl GatewayConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read gateway config at {}", path.display()))?;
        let mut config: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse gateway config at {}", path.display()))?;

        // Override sensitive fields from environment variables
        if let Ok(secret) = std::env::var("NOVA_JWT_SECRET") {
            config.jwt_secret = secret;
        }
        if let Ok(url) = std::env::var("NOVA_AI_ENGINE_URL") {
            config.ai_engine_url = url;
        }
        if let Ok(url) = std::env::var("NOVA_REDIS_URL") {
            config.redis_url = url;
        }
        if let Ok(url) = std::env::var("NOVA_BACKEND_URL") {
            config.backend_base_url = url;
        }
        if let Ok(val) = std::env::var("NOVA_AI_ENABLED") {
            config.ai_enabled = val == "true" || val == "1";
        }

        Ok(config)
    }
}
