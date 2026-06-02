use anyhow::Context;
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub listen_addr: String,
    pub jwt_secret: String,
    pub token_ttl_secs: u64,
    pub issuer: String,
}

impl BackendConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read backend config at {}", path.display()))?;
        let mut config: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse backend config at {}", path.display()))?;

        // Override sensitive fields from environment variables
        if let Ok(secret) = std::env::var("NOVA_JWT_SECRET") {
            config.jwt_secret = secret;
        }

        Ok(config)
    }
}
