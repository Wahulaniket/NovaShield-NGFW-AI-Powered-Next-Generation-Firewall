use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum AiDecision {
    Allow,
    Block,
    Fallback,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiRequest {
    pub ip: String,
    pub path: String,
    pub method: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiResponse {
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
}

/// Query the AI engine for a threat assessment of the incoming request.
///
/// Returns `AiDecision::Fallback` (fail-open) when the AI engine is
/// unreachable or responds with an unexpected payload. This prevents the AI
/// service from becoming a single point of failure.
pub async fn check(
    client: &Client,
    ai_url: &str,
    timeout_ms: u64,
    request: &AiRequest,
) -> AiDecision {
    let url = format!("{}/predict", ai_url.trim_end_matches('/'));

    let result = client
        .post(&url)
        .json(request)
        .timeout(Duration::from_millis(timeout_ms))
        .send()
        .await;

    match result {
        Ok(response) => {
            if !response.status().is_success() {
                warn!(
                    status = %response.status(),
                    "AI engine returned non-success status, falling back to allow"
                );
                return AiDecision::Fallback;
            }

            match response.json::<AiResponse>().await {
                Ok(ai_response) => {
                    let decision_str = ai_response
                        .decision
                        .as_deref()
                        .unwrap_or("allow");

                    let decision = if decision_str.eq_ignore_ascii_case("block") {
                        AiDecision::Block
                    } else {
                        AiDecision::Allow
                    };

                    info!(
                        ip = %request.ip,
                        path = %request.path,
                        ai_decision = ?decision,
                        label = ?ai_response.label,
                        confidence = ?ai_response.confidence,
                        "AI engine verdict"
                    );

                    decision
                }
                Err(error) => {
                    warn!(%error, "failed to parse AI engine response, falling back to allow");
                    AiDecision::Fallback
                }
            }
        }
        Err(error) => {
            if error.is_timeout() {
                warn!("AI engine timed out after {}ms, falling back to allow", timeout_ms);
            } else {
                warn!(%error, "AI engine request failed, falling back to allow");
            }
            AiDecision::Fallback
        }
    }
}
