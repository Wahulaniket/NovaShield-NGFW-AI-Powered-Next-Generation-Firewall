mod ai_client;
mod auth;
mod config;
mod metrics;
mod proxy;
mod redis_store;
mod security;
mod state;

use axum_server::{Handle, tls_rustls::RustlsConfig};
use config::GatewayConfig;
use shared::{Severity, SystemNotice};
use state::AppState;
use std::{net::SocketAddr, time::Duration};
use tower_http::cors::CorsLayer;
use tracing::info;
use uuid::Uuid;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "gateway=info,tower_http=info,axum=info".to_string()),
        )
        .json()
        .init();

    let config_path = std::env::var("NOVA_CONFIG_PATH")
        .unwrap_or_else(|_| "config/gateway.json".to_string());
    let config = GatewayConfig::load(&config_path)?;
    let state = AppState::from_config(config.clone()).await?;
    state
        .observability
        .record_notice(SystemNotice {
            id: Uuid::now_v7(),
            timestamp: chrono::Utc::now(),
            level: Severity::Info,
            message: format!(
                "gateway booted — backend={} tls={} ai={} redis={}",
                config.backend_base_url,
                if config.tls.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                if config.ai_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                if state.redis.is_some() {
                    "connected"
                } else {
                    "in-memory"
                },
            ),
        })
        .await;

    let app = proxy::router(state).layer(CorsLayer::permissive());

    let http_addr: SocketAddr = config.listen_addr.parse()?;

    if config.tls.enabled {
        let tls_addr: SocketAddr = config.tls_listen_addr.parse()?;
        let tls = RustlsConfig::from_pem_file(config.tls.cert_path, config.tls.key_path).await?;
        let http_handle = Handle::new();
        let tls_handle = Handle::new();
        let shutdown_http = http_handle.clone();
        let shutdown_tls = tls_handle.clone();

        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                shutdown_http.graceful_shutdown(Some(Duration::from_secs(10)));
                shutdown_tls.graceful_shutdown(Some(Duration::from_secs(10)));
            }
        });

        info!(%http_addr, "gateway listening without tls");
        info!(%tls_addr, "gateway listening with tls");

        let http_server = axum_server::bind(http_addr)
            .handle(http_handle)
            .serve(app.clone().into_make_service_with_connect_info::<SocketAddr>());

        let tls_server = axum_server::bind_rustls(tls_addr, tls)
            .handle(tls_handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());

        tokio::try_join!(http_server, tls_server)?;
    } else {
        let handle = Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            }
        });

        info!(%http_addr, "gateway listening without tls");
        axum_server::bind(http_addr)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }

    Ok(())
}
