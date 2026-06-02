#![allow(dead_code)]

use shared::{BlacklistedIpEntry, RequestLogEntry};
use std::time::Duration;
use tracing::{error, info, warn};

/// Redis-backed persistent storage for blacklists, rate limiting, and event logs.
///
/// When Redis is unavailable, the gateway falls back to in-memory DashMap storage.
/// This module provides an optional overlay — callers should check `is_connected()`.
#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
    connection: Option<redis::aio::MultiplexedConnection>,
}

impl RedisStore {
    /// Attempt to connect to Redis. Returns `None` if the URL is empty or connection fails.
    pub async fn try_connect(url: &str) -> Option<Self> {
        if url.is_empty() {
            info!("Redis URL not configured, using in-memory storage");
            return None;
        }

        let client = match redis::Client::open(url) {
            Ok(client) => client,
            Err(error) => {
                warn!(%error, "failed to create Redis client, using in-memory storage");
                return None;
            }
        };

        match tokio::time::timeout(
            Duration::from_secs(5),
            client.get_multiplexed_async_connection(),
        )
        .await
        {
            Ok(Ok(connection)) => {
                info!("connected to Redis at {}", url);
                Some(Self {
                    client,
                    connection: Some(connection),
                })
            }
            Ok(Err(error)) => {
                warn!(%error, "failed to connect to Redis, using in-memory storage");
                None
            }
            Err(_) => {
                warn!("Redis connection timed out, using in-memory storage");
                None
            }
        }
    }

    fn conn(&self) -> Option<redis::aio::MultiplexedConnection> {
        self.connection.clone()
    }

    // ── Blacklist operations ─────────────────────────────────────────────

    pub async fn add_blacklist(&self, ip: &str, reason: &str) -> bool {
        let Some(mut conn) = self.conn() else {
            return false;
        };
        let result: Result<(), _> =
            redis::cmd("HSET")
                .arg("nova:blacklist")
                .arg(ip)
                .arg(reason)
                .query_async(&mut conn)
                .await;
        if let Err(error) = &result {
            error!(%error, "Redis HSET blacklist failed");
        }
        result.is_ok()
    }

    pub async fn remove_blacklist(&self, ip: &str) -> bool {
        let Some(mut conn) = self.conn() else {
            return false;
        };
        let result: Result<i64, _> =
            redis::cmd("HDEL")
                .arg("nova:blacklist")
                .arg(ip)
                .query_async(&mut conn)
                .await;
        match result {
            Ok(removed) => removed > 0,
            Err(error) => {
                error!(%error, "Redis HDEL blacklist failed");
                false
            }
        }
    }

    pub async fn is_blacklisted(&self, ip: &str) -> Option<String> {
        let Some(mut conn) = self.conn() else {
            return None;
        };
        let result: Result<Option<String>, _> =
            redis::cmd("HGET")
                .arg("nova:blacklist")
                .arg(ip)
                .query_async(&mut conn)
                .await;
        match result {
            Ok(reason) => reason,
            Err(error) => {
                error!(%error, "Redis HGET blacklist failed");
                None
            }
        }
    }

    pub async fn get_blacklist(&self) -> Vec<BlacklistedIpEntry> {
        let Some(mut conn) = self.conn() else {
            return Vec::new();
        };
        let result: Result<Vec<(String, String)>, _> =
            redis::cmd("HGETALL")
                .arg("nova:blacklist")
                .query_async(&mut conn)
                .await;
        match result {
            Ok(pairs) => pairs
                .into_iter()
                .map(|(ip, reason)| BlacklistedIpEntry { ip, reason })
                .collect(),
            Err(error) => {
                error!(%error, "Redis HGETALL blacklist failed");
                Vec::new()
            }
        }
    }

    /// Seed the initial blacklist from config into Redis (only adds, never removes).
    pub async fn seed_blacklist(&self, entries: &[(String, String)]) {
        for (ip, reason) in entries {
            self.add_blacklist(ip, reason).await;
        }
    }

    // ── Rate limiting ────────────────────────────────────────────────────

    /// Check and increment rate limit. Returns `true` if the request is over the limit.
    pub async fn check_rate_limit(&self, ip: &str, route: &str, limit: u32, window_secs: u64) -> Option<(bool, u32)> {
        let Some(mut conn) = self.conn() else {
            return None;
        };
        let key = format!("nova:rate:{}:{}", ip, route);

        // INCR + conditional EXPIRE in a pipeline
        let result: Result<(i64,), _> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(&key)
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                // Set TTL on first hit
                if count == 1 {
                    let _: Result<(), _> = redis::cmd("EXPIRE")
                        .arg(&key)
                        .arg(window_secs)
                        .query_async(&mut conn)
                        .await;
                }
                let over_limit = count as u32 > limit;
                let remaining = if over_limit { 0 } else { limit - count as u32 };
                Some((over_limit, remaining))
            }
            Err(error) => {
                error!(%error, "Redis rate limit check failed");
                None
            }
        }
    }

    // ── Event logs ───────────────────────────────────────────────────────

    pub async fn push_log(&self, entry: &RequestLogEntry) {
        let Some(mut conn) = self.conn() else {
            return;
        };
        let json = match serde_json::to_string(entry) {
            Ok(json) => json,
            Err(_) => return,
        };
        let _: Result<(), _> = redis::pipe()
            .atomic()
            .cmd("LPUSH")
            .arg("nova:logs")
            .arg(&json)
            .cmd("LTRIM")
            .arg("nova:logs")
            .arg(0i64)
            .arg(999i64)
            .query_async(&mut conn)
            .await;
    }

    pub async fn recent_logs(&self, limit: i64) -> Vec<RequestLogEntry> {
        let Some(mut conn) = self.conn() else {
            return Vec::new();
        };
        let result: Result<Vec<String>, _> =
            redis::cmd("LRANGE")
                .arg("nova:logs")
                .arg(0i64)
                .arg(limit - 1)
                .query_async(&mut conn)
                .await;
        match result {
            Ok(entries) => entries
                .iter()
                .filter_map(|json| serde_json::from_str(json).ok())
                .collect(),
            Err(error) => {
                error!(%error, "Redis LRANGE logs failed");
                Vec::new()
            }
        }
    }
}
