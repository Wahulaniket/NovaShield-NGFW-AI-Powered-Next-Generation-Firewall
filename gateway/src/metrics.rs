use chrono::Utc;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use shared::{
    BlacklistedIpEntry, DashboardSnapshot, LiveEvent, RequestDecision, RequestLogEntry,
    SecurityEvent, SystemNotice, TrafficCounters,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{RwLock, broadcast};

#[derive(Clone)]
pub struct Observability {
    counters: Arc<Counters>,
    recent_logs: Arc<RwLock<VecDeque<RequestLogEntry>>>,
    recent_security_events: Arc<RwLock<VecDeque<SecurityEvent>>>,
    stream: broadcast::Sender<LiveEvent>,
    history_limit: usize,
    prometheus: Arc<PrometheusBundle>,
}

struct Counters {
    total_requests: AtomicU64,
    allowed_requests: AtomicU64,
    blocked_requests: AtomicU64,
    rate_limited_requests: AtomicU64,
    auth_failures: AtomicU64,
    upstream_errors: AtomicU64,
    active_websockets: AtomicU64,
    ai_blocked_requests: AtomicU64,
}

struct PrometheusBundle {
    registry: Registry,
    total_requests: IntCounter,
    allowed_requests: IntCounter,
    blocked_requests: IntCounter,
    rate_limited_requests: IntCounter,
    auth_failures: IntCounter,
    upstream_errors: IntCounter,
    active_websockets: IntGauge,
    ai_blocked_requests: IntCounter,
}

impl Observability {
    pub fn new(history_limit: usize) -> anyhow::Result<Self> {
        let registry = Registry::new();
        let total_requests = IntCounter::new("nova_total_requests", "All gateway requests")?;
        let allowed_requests =
            IntCounter::new("nova_allowed_requests", "Requests successfully forwarded")?;
        let blocked_requests = IntCounter::new(
            "nova_blocked_requests",
            "Requests blocked by security filters",
        )?;
        let rate_limited_requests = IntCounter::new(
            "nova_rate_limited_requests",
            "Requests blocked by rate limiting",
        )?;
        let auth_failures =
            IntCounter::new("nova_auth_failures", "Requests rejected by JWT validation")?;
        let upstream_errors = IntCounter::new(
            "nova_upstream_errors",
            "Requests that failed against upstream",
        )?;
        let active_websockets = IntGauge::new(
            "nova_active_websockets",
            "Active dashboard websocket sessions",
        )?;
        let ai_blocked_requests = IntCounter::new(
            "nova_ai_blocked_requests",
            "Requests blocked by AI engine",
        )?;

        registry.register(Box::new(total_requests.clone()))?;
        registry.register(Box::new(allowed_requests.clone()))?;
        registry.register(Box::new(blocked_requests.clone()))?;
        registry.register(Box::new(rate_limited_requests.clone()))?;
        registry.register(Box::new(auth_failures.clone()))?;
        registry.register(Box::new(upstream_errors.clone()))?;
        registry.register(Box::new(active_websockets.clone()))?;
        registry.register(Box::new(ai_blocked_requests.clone()))?;

        let (stream, _) = broadcast::channel(512);

        Ok(Self {
            counters: Arc::new(Counters {
                total_requests: AtomicU64::new(0),
                allowed_requests: AtomicU64::new(0),
                blocked_requests: AtomicU64::new(0),
                rate_limited_requests: AtomicU64::new(0),
                auth_failures: AtomicU64::new(0),
                upstream_errors: AtomicU64::new(0),
                active_websockets: AtomicU64::new(0),
                ai_blocked_requests: AtomicU64::new(0),
            }),
            recent_logs: Arc::new(RwLock::new(VecDeque::with_capacity(history_limit))),
            recent_security_events: Arc::new(RwLock::new(VecDeque::with_capacity(history_limit))),
            stream,
            history_limit,
            prometheus: Arc::new(PrometheusBundle {
                registry,
                total_requests,
                allowed_requests,
                blocked_requests,
                rate_limited_requests,
                auth_failures,
                upstream_errors,
                active_websockets,
                ai_blocked_requests,
            }),
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LiveEvent> {
        self.stream.subscribe()
    }

    pub async fn record_request(&self, entry: RequestLogEntry) {
        self.counters.total_requests.fetch_add(1, Ordering::Relaxed);
        self.prometheus.total_requests.inc();

        match entry.decision {
            RequestDecision::Allowed => {
                self.counters
                    .allowed_requests
                    .fetch_add(1, Ordering::Relaxed);
                self.prometheus.allowed_requests.inc();
            }
            RequestDecision::Blocked => {
                self.counters
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                self.prometheus.blocked_requests.inc();
            }
            RequestDecision::RateLimited => {
                self.counters
                    .rate_limited_requests
                    .fetch_add(1, Ordering::Relaxed);
                self.prometheus.rate_limited_requests.inc();
            }
            RequestDecision::AuthFailed => {
                self.counters.auth_failures.fetch_add(1, Ordering::Relaxed);
                self.prometheus.auth_failures.inc();
            }
            RequestDecision::UpstreamError => {
                self.counters
                    .upstream_errors
                    .fetch_add(1, Ordering::Relaxed);
                self.prometheus.upstream_errors.inc();
            }
            RequestDecision::AiBlocked => {
                self.counters
                    .ai_blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                self.prometheus.ai_blocked_requests.inc();
            }
        }

        let mut logs = self.recent_logs.write().await;
        if logs.len() >= self.history_limit {
            logs.pop_front();
        }
        logs.push_back(entry.clone());
        let _ = self.stream.send(LiveEvent::RequestLog { entry });
    }

    pub async fn record_security(&self, event: SecurityEvent) {
        let mut events = self.recent_security_events.write().await;
        if events.len() >= self.history_limit {
            events.pop_front();
        }
        events.push_back(event.clone());
        let _ = self.stream.send(LiveEvent::SecurityEvent { entry: event });
    }

    pub async fn record_notice(&self, notice: SystemNotice) {
        let _ = self.stream.send(LiveEvent::SystemNotice { notice });
    }

    pub async fn snapshot(&self, blacklisted_ips: Vec<BlacklistedIpEntry>) -> DashboardSnapshot {
        let logs = self.recent_logs.read().await;
        let events = self.recent_security_events.read().await;

        DashboardSnapshot {
            generated_at: Utc::now(),
            counters: TrafficCounters {
                total_requests: self.counters.total_requests.load(Ordering::Relaxed),
                allowed_requests: self.counters.allowed_requests.load(Ordering::Relaxed),
                blocked_requests: self.counters.blocked_requests.load(Ordering::Relaxed),
                rate_limited_requests: self.counters.rate_limited_requests.load(Ordering::Relaxed),
                auth_failures: self.counters.auth_failures.load(Ordering::Relaxed),
                upstream_errors: self.counters.upstream_errors.load(Ordering::Relaxed),
                active_websockets: self.counters.active_websockets.load(Ordering::Relaxed),
                ai_blocked_requests: self.counters.ai_blocked_requests.load(Ordering::Relaxed),
            },
            blacklisted_ips,
            recent_logs: logs.iter().cloned().collect(),
            recent_security_events: events.iter().cloned().collect(),
        }
    }

    pub fn websocket_connected(&self) {
        self.counters
            .active_websockets
            .fetch_add(1, Ordering::Relaxed);
        self.prometheus.active_websockets.inc();
    }

    pub fn websocket_disconnected(&self) {
        self.counters
            .active_websockets
            .fetch_sub(1, Ordering::Relaxed);
        self.prometheus.active_websockets.dec();
    }

    pub fn render_prometheus(&self) -> anyhow::Result<String> {
        let families = self.prometheus.registry.gather();
        let mut encoded = Vec::new();
        TextEncoder::new().encode(&families, &mut encoded)?;
        Ok(String::from_utf8(encoded)?)
    }
}
