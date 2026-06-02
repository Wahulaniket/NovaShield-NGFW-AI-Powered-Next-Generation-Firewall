import { useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

const SNAPSHOT_URL = '/api/admin/snapshot';
const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/live`;
const PIE_COLORS = ['#1b998b', '#ff9f1c', '#ef476f', '#118ab2', '#a855f7', '#735d78'];

function formatClock(value) {
  return new Date(value).toLocaleTimeString();
}

function buildTimeline(logs) {
  return logs.slice(-30).map((entry) => ({
    time: formatClock(entry.timestamp),
    latency: entry.latency_ms,
    status: entry.status,
    blocked:
      entry.decision === 'blocked' ||
      entry.decision === 'rate_limited' ||
      entry.decision === 'auth_failed' ||
      entry.decision === 'ai_blocked'
        ? 1
        : 0,
  }));
}

function App() {
  const [snapshot, setSnapshot] = useState(null);
  const [connectionState, setConnectionState] = useState('connecting');

  useEffect(() => {
    let ws;
    let reconnectTimer;

    async function loadSnapshot() {
      try {
        const response = await fetch(SNAPSHOT_URL);
        if (response.ok) {
          const data = await response.json();
          setSnapshot(data);
        }
      } catch {
        // Snapshot may require admin auth; WebSocket will provide data
      }
    }

    function connect() {
      setConnectionState('connecting');
      ws = new WebSocket(WS_URL);

      ws.onopen = () => setConnectionState('live');
      ws.onclose = () => {
        setConnectionState('reconnecting');
        reconnectTimer = window.setTimeout(connect, 2000);
      };
      ws.onerror = () => setConnectionState('error');
      ws.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        setSnapshot((current) => applyLiveEvent(current, payload));
      };
    }

    loadSnapshot();
    connect();

    return () => {
      window.clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, []);

  const counters = snapshot?.counters ?? {
    total_requests: 0,
    allowed_requests: 0,
    blocked_requests: 0,
    rate_limited_requests: 0,
    auth_failures: 0,
    upstream_errors: 0,
    active_websockets: 0,
    ai_blocked_requests: 0,
  };

  const timeline = useMemo(
    () => buildTimeline(snapshot?.recent_logs ?? []),
    [snapshot?.recent_logs],
  );

  const mix = useMemo(
    () => [
      { name: 'Allowed', value: counters.allowed_requests },
      { name: 'Blocked', value: counters.blocked_requests },
      { name: 'Rate Limited', value: counters.rate_limited_requests },
      { name: 'Auth Failures', value: counters.auth_failures },
      { name: 'AI Blocked', value: counters.ai_blocked_requests },
      { name: 'Upstream Errors', value: counters.upstream_errors },
    ],
    [counters],
  );

  return (
    <div className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">AI-Powered Next-Generation Firewall</p>
          <h1>NovaShield Command Center</h1>
          <p className="lead">
            Real-time gateway telemetry, AI threat classification, security events,
            and streaming performance signals.
          </p>
        </div>
        <div className={`status-pill status-${connectionState}`}>
          {connectionState}
        </div>
      </header>

      <section className="card-grid">
        <MetricCard title="Total Requests" value={counters.total_requests} />
        <MetricCard title="Allowed" value={counters.allowed_requests} accent="good" />
        <MetricCard title="WAF Blocked" value={counters.blocked_requests} accent="bad" />
        <MetricCard title="AI Blocked" value={counters.ai_blocked_requests} accent="ai" />
        <MetricCard
          title="Rate Limited"
          value={counters.rate_limited_requests}
          accent="warn"
        />
        <MetricCard title="JWT Failures" value={counters.auth_failures} />
        <MetricCard
          title="WebSocket Clients"
          value={counters.active_websockets}
          accent="cool"
        />
      </section>

      <section className="visual-grid">
        <article className="panel wide">
          <div className="panel-head">
            <h2>Latency and Block Timeline</h2>
            <span>Last {timeline.length} requests</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="time" stroke="#c8d5d1" />
              <YAxis yAxisId="left" stroke="#c8d5d1" />
              <YAxis yAxisId="right" orientation="right" stroke="#f4b942" />
              <Tooltip />
              <Line
                yAxisId="left"
                type="monotone"
                dataKey="latency"
                stroke="#1b998b"
                strokeWidth={3}
                dot={false}
              />
              <Line
                yAxisId="right"
                type="stepAfter"
                dataKey="blocked"
                stroke="#ef476f"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Traffic Outcome Mix</h2>
            <span>Live totals</span>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={mix} dataKey="value" innerRadius={55} outerRadius={90}>
                {mix.map((entry, index) => (
                  <Cell
                    key={entry.name}
                    fill={PIE_COLORS[index % PIE_COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </article>

        <article className="panel wide">
          <div className="panel-head">
            <h2>Recent Status Codes</h2>
            <span>Operational health</span>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="statusFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#118ab2" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#118ab2" stopOpacity={0.1} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="time" stroke="#c8d5d1" />
              <YAxis stroke="#c8d5d1" />
              <Tooltip />
              <Area
                type="monotone"
                dataKey="status"
                stroke="#118ab2"
                fill="url(#statusFill)"
                strokeWidth={3}
              />
            </AreaChart>
          </ResponsiveContainer>
        </article>
      </section>

      <section className="tables">
        <article className="panel">
          <div className="panel-head">
            <h2>Security Events</h2>
            <span>{snapshot?.recent_security_events?.length ?? 0} recent</span>
          </div>
          <div className="log-list">
            {(snapshot?.recent_security_events ?? [])
              .slice()
              .reverse()
              .map((event) => (
                <div key={event.id} className="log-item danger">
                  <strong>{event.rule}</strong>
                  <span>{event.message}</span>
                  <small>
                    {event.ip} | {event.path} | {formatClock(event.timestamp)}
                  </small>
                </div>
              ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Current Blacklist</h2>
            <span>{snapshot?.blacklisted_ips?.length ?? 0} IPs</span>
          </div>
          <div className="log-list">
            {(snapshot?.blacklisted_ips ?? []).map((entry) => (
              <div key={entry.ip} className="log-item danger">
                <strong>{entry.ip}</strong>
                <span>{entry.reason}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Request Log Stream</h2>
            <span>{snapshot?.recent_logs?.length ?? 0} recent</span>
          </div>
          <div className="log-list">
            {(snapshot?.recent_logs ?? [])
              .slice()
              .reverse()
              .map((entry) => (
                <div key={entry.id} className={`log-item ${entry.decision}`}>
                  <strong>
                    {entry.method} {entry.path}
                  </strong>
                  <span>
                    {entry.ip} | {entry.status} | {entry.latency_ms}ms
                  </span>
                  <small>{formatClock(entry.timestamp)}</small>
                </div>
              ))}
          </div>
        </article>
      </section>
    </div>
  );
}

function MetricCard({ title, value, accent = 'plain' }) {
  return (
    <article className={`metric-card accent-${accent}`}>
      <span>{title}</span>
      <strong>{value}</strong>
    </article>
  );
}

function applyLiveEvent(current, event) {
  const fallback = current ?? {
    generated_at: new Date().toISOString(),
    counters: {
      total_requests: 0,
      allowed_requests: 0,
      blocked_requests: 0,
      rate_limited_requests: 0,
      auth_failures: 0,
      upstream_errors: 0,
      active_websockets: 0,
      ai_blocked_requests: 0,
    },
    blacklisted_ips: [],
    recent_logs: [],
    recent_security_events: [],
  };

  switch (event.event) {
    case 'snapshot':
      return event.snapshot;
    case 'request_log':
      return {
        ...fallback,
        counters: incrementCounters(fallback.counters, event.entry.decision),
        recent_logs: [...fallback.recent_logs.slice(-399), event.entry],
      };
    case 'security_event': {
      const wafRules = [
        'waf_sqli', 'waf_xss', 'waf_traversal', 'waf_command_injection',
        'waf_null_byte', 'waf_crlf', 'waf_ssrf', 'blacklist',
      ];
      const shouldMerge = wafRules.includes(event.entry.rule);
      return {
        ...fallback,
        blacklisted_ips: shouldMerge
          ? mergeBlacklistedIp(fallback.blacklisted_ips, event.entry)
          : fallback.blacklisted_ips,
        recent_security_events: [...fallback.recent_security_events.slice(-399), event.entry],
      };
    }
    default:
      return fallback;
  }
}

function mergeBlacklistedIp(current, event) {
  const reason = event.message
    .replace('request rejected by IP blacklist: ', '')
    .trim();

  if (current.some((entry) => entry.ip === event.ip)) {
    return current.map((entry) =>
      entry.ip === event.ip
        ? {
            ...entry,
            reason:
              shouldReplaceReason(entry.reason, reason) ? reason || entry.reason : entry.reason,
          }
        : entry,
    );
  }

  return [{ ip: event.ip, reason: reason || 'blocked' }, ...current];
}

function shouldReplaceReason(currentReason, nextReason) {
  if (!nextReason) return false;
  if (!currentReason) return true;

  const currentIsJwt = currentReason.toLowerCase().includes('jwt validation');
  const nextIsJwt = nextReason.toLowerCase().includes('jwt validation');

  if (!currentIsJwt && nextIsJwt) {
    return false;
  }

  return true;
}

function incrementCounters(counters, decision) {
  const next = {
    ...counters,
    total_requests: counters.total_requests + 1,
  };

  if (decision === 'allowed') next.allowed_requests += 1;
  if (decision === 'blocked') next.blocked_requests += 1;
  if (decision === 'rate_limited') next.rate_limited_requests += 1;
  if (decision === 'auth_failed') next.auth_failures += 1;
  if (decision === 'upstream_error') next.upstream_errors += 1;
  if (decision === 'ai_blocked') next.ai_blocked_requests += 1;

  return next;
}

export default App;
