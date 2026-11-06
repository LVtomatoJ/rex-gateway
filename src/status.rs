use std::time::Instant;
use serde_json::{json, Value};
use crate::{metrics::MetricsSnapshot, pool::Upstream};

/// Builds the `/status` JSON. `upstreams` must already be filtered by the caller's ACL
/// (see `UpstreamPool::list_allowed`). Counters are gateway-wide.
pub fn build(upstreams: &[Upstream], pending_tickets: usize, counters: MetricsSnapshot, now: Instant) -> Value {
    json!({
        "upstreams": upstreams.iter().map(|u| json!({
            "id": u.id,
            "url": u.url,
            "source": u.source.as_str(),
            "state": u.state.as_str(),
            "latency_ms": u.latency_ms,
            "consecutive_failures": u.consecutive_failures,
            "last_error": u.last_error,
            "last_probe_age_ms": u.last_probe.map(|t| now.saturating_duration_since(t).as_millis() as u64),
            "session_count": u.session_count,
        })).collect::<Vec<_>>(),
        "counters": {
            "pending_tickets": pending_tickets,
            "active_control_connections": counters.active_control,
            "active_data_streams": counters.active_data,
            "tickets_issued": counters.tickets_issued,
            "tickets_consumed": counters.tickets_consumed,
            "tickets_expired": counters.tickets_expired,
            "tickets_evicted": counters.tickets_evicted,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{Source, UpstreamPool, UpstreamState};

    #[tokio::test]
    async fn builds_json_and_filters_by_acl() {
        let pool = UpstreamPool::new();
        pool.upsert("a", "http://a:1", Source::Manual).await;
        pool.upsert("b", "http://b:2", Source::Tailnet).await;
        pool.upsert("c", "http://c:3", Source::Lan).await;
        pool.mark("a", UpstreamState::Online, Some(12), 3).await;
        pool.mark_failure("b", "connection refused".into()).await;
        let counters = MetricsSnapshot { tickets_issued: 5, tickets_consumed: 3, tickets_expired: 1, tickets_evicted: 1, active_control: 2, active_data: 1 };

        let all = build(&pool.list_allowed(&["*".into()]).await, 4, counters, Instant::now());
        let ups = all["upstreams"].as_array().unwrap();
        assert_eq!(ups.iter().map(|u| u["id"].as_str().unwrap()).collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(ups[0]["state"], "Online");
        assert_eq!(ups[0]["source"], "Manual");
        assert_eq!(ups[0]["url"], "http://a:1");
        assert_eq!(ups[0]["latency_ms"], 12);
        assert_eq!(ups[0]["consecutive_failures"], 0);
        assert!(ups[0]["last_error"].is_null());
        assert!(ups[0]["last_probe_age_ms"].is_u64());
        assert_eq!(ups[1]["state"], "Degraded");
        assert_eq!(ups[1]["source"], "Tailnet");
        assert_eq!(ups[1]["consecutive_failures"], 1);
        assert_eq!(ups[1]["last_error"], "connection refused");
        assert!(ups[1]["latency_ms"].is_null());
        assert_eq!(ups[2]["state"], "Unknown");
        assert_eq!(ups[2]["source"], "Lan");
        assert!(ups[2]["last_probe_age_ms"].is_null());
        assert_eq!(all["counters"], json!({
            "pending_tickets": 4, "active_control_connections": 2, "active_data_streams": 1,
            "tickets_issued": 5, "tickets_consumed": 3, "tickets_expired": 1, "tickets_evicted": 1,
        }));

        let some = build(&pool.list_allowed(&["b".into(), "nonexistent".into()]).await, 0, counters, Instant::now());
        assert_eq!(some["upstreams"].as_array().unwrap().len(), 1);
        assert_eq!(some["upstreams"][0]["id"], "b");
        let none = build(&pool.list_allowed(&[]).await, 0, counters, Instant::now());
        assert!(none["upstreams"].as_array().unwrap().is_empty());
    }
}
