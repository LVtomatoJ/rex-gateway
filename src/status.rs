use std::time::Instant;
use serde_json::{json, Value};
use crate::{discovery::DiscoverySnapshot, metrics::MetricsSnapshot, pool::Upstream};

/// Strips credentials from an upstream URL before it is displayed: userinfo (`user:pass@`),
/// query string and fragment are removed; scheme, host, port and path are kept.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') { Some(i) => rest.split_at(i), None => (rest, "") };
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    match scheme { Some(scheme) => format!("{scheme}://{host}{path}"), None => format!("{host}{path}") }
}

/// Builds the `/status` JSON. `upstreams` must already be filtered by the caller's ACL
/// (see `UpstreamPool::list_allowed`). Counters and discovery health are gateway-wide.
pub fn build(upstreams: &[Upstream], pending_tickets: usize, counters: MetricsSnapshot, discovery: DiscoverySnapshot, now: Instant) -> Value {
    json!({
        "upstreams": upstreams.iter().map(|u| json!({
            "id": u.id,
            "url": redact_url(&u.url),
            "source": u.source.as_str(),
            "state": u.state.as_str(),
            "latency_ms": u.latency_ms,
            "consecutive_failures": u.consecutive_failures,
            // Errors may quote the URL; make sure they cannot leak embedded credentials either.
            "last_error": u.last_error.as_ref().map(|e| e.replace(&u.url, &redact_url(&u.url))),
            "last_probe_age_ms": u.last_probe.map(|t| now.saturating_duration_since(t).as_millis() as u64),
            "session_count": u.session_count,
            "reserved_session_count": u.reserved_sessions,
            "effective_session_count": u.session_count + u.reserved_sessions,
            "tags": u.tags,
            "description": u.description,
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
        "discovery": {
            "enabled": discovery.enabled,
            "mode": discovery.mode,
            "last_success_age_ms": discovery.last_success_age_ms,
            "last_error": discovery.last_error,
            "last_error_age_ms": discovery.last_error_age_ms,
            "last_applied": discovery.last_applied,
            "refresh_count": discovery.refresh_count,
            "error_count": discovery.error_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryHealth;
    use crate::pool::{Source, UpstreamPool, UpstreamState};

    fn disc() -> crate::discovery::DiscoverySnapshot {
        DiscoveryHealth::disabled().snapshot(Instant::now())
    }

    #[test]
    fn redacts_userinfo_query_and_fragment() {
        assert_eq!(redact_url("http://127.0.0.1:7297"), "http://127.0.0.1:7297");
        assert_eq!(redact_url("https://u:p%40ss@host.ts.net/rex?token=abc&x=1#frag"), "https://host.ts.net/rex");
        assert_eq!(redact_url("https://secret@host:8443/"), "https://host:8443/");
        assert_eq!(redact_url("http://a@b@host:1"), "http://host:1", "last @ delimits userinfo");
        assert_eq!(redact_url("https://host?token=abc"), "https://host");
        assert_eq!(redact_url("https://host#x"), "https://host");
        assert_eq!(redact_url("http://[::1]:7297/x"), "http://[::1]:7297/x");
        assert_eq!(redact_url("user:pw@host:1/p?q=1"), "host:1/p", "schemeless");
        assert_eq!(redact_url("http://u:p@host/a@b"), "http://host/a@b", "@ in the path is not userinfo");
    }

    #[tokio::test]
    async fn status_json_never_contains_url_credentials() {
        let pool = UpstreamPool::new();
        let url = "https://bob:hunter2@h.example:9/rex?key=SECRETKEY";
        pool.upsert("x", url, Source::Manual).await;
        pool.mark_failure("x", format!("connect to {url} failed")).await;
        let body = build(&pool.list_allowed(&["*".into()]).await, 0, MetricsSnapshot::default(), disc(), Instant::now()).to_string();
        for leaked in ["bob", "hunter2", "SECRETKEY", "key="] { assert!(!body.contains(leaked), "{leaked} leaked in {body}"); }
        assert!(body.contains("https://h.example:9/rex"));
    }

    #[tokio::test]
    async fn builds_json_and_filters_by_acl() {
        let pool = UpstreamPool::new();
        pool.upsert("a", "http://a:1", Source::Manual).await;
        pool.upsert("b", "http://b:2", Source::Tailnet).await;
        pool.upsert("c", "http://c:3", Source::Lan).await;
        pool.mark("a", UpstreamState::Online, Some(12), 3).await;
        pool.mark_failure("b", "connection refused".into()).await;
        let counters = MetricsSnapshot { tickets_issued: 5, tickets_consumed: 3, tickets_expired: 1, tickets_evicted: 1, active_control: 2, active_data: 1 };

        let all = build(&pool.list_allowed(&["*".into()]).await, 4, counters, disc(), Instant::now());
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
        assert_eq!(all["discovery"], json!({
            "enabled": false, "mode": "none", "last_success_age_ms": null, "last_error": null,
            "last_error_age_ms": null, "last_applied": false, "refresh_count": 0, "error_count": 0,
        }));

        let some = build(&pool.list_allowed(&["b".into(), "nonexistent".into()]).await, 0, counters, disc(), Instant::now());
        assert_eq!(some["upstreams"].as_array().unwrap().len(), 1);
        assert_eq!(some["upstreams"][0]["id"], "b");
        let none = build(&pool.list_allowed(&[]).await, 0, counters, disc(), Instant::now());
        assert!(none["upstreams"].as_array().unwrap().is_empty());
    }

    #[test]
    fn discovery_object_reflects_health_snapshot() {
        let health = DiscoveryHealth::enabled("file");
        health.record_ok(true);
        health.record_err("bad json".into());
        let snap = health.snapshot(Instant::now());
        let body = build(&[], 0, MetricsSnapshot::default(), snap, Instant::now());
        assert_eq!(body["discovery"]["enabled"], true);
        assert_eq!(body["discovery"]["mode"], "file");
        assert_eq!(body["discovery"]["last_error"], "bad json");
        assert_eq!(body["discovery"]["last_applied"], false);
        assert_eq!(body["discovery"]["refresh_count"], 1);
        assert_eq!(body["discovery"]["error_count"], 1);
        assert!(body["discovery"]["last_success_age_ms"].is_u64());
        assert!(body["discovery"]["last_error_age_ms"].is_u64());
    }

}
