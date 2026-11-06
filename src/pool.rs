use std::{cmp::Ordering, collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use crate::auth::Authenticator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamState { Unknown, Online, Degraded, Offline }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Tailnet and Lan are reserved for discovery, not static configuration.
pub enum Source { Manual, Tailnet, Lan }
#[derive(Debug, Clone)]
pub struct Upstream {
    pub id: String, pub url: String, pub source: Source, pub state: UpstreamState,
    pub latency_ms: Option<u64>, pub session_count: usize, pub last_probe: Option<Instant>,
    pub consecutive_failures: u32, pub last_error: Option<String>,
}
impl UpstreamState {
    pub fn as_str(self) -> &'static str {
        match self { Self::Unknown => "Unknown", Self::Online => "Online", Self::Degraded => "Degraded", Self::Offline => "Offline" }
    }
    /// Online and Degraded are eligible for create / default routing (Degraded is lower priority).
    pub fn is_routable(self) -> bool {
        matches!(self, Self::Online | Self::Degraded)
    }
}
impl Source {
    pub fn as_str(self) -> &'static str {
        match self { Self::Manual => "Manual", Self::Tailnet => "Tailnet", Self::Lan => "Lan" }
    }
}
pub const OFFLINE_AFTER: u32 = 2;
#[derive(Clone)]
pub struct UpstreamPool { inner: Arc<RwLock<HashMap<String, Upstream>>> }

/// Least sessions, then lowest known latency (`None` after `Some`), then id ascending.
fn cmp_create_preference(a: &Upstream, b: &Upstream) -> Ordering {
    a.session_count.cmp(&b.session_count)
        .then_with(|| match (a.latency_ms, b.latency_ms) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| a.id.cmp(&b.id))
}

impl UpstreamPool {
    pub fn new() -> Self { Self { inner: Arc::new(RwLock::new(HashMap::new())) } }
    pub async fn upsert(&self, id: &str, url: &str, source: Source) {
        self.inner.write().await.entry(id.to_owned()).and_modify(|u| { u.url = url.to_owned(); u.source = source; }).or_insert_with(|| Upstream {
            id: id.to_owned(), url: url.to_owned(), source, state: UpstreamState::Unknown,
            latency_ms: None, session_count: 0, last_probe: None,
            consecutive_failures: 0, last_error: None,
        });
    }
    pub async fn get(&self, id: &str) -> Option<Upstream> { self.inner.read().await.get(id).cloned() }
/// Allowed Online|Degraded upstreams, Online group first then Degraded, each sorted by create preference.
    pub async fn list_allowed_routable(&self, acl: &[String]) -> Vec<Upstream> {
        let mut online = Vec::new();
        let mut degraded = Vec::new();
        for upstream in self.inner.read().await.values() {
            if !Authenticator::permits(acl, &upstream.id) { continue; }
            match upstream.state {
                UpstreamState::Online => online.push(upstream.clone()),
                UpstreamState::Degraded => degraded.push(upstream.clone()),
                _ => {}
            }
        }
        online.sort_by(cmp_create_preference);
        degraded.sort_by(cmp_create_preference);
        online.extend(degraded);
        online
    }
    /// Pick an upstream for `session.create` / hostless default routing:
    /// prefer allowed Online (least `session_count`, then lowest `latency_ms`, then `id`);
    /// if none, the same order among allowed Degraded.
    pub async fn pick_for_create(&self, acl: &[String]) -> Option<Upstream> {
        self.list_allowed_routable(acl).await.into_iter().next()
    }
    /// All upstreams the ACL permits, in any state, sorted by id (for `/status`).
    pub async fn list_allowed(&self, acl: &[String]) -> Vec<Upstream> {
        let mut result: Vec<_> = self.inner.read().await.values().filter(|u| Authenticator::permits(acl, &u.id)).cloned().collect();
        result.sort_by(|a,b| a.id.cmp(&b.id)); result
    }
    /// Records a completed probe that reached the upstream. Resets the failure streak and
    /// stores `error` only for soft problems (e.g. a malformed reply) that still count as reachable.
    #[cfg(test)]
    pub async fn mark(&self, id: &str, state: UpstreamState, latency: Option<u64>, count: usize) {
        self.mark_with_error(id, state, latency, count, None).await
    }
    pub async fn mark_with_error(&self, id: &str, state: UpstreamState, latency: Option<u64>, count: usize, error: Option<String>) {
        if let Some(upstream) = self.inner.write().await.get_mut(id) {
            upstream.state = state; upstream.latency_ms = latency; upstream.session_count = count; upstream.last_probe = Some(Instant::now());
            upstream.consecutive_failures = 0; upstream.last_error = error;
        }
    }
    /// Records a failed probe: bumps the failure streak and stores the error. First failure =
    /// Degraded, `OFFLINE_AFTER` consecutive failures = Offline. Returns the new streak.
    pub async fn mark_failure(&self, id: &str, error: String) -> u32 {
        let mut guard = self.inner.write().await;
        let Some(upstream) = guard.get_mut(id) else { return 0 };
        upstream.consecutive_failures += 1;
        upstream.state = if upstream.consecutive_failures >= OFFLINE_AFTER { UpstreamState::Offline } else { UpstreamState::Degraded };
        upstream.latency_ms = None; upstream.session_count = 0; upstream.last_probe = Some(Instant::now());
        upstream.last_error = Some(error);
        upstream.consecutive_failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn state_transitions_and_acl() {
        let pool = UpstreamPool::new(); pool.upsert("a", "http://a", Source::Manual).await;
        pool.upsert("b", "http://b", Source::Lan).await;
        assert_eq!(pool.inner.read().await["a"].state, UpstreamState::Unknown);
        for (state, latency, count) in [(UpstreamState::Degraded,Some(600),0),(UpstreamState::Online,Some(10),2),(UpstreamState::Offline,None,0)] {
            pool.mark("a",state,latency,count).await;
            let u=pool.inner.read().await["a"].clone();
            assert_eq!(u.state,state); assert_eq!(u.latency_ms,latency); assert_eq!(u.session_count,count); assert!(u.last_probe.is_some());
        }
        pool.mark("a", UpstreamState::Online, Some(10),2).await; pool.mark("b", UpstreamState::Online,Some(20),1).await;
        assert_eq!(pool.list_allowed_routable(&["a".into()]).await.len(),1);
        assert_eq!(pool.list_allowed_routable(&["*".into()]).await.len(),2);
        assert_eq!(pool.list_allowed_routable(&[]).await.len(),0);
    }

    #[tokio::test]
    async fn failures_accumulate_and_reset() {
        let pool = UpstreamPool::new(); pool.upsert("a", "http://a", Source::Manual).await;
        assert_eq!(pool.mark_failure("a", "boom".into()).await, 1);
        let u = pool.get("a").await.unwrap();
        assert_eq!((u.state, u.consecutive_failures, u.last_error.as_deref(), u.latency_ms), (UpstreamState::Degraded, 1, Some("boom"), None));
        assert_eq!(pool.mark_failure("a", "bang".into()).await, 2);
        let u = pool.get("a").await.unwrap();
        assert_eq!((u.state, u.last_error.as_deref()), (UpstreamState::Offline, Some("bang")));
        pool.mark("a", UpstreamState::Online, Some(5), 0).await;
        let u = pool.get("a").await.unwrap();
        assert_eq!((u.state, u.consecutive_failures, u.last_error.clone()), (UpstreamState::Online, 0, None));
        assert_eq!(pool.mark_failure("missing", "x".into()).await, 0);
    }

    #[tokio::test]
    async fn list_allowed_includes_all_states() {
        let pool = UpstreamPool::new(); pool.upsert("b", "http://b", Source::Manual).await; pool.upsert("a", "http://a", Source::Manual).await;
        pool.mark_failure("b", "x".into()).await;
        let ids: Vec<_> = pool.list_allowed(&["*".into()]).await.into_iter().map(|u| u.id).collect();
        assert_eq!(ids, ["a", "b"]);
        assert_eq!(pool.list_allowed(&["b".into()]).await.len(), 1);
        assert!(pool.list_allowed(&[]).await.is_empty());
    }

    #[tokio::test]
    async fn pick_for_create_orders_by_load_latency_then_id() {
        let pool = UpstreamPool::new();
        for id in ["c", "b", "a"] { pool.upsert(id, &format!("http://{id}"), Source::Manual).await; }
        pool.mark("a", UpstreamState::Online, Some(50), 2).await;
        pool.mark("b", UpstreamState::Online, Some(10), 2).await; // same load, lower latency
        pool.mark("c", UpstreamState::Online, Some(5), 5).await;  // higher load
        assert_eq!(pool.pick_for_create(&["*".into()]).await.unwrap().id, "b");

        // None latency sorts after Some
        pool.mark("a", UpstreamState::Online, None, 1).await;
        pool.mark("b", UpstreamState::Online, Some(99), 1).await;
        pool.mark("c", UpstreamState::Online, Some(1), 3).await;
        assert_eq!(pool.pick_for_create(&["*".into()]).await.unwrap().id, "b");

        // Equal load + latency → id ascending
        pool.mark("a", UpstreamState::Online, Some(10), 0).await;
        pool.mark("b", UpstreamState::Online, Some(10), 0).await;
        pool.mark("c", UpstreamState::Online, Some(10), 0).await;
        assert_eq!(pool.pick_for_create(&["*".into()]).await.unwrap().id, "a");
    }

    #[tokio::test]
    async fn pick_for_create_prefers_online_over_degraded_and_respects_acl() {
        let pool = UpstreamPool::new();
        pool.upsert("busy", "http://busy", Source::Manual).await;
        pool.upsert("slow", "http://slow", Source::Manual).await;
        pool.upsert("denied", "http://denied", Source::Manual).await;
        // busy is Online but loaded; slow is Degraded and empty — Online still wins
        pool.mark("busy", UpstreamState::Online, Some(5), 10).await;
        pool.mark("slow", UpstreamState::Degraded, Some(1), 0).await;
        pool.mark("denied", UpstreamState::Online, Some(1), 0).await;
        assert_eq!(pool.pick_for_create(&["busy".into(), "slow".into()]).await.unwrap().id, "busy");

        // No Online in ACL → fall back to Degraded
        pool.mark("busy", UpstreamState::Offline, None, 0).await;
        assert_eq!(pool.pick_for_create(&["busy".into(), "slow".into()]).await.unwrap().id, "slow");

        // Empty ACL / nothing routable
        assert!(pool.pick_for_create(&[]).await.is_none());
        assert!(pool.pick_for_create(&["denied".into()]).await.is_some()); // denied is Online
        pool.mark("denied", UpstreamState::Unknown, None, 0).await;
        assert!(pool.pick_for_create(&["denied".into()]).await.is_none());
        assert!(pool.pick_for_create(&["busy".into()]).await.is_none()); // Offline only
    }

    #[tokio::test]
    async fn list_allowed_routable_online_before_degraded() {
        let pool = UpstreamPool::new();
        pool.upsert("d", "http://d", Source::Manual).await;
        pool.upsert("o", "http://o", Source::Manual).await;
        pool.upsert("x", "http://x", Source::Manual).await;
        pool.mark("d", UpstreamState::Degraded, Some(1), 0).await;
        pool.mark("o", UpstreamState::Online, Some(1), 0).await;
        pool.mark("x", UpstreamState::Offline, None, 0).await;
        let ids: Vec<_> = pool.list_allowed_routable(&["*".into()]).await.into_iter().map(|u| u.id).collect();
        assert_eq!(ids, ["o", "d"]);
    }
}
