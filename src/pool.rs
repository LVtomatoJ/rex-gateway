use std::{collections::HashMap, sync::{Arc,Mutex}, time::{Duration, Instant}};

use crate::auth::Authenticator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamState { Unknown, Online, Degraded, Offline }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Reserved for rex-discover discovery.
pub enum Source { Manual, Tailnet, Lan }
#[derive(Debug, Clone)]
pub struct Upstream {
    pub id: String, pub url: String, pub source: Source, pub state: UpstreamState,
    pub latency_ms: Option<u64>, pub session_count: usize, pub last_probe: Option<Instant>,
    pub consecutive_failures: u32, pub last_error: Option<String>,
    pub tags: Vec<String>, pub description: Option<String>,
    /// Number of recent selects whose create has not completed (or whose TTL has not expired).
    pub reserved_sessions: usize,
    #[doc(hidden)] pub reservations: Vec<Instant>,
}

#[derive(Debug, Clone, Default)]
pub struct TagPreferences { pub prefer: Vec<String>, pub avoid: Vec<String> }
#[cfg_attr(test, derive(Debug))]
pub struct Reservation { pool: UpstreamPool, id: String, expires: Instant, active: bool }
impl Reservation {
    /// Confirm immediately after create returns. The normal probe observes the real session.
    pub fn finish(mut self) { if self.active { self.pool.release_expired_sync(&self.id, self.expires); self.active = false; } }
}
impl Drop for Reservation { fn drop(&mut self) { if self.active { self.pool.release_expired_sync(&self.id, self.expires); self.active = false; } } }

impl UpstreamState {
    pub fn as_str(self) -> &'static str { match self { Self::Unknown => "Unknown", Self::Online => "Online", Self::Degraded => "Degraded", Self::Offline => "Offline" } }
    pub fn is_routable(self) -> bool { matches!(self, Self::Online | Self::Degraded) }
}
impl Source { pub fn as_str(self) -> &'static str { match self { Self::Manual => "Manual", Self::Tailnet => "Tailnet", Self::Lan => "Lan" } } }
pub const OFFLINE_AFTER: u32 = 2;
#[derive(Debug, Clone)]
pub struct UpstreamPool { inner: Arc<Mutex<HashMap<String, Upstream>>> }

fn effective_load(u: &Upstream) -> usize { u.session_count.saturating_add(u.reserved_sessions) }
fn latency_key(u: &Upstream) -> u64 { u.latency_ms.unwrap_or(u64::MAX) }
fn score(u: &Upstream, prefs: &TagPreferences) -> i64 {
    let matched = prefs.prefer.iter().filter(|tag| u.tags.contains(tag)).count() as i64;
    let health = if u.state == UpstreamState::Online { 1_000_000 } else { 0 };
    health + matched * 10_000 - effective_load(u) as i64
}


impl UpstreamPool {
    pub fn new() -> Self { Self { inner: Arc::new(Mutex::new(HashMap::new())) } }
    pub async fn upsert_with_metadata(&self, id: &str, url: &str, source: Source, tags: Vec<String>, description: Option<String>) {
        let mut guard = self.inner.lock().expect("pool mutex");
        let entry = guard.entry(id.to_owned()).or_insert_with(|| Upstream {
            id: id.to_owned(), url: url.to_owned(), source, state: UpstreamState::Unknown,
            latency_ms: None, session_count: 0, last_probe: None, consecutive_failures: 0,
            last_error: None, tags: Vec::new(), description: None, reserved_sessions: 0, reservations: Vec::new(),
        });
        entry.url = url.to_owned(); entry.source = source;
        entry.tags = tags; entry.description = description;
    }
    pub async fn get(&self, id: &str) -> Option<Upstream> { self.inner.lock().expect("pool mutex").get(id).cloned() }
    pub async fn reserve_for_create(&self, acl: &[String], prefs: &TagPreferences, ttl: Duration) -> Result<(Upstream, Reservation), String> {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("pool mutex");
        let allowed: Vec<&Upstream> = guard.values().filter(|u| Authenticator::permits(acl, &u.id)).collect();
        if allowed.is_empty() { return Err("no allowed upstream".into()); }
        if !allowed.iter().any(|u| u.state.is_routable()) { return Err("no routable upstream: all allowed upstreams are Offline or Unknown".into()); }
        if !prefs.prefer.is_empty() && !allowed.iter().any(|u| u.state.is_routable() && prefs.prefer.iter().all(|tag| u.tags.contains(tag))) {
            return Err(format!("no upstream matches required tags [{}]; change tag requirements or wait for a matching upstream", prefs.prefer.join(",")));
        }
        let mut candidates: Vec<Upstream> = allowed.into_iter().filter(|u| u.state.is_routable()
            && prefs.prefer.iter().all(|tag| u.tags.contains(tag))
            && !prefs.avoid.iter().any(|tag| u.tags.contains(tag))).cloned().collect();
        if candidates.is_empty() { return Err("no upstream matches tags: all matching candidates are excluded by avoid_tags".into()); }
        for u in &mut candidates { u.reservations.retain(|at| *at > now); u.reserved_sessions = u.reservations.len(); }
        candidates.sort_by(|a,b| score(b,prefs).cmp(&score(a,prefs)).then_with(|| latency_key(a).cmp(&latency_key(b))).then_with(|| a.id.cmp(&b.id)));
        let selected = candidates.remove(0);
        let expires = now + ttl;
        let upstream = guard.get_mut(&selected.id).expect("selected while locked");
        upstream.reservations.retain(|at| *at > now);
        upstream.reservations.push(expires); upstream.reserved_sessions = upstream.reservations.len();
        drop(guard);
        let reservation = Reservation { pool: self.clone(), id: selected.id.clone(), expires, active: true };
        Ok((selected, reservation))
    }
    fn release_expired_sync(&self, id: &str, expires: Instant) {
        let mut guard = self.inner.lock().expect("pool mutex");
        if let Some(u) = guard.get_mut(id) {
            if let Some(at) = u.reservations.iter().position(|at| *at == expires) { u.reservations.remove(at); }
            u.reserved_sessions = u.reservations.len();
        }
    }
    /// Fallback expiry (also ensures a contended Drop cannot leak a reservation).
    pub async fn reap_reservations(&self) {
        let now = Instant::now();
        for u in self.inner.lock().expect("pool mutex").values_mut() { u.reservations.retain(|at| *at > now); u.reserved_sessions = u.reservations.len(); }
    }
    pub async fn list_allowed(&self, acl: &[String]) -> Vec<Upstream> {
        self.reap_reservations().await;
        let mut result: Vec<_> = self.inner.lock().expect("pool mutex").values().filter(|u| Authenticator::permits(acl, &u.id)).cloned().collect();
        result.sort_by(|a,b| a.id.cmp(&b.id)); result
    }


    pub async fn mark_with_error(&self, id: &str, state: UpstreamState, latency: Option<u64>, count: usize, error: Option<String>) {
        if let Some(upstream) = self.inner.lock().expect("pool mutex").get_mut(id) {
            upstream.state=state; upstream.latency_ms=latency; upstream.session_count=count; upstream.last_probe=Some(Instant::now());
            upstream.consecutive_failures=0; upstream.last_error=error;
        }
    }
    pub async fn mark_failure(&self, id: &str, error: String) -> u32 {
        let mut guard=self.inner.lock().expect("pool mutex");
        let Some(upstream)=guard.get_mut(id) else { return 0 };
        upstream.consecutive_failures+=1;
        upstream.state=if upstream.consecutive_failures>=OFFLINE_AFTER { UpstreamState::Offline } else { UpstreamState::Degraded };
        upstream.latency_ms=None; upstream.session_count=0; upstream.last_probe=Some(Instant::now()); upstream.last_error=Some(error);
        upstream.consecutive_failures
    }
}

#[cfg(test)]
impl UpstreamPool {
    pub async fn upsert(&self,id:&str,url:&str,source:Source){self.upsert_with_metadata(id,url,source,Vec::new(),None).await;}
    pub async fn list_allowed_routable(&self, acl:&[String])->Vec<Upstream>{
        let mut result:Vec<_>=self.inner.lock().expect("pool mutex").values().filter(|u|Authenticator::permits(acl,&u.id)&&u.state.is_routable()).cloned().collect();
        result.sort_by_key(|u|(u.state!=UpstreamState::Online,u.id.clone()));result
    }
    pub async fn pick_for_create(&self,acl:&[String])->Option<Upstream>{self.reserve_for_create(acl,&TagPreferences::default(),Duration::from_secs(5)).await.ok().map(|(u,_)|u)}
    pub async fn mark(&self,id:&str,state:UpstreamState,latency:Option<u64>,count:usize){self.mark_with_error(id,state,latency,count,None).await;}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn state_transitions_and_acl() {
        let pool = UpstreamPool::new(); pool.upsert("a", "http://a", Source::Manual).await;
        pool.upsert("b", "http://b", Source::Lan).await;
        assert_eq!(pool.inner.lock().expect("pool mutex")["a"].state, UpstreamState::Unknown);
        for (state, latency, count) in [(UpstreamState::Degraded,Some(600),0),(UpstreamState::Online,Some(10),2),(UpstreamState::Offline,None,0)] {
            pool.mark("a",state,latency,count).await;
            let u=pool.inner.lock().expect("pool mutex")["a"].clone();
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

    async fn tagged_pool() -> UpstreamPool {
        let pool=UpstreamPool::new();
        pool.upsert_with_metadata("perf-a","http://a",Source::Manual,vec!["perf".into()],Some("fast a".into())).await;
        pool.upsert_with_metadata("perf-b","http://b",Source::Manual,vec!["perf".into(),"prod-svc".into()],None).await;
        pool.upsert_with_metadata("mac","http://c",Source::Manual,vec!["macos".into()],None).await;
        pool.upsert_with_metadata("plain","http://d",Source::Manual,Vec::new(),None).await;
        pool
    }
    #[tokio::test]
    async fn tags_match_exclude_and_never_downgrade() {
        let p=tagged_pool().await;
        for id in ["perf-a","perf-b","mac","plain"] { p.mark(id,UpstreamState::Online,Some(1),0).await; }
        let (u,r)=p.reserve_for_create(&["*".into()],&TagPreferences { prefer:vec!["perf".into()],avoid:vec!["prod-svc".into()] },Duration::from_secs(1)).await.unwrap();
        assert_eq!(u.id,"perf-a"); r.finish();
        let e=p.reserve_for_create(&["*".into()],&TagPreferences { prefer:vec!["nonexistent".into()],avoid:vec![] },Duration::from_secs(1)).await.unwrap_err();
        assert!(e.contains("change tag requirements"),"{e}");
        p.mark("mac",UpstreamState::Offline,None,0).await;
        let e=p.reserve_for_create(&["*".into()],&TagPreferences { prefer:vec!["macos".into()],avoid:vec![] },Duration::from_secs(1)).await.unwrap_err();
        assert!(e.contains("required tags"),"{e}");
    }
    #[tokio::test]
    async fn all_avoided_and_all_unavailable_fail_clearly() {
        let p=tagged_pool().await;
        for id in ["perf-a","perf-b","mac","plain"] { p.mark(id,UpstreamState::Online,Some(1),0).await; }
        let e=p.reserve_for_create(&["*".into()],&TagPreferences { prefer:vec![],avoid:vec!["perf".into(),"macos".into()] },Duration::from_secs(1)).await;
        assert_eq!(e.unwrap().0.id,"plain");
        let e=p.reserve_for_create(&["perf-a".into(),"perf-b".into()],&TagPreferences { prefer:vec![],avoid:vec!["perf".into()] },Duration::from_secs(1)).await.unwrap_err();
        assert!(e.contains("avoid_tags"),"{e}");
        p.mark("plain",UpstreamState::Unknown,None,0).await;
        let e=p.reserve_for_create(&["plain".into()],&TagPreferences::default(),Duration::from_secs(1)).await.unwrap_err();
        assert!(e.contains("no routable upstream"),"{e}");
    }
    #[tokio::test]
    async fn concurrent_reservations_never_stick_to_one_idle_host() {
        let p=UpstreamPool::new();
        p.upsert("a","http://a",Source::Manual).await;p.upsert("b","http://b",Source::Manual).await;
        p.mark("a",UpstreamState::Online,Some(1),0).await;p.mark("b",UpstreamState::Online,Some(1),0).await;
        let mut held=Vec::new();
        for _ in 0..64 { held.push(p.reserve_for_create(&["*".into()],&TagPreferences::default(),Duration::from_secs(2)).await.unwrap()); }
        assert_eq!(p.get("a").await.unwrap().reserved_sessions,32);
        assert_eq!(p.get("b").await.unwrap().reserved_sessions,32);
        drop(held);
        assert_eq!(p.get("a").await.unwrap().reserved_sessions,0);
        let (_u,held)=p.reserve_for_create(&["*".into()],&TagPreferences::default(),Duration::from_millis(5)).await.unwrap();
        drop(held); // finish releases early
        assert_eq!(p.get("a").await.unwrap().reserved_sessions,0);
        let (_u, _reservation)=p.reserve_for_create(&["*".into()],&TagPreferences::default(),Duration::from_millis(2)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        p.reap_reservations().await; // TTL reaps a reservation whose guard was leaked
        assert_eq!(p.get("a").await.unwrap().reserved_sessions,0);
    }
}
