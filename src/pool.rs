use std::{collections::HashMap, sync::Arc, time::Instant};
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
}
#[derive(Clone)]
pub struct UpstreamPool { inner: Arc<RwLock<HashMap<String, Upstream>>> }

impl UpstreamPool {
    pub fn new() -> Self { Self { inner: Arc::new(RwLock::new(HashMap::new())) } }
    pub async fn upsert(&self, id: &str, url: &str, source: Source) {
        self.inner.write().await.entry(id.to_owned()).and_modify(|u| { u.url = url.to_owned(); u.source = source; }).or_insert_with(|| Upstream {
            id: id.to_owned(), url: url.to_owned(), source, state: UpstreamState::Unknown,
            latency_ms: None, session_count: 0, last_probe: None,
        });
    }
    pub async fn list_allowed_online(&self, acl: &[String]) -> Vec<Upstream> {
        let mut result: Vec<_> = self.inner.read().await.values().filter(|u| u.state == UpstreamState::Online && Authenticator::permits(acl, &u.id)).cloned().collect();
        result.sort_by(|a,b| a.id.cmp(&b.id)); result
    }
    pub async fn mark(&self, id: &str, state: UpstreamState, latency: Option<u64>, count: usize) {
        if let Some(upstream) = self.inner.write().await.get_mut(id) {
            upstream.state = state; upstream.latency_ms = latency; upstream.session_count = count; upstream.last_probe = Some(Instant::now());
        }
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
        assert_eq!(pool.list_allowed_online(&["a".into()]).await.len(),1);
        assert_eq!(pool.list_allowed_online(&["*".into()]).await.len(),2);
        assert_eq!(pool.list_allowed_online(&[]).await.len(),0);
    }
}
