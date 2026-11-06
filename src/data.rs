use std::{
    collections::{BTreeMap, HashMap},
    sync::{atomic::Ordering::Relaxed, Arc, Mutex},
    time::Duration,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::time::Instant;

use crate::metrics::Metrics;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub upstream: String,
    pub upstream_ticket: String,
    owner: String,
}

struct Entry { ticket: Ticket, created: Instant, seq: u64 }

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// Insertion order (`seq` -> external ticket). All tickets share one TTL, so the oldest
    /// entry is also the first to expire, which makes both eviction and reaping cheap.
    order: BTreeMap<u64, String>,
    next_seq: u64,
}

/// Single-use, bearer-bound mapping from gateway tickets to upstream tickets.
/// Unused tickets live at most `ttl` and at most `max` are kept (oldest evicted first).
///
/// Every operation has an `_at(now)` form so tests can drive the clock explicitly; the plain
/// forms use `tokio::time::Instant::now()` (which also honours `tokio::time::pause`).
#[derive(Clone)]
pub struct TicketMap {
    inner: Arc<Mutex<Inner>>,
    ttl: Duration,
    max: usize,
    metrics: Arc<Metrics>,
}

impl TicketMap {
    pub fn new(ttl: Duration, max: usize, metrics: Arc<Metrics>) -> Self {
        Self { inner: Arc::default(), ttl, max: max.max(1), metrics }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn expired(&self, created: Instant, now: Instant) -> bool {
        now.saturating_duration_since(created) >= self.ttl
    }

    pub fn insert(&self, upstream: &str, upstream_ticket: &str, owner: &str) -> String {
        self.insert_at(upstream, upstream_ticket, owner, Instant::now())
    }

    pub fn insert_at(&self, upstream: &str, upstream_ticket: &str, owner: &str, now: Instant) -> String {
        let external = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
        let mut inner = self.lock();
        while inner.entries.len() >= self.max {
            let Some((_, oldest)) = inner.order.pop_first() else { break };
            inner.entries.remove(&oldest);
            self.metrics.tickets_evicted.fetch_add(1, Relaxed);
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.order.insert(seq, external.clone());
        inner.entries.insert(external.clone(), Entry {
            ticket: Ticket { upstream: upstream.to_owned(), upstream_ticket: upstream_ticket.to_owned(), owner: owner.to_owned() },
            created: now,
            seq,
        });
        self.metrics.tickets_issued.fetch_add(1, Relaxed);
        external
    }

    pub fn take(&self, external: &str, owner: &str) -> Option<Ticket> {
        self.take_at(external, owner, Instant::now())
    }

    /// Consumes a ticket. Unknown, expired, already-used and wrong-owner tickets all yield `None`
    /// (callers cannot tell them apart). A wrong-owner attempt does not burn a live ticket.
    pub fn take_at(&self, external: &str, owner: &str, now: Instant) -> Option<Ticket> {
        let mut inner = self.lock();
        let entry = inner.entries.get(external)?;
        if self.expired(entry.created, now) {
            let seq = entry.seq;
            inner.entries.remove(external);
            inner.order.remove(&seq);
            self.metrics.tickets_expired.fetch_add(1, Relaxed);
            return None;
        }
        if !crate::auth::ct_eq(entry.ticket.owner.as_bytes(), owner.as_bytes()) { return None; }
        let entry = inner.entries.remove(external)?;
        inner.order.remove(&entry.seq);
        self.metrics.tickets_consumed.fetch_add(1, Relaxed);
        Some(entry.ticket)
    }

    /// Purges every expired entry and returns how many were removed.
    pub fn reap_at(&self, now: Instant) -> usize {
        let mut inner = self.lock();
        let mut removed = 0;
        while let Some((&seq, external)) = inner.order.first_key_value() {
            let external = external.clone();
            let Some(entry) = inner.entries.get(&external) else { inner.order.remove(&seq); continue };
            if !self.expired(entry.created, now) { break; }
            inner.entries.remove(&external);
            inner.order.remove(&seq);
            removed += 1;
        }
        if removed > 0 { self.metrics.tickets_expired.fetch_add(removed as u64, Relaxed); }
        removed
    }

    pub fn pending(&self) -> usize { self.lock().entries.len() }

    /// Background task that purges expired tickets so unused ones never linger past the TTL
    /// by more than roughly one reaper period.
    pub fn spawn_reaper(&self) -> tokio::task::JoinHandle<()> {
        let map = self.clone();
        let period = (self.ttl / 2).clamp(Duration::from_millis(50), Duration::from_secs(5));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let removed = map.reap_at(Instant::now());
                if removed > 0 { tracing::debug!(removed, "reaped expired data tickets"); }
            }
        })
    }
}

pub fn decode_hello(bytes: &[u8]) -> Option<String> {
    let ticket = bytes.strip_prefix(&[1])?;
    (ticket.len() == 16).then(|| URL_SAFE_NO_PAD.encode(ticket))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    fn map(max: usize) -> (TicketMap, Arc<Metrics>) {
        let metrics = Metrics::new();
        (TicketMap::new(TTL, max, metrics.clone()), metrics)
    }

    #[test]
    fn ticket_routes_once_and_checks_owner() {
        let (map, metrics) = map(8);
        let now = Instant::now();
        let external = map.insert_at("local", "real-ticket", "secret", now);
        assert_eq!(map.take_at(&external, "other", now), None);
        assert_eq!(map.pending(), 1, "wrong owner must not burn the ticket");
        assert_eq!(map.take_at(&external, "secret", now), Some(Ticket {
            upstream: "local".into(), upstream_ticket: "real-ticket".into(), owner: "secret".into(),
        }));
        assert_eq!(map.take_at(&external, "secret", now), None, "single use");
        assert_eq!(map.pending(), 0);
        let snap = metrics.snapshot();
        assert_eq!((snap.tickets_issued, snap.tickets_consumed, snap.tickets_expired), (1, 1, 0));
    }

    #[test]
    fn unknown_ticket_is_rejected() {
        let (map, _) = map(8);
        assert_eq!(map.take_at("nope", "secret", Instant::now()), None);
    }

    #[test]
    fn expired_on_consume_is_rejected_and_removed() {
        let (map, metrics) = map(8);
        let t0 = Instant::now();
        let fresh = map.insert_at("a", "t1", "secret", t0);
        let stale = map.insert_at("a", "t2", "secret", t0);
        assert!(map.take_at(&fresh, "secret", t0 + TTL - Duration::from_millis(1)).is_some(), "just before TTL is valid");
        assert_eq!(map.take_at(&stale, "secret", t0 + TTL), None, "at TTL it is expired");
        assert_eq!(map.pending(), 0, "expired entry removed on consume");
        assert_eq!(metrics.snapshot().tickets_expired, 1);
        assert_eq!(metrics.snapshot().tickets_consumed, 1);
    }

    #[test]
    fn expired_wrong_owner_is_still_rejected() {
        let (map, _) = map(8);
        let t0 = Instant::now();
        let external = map.insert_at("a", "t", "secret", t0);
        assert_eq!(map.take_at(&external, "other", t0 + TTL * 2), None);
        assert_eq!(map.take_at(&external, "secret", t0 + TTL * 2), None);
    }

    #[test]
    fn reap_purges_only_expired() {
        let (map, metrics) = map(8);
        let t0 = Instant::now();
        let old1 = map.insert_at("a", "t1", "secret", t0);
        let _old2 = map.insert_at("a", "t2", "secret", t0 + Duration::from_secs(5));
        let young = map.insert_at("a", "t3", "secret", t0 + Duration::from_secs(20));
        assert_eq!(map.reap_at(t0 + Duration::from_secs(29)), 0);
        assert_eq!(map.reap_at(t0 + Duration::from_secs(36)), 2);
        assert_eq!(map.pending(), 1);
        assert_eq!(map.take_at(&old1, "secret", t0 + Duration::from_secs(36)), None);
        assert!(map.take_at(&young, "secret", t0 + Duration::from_secs(36)).is_some());
        assert_eq!(metrics.snapshot().tickets_expired, 2);
        assert_eq!(map.reap_at(t0 + Duration::from_secs(500)), 0);
        assert!(map.lock().order.is_empty());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let (map, metrics) = map(3);
        let t0 = Instant::now();
        let ids: Vec<_> = (0..5).map(|i| map.insert_at("a", &format!("t{i}"), "secret", t0 + Duration::from_millis(i))).collect();
        assert_eq!(map.pending(), 3, "never grows past the cap");
        assert_eq!(map.take_at(&ids[0], "secret", t0), None);
        assert_eq!(map.take_at(&ids[1], "secret", t0), None);
        for id in &ids[2..] { assert!(map.take_at(id, "secret", t0).is_some()); }
        let snap = metrics.snapshot();
        assert_eq!((snap.tickets_issued, snap.tickets_evicted, snap.tickets_consumed), (5, 2, 3));
    }

    #[test]
    fn capacity_after_consume_does_not_evict_live_tickets() {
        let (map, metrics) = map(2);
        let t0 = Instant::now();
        let a = map.insert_at("a", "t0", "secret", t0);
        let b = map.insert_at("a", "t1", "secret", t0);
        assert!(map.take_at(&a, "secret", t0).is_some());
        let c = map.insert_at("a", "t2", "secret", t0);
        assert_eq!(metrics.snapshot().tickets_evicted, 0);
        assert!(map.take_at(&b, "secret", t0).is_some());
        assert!(map.take_at(&c, "secret", t0).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn background_reaper_purges_expired_tickets() {
        let (map, metrics) = map(8);
        let external = map.insert("a", "t", "secret");
        let reaper = map.spawn_reaper();
        tokio::time::sleep(TTL / 2).await;
        assert_eq!(map.pending(), 1, "still alive before TTL");
        tokio::time::sleep(TTL).await;
        assert_eq!(map.pending(), 0, "reaper purged it without any consume");
        assert_eq!(metrics.snapshot().tickets_expired, 1);
        assert_eq!(map.take(&external, "secret"), None);
        reaper.abort();
    }

    #[test]
    fn decodes_binary_hello() {
        let raw = [7u8; 16];
        assert_eq!(decode_hello(&[&[1][..], &raw].concat()).unwrap(), URL_SAFE_NO_PAD.encode(raw));
        assert_eq!(decode_hello(&raw), None);
        assert_eq!(decode_hello(&[1, 2]), None);
    }
}
