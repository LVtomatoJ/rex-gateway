use std::sync::{
    atomic::{AtomicU64, Ordering::Relaxed},
    Arc,
};

/// Gateway-wide counters shared by the ticket map, the inbound server and `/status`.
/// Totals only ever grow; the `active_*` fields are gauges maintained by [`Guard`]s.
#[derive(Debug, Default)]
pub struct Metrics {
    pub tickets_issued: AtomicU64,
    pub tickets_consumed: AtomicU64,
    /// Tickets that passed their TTL (purged by the reaper or rejected on consume).
    pub tickets_expired: AtomicU64,
    /// Tickets dropped early because the map was at capacity.
    pub tickets_evicted: AtomicU64,
    pub active_control: AtomicU64,
    pub active_data: AtomicU64,
    /// Hostless `session.create` transport-error hops (each tried upstream recorded).
    pub create_transport_failovers: AtomicU64,
    /// Other hostless RPC transport-error hops.
    pub hostless_transport_failovers: AtomicU64,
    /// `session.create` exhausted every candidate with transport errors.
    pub create_failover_exhausted: AtomicU64,
    /// Hostless non-create RPC exhausted every candidate with transport errors.
    pub hostless_failover_exhausted: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    pub tickets_issued: u64,
    pub tickets_consumed: u64,
    pub tickets_expired: u64,
    pub tickets_evicted: u64,
    pub active_control: u64,
    pub active_data: u64,
    pub create_transport_failovers: u64,
    pub hostless_transport_failovers: u64,
    pub create_failover_exhausted: u64,
    pub hostless_failover_exhausted: u64,
}

#[derive(Clone, Copy)]
pub enum Gauge { Control, Data }

/// Increments a gauge on creation and decrements it on drop (including panics/early returns).
pub struct Guard { metrics: Arc<Metrics>, gauge: Gauge }

impl Metrics {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            tickets_issued: self.tickets_issued.load(Relaxed),
            tickets_consumed: self.tickets_consumed.load(Relaxed),
            tickets_expired: self.tickets_expired.load(Relaxed),
            tickets_evicted: self.tickets_evicted.load(Relaxed),
            active_control: self.active_control.load(Relaxed),
            active_data: self.active_data.load(Relaxed),
            create_transport_failovers: self.create_transport_failovers.load(Relaxed),
            hostless_transport_failovers: self.hostless_transport_failovers.load(Relaxed),
            create_failover_exhausted: self.create_failover_exhausted.load(Relaxed),
            hostless_failover_exhausted: self.hostless_failover_exhausted.load(Relaxed),
        }
    }

    #[allow(dead_code)] // unconditional form; production paths use try_track
    pub fn track(self: &Arc<Self>, gauge: Gauge) -> Guard {
        Self::cell(self, gauge).fetch_add(1, Relaxed);
        Guard { metrics: self.clone(), gauge }
    }

    /// Atomically reserves a gauge slot if under `max`. Used for connection/stream backpressure.
    pub fn try_track(self: &Arc<Self>, gauge: Gauge, max: usize) -> Option<Guard> {
        let cell = Self::cell(self, gauge);
        let max = max as u64;
        loop {
            let cur = cell.load(std::sync::atomic::Ordering::Acquire);
            if cur >= max { return None; }
            if cell.compare_exchange(cur, cur + 1, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire).is_ok() {
                return Some(Guard { metrics: self.clone(), gauge });
            }
        }
    }

    fn cell(&self, gauge: Gauge) -> &AtomicU64 {
        match gauge { Gauge::Control => &self.active_control, Gauge::Data => &self.active_data }
    }
}

/// Per-bearer active connection/stream counter. Paired with a gateway-wide gauge.
#[derive(Clone, Default)]
pub struct OwnerLimiter {
    by_owner: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
}

pub struct OwnerGuard {
    limiter: OwnerLimiter,
    owner: String,
}

impl OwnerLimiter {
    pub fn new() -> Self { Self::default() }

    pub fn try_acquire(&self, owner: &str, max_per_token: usize) -> Option<OwnerGuard> {
        let mut map = self.by_owner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = map.entry(owner.to_owned()).or_insert(0);
        if *entry >= max_per_token as u64 { return None; }
        *entry += 1;
        Some(OwnerGuard { limiter: self.clone(), owner: owner.to_owned() })
    }
}

impl Drop for OwnerGuard {
    fn drop(&mut self) {
        let mut map = self.limiter.by_owner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = map.get_mut(&self.owner) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 { map.remove(&self.owner); }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) { self.metrics.cell(self.gauge).fetch_sub(1, Relaxed); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_balance_gauges() {
        let metrics = Metrics::new();
        let a = metrics.track(Gauge::Control);
        let b = metrics.track(Gauge::Control);
        let c = metrics.track(Gauge::Data);
        assert_eq!((metrics.snapshot().active_control, metrics.snapshot().active_data), (2, 1));
        drop(a); drop(c);
        assert_eq!((metrics.snapshot().active_control, metrics.snapshot().active_data), (1, 0));
        drop(b);
        assert_eq!(metrics.snapshot(), MetricsSnapshot::default());
    }

    #[test]
    fn try_track_respects_max() {
        let metrics = Metrics::new();
        let a = metrics.try_track(Gauge::Data, 1).unwrap();
        assert!(metrics.try_track(Gauge::Data, 1).is_none());
        drop(a);
        assert!(metrics.try_track(Gauge::Data, 1).is_some());
    }

    #[test]
    fn owner_limiter_caps_per_owner() {
        let limiter = OwnerLimiter::new();
        let a = limiter.try_acquire("Bearer a", 1).unwrap();
        assert!(limiter.try_acquire("Bearer a", 1).is_none());
        assert!(limiter.try_acquire("Bearer b", 1).is_some());
        drop(a);
        assert!(limiter.try_acquire("Bearer a", 1).is_some());
    }

    #[test]
    fn failover_counters_accumulate() {
        let metrics = Metrics::new();
        metrics.create_transport_failovers.fetch_add(2, Relaxed);
        metrics.hostless_transport_failovers.fetch_add(3, Relaxed);
        metrics.create_failover_exhausted.fetch_add(1, Relaxed);
        metrics.hostless_failover_exhausted.fetch_add(1, Relaxed);
        let snap = metrics.snapshot();
        assert_eq!(snap.create_transport_failovers, 2);
        assert_eq!(snap.hostless_transport_failovers, 3);
        assert_eq!(snap.create_failover_exhausted, 1);
        assert_eq!(snap.hostless_failover_exhausted, 1);
    }
}
