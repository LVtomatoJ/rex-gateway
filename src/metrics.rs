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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    pub tickets_issued: u64,
    pub tickets_consumed: u64,
    pub tickets_expired: u64,
    pub tickets_evicted: u64,
    pub active_control: u64,
    pub active_data: u64,
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
        }
    }

    pub fn track(self: &Arc<Self>, gauge: Gauge) -> Guard {
        Self::cell(self, gauge).fetch_add(1, Relaxed);
        Guard { metrics: self.clone(), gauge }
    }

    fn cell(&self, gauge: Gauge) -> &AtomicU64 {
        match gauge { Gauge::Control => &self.active_control, Gauge::Data => &self.active_data }
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
}
