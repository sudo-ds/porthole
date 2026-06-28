use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySnapshot {
    pub samples: u64,
    pub last_us: u64,
    pub avg_us: u64,
    pub min_us: u64,
    pub max_us: u64,
}

#[derive(Default)]
pub struct LatencyStats {
    samples: AtomicU64,
    total_us: AtomicU64,
    last_us: AtomicU64,
    min_us: AtomicU64,
    max_us: AtomicU64,
}

impl LatencyStats {
    pub fn record(&self, elapsed: Duration) {
        let us = duration_us(elapsed);
        self.samples.fetch_add(1, Relaxed);
        self.total_us.fetch_add(us, Relaxed);
        self.last_us.store(us, Relaxed);
        update_min(&self.min_us, us);
        update_max(&self.max_us, us);
    }

    pub fn snapshot(&self) -> Option<LatencySnapshot> {
        let samples = self.samples.load(Relaxed);
        if samples == 0 {
            return None;
        }
        Some(LatencySnapshot {
            samples,
            last_us: self.last_us.load(Relaxed),
            avg_us: self.total_us.load(Relaxed) / samples,
            min_us: self.min_us.load(Relaxed),
            max_us: self.max_us.load(Relaxed),
        })
    }

    pub fn reset(&self) {
        self.samples.store(0, Relaxed);
        self.total_us.store(0, Relaxed);
        self.last_us.store(0, Relaxed);
        self.min_us.store(0, Relaxed);
        self.max_us.store(0, Relaxed);
    }
}

#[derive(Default)]
pub struct LatencyMirror {
    samples: AtomicU64,
    last_us: AtomicU64,
    avg_us: AtomicU64,
    min_us: AtomicU64,
    max_us: AtomicU64,
}

impl LatencyMirror {
    pub fn store(&self, snapshot: Option<LatencySnapshot>) {
        let Some(snapshot) = snapshot else {
            self.reset();
            return;
        };
        self.samples.store(snapshot.samples, Relaxed);
        self.last_us.store(snapshot.last_us, Relaxed);
        self.avg_us.store(snapshot.avg_us, Relaxed);
        self.min_us.store(snapshot.min_us, Relaxed);
        self.max_us.store(snapshot.max_us, Relaxed);
    }

    pub fn snapshot(&self) -> Option<LatencySnapshot> {
        let samples = self.samples.load(Relaxed);
        if samples == 0 {
            return None;
        }
        Some(LatencySnapshot {
            samples,
            last_us: self.last_us.load(Relaxed),
            avg_us: self.avg_us.load(Relaxed),
            min_us: self.min_us.load(Relaxed),
            max_us: self.max_us.load(Relaxed),
        })
    }

    pub fn reset(&self) {
        self.samples.store(0, Relaxed);
        self.last_us.store(0, Relaxed);
        self.avg_us.store(0, Relaxed);
        self.min_us.store(0, Relaxed);
        self.max_us.store(0, Relaxed);
    }
}

#[derive(Default)]
pub struct PlainUdpDiagnostics {
    pub rtt: LatencyStats,
    pub client_server_to_local: LatencyStats,
    pub client_local_to_server: LatencyStats,
    pub server_public_to_client: LatencyMirror,
    pub server_client_to_public: LatencyMirror,
}

impl PlainUdpDiagnostics {
    pub fn reset(&self) {
        self.rtt.reset();
        self.client_server_to_local.reset();
        self.client_local_to_server.reset();
        self.server_public_to_client.reset();
        self.server_client_to_public.reset();
    }
}

fn duration_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn update_min(slot: &AtomicU64, value: u64) {
    let mut current = slot.load(Relaxed);
    while current == 0 || value < current {
        match slot.compare_exchange_weak(current, value, Relaxed, Relaxed) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

fn update_max(slot: &AtomicU64, value: u64) {
    let mut current = slot.load(Relaxed);
    while value > current {
        match slot.compare_exchange_weak(current, value, Relaxed, Relaxed) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_tracks_basic_snapshot() {
        let stats = LatencyStats::default();
        assert!(stats.snapshot().is_none());

        stats.record(Duration::from_micros(10));
        stats.record(Duration::from_micros(30));

        let snap = stats.snapshot().unwrap();
        assert_eq!(snap.samples, 2);
        assert_eq!(snap.last_us, 30);
        assert_eq!(snap.avg_us, 20);
        assert_eq!(snap.min_us, 10);
        assert_eq!(snap.max_us, 30);
    }

    #[test]
    fn latency_mirror_stores_and_resets_snapshot() {
        let mirror = LatencyMirror::default();
        let snap = LatencySnapshot {
            samples: 3,
            last_us: 7,
            avg_us: 5,
            min_us: 2,
            max_us: 9,
        };
        mirror.store(Some(snap));
        assert_eq!(mirror.snapshot(), Some(snap));

        mirror.store(None);
        assert!(mirror.snapshot().is_none());
    }
}
