// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic metric counters for the rate limiter.
//!
//! The limiter's hot-path counters live in atomics outside the main
//! mutex so a future metrics-exporter thread can snapshot them without
//! contending the packet processing lock.

use std::sync::atomic::{AtomicU64, Ordering};

/// Internal atomic counter block. Accessed via shared reference because
/// all fields are interior-mutable via atomics.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) allowed: AtomicU64,
    pub(crate) dropped_per_source: AtomicU64,
    pub(crate) dropped_global: AtomicU64,
    pub(crate) promotions: AtomicU64,
    pub(crate) evictions: AtomicU64,
}

impl Stats {
    pub(crate) fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            allowed: self.allowed.load(Ordering::Relaxed),
            dropped_per_source: self.dropped_per_source.load(Ordering::Relaxed),
            dropped_global: self.dropped_global.load(Ordering::Relaxed),
            promotions: self.promotions.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn incr_allowed(&self) {
        self.allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn incr_dropped_per_source(&self) {
        self.dropped_per_source.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn incr_dropped_global(&self) {
        self.dropped_global.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn incr_promotions(&self) {
        self.promotions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn incr_evictions(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }
}

/// A point-in-time snapshot of rate limiter counters.
///
/// Returned by [`RateLimiter::stats`](crate::RateLimiter::stats). The
/// snapshot is atomic on each field but not consistent across fields —
/// values are loaded one at a time with `Relaxed` ordering, so a
/// concurrent packet could increment `allowed` between the loads of
/// `dropped_per_source` and `promotions`. This is acceptable for
/// metrics use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Total packets that passed the rate limiter.
    pub allowed: u64,
    /// Total packets dropped because an exact-tracked source's bucket was empty.
    pub dropped_per_source: u64,
    /// Total packets dropped because the global fallback bucket was empty.
    pub dropped_global: u64,
    /// Total sources that were promoted from the candidates map into the tracked LRU.
    pub promotions: u64,
    /// Total entries evicted from the tracked LRU due to capacity pressure.
    pub evictions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_start_at_zero() {
        let s = Stats::default();
        let snap = s.snapshot();
        assert_eq!(snap, StatsSnapshot::default());
    }

    #[test]
    fn incr_allowed_increments_allowed_only() {
        let s = Stats::default();
        s.incr_allowed();
        s.incr_allowed();
        let snap = s.snapshot();
        assert_eq!(snap.allowed, 2);
        assert_eq!(snap.dropped_per_source, 0);
        assert_eq!(snap.dropped_global, 0);
        assert_eq!(snap.promotions, 0);
        assert_eq!(snap.evictions, 0);
    }

    #[test]
    fn all_counters_independent() {
        let s = Stats::default();
        s.incr_allowed();
        s.incr_dropped_per_source();
        s.incr_dropped_per_source();
        s.incr_dropped_global();
        s.incr_dropped_global();
        s.incr_dropped_global();
        s.incr_promotions();
        s.incr_evictions();
        let snap = s.snapshot();
        assert_eq!(snap.allowed, 1);
        assert_eq!(snap.dropped_per_source, 2);
        assert_eq!(snap.dropped_global, 3);
        assert_eq!(snap.promotions, 1);
        assert_eq!(snap.evictions, 1);
    }

    #[test]
    fn snapshot_is_a_snapshot_not_a_reset() {
        let s = Stats::default();
        s.incr_allowed();
        let snap1 = s.snapshot();
        let snap2 = s.snapshot();
        assert_eq!(snap1, snap2);
        assert_eq!(snap1.allowed, 1);
    }
}
