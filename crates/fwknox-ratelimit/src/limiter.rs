// SPDX-License-Identifier: AGPL-3.0-or-later

// The skeleton populates `Inner` fields (tracked, candidates, global,
// clock, last_global_drop_warn) in the constructor, but the no-op
// `check` body doesn't read them until Tasks 9–11 wire up the real
// algorithm. Suppress `dead_code` until then; Tasks 9+ will remove
// this allow once every field is live.
#![allow(dead_code)]

//! The public `RateLimiter` type and its core `check` algorithm.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

use fwknox_config::RateLimitSection;
use lru::LruCache;

use crate::bucket::TokenBucket;
use crate::clock::{Clock, SystemClock};
use crate::key::SourceKey;
use crate::stats::{Stats, StatsSnapshot};

/// The outcome of a single rate limiter check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Packet may proceed to the crypto pipeline.
    Pass,
    /// Packet must be dropped. The variant indicates which bucket rejected it.
    Drop(DropReason),
}

/// Why a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The source's per-source (exact-tracked) bucket was empty.
    PerSourceExhausted,
    /// The global fallback bucket was empty.
    GlobalExhausted,
}

/// The rate limiter. One instance is constructed per daemon process
/// and shared by reference across the capture path(s).
pub struct RateLimiter {
    config: RateLimitSection,
    /// `None` when `config.enabled == false`. Short-circuit path in
    /// `check` avoids the mutex altogether in that case.
    inner: Option<Mutex<Inner>>,
    stats: Stats,
}

struct Inner {
    tracked: LruCache<SourceKey, TokenBucket>,
    candidates: LruCache<SourceKey, u32>,
    global: TokenBucket,
    clock: Box<dyn Clock>,
    /// Last time a global-bucket-drop warning was logged. Throttles
    /// warn-level spam on sustained floods.
    last_global_drop_warn: Option<Instant>,
}

impl RateLimiter {
    /// Constructs a rate limiter from the daemon's `[rate_limit]`
    /// section. Uses the production `SystemClock`.
    ///
    /// # Panics
    ///
    /// Panics if `config.tracked_sources_capacity == 0`. Config
    /// validation (`DaemonConfig::validate`) rejects zero capacity at
    /// daemon startup, so this is unreachable in practice.
    #[must_use]
    pub fn from_config(config: &RateLimitSection) -> Self {
        Self::with_clock(config, Box::new(SystemClock))
    }

    /// Constructs a rate limiter with a caller-supplied clock. Used by
    /// tests to inject a [`MockClock`](crate::MockClock).
    #[must_use]
    pub fn with_clock(config: &RateLimitSection, clock: Box<dyn Clock>) -> Self {
        if !config.enabled {
            return Self {
                config: config.clone(),
                inner: None,
                stats: Stats::default(),
            };
        }
        let now = clock.now();
        let capacity = NonZeroUsize::new(config.tracked_sources_capacity)
            .expect("tracked_sources_capacity >= 1 (enforced by config validation)");
        let inner = Inner {
            tracked: LruCache::new(capacity),
            candidates: LruCache::new(capacity),
            global: TokenBucket::new(config.global_rate_per_sec, config.global_burst, now),
            clock,
            last_global_drop_warn: None,
        };
        Self {
            config: config.clone(),
            inner: Some(Mutex::new(inner)),
            stats: Stats::default(),
        }
    }

    /// Checks whether a packet from `src_ip` may proceed.
    ///
    /// This method cannot fail — all operations are in-memory. A
    /// poisoned mutex is recovered via `into_inner` so the final
    /// packets before process death still receive a decision.
    pub fn check(&self, src_ip: IpAddr) -> Decision {
        let Some(ref mutex) = self.inner else {
            // Disabled mode: short-circuit before the mutex.
            self.stats.incr_allowed();
            return Decision::Pass;
        };

        let mut inner = mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = src_ip; // used in Task 9+
        let _ = &mut *inner; // silence "unused" on the skeleton
        // Full algorithm lands in Tasks 9 (Tier 1), 10 (Tier 2),
        // 11 (promotion). For now the skeleton passes everything
        // that reaches the mutex.
        self.stats.incr_allowed();
        Decision::Pass
    }

    /// Returns a point-in-time snapshot of the limiter's counters.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockClock;

    fn default_config() -> RateLimitSection {
        RateLimitSection::default()
    }

    fn disabled_config() -> RateLimitSection {
        let mut c = default_config();
        c.enabled = false;
        c
    }

    #[test]
    fn disabled_mode_always_passes() {
        let limiter = RateLimiter::from_config(&disabled_config());
        for _ in 0..100 {
            assert_eq!(
                limiter.check("1.2.3.4".parse().unwrap()),
                Decision::Pass
            );
        }
        let snap = limiter.stats();
        assert_eq!(snap.allowed, 100);
        assert_eq!(snap.dropped_per_source, 0);
        assert_eq!(snap.dropped_global, 0);
    }

    #[test]
    fn disabled_mode_has_no_inner_state() {
        let limiter = RateLimiter::from_config(&disabled_config());
        assert!(limiter.inner.is_none(),
            "disabled limiter must not allocate the LRUs or global bucket");
    }

    #[test]
    fn enabled_mode_constructs_with_inner_state() {
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(MockClock::new()),
        );
        assert!(limiter.inner.is_some());
    }

    #[test]
    fn stats_snapshot_starts_at_zero() {
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(MockClock::new()),
        );
        let snap = limiter.stats();
        assert_eq!(snap, StatsSnapshot::default());
    }
}
