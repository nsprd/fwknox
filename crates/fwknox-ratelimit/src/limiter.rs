// SPDX-License-Identifier: AGPL-3.0-or-later

// The skeleton populates `Inner` fields (tracked, candidates, global,
// clock, last_global_drop_warn) in the constructor, but the no-op
// `check` body doesn't read them until Tasks 9–11 wire up the real
// algorithm. Suppress `dead_code` until then; Tasks 9+ will remove
// this allow once every field is live.
#![allow(dead_code)]

//! The public `RateLimiter` type and its core `check` algorithm.

use std::{net::IpAddr, num::NonZeroUsize, sync::Mutex, time::Instant};

use fwknox_config::RateLimitSection;
use lru::LruCache;

use crate::{
    bucket::{BucketDecision, TokenBucket},
    clock::{Clock, SystemClock},
    key::SourceKey,
    stats::{Stats, StatsSnapshot},
};

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
            self.stats.incr_allowed();
            return Decision::Pass;
        };

        let key = SourceKey::from_ip(src_ip, self.config.ipv6_prefix_len);
        let mut inner = mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = inner.clock.now();

        // Tier 1: exact-tracked hot source.
        // `get_mut` moves the entry to MRU on access.
        if let Some(bucket) = inner.tracked.get_mut(&key) {
            let decision = bucket.consume(now);
            return match decision {
                BucketDecision::Pass => {
                    self.stats.incr_allowed();
                    Decision::Pass
                }
                BucketDecision::Drop => {
                    self.stats.incr_dropped_per_source();
                    Decision::Drop(DropReason::PerSourceExhausted)
                }
            };
        }

        // Tier 2 and promotion land in Tasks 10 and 11. For now, sources
        // not in the tracked LRU pass through without being counted against
        // the global bucket — this means Task 8's disabled-mode and Task 9's
        // tracked-source tests all pass, but Task 10 tests will fail until
        // the Tier 2 path is implemented.
        self.stats.incr_allowed();
        Decision::Pass
    }

    /// Returns a point-in-time snapshot of the limiter's counters.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }
}

/// Test-only helper: pre-seed a source directly into the tracked LRU,
/// bypassing the promotion flow. Lets us exercise Tier 1 in isolation.
#[cfg(test)]
impl RateLimiter {
    fn insert_tracked_for_test(&self, src_ip: IpAddr) {
        let Some(ref mutex) = self.inner else {
            panic!("disabled")
        };
        let mut inner = mutex.lock().unwrap();
        let now = inner.clock.now();
        let key = SourceKey::from_ip(src_ip, self.config.ipv6_prefix_len);
        let bucket = TokenBucket::new(
            self.config.per_source_rate_per_sec,
            self.config.per_source_burst,
            now,
        );
        inner.tracked.push(key, bucket);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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
            assert_eq!(limiter.check("1.2.3.4".parse().unwrap()), Decision::Pass);
        }
        let snap = limiter.stats();
        assert_eq!(snap.allowed, 100);
        assert_eq!(snap.dropped_per_source, 0);
        assert_eq!(snap.dropped_global, 0);
    }

    #[test]
    fn disabled_mode_has_no_inner_state() {
        let limiter = RateLimiter::from_config(&disabled_config());
        assert!(
            limiter.inner.is_none(),
            "disabled limiter must not allocate the LRUs or global bucket"
        );
    }

    #[test]
    fn enabled_mode_constructs_with_inner_state() {
        let limiter = RateLimiter::with_clock(&default_config(), Box::new(MockClock::new()));
        assert!(limiter.inner.is_some());
    }

    #[test]
    fn stats_snapshot_starts_at_zero() {
        let limiter = RateLimiter::with_clock(&default_config(), Box::new(MockClock::new()));
        let snap = limiter.stats();
        assert_eq!(snap, StatsSnapshot::default());
    }

    #[test]
    fn tracked_source_passes_up_to_burst() {
        // Burst 20 → 20 pass, 21st drops.
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.insert_tracked_for_test(ip);
        for i in 0..20 {
            assert_eq!(limiter.check(ip), Decision::Pass, "packet {i}");
        }
        assert_eq!(
            limiter.check(ip),
            Decision::Drop(DropReason::PerSourceExhausted)
        );
        let snap = limiter.stats();
        assert_eq!(snap.allowed, 20);
        assert_eq!(snap.dropped_per_source, 1);
        assert_eq!(snap.dropped_global, 0);
    }

    #[test]
    fn tracked_source_refills_over_time() {
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.insert_tracked_for_test(ip);
        // Drain the burst.
        for _ in 0..20 {
            limiter.check(ip);
        }
        assert_eq!(
            limiter.check(ip),
            Decision::Drop(DropReason::PerSourceExhausted)
        );
        // Advance 1 second: rate=10 → 10 more tokens, capped at burst=20.
        clock.advance(Duration::from_secs(1));
        for _ in 0..10 {
            assert_eq!(limiter.check(ip), Decision::Pass);
        }
        assert_eq!(
            limiter.check(ip),
            Decision::Drop(DropReason::PerSourceExhausted)
        );
    }

    /// `Box<dyn Clock>` can't be cloned, and multiple test call-sites need
    /// to share the same underlying `MockClock`. This wrapper holds an
    /// `Arc<MockClock>` and implements `Clock` so both the test code and
    /// the limiter's boxed clock point at the same mock.
    struct CloneableMockClock(std::sync::Arc<MockClock>);

    impl Clock for CloneableMockClock {
        fn now(&self) -> Instant {
            self.0.now()
        }
    }
}
