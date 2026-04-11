// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// Checks whether a warn-level log should be emitted for a drop,
/// given the last-warn timestamp and the current time. Returns
/// `true` if at least 1 second has elapsed (or this is the first
/// drop). Mutates the timestamp to `now` if it returns `true`.
fn should_warn_log(last: &mut Option<Instant>, now: Instant) -> bool {
    const WARN_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
    match *last {
        Some(prev) if now.duration_since(prev) < WARN_WINDOW => false,
        _ => {
            *last = Some(now);
            true
        }
    }
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
        if let Some(bucket) = inner.tracked.get_mut(&key) {
            let decision = bucket.consume(now);
            return match decision {
                BucketDecision::Pass => {
                    self.stats.incr_allowed();
                    Decision::Pass
                }
                BucketDecision::Drop => {
                    self.stats.incr_dropped_per_source();
                    if should_warn_log(&mut bucket.last_warn_log, now) {
                        tracing::warn!(
                            source = %src_ip,
                            "rate limit: per-source bucket exhausted"
                        );
                    } else {
                        tracing::debug!(
                            source = %src_ip,
                            "rate limit: per-source bucket exhausted"
                        );
                    }
                    Decision::Drop(DropReason::PerSourceExhausted)
                }
            };
        }

        // Tier 2: global fallback bucket.
        match inner.global.consume(now) {
            BucketDecision::Drop => {
                self.stats.incr_dropped_global();
                if should_warn_log(&mut inner.last_global_drop_warn, now) {
                    tracing::warn!(
                        source = %src_ip,
                        "rate limit: global bucket exhausted"
                    );
                } else {
                    tracing::debug!(
                        source = %src_ip,
                        "rate limit: global bucket exhausted"
                    );
                }
                return Decision::Drop(DropReason::GlobalExhausted);
                // NOTE: Option A — rejected traffic does not increment the
                // candidate counter. This is the load-bearing invariant.
            }
            BucketDecision::Pass => {}
        }

        // Packet passed the global bucket. Bump the candidates counter and
        // promote if the threshold is reached.
        let new_count = if let Some(count) = inner.candidates.get_mut(&key) {
            *count += 1;
            *count
        } else {
            // `push` on an LruCache returns Some((k, v)) if a value was
            // evicted due to capacity. We don't care — the evicted
            // candidate just loses its partial progress, which is fine.
            inner.candidates.push(key, 1);
            1
        };

        if new_count >= self.config.promotion_threshold {
            let bucket = TokenBucket::new(
                self.config.per_source_rate_per_sec,
                self.config.per_source_burst,
                now,
            );
            inner.candidates.pop(&key);
            // `push` on the tracked LRU tells us whether we evicted. The
            // distinguishing check: if `push` returns Some((k, _)) and the
            // returned key *differs* from the one we just pushed, it's a
            // capacity eviction (not a key replacement — which is
            // impossible here because we just popped the candidate).
            if let Some((evicted_key, _)) = inner.tracked.push(key, bucket) {
                if evicted_key != key {
                    self.stats.incr_evictions();
                }
            }
            self.stats.incr_promotions();
        }

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

    #[test]
    fn global_bucket_absorbs_first_contact_packets() {
        // 100 distinct sources, 1 packet each within 1 second. With the
        // default global_burst=1000, all should pass. None should promote
        // yet (threshold=5, each source only sends one packet).
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        for i in 0..100u32 {
            let ip: IpAddr = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
            assert_eq!(limiter.check(ip), Decision::Pass, "source {i}");
        }
        let snap = limiter.stats();
        assert_eq!(snap.allowed, 100);
        assert_eq!(snap.dropped_global, 0);
        // Promotion is not yet implemented (Task 11), so promotions==0.
        assert_eq!(snap.promotions, 0);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // `i / 256` and `i % 256` both fit in u8 for i < 10_000
    #[allow(clippy::match_wildcard_for_single_variants)] // defensive: panic on any unexpected drop reason
    fn global_bucket_drops_overflow() {
        // Default global_burst=1000. Send 10_000 distinct sources as fast
        // as possible — only 1000 should pass.
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let mut passes = 0u32;
        let mut drops = 0u32;
        for i in 0..10_000u32 {
            // Use /16 of 10.x.x.x — that's plenty unique.
            let octet2 = (i / 256) as u8;
            let octet3 = (i % 256) as u8;
            let ip: IpAddr = format!("10.0.{octet2}.{octet3}").parse().unwrap();
            match limiter.check(ip) {
                Decision::Pass => passes += 1,
                Decision::Drop(DropReason::GlobalExhausted) => drops += 1,
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(passes, 1000);
        assert_eq!(drops, 9000);
        let snap = limiter.stats();
        assert_eq!(snap.dropped_global, 9000);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn rejected_global_bucket_packets_do_not_promote() {
        // Critical Option A invariant: under an active flood where the
        // global bucket is drained, a fresh source hammering the limiter
        // must NOT accumulate promotion credit.
        //
        // The flood is modeled as 1005 distinct source IPs each sending
        // exactly one packet. None individually reach promotion_threshold
        // (each sends 1 packet, threshold is 5), so no flooder self-
        // promotes; every packet goes through the global bucket. The
        // first 1000 pass and drain the bucket; the last 5 drop with
        // GlobalExhausted.
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        // Drain the global bucket with 1005 distinct flooders. Use the
        // 10.1.0.0/16 subnet (65k addresses available, non-overlapping
        // with the fresh source's 10.0.0.42).
        for i in 0..1005u32 {
            let octet2 = (i / 256) as u8;
            let octet3 = (i % 256) as u8;
            let flooder: IpAddr = format!("10.1.{octet2}.{octet3}").parse().unwrap();
            limiter.check(flooder);
        }
        // Fresh source sends promotion_threshold*10 packets. With no
        // clock advance, the global bucket stays empty; every packet is
        // rejected and the candidates counter should stay at zero.
        let fresh: IpAddr = "10.0.0.42".parse().unwrap();
        let threshold = default_config().promotion_threshold;
        for _ in 0..(threshold * 10) {
            assert_eq!(
                limiter.check(fresh),
                Decision::Drop(DropReason::GlobalExhausted),
                "fresh source must be rejected when global is drained"
            );
        }
        let snap = limiter.stats();
        assert_eq!(snap.promotions, 0, "rejected packets must not promote");
        // Fresh source must still be rejected from the global path, proving
        // it was never promoted into the tracked LRU.
        assert_eq!(
            limiter.check(fresh),
            Decision::Drop(DropReason::GlobalExhausted),
        );
    }

    #[test]
    fn successful_global_bucket_consumptions_promote_at_threshold() {
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let threshold = default_config().promotion_threshold;
        // Send exactly `threshold` packets. Global has 1000 tokens, so all
        // pass. The threshold-th packet triggers promotion.
        for _ in 0..threshold {
            assert_eq!(limiter.check(ip), Decision::Pass);
        }
        let snap = limiter.stats();
        assert_eq!(snap.promotions, 1);
        assert_eq!(snap.allowed, u64::from(threshold));
    }

    fn tiny_tracked_config() -> RateLimitSection {
        // Tiny tracked LRU to make eviction testing trivial.
        let mut c = default_config();
        c.tracked_sources_capacity = 3;
        // Lower promotion threshold so the test doesn't need to send 5
        // packets per source just to get them tracked.
        c.promotion_threshold = 1;
        c
    }

    #[test]
    fn tracked_lru_evicts_least_recently_used_when_full() {
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &tiny_tracked_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        // Promote 3 sources. With promotion_threshold=1, each promotes on
        // its first packet.
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();
        assert_eq!(limiter.check(a), Decision::Pass);
        assert_eq!(limiter.check(b), Decision::Pass);
        assert_eq!(limiter.check(c), Decision::Pass);
        assert_eq!(limiter.stats().promotions, 3);
        assert_eq!(limiter.stats().evictions, 0);
        // Promote a 4th — must evict the LRU (which is `a`).
        let d: IpAddr = "10.0.0.4".parse().unwrap();
        assert_eq!(limiter.check(d), Decision::Pass);
        assert_eq!(limiter.stats().promotions, 4);
        assert_eq!(limiter.stats().evictions, 1);
    }

    #[test]
    fn lru_refresh_keeps_hot_sources_warm() {
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &tiny_tracked_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();
        limiter.check(a);
        limiter.check(b);
        limiter.check(c);
        // Touch `a` again — it becomes MRU; `b` is now the LRU.
        limiter.check(a);
        // Promote a 4th. Eviction target must be `b`, NOT `a`.
        let d: IpAddr = "10.0.0.4".parse().unwrap();
        limiter.check(d);
        // Verify: `a` still behaves as tracked (would need another tracked
        // hit to confirm). Easiest proof: `a`'s per-source bucket was drained
        // by an earlier check, and re-hits still go through the tracked
        // path. We can't directly inspect the LRU, but we can verify that
        // an attempt to promote `b` (by calling it again) succeeds, which
        // only happens if `b` was evicted.
        let stats_before = limiter.stats();
        limiter.check(b);
        let stats_after = limiter.stats();
        assert_eq!(
            stats_after.promotions,
            stats_before.promotions + 1,
            "b should have been re-promoted, proving it was evicted"
        );
    }

    #[test]
    fn fresh_source_end_to_end_25_pass_75_drop() {
        // Spec test 3: a fresh source sends 100 packets at T0 with no
        // clock advance. Expected:
        //   - 5 pass via global bucket → promotion fires
        //   - 20 pass via newly-created per-source bucket (burst)
        //   - 75 drop with dropped_per_source
        // Total: allowed=25, dropped_per_source=75, promotions=1.
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut passes = 0u32;
        let mut per_source_drops = 0u32;
        let mut global_drops = 0u32;
        for _ in 0..100 {
            match limiter.check(ip) {
                Decision::Pass => passes += 1,
                Decision::Drop(DropReason::PerSourceExhausted) => per_source_drops += 1,
                Decision::Drop(DropReason::GlobalExhausted) => global_drops += 1,
            }
        }
        assert_eq!(passes, 25);
        assert_eq!(per_source_drops, 75);
        assert_eq!(global_drops, 0);
        let snap = limiter.stats();
        assert_eq!(snap.allowed, 25);
        assert_eq!(snap.dropped_per_source, 75);
        assert_eq!(snap.dropped_global, 0);
        assert_eq!(snap.promotions, 1);
    }

    #[test]
    fn ipv6_slash_64_collapses_distinct_addresses_to_one_source() {
        // Spec test 10: send packets from 64 distinct addresses within
        // 2001:db8::/64. Under /64 masking they must all key to the same
        // source. Expected behavior matches test 3: 25 pass, 75 drop.
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let mut passes = 0u32;
        let mut drops = 0u32;
        // Send 100 packets total, rotating through 64 /128 addresses in
        // the same /64. The first 25 should pass (5 via global promoting
        // the masked /64 key, then 20 via the resulting per-source bucket).
        for i in 0..100u32 {
            let ip: IpAddr = format!("2001:db8::{:x}", i % 64).parse().unwrap();
            match limiter.check(ip) {
                Decision::Pass => passes += 1,
                Decision::Drop(_) => drops += 1,
            }
        }
        assert_eq!(passes, 25, "IPv6 /64 masking must collapse all to one");
        assert_eq!(drops, 75);
        let snap = limiter.stats();
        assert_eq!(
            snap.promotions, 1,
            "exactly one masked key should have promoted"
        );
    }

    #[test]
    fn ipv4_distinct_sources_keep_independent_buckets() {
        // Counterpoint to the IPv6 test: two distinct IPv4 sources should
        // each pass `per_source_burst` packets independently.
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        // Burn through a's quota entirely: 5 global + 20 per-source = 25.
        for _ in 0..25 {
            assert_eq!(limiter.check(a), Decision::Pass);
        }
        assert_eq!(
            limiter.check(a),
            Decision::Drop(DropReason::PerSourceExhausted)
        );
        // b is independent: should still have its full 25-packet budget.
        for _ in 0..25 {
            assert_eq!(limiter.check(b), Decision::Pass);
        }
        assert_eq!(
            limiter.check(b),
            Decision::Drop(DropReason::PerSourceExhausted)
        );
    }

    #[test]
    fn poisoned_mutex_is_recovered() {
        use std::{
            panic::{catch_unwind, AssertUnwindSafe},
            sync::Arc,
        };

        let limiter = Arc::new(RateLimiter::with_clock(
            &default_config(),
            Box::new(MockClock::new()),
        ));

        // Force-poison the mutex by panicking while holding the lock. We
        // do this via a spawned thread so the panic doesn't propagate to
        // the test runner.
        let poisoner_limiter = limiter.clone();
        let handle = std::thread::spawn(move || {
            let Some(ref mutex) = poisoner_limiter.inner else {
                return;
            };
            let _guard = mutex.lock().unwrap();
            panic!("deliberate poison");
        });
        // The panic is expected; we don't care about the error.
        let _ = handle.join();

        // At this point the mutex is poisoned. `check` must still return
        // a Decision via the unwrap_or_else(into_inner) recovery.
        let result = catch_unwind(AssertUnwindSafe(|| {
            limiter.check("10.0.0.1".parse().unwrap())
        }));
        assert!(result.is_ok(), "check must not panic on a poisoned mutex");
        // Further checks should also work.
        let _ = limiter.check("10.0.0.2".parse().unwrap());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn global_drop_warn_throttle_state_updates_on_first_drop() {
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        // Drain global using 1005 DISTINCT flooder IPs (each sending one
        // packet so nobody self-promotes — same fix as Task 11's
        // rejected_global_bucket_packets_do_not_promote).
        for i in 0..1005u32 {
            let octet2 = (i / 256) as u8;
            let octet3 = (i % 256) as u8;
            let flooder: IpAddr = format!("10.1.{octet2}.{octet3}").parse().unwrap();
            limiter.check(flooder);
        }
        // At this point a global drop has occurred; last_global_drop_warn
        // should be set.
        {
            let inner = limiter.inner.as_ref().unwrap().lock().unwrap();
            assert!(
                inner.last_global_drop_warn.is_some(),
                "first global drop must update the warn-throttle timestamp"
            );
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn global_drop_warn_throttle_does_not_update_more_than_once_per_second() {
        let clock = std::sync::Arc::new(MockClock::new());
        let limiter = RateLimiter::with_clock(
            &default_config(),
            Box::new(CloneableMockClock(clock.clone())),
        );
        // First, drain global with 1005 distinct flooders.
        for i in 0..1005u32 {
            let octet2 = (i / 256) as u8;
            let octet3 = (i % 256) as u8;
            let flooder: IpAddr = format!("10.1.{octet2}.{octet3}").parse().unwrap();
            limiter.check(flooder);
        }
        let first_ts = {
            let inner = limiter.inner.as_ref().unwrap().lock().unwrap();
            inner.last_global_drop_warn.unwrap()
        };
        // More drops within the same mock-clock instant: timestamp must
        // not update (would indicate a second warn log was emitted). Use
        // a different fresh source so we don't accidentally promote it
        // via Tier 1.
        let fresh: IpAddr = "10.0.0.42".parse().unwrap();
        for _ in 0..100 {
            limiter.check(fresh);
        }
        let second_ts = {
            let inner = limiter.inner.as_ref().unwrap().lock().unwrap();
            inner.last_global_drop_warn.unwrap()
        };
        assert_eq!(
            first_ts, second_ts,
            "warn throttle must suppress subsequent logs within 1s"
        );
        // Advance 1.1 seconds — global bucket refills by ~550 tokens.
        clock.advance(Duration::from_millis(1100));
        // Drain the refilled tokens with another mini-flood so the next
        // drop actually happens, at a time >1s after first_ts. Use a
        // fresh subnet (10.2.x.y) to avoid colliding with the earlier
        // flooder pool.
        for i in 0..600u32 {
            let octet2 = (i / 256) as u8;
            let octet3 = (i % 256) as u8;
            let drainer: IpAddr = format!("10.2.{octet2}.{octet3}").parse().unwrap();
            limiter.check(drainer);
        }
        let third_ts = {
            let inner = limiter.inner.as_ref().unwrap().lock().unwrap();
            inner.last_global_drop_warn.unwrap()
        };
        assert!(
            third_ts > second_ts,
            "after 1s the next drop must re-fire the warn log"
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
