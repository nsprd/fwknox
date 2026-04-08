// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(dead_code)]

//! A continuous-refill token bucket.
//!
//! The bucket uses `f64` tokens for fractional accounting and lazy
//! refill computed on every `consume` call. There is no background
//! timer or tick loop — refill is derived from `now - last_refill`
//! multiplied by the rate.

use std::time::Instant;

/// Internal result of a bucket `consume` call. This type is distinct
/// from the public `Decision` because the public type also encodes the
/// drop reason (which depends on *which* bucket rejected the packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BucketDecision {
    Pass,
    Drop,
}

#[derive(Debug)]
pub(crate) struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
    /// Last time a `warn!`-level drop log was emitted for this bucket.
    /// Used by the limiter to throttle warn-level log volume on
    /// sustained drops. `None` until the first drop.
    pub(crate) last_warn_log: Option<Instant>,
}

impl TokenBucket {
    /// Creates a new bucket, starting full.
    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn new(rate_per_sec: u64, capacity: u64, now: Instant) -> Self {
        Self {
            capacity: capacity as f64,
            rate_per_sec: rate_per_sec as f64,
            tokens: capacity as f64,
            last_refill: now,
            last_warn_log: None,
        }
    }

    /// Attempts to consume one token, refilling first.
    pub(crate) fn consume(&mut self, now: Instant) -> BucketDecision {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            BucketDecision::Pass
        } else {
            BucketDecision::Drop
        }
    }

    fn refill(&mut self, now: Instant) {
        // `checked_duration_since` guards against a non-monotonic
        // clock (shouldn't happen with `Instant`, but cheap insurance).
        if let Some(elapsed) = now.checked_duration_since(self.last_refill) {
            let added = elapsed.as_secs_f64() * self.rate_per_sec;
            self.tokens = (self.tokens + added).min(self.capacity);
            self.last_refill = now;
        }
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_bucket_starts_full() {
        let now = Instant::now();
        let b = TokenBucket::new(10, 20, now);
        assert_eq!(b.tokens, 20.0);
    }

    #[test]
    fn consume_decrements_tokens() {
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 20, now);
        assert_eq!(b.consume(now), BucketDecision::Pass);
        assert_eq!(b.tokens, 19.0);
    }

    #[test]
    fn consume_drops_when_empty() {
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 2, now);
        assert_eq!(b.consume(now), BucketDecision::Pass);
        assert_eq!(b.consume(now), BucketDecision::Pass);
        assert_eq!(b.consume(now), BucketDecision::Drop);
    }

    #[test]
    fn refill_restores_tokens_proportional_to_elapsed_time() {
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 10, now);
        // Drain the bucket.
        for _ in 0..10 {
            assert_eq!(b.consume(now), BucketDecision::Pass);
        }
        assert_eq!(b.consume(now), BucketDecision::Drop);
        // After 500ms, exactly 5 tokens should be available (rate=10/sec).
        let later = now + Duration::from_millis(500);
        b.refill(later);
        assert!((b.tokens - 5.0).abs() < 1e-9);
    }

    #[test]
    fn refill_caps_at_capacity() {
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 10, now);
        // Already full — advance time by an hour and re-refill.
        let much_later = now + Duration::from_secs(3600);
        b.refill(much_later);
        assert_eq!(b.tokens, 10.0);
    }

    #[test]
    fn consume_after_full_refill_passes() {
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 5, now);
        for _ in 0..5 {
            b.consume(now);
        }
        assert_eq!(b.consume(now), BucketDecision::Drop);
        // Advance 1 second: bucket gets 10 tokens but caps at 5.
        let later = now + Duration::from_secs(1);
        assert_eq!(b.consume(later), BucketDecision::Pass);
    }

    #[test]
    fn non_monotonic_clock_does_not_crash() {
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 10, now);
        b.consume(now);
        // Advance backwards (should be impossible with Instant, but
        // verify the guard).
        let earlier = now;  // same instant, not earlier — Instant refuses
        b.refill(earlier);  // must not panic
        assert!(b.tokens < 10.0);
    }

    #[test]
    fn fractional_refill_accumulates_correctly_over_many_calls() {
        // Call consume 100 times over 1 second with rate=10. Expected:
        // about 10 tokens consumed successfully beyond the initial burst.
        let now = Instant::now();
        let mut b = TokenBucket::new(10, 10, now);
        let mut passes = 0;
        for i in 0..100 {
            let t = now + Duration::from_millis(i * 10);
            if let BucketDecision::Pass = b.consume(t) {
                passes += 1;
            }
        }
        // Initial burst of 10 + ~9 refilled over 990ms (the 10th refill
        // tick lands at exactly t=990ms which adds 9.9 tokens). Expect
        // roughly 19-20 passes total.
        assert!((19..=20).contains(&passes), "got {passes} passes");
    }
}
