// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time source abstraction for the rate limiter.
//!
//! Production code uses [`SystemClock`] which delegates to
//! `Instant::now()`. Tests and integration harnesses use
//! [`MockClock`], which returns a manually-advanced fixed time.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A monotonic time source.
///
/// The trait takes `&self` (not `&mut self`) because production
/// `Instant::now()` is side-effect-free and the mock uses interior
/// mutability.
pub trait Clock: Send + Sync {
    /// Returns the current monotonic instant from this clock.
    fn now(&self) -> Instant;
}

/// Production clock. Delegates to `Instant::now()`.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Test clock. Returns a fixed [`Instant`] that advances only when
/// [`MockClock::advance`] is called. Interior-mutable via [`Mutex`]
/// so the clock can be shared immutably.
pub struct MockClock {
    current: Mutex<Instant>,
}

impl MockClock {
    /// Creates a new mock clock anchored at an arbitrary starting
    /// instant. The anchor is not observable to callers — only the
    /// relative advances matter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: Mutex::new(Instant::now()),
        }
    }

    /// Advances the mock clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        let mut current = self.current.lock().expect("mock clock poisoned");
        *current += delta;
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        *self.current.lock().expect("mock clock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_advances_over_time() {
        let clock = SystemClock;
        let t0 = clock.now();
        std::thread::sleep(Duration::from_millis(1));
        let t1 = clock.now();
        assert!(t1 > t0);
    }

    #[test]
    fn mock_clock_returns_fixed_time_without_advance() {
        let clock = MockClock::new();
        let t0 = clock.now();
        let t1 = clock.now();
        assert_eq!(t0, t1);
    }

    #[test]
    fn mock_clock_advances_by_exact_delta() {
        let clock = MockClock::new();
        let t0 = clock.now();
        clock.advance(Duration::from_secs(5));
        let t1 = clock.now();
        assert_eq!(t1 - t0, Duration::from_secs(5));
    }

    #[test]
    fn mock_clock_multiple_advances_accumulate() {
        let clock = MockClock::new();
        let t0 = clock.now();
        clock.advance(Duration::from_millis(100));
        clock.advance(Duration::from_millis(200));
        clock.advance(Duration::from_millis(300));
        assert_eq!(clock.now() - t0, Duration::from_millis(600));
    }
}
