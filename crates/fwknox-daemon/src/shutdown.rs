// SPDX-License-Identifier: AGPL-3.0-or-later

//! Graceful-shutdown signaling.
//!
//! The daemon's main loop polls a [`ShutdownSignal`] every iteration.
//! Setting up signal handlers via [`ShutdownSignal::install_handlers`]
//! makes `SIGTERM` and `SIGINT` flip the flag, so the next pass through
//! the loop notices and exits cleanly (flushes the firewall, saves the
//! replay cache).

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Atomic shutdown flag shared between the signal handler and the main loop.
#[derive(Debug, Clone, Default)]
pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
}

impl ShutdownSignal {
    /// Construct a fresh signal in the "running" state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install `SIGTERM` and `SIGINT` handlers that flip the flag.
    ///
    /// Calling this more than once is safe — `signal_hook::flag::register`
    /// stacks handlers without removing the existing ones, but each
    /// installed handler will see the same `Arc<AtomicBool>`.
    pub fn install_handlers(&self) -> Result<(), std::io::Error> {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&self.flag))?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&self.flag))?;
        Ok(())
    }

    /// Returns `true` once a shutdown signal has been received.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Manually trip the shutdown flag (used by tests and by the main
    /// loop's error-recovery path).
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_signal_is_not_shutdown() {
        let s = ShutdownSignal::new();
        assert!(!s.is_shutdown());
    }

    #[test]
    fn trigger_flips_the_flag() {
        let s = ShutdownSignal::new();
        s.trigger();
        assert!(s.is_shutdown());
    }

    #[test]
    fn clones_share_state() {
        let a = ShutdownSignal::new();
        let b = a.clone();
        a.trigger();
        assert!(b.is_shutdown());
    }
}
