// SPDX-License-Identifier: AGPL-3.0-or-later

//! `sd_notify` wrappers for systemd integration.
//!
//! systemd tracks daemon lifecycle via `$NOTIFY_SOCKET` and the
//! `sd_notify` protocol:
//!
//! - `READY=1` tells systemd the daemon is fully initialised and ready
//!   to receive traffic. Type=notify units wait for this before
//!   considering the service started.
//! - `WATCHDOG=1` is the watchdog heartbeat. If the unit sets
//!   `WatchdogSec=`, systemd will kill the daemon if no heartbeat
//!   arrives within that window.
//! - `STOPPING=1` tells systemd the daemon has started its shutdown
//!   sequence so systemd doesn't count the shutdown delay as a hang.
//!
//! All three functions are no-ops (returning `Ok(())`) when
//! `$NOTIFY_SOCKET` is unset, so they're safe to call unconditionally
//! during development or under direct invocation.

use crate::error::SandboxError;

/// Send `READY=1` to systemd.
pub fn ready() -> Result<(), SandboxError> {
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).map_err(SandboxError::SdNotify)
}

/// Send a watchdog heartbeat (`WATCHDOG=1`) to systemd.
pub fn watchdog() -> Result<(), SandboxError> {
    sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]).map_err(SandboxError::SdNotify)
}

/// Send `STOPPING=1` to systemd so it doesn't treat the shutdown
/// sequence as a hang.
pub fn stopping() -> Result<(), SandboxError> {
    sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]).map_err(SandboxError::SdNotify)
}

/// Returns the configured watchdog interval, if any. The daemon should
/// call this once at startup and schedule heartbeats well inside the
/// returned window.
#[must_use]
pub fn watchdog_interval() -> Option<std::time::Duration> {
    // sd_notify's watchdog_enabled returns a microsecond count.
    let mut usec: u64 = 0;
    if sd_notify::watchdog_enabled(false, &mut usec) {
        Some(std::time::Duration::from_micros(usec))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_calls_are_noops_outside_systemd() {
        // With no $NOTIFY_SOCKET in the test environment, sd_notify
        // returns Ok(()). These calls must not panic or error.
        ready().unwrap();
        watchdog().unwrap();
        stopping().unwrap();
    }

    #[test]
    fn watchdog_interval_is_none_outside_systemd() {
        assert!(watchdog_interval().is_none());
    }
}
