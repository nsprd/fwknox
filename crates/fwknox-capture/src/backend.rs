// SPDX-License-Identifier: AGPL-3.0-or-later

//! The [`CaptureBackend`] trait.

use std::time::Duration;

use crate::error::CaptureError;
use crate::packet::CapturedPacket;

/// A pluggable packet capture source. Implementations must be
/// `Send + Sync` because the daemon's capture worker may be a separate
/// thread or process.
pub trait CaptureBackend: Send + Sync {
    /// Block until the next packet arrives.
    ///
    /// Implementations should return [`CaptureError::Recv`] for transient
    /// failures (e.g., interrupted system call); the caller is expected
    /// to log and continue.
    fn recv(&self) -> Result<CapturedPacket, CaptureError>;

    /// Wait up to `timeout` for a packet. Returns `Ok(None)` on timeout.
    ///
    /// The daemon's main loop uses this so it can poll its shutdown flag
    /// without holding a thread inside a syscall indefinitely.
    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<CapturedPacket>, CaptureError>;
}
