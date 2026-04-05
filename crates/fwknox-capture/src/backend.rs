// SPDX-License-Identifier: AGPL-3.0-or-later

//! The [`CaptureBackend`] trait.

use std::time::Duration;

use crate::{error::CaptureError, packet::CapturedPacket};

/// A pluggable packet capture source. Implementations must be
/// `Send + Sync` because the daemon's capture worker may be a separate
/// thread or process.
///
/// [`recv_timeout`](CaptureBackend::recv_timeout) is the only supported
/// operation: the daemon always polls with a bounded timeout so it can
/// check its shutdown flag, and there is no production caller that needs
/// an indefinitely-blocking receive.
pub trait CaptureBackend: Send + Sync {
    /// Wait up to `timeout` for a packet. Returns `Ok(None)` on timeout.
    ///
    /// The daemon's main loop uses this so it can poll its shutdown flag
    /// without holding a thread inside a syscall indefinitely.
    fn recv_timeout(&self, timeout: Duration) -> Result<Option<CapturedPacket>, CaptureError>;
}
