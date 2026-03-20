// SPDX-License-Identifier: AGPL-3.0-or-later

//! The [`CaptureBackend`] trait.

use crate::{error::CaptureError, packet::CapturedPacket};

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
}
