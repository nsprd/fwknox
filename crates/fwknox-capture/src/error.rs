// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox capture crate.

use thiserror::Error;

/// All errors that can be produced by a capture backend.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// Failed to bind the underlying socket.
    #[error("failed to bind capture socket: {0}")]
    Bind(#[source] std::io::Error),

    /// Failed to receive a packet from the socket.
    #[error("failed to receive packet: {0}")]
    Recv(#[source] std::io::Error),
}
