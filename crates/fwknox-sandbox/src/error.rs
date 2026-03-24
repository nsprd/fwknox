// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox sandbox crate.

use thiserror::Error;

/// All errors that can be produced by the fwknox sandbox crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SandboxError {
    /// Failed to enumerate or modify process capabilities.
    #[error("capability error: {0}")]
    Capability(String),

    /// Failed to look up or drop to the target user/group.
    #[error("user/group drop error: {0}")]
    PrivDrop(String),

    /// Failed to construct or apply a Landlock ruleset.
    #[error("landlock error: {0}")]
    Landlock(String),

    /// Failed to communicate with systemd via `sd_notify`.
    #[error("sd_notify error: {0}")]
    SdNotify(#[source] std::io::Error),

    /// A required configuration field was missing or invalid.
    #[error("sandbox configuration error: {0}")]
    Configuration(String),
}
