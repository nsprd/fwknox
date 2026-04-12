// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox daemon.

use thiserror::Error;

/// All errors that can be produced by the fwknox daemon library.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DaemonError {
    /// Failed to load or validate the daemon's TOML config file.
    #[error("config error: {0}")]
    Config(#[from] fwknox_config::ConfigError),

    /// The firewall backend failed (init, install, or flush).
    #[error("firewall error: {0}")]
    Firewall(#[from] fwknox_firewall::FirewallError),

    /// The capture backend failed (bind or recv).
    #[error("capture error: {0}")]
    Capture(#[from] fwknox_capture::CaptureError),

    /// The replay-detection cache failed (load or save).
    #[error("replay cache error: {0}")]
    Replay(#[from] fwknox_replay::ReplayError),

    /// The sandbox layer failed to apply.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] fwknox_sandbox::SandboxError),

    /// A protocol-layer failure during processing.
    #[error("protocol error: {0}")]
    Proto(#[from] fwknox_proto::ProtoError),

    /// A privilege-separation operation failed.
    #[error("privsep error: {0}")]
    Privsep(#[from] fwknox_privsep::PrivsepError),

    /// An I/O failure during signal-handler setup or other host work.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An internal invariant was violated (e.g. a stanza name produced
    /// by the matcher was not found in the config). These are
    /// "should-never-happen" conditions that we prefer to surface as
    /// errors rather than panics so the daemon can log and drop the
    /// offending packet instead of crashing the whole process.
    #[error("internal invariant violated: {0}")]
    InvariantViolation(String),
}
