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

    /// An I/O failure during signal-handler setup or other host work.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
