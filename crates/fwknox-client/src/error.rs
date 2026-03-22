// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox client library.

use thiserror::Error;

/// All errors that can be produced by the fwknox client library.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Failed to load or validate the client TOML config.
    #[error("config error: {0}")]
    Config(#[from] fwknox_config::ConfigError),

    /// A protocol-layer failure (encode, encrypt, HMAC).
    #[error("protocol error: {0}")]
    Proto(#[from] fwknox_proto::ProtoError),

    /// I/O failure (socket bind, address resolution, send).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The CLI invocation was missing required information.
    #[error("missing argument: {0}")]
    MissingArgument(&'static str),

    /// A field could not be parsed (e.g., a malformed `tcp/22`).
    #[error("invalid argument {field}: {reason}")]
    InvalidArgument {
        /// Name of the offending CLI flag or config field.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// The named server entry could not be found in the config.
    #[error("server entry {0} not found in client config")]
    UnknownServer(String),
}
