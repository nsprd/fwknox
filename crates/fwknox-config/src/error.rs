// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox config crate.

use std::path::PathBuf;

use thiserror::Error;

/// All errors that can be produced by the fwknox config crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Failed to read a config file from disk.
    #[error("failed to read config file {path}: {source}", path = path.display())]
    Io {
        /// Path that failed to load.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse the TOML body of a config file.
    #[error("failed to parse TOML in {path}: {source}", path = path.display())]
    Toml {
        /// Path of the file with invalid TOML.
        path: PathBuf,
        /// Underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },

    /// A semantic constraint of the config was violated (e.g., empty list,
    /// duplicate name, contradictory fields).
    #[error("invalid configuration: {0}")]
    Invalid(String),

    /// A field expected to contain base64 had invalid encoding.
    #[error("invalid base64 in field {field}: {source}")]
    Base64 {
        /// Name of the field that failed to decode.
        field: &'static str,
        /// Underlying base64 decoder error.
        #[source]
        source: base64::DecodeError,
    },
}

impl ConfigError {
    /// Convenience constructor for the [`Invalid`](Self::Invalid) variant.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_helper_constructs_variant() {
        let err = ConfigError::invalid("oh no");
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("oh no"));
    }
}
