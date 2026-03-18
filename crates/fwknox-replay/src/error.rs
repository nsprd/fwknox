// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox replay-detection cache.

use std::path::PathBuf;

use thiserror::Error;

/// All errors that can be produced by the fwknox replay crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReplayError {
    /// Failed to read the cache file from disk.
    #[error("failed to read replay cache {path}: {source}", path = path.display())]
    Read {
        /// Path that failed to load.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to write the cache file to disk.
    #[error("failed to write replay cache {path}: {source}", path = path.display())]
    Write {
        /// Path that failed to write.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The cache file format is unrecognized or corrupted.
    #[error("invalid cache format in {path}: {reason}", path = path.display())]
    InvalidFormat {
        /// Path of the file with the bad data.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
}
