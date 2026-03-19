// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the fwknox firewall crate.

use thiserror::Error;

/// All errors that can be produced by a `FirewallBackend`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FirewallError {
    /// The backend (e.g. `nftables-rs`) failed to apply a ruleset.
    ///
    /// The wrapped string is the human-readable representation of the
    /// underlying error; we deliberately do not expose the concrete
    /// `nftables::helper::NftablesError` type so that swapping in a
    /// different backend later does not break this enum's API.
    #[error("nftables backend failure: {0}")]
    Backend(String),

    /// A rule with the given handle was not found.
    #[error("rule not found: {0}")]
    RuleNotFound(String),

    /// The backend is in an inconsistent state (e.g. table missing, init not called).
    #[error("backend in inconsistent state: {0}")]
    InconsistentState(String),

    /// The requested operation is not supported in this phase.
    #[error("operation not supported: {0}")]
    Unsupported(&'static str),
}
