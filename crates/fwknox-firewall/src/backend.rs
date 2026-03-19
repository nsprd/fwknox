// SPDX-License-Identifier: AGPL-3.0-or-later

//! The [`FirewallBackend`] trait.

use crate::error::FirewallError;
use crate::rule::{AccessRule, RuleHandle};

/// Pluggable firewall backend used by the daemon. Implementations must be
/// `Send + Sync` because the daemon may invoke them from a worker pool.
pub trait FirewallBackend: Send + Sync {
    /// Initialise the backend (create tables, chains, sets).
    ///
    /// Implementations should be idempotent — calling `init` twice on a
    /// freshly-flushed backend must succeed.
    fn init(&mut self) -> Result<(), FirewallError>;

    /// Install an access rule and return a handle for later removal.
    fn open_access(&self, rule: &AccessRule) -> Result<RuleHandle, FirewallError>;

    /// Remove a previously-installed rule.
    fn remove_rule(&self, handle: &RuleHandle) -> Result<(), FirewallError>;

    /// Tear down all fwknox-managed firewall state.
    fn flush(&mut self) -> Result<(), FirewallError>;
}
