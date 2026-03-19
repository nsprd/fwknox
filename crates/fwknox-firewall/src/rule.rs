// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule and rule-handle types used by the [`FirewallBackend`](crate::FirewallBackend) trait.

use std::{net::IpAddr, time::Duration};

use fwknox_proto::PortProto;

/// One firewall access rule: open `ports` from `source_ip` for `timeout`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRule {
    /// Source IP that should be allowed through.
    pub source_ip: IpAddr,
    /// Allowed `proto/port` pairs.
    pub ports: Vec<PortProto>,
    /// How long the rule should remain in place.
    pub timeout: Duration,
    /// Free-form comment for auditability (e.g., "fwknox:alice:1700000000").
    pub comment: String,
}

/// Opaque identifier for a rule that has been installed in a backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleHandle(pub String);

impl RuleHandle {
    /// Construct a rule handle from a backend-specific string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
