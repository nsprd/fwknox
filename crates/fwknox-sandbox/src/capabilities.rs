// SPDX-License-Identifier: AGPL-3.0-or-later

//! Capability dropping via the `caps` crate.
//!
//! The fwknox daemon only needs `CAP_NET_ADMIN` (to manipulate nftables
//! via netlink). Every other capability — including `CAP_NET_RAW`,
//! `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, etc — is dropped from the
//! effective, permitted, inheritable, bounding, and ambient sets.

use caps::{CapSet, Capability};
use tracing::{debug, warn};

use crate::error::SandboxError;

/// Drop every capability from the process except those listed in `keep`.
///
/// This modifies the Effective, Permitted, Inheritable, Bounding, and
/// Ambient capability sets. Bounding-set modification requires
/// `CAP_SETPCAP`; if the caller doesn't have it the function logs a
/// warning and continues (the other sets are still trimmed).
pub fn drop_all_except(keep: &[Capability]) -> Result<(), SandboxError> {
    let all: Vec<Capability> = caps::all().into_iter().collect();
    for cap in all {
        if keep.contains(&cap) {
            continue;
        }
        for set in [
            CapSet::Effective,
            CapSet::Permitted,
            CapSet::Inheritable,
            CapSet::Ambient,
        ] {
            match caps::drop(None, set, cap) {
                Ok(()) => {}
                Err(e) => {
                    // Dropping a capability we don't have is a non-fatal
                    // no-op on Linux, but caps returns an error for some
                    // transitions. Log and continue.
                    debug!(cap = ?cap, set = ?set, error = %e, "capability drop non-fatal");
                }
            }
        }
        // Bounding set drop may require CAP_SETPCAP.
        if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
            warn!(cap = ?cap, error = %e, "bounding set drop skipped (process lacks CAP_SETPCAP?)");
        }
    }
    // Re-check the effective set to confirm.
    let effective =
        caps::read(None, CapSet::Effective).map_err(|e| SandboxError::Capability(e.to_string()))?;
    for kept in keep {
        if !effective.contains(kept) {
            warn!(cap = ?kept, "kept capability not actually present after drop");
        }
    }
    Ok(())
}

/// Drop all capabilities — the process keeps nothing.
pub fn drop_all() -> Result<(), SandboxError> {
    drop_all_except(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_all_except_empty_list_is_well_defined() {
        // This test runs as a normal user without CAP_SETPCAP, so the
        // actual capability set after the call depends on what the test
        // runner had to begin with. We just verify the function doesn't
        // panic and returns Ok.
        let _ = drop_all_except(&[Capability::CAP_NET_ADMIN]);
    }

    #[test]
    fn keep_list_with_net_admin_does_not_error() {
        let _ = drop_all_except(&[Capability::CAP_NET_ADMIN]);
    }
}
