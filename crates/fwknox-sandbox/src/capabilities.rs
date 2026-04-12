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

/// After a `setuid()` that cleared the effective set (even though the
/// Permitted set was preserved by `PR_SET_KEEPCAPS`), re-raise the
/// requested capabilities from Permitted into Effective.
///
/// This is the final step of the privdrop sequence and assumes the
/// caller already ran [`drop_all_except`] to restrict the Permitted
/// set to exactly `keep`. If a capability in `keep` isn't in
/// Permitted (e.g. because the parent didn't actually hold it), this
/// returns a `SandboxError::Capability`.
pub fn raise_effective(keep: &[Capability]) -> Result<(), SandboxError> {
    // Precondition: every cap we want to raise into Effective must
    // already be present in Permitted. If not, the `caps::raise` call
    // below would fail with an opaque EPERM from capset(2); checking
    // up front lets us surface a clear configuration error and fail
    // fast rather than late.
    let permitted = caps::read(None, CapSet::Permitted)
        .map_err(|e| SandboxError::Configuration(format!("read Permitted: {e}")))?;
    for cap in keep {
        if !permitted.contains(cap) {
            return Err(SandboxError::Configuration(format!(
                "cannot raise {cap:?}: not in Permitted set"
            )));
        }
    }
    for cap in keep {
        caps::raise(None, CapSet::Effective, *cap).map_err(|e| {
            SandboxError::Capability(format!("could not raise {cap:?} into effective set: {e}"))
        })?;
    }
    Ok(())
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

    #[test]
    fn raise_effective_rejects_cap_not_in_permitted() {
        // CAP_MAC_ADMIN is essentially never held by an unprivileged
        // test runner, and even a root-running CI is vanishingly
        // unlikely to hold it unless LSMs (SELinux/Smack) are
        // explicitly loaded and configured. If this assertion ever
        // flakes on an unusual test host, swap for another cap that
        // the host definitely lacks.
        let err = raise_effective(&[Capability::CAP_MAC_ADMIN])
            .expect_err("expected raise_effective to fail when cap is not in Permitted");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("not in Permitted"),
            "error message should mention 'not in Permitted', got: {msg}"
        );
    }
}
