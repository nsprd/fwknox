// SPDX-License-Identifier: AGPL-3.0-or-later

//! Drop the process user/group to an unprivileged account.
//!
//! This is called after the daemon binds its capture socket and
//! initialises the firewall backend (both of which may need root or
//! `CAP_NET_ADMIN`). Order matters: set the gid first, then the uid —
//! reversing the order means `setgid` runs with the new uid's
//! (typically fewer) permissions and may fail.

use nix::unistd::{setgid, setgroups, setuid, Gid, Group, Uid, User};
use tracing::info;

use crate::error::SandboxError;

/// Look up a user by name and return its uid.
pub fn resolve_user(name: &str) -> Result<Uid, SandboxError> {
    User::from_name(name)
        .map_err(|e| SandboxError::PrivDrop(format!("user lookup failed for {name}: {e}")))?
        .map(|u| u.uid)
        .ok_or_else(|| SandboxError::PrivDrop(format!("user {name} not found")))
}

/// Look up a group by name and return its gid.
pub fn resolve_group(name: &str) -> Result<Gid, SandboxError> {
    Group::from_name(name)
        .map_err(|e| SandboxError::PrivDrop(format!("group lookup failed for {name}: {e}")))?
        .map(|g| g.gid)
        .ok_or_else(|| SandboxError::PrivDrop(format!("group {name} not found")))
}

/// Drop to the given user and group.
///
/// The sequence is:
///
/// 1. `setgroups(&[gid])` — clear supplementary groups.
/// 2. `setgid(gid)` — change the primary group.
/// 3. `setuid(uid)` — change the user; after this the process is unprivileged.
///
/// All three require either `CAP_SETGID`/`CAP_SETUID` (for a privileged
/// process) or running as root. Calling this as a non-root user without
/// the relevant capabilities returns `SandboxError::PrivDrop`.
pub fn drop_to(user: &str, group: &str) -> Result<(), SandboxError> {
    let uid = resolve_user(user)?;
    let gid = resolve_group(group)?;
    info!(
        user,
        group,
        uid = uid.as_raw(),
        gid = gid.as_raw(),
        "dropping privileges"
    );

    setgroups(&[gid]).map_err(|e| SandboxError::PrivDrop(format!("setgroups failed: {e}")))?;
    setgid(gid).map_err(|e| SandboxError::PrivDrop(format!("setgid failed: {e}")))?;

    // Preserve Permitted capabilities across setuid. Without this,
    // the kernel clears Permitted/Effective/Ambient during the setuid
    // fixup (capabilities(7) "Effect of user ID changes on
    // capabilities"). The caller is responsible for re-raising the
    // effective set afterwards via `capabilities::raise_effective`.
    caps::securebits::set_keepcaps(true)
        .map_err(|e| SandboxError::PrivDrop(format!("set_keepcaps(true) failed: {e}")))?;

    setuid(uid).map_err(|e| SandboxError::PrivDrop(format!("setuid failed: {e}")))?;

    // Clear the keepcaps bit now that the setuid is done; we don't
    // want it to persist for future setuid calls (there shouldn't be
    // any, but this is defensive).
    caps::securebits::set_keepcaps(false)
        .map_err(|e| SandboxError::PrivDrop(format!("set_keepcaps(false) failed: {e}")))?;

    Ok(())
}

/// Returns `true` if the current process is running as uid 0.
#[must_use]
pub fn is_root() -> bool {
    Uid::current().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_nonexistent_user_errors() {
        let err = resolve_user("definitely-not-a-real-user-xyz").unwrap_err();
        assert!(matches!(err, SandboxError::PrivDrop(_)));
    }

    #[test]
    fn resolve_nonexistent_group_errors() {
        let err = resolve_group("definitely-not-a-real-group-xyz").unwrap_err();
        assert!(matches!(err, SandboxError::PrivDrop(_)));
    }

    #[test]
    fn is_root_returns_boolean() {
        // Just call it to make sure it doesn't panic.
        let _ = is_root();
    }
}
