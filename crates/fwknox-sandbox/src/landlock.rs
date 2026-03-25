// SPDX-License-Identifier: AGPL-3.0-or-later

//! Landlock filesystem restrictions.
//!
//! Landlock is a Linux kernel security feature (5.13+) that lets a
//! process permanently restrict its own filesystem access to a
//! declared set of paths. Once applied, the restrictions are
//! IRREVOCABLE — the process cannot widen its own access later.

use std::path::Path;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use tracing::{debug, info, warn};

use crate::error::SandboxError;

/// Landlock ABI version fwknox targets.
///
/// ABI 1 = Linux 5.13+ filesystem restrictions. We don't yet use the
/// ABI 2+ network restrictions because we bind our capture socket
/// before the sandbox is applied, and outbound traffic isn't part of
/// the normal daemon path.
const TARGET_ABI: ABI = ABI::V1;

/// Description of the filesystem access policy for the daemon.
#[derive(Debug, Clone)]
pub struct FilesystemPolicy<'a> {
    /// Directories the daemon needs read-only access to (e.g. the
    /// directory containing the TOML config file).
    pub read_only: &'a [&'a Path],
    /// Directories the daemon needs read-write access to (e.g. the
    /// replay-cache directory and the PID-file directory).
    pub read_write: &'a [&'a Path],
}

/// Apply the Landlock policy to the current process.
///
/// This is IRREVOCABLE once it succeeds. Calling code should make sure
/// every path is final before calling.
pub fn apply(policy: &FilesystemPolicy<'_>) -> Result<(), SandboxError> {
    let read_only_access = AccessFs::from_read(TARGET_ABI);
    let read_write_access = AccessFs::from_all(TARGET_ABI);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| SandboxError::Landlock(format!("handle_access failed: {e}")))?
        .create()
        .map_err(|e| SandboxError::Landlock(format!("ruleset create failed: {e}")))?;

    for path in policy.read_only {
        debug!(path = %path.display(), "landlock: adding read-only rule");
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Landlock(format!("open {}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, read_only_access))
            .map_err(|e| SandboxError::Landlock(format!("add_rule ro: {e}")))?;
    }
    for path in policy.read_write {
        debug!(path = %path.display(), "landlock: adding read-write rule");
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Landlock(format!("open {}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, read_write_access))
            .map_err(|e| SandboxError::Landlock(format!("add_rule rw: {e}")))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("restrict_self failed: {e}")))?;

    // `restrict_self` succeeds on unsupported kernels but returns a
    // status indicating the ruleset wasn't actually enforced. Check.
    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {
            info!("landlock: ruleset fully enforced");
        }
        landlock::RulesetStatus::PartiallyEnforced => {
            warn!("landlock: ruleset only partially enforced (older kernel features unavailable)");
        }
        landlock::RulesetStatus::NotEnforced => {
            return Err(SandboxError::Landlock(
                "kernel does not support Landlock (needs Linux 5.13+)".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn filesystem_policy_construction() {
        // This test just constructs a policy and asserts we can clone /
        // borrow it. We do NOT call `apply` because Landlock is
        // irrevocable and would break the rest of the test runner's
        // filesystem access.
        let ro_paths = [PathBuf::from("/etc"), PathBuf::from("/usr")];
        let ro_refs: Vec<&Path> = ro_paths.iter().map(PathBuf::as_path).collect();
        let policy = FilesystemPolicy {
            read_only: &ro_refs,
            read_write: &[],
        };
        assert_eq!(policy.read_only.len(), 2);
        assert_eq!(policy.read_write.len(), 0);
    }
}
