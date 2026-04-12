// SPDX-License-Identifier: AGPL-3.0-or-later

//! Landlock filesystem restrictions.
//!
//! Landlock is a Linux kernel security feature (5.13+) that lets a
//! process permanently restrict its own filesystem access to a
//! declared set of paths. Once applied, the restrictions are
//! IRREVOCABLE — the process cannot widen its own access later.

use std::path::Path;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use tracing::{debug, info, warn};

use crate::error::SandboxError;

/// Outcome of interpreting a Landlock `RulesetStatus` in the context of
/// the policy that was installed. This lets callers (daemon vs. worker)
/// treat `PartiallyEnforced` differently depending on whether any
/// explicit allow rules were present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RulesetOutcome {
    /// The ruleset provides the protection the caller expected.
    Enforced,
    /// The kernel did not provide sufficient enforcement for the caller's
    /// threat model; the caller MUST fail closed.
    Insufficient,
}

/// Classify a `RulesetStatus` against whether the installed policy was
/// empty (i.e. zero allow rules — total filesystem denial was the
/// intent, as in the worker sandbox).
///
/// - `FullyEnforced` is always sufficient.
/// - `NotEnforced` is always insufficient (kernel < 5.13 or disabled).
/// - `PartiallyEnforced` with an empty policy is insufficient: the
///   worker sandbox relies on the full ruleset being active to deny all
///   filesystem access. If the kernel only partially applied it, the
///   worker may still reach the filesystem, which violates the sandbox
///   contract. Fail closed.
/// - `PartiallyEnforced` with a non-empty policy is acceptable: the
///   daemon installs explicit allow rules over an otherwise denied set,
///   so partial enforcement still narrows access relative to no
///   sandbox at all. Log and continue.
pub(crate) fn classify_status(status: &RulesetStatus, policy_is_empty: bool) -> RulesetOutcome {
    // The four arms are kept enumerated (rather than merged) so the
    // audit-visible mapping from (status, policy-shape) -> outcome stays
    // 1:1 with the doc comment above. Merging via `|` would obscure the
    // asymmetry between the two `PartiallyEnforced` cases, which is the
    // whole point of this helper.
    #[allow(clippy::match_same_arms)]
    match (status, policy_is_empty) {
        (RulesetStatus::FullyEnforced, _) => RulesetOutcome::Enforced,
        (RulesetStatus::PartiallyEnforced, true) => RulesetOutcome::Insufficient,
        (RulesetStatus::PartiallyEnforced, false) => RulesetOutcome::Enforced,
        (RulesetStatus::NotEnforced, _) => RulesetOutcome::Insufficient,
    }
}

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
    let policy_is_empty = policy.read_only.is_empty() && policy.read_write.is_empty();
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
    // status indicating the ruleset wasn't actually enforced. Check,
    // and treat `PartiallyEnforced` as fail-closed when the policy is
    // empty (the worker sandbox case — see `classify_status` docs).
    match classify_status(&status.ruleset, policy_is_empty) {
        RulesetOutcome::Enforced => match status.ruleset {
            RulesetStatus::FullyEnforced => {
                info!("landlock: ruleset fully enforced");
            }
            RulesetStatus::PartiallyEnforced => {
                warn!(
                    "landlock: ruleset only partially enforced \
                     (older kernel features unavailable); \
                     explicit allow rules still narrow access"
                );
            }
            RulesetStatus::NotEnforced => {
                unreachable!("classify_status never returns Enforced for NotEnforced")
            }
        },
        RulesetOutcome::Insufficient => {
            return Err(SandboxError::Landlock(match status.ruleset {
                RulesetStatus::NotEnforced => {
                    "kernel does not support Landlock (needs Linux 5.13+)".into()
                }
                RulesetStatus::PartiallyEnforced => {
                    // Empty policy + PartiallyEnforced: the worker
                    // sandbox's total-deny intent cannot be guaranteed.
                    "landlock: kernel only partially enforced an empty policy; \
                     refusing to run worker without full filesystem denial"
                        .into()
                }
                RulesetStatus::FullyEnforced => {
                    unreachable!("classify_status never returns Insufficient for FullyEnforced")
                }
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn classify_fully_enforced_is_always_enforced() {
        // FullyEnforced means the kernel installed every rule we asked
        // for. Policy shape (empty or not) is irrelevant.
        assert_eq!(
            classify_status(&RulesetStatus::FullyEnforced, true),
            RulesetOutcome::Enforced
        );
        assert_eq!(
            classify_status(&RulesetStatus::FullyEnforced, false),
            RulesetOutcome::Enforced
        );
    }

    #[test]
    fn classify_partially_enforced_empty_policy_is_insufficient() {
        // Worker sandbox case: empty policy = "deny everything". If the
        // kernel only partially enforced it, we have no guarantee the
        // worker is actually blocked from the filesystem.
        assert_eq!(
            classify_status(&RulesetStatus::PartiallyEnforced, true),
            RulesetOutcome::Insufficient
        );
    }

    #[test]
    fn classify_partially_enforced_non_empty_policy_is_enforced() {
        // Daemon sandbox case: explicit allow rules. Partial
        // enforcement still narrows the process relative to no
        // sandbox, so we accept it with a warning.
        assert_eq!(
            classify_status(&RulesetStatus::PartiallyEnforced, false),
            RulesetOutcome::Enforced
        );
    }

    #[test]
    fn classify_not_enforced_is_always_insufficient() {
        // NotEnforced means Landlock isn't active at all (old kernel or
        // disabled). Never acceptable, regardless of policy shape.
        assert_eq!(
            classify_status(&RulesetStatus::NotEnforced, true),
            RulesetOutcome::Insufficient
        );
        assert_eq!(
            classify_status(&RulesetStatus::NotEnforced, false),
            RulesetOutcome::Insufficient
        );
    }

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
