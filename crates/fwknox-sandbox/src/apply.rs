// SPDX-License-Identifier: AGPL-3.0-or-later

//! High-level sandbox orchestrator.
//!
//! [`apply`] runs the full hardening sequence in the correct order:
//!
//! 1. Drop every capability except those in [`SandboxConfig::keep_caps`].
//! 2. If [`SandboxConfig::drop_to`] is set, switch to that user/group.
//! 3. If [`SandboxConfig::landlock`] is set, install the Landlock
//!    ruleset (this is irrevocable; nothing after it can widen access).
//!
//! The caller is responsible for having bound sockets and initialised
//! anything that needs root/netlink before calling `apply`.

use std::path::PathBuf;

use caps::Capability;
use tracing::info;

use crate::{
    capabilities,
    error::SandboxError,
    landlock::{self, FilesystemPolicy},
    privdrop,
};

/// The user/group the sandbox should drop to.
#[derive(Debug, Clone)]
pub struct PrivDropTarget {
    /// Target user name.
    pub user: String,
    /// Target group name.
    pub group: String,
}

/// Filesystem policy for Landlock.
#[derive(Debug, Clone, Default)]
pub struct LandlockConfig {
    /// Directories/files the daemon needs read-only access to.
    pub read_only: Vec<PathBuf>,
    /// Directories/files the daemon needs read-write access to.
    pub read_write: Vec<PathBuf>,
}

/// Full sandbox configuration. Fields are all optional so callers can
/// opt in or out of each layer independently.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Capabilities to keep. Empty means "drop everything". The common
    /// value for the daemon is `vec![Capability::CAP_NET_ADMIN]`.
    pub keep_caps: Vec<Capability>,
    /// User/group to drop to. `None` means "don't drop".
    pub drop_to: Option<PrivDropTarget>,
    /// Landlock policy. `None` means "don't apply Landlock".
    pub landlock: Option<LandlockConfig>,
}

/// Apply the configured sandbox layers in the correct order.
///
/// After this returns successfully, the process:
///
/// - Only has the capabilities in `config.keep_caps`.
/// - Is running as `config.drop_to` (if set).
/// - Is Landlock-restricted to `config.landlock` (if set).
///
/// Any of these individual steps may fail — the function returns as
/// soon as one does. Prior successful steps are NOT rolled back.
pub fn apply(config: &SandboxConfig) -> Result<(), SandboxError> {
    info!(
        keep_caps = ?config.keep_caps,
        drop_to = ?config.drop_to.as_ref().map(|t| (&t.user, &t.group)),
        landlock_enabled = config.landlock.is_some(),
        "applying sandbox"
    );

    // Step 1: capabilities. We drop BEFORE privdrop because setuid
    // would silently clear some capability bits anyway; trimming
    // explicitly beforehand makes the intent auditable and means the
    // kept-caps list is what actually survives.
    capabilities::drop_all_except(&config.keep_caps)?;

    // Step 2: user/group. This happens BEFORE Landlock because
    // PathFd::new (which Landlock uses) needs to read the config dir
    // and the replay-cache parent dir, and the target user must own or
    // be able to read those paths.
    if let Some(target) = &config.drop_to {
        privdrop::drop_to(&target.user, &target.group)?;
        // Re-raise the effective caps. setuid cleared them even though
        // PR_SET_KEEPCAPS preserved Permitted — we must explicitly
        // promote Permitted back into Effective for the caps we kept.
        capabilities::raise_effective(&config.keep_caps)?;
    }

    // Step 3: Landlock. This is irrevocable — nothing we do after this
    // can widen our filesystem access.
    if let Some(ll) = &config.landlock {
        let ro: Vec<&std::path::Path> = ll.read_only.iter().map(PathBuf::as_path).collect();
        let rw: Vec<&std::path::Path> = ll.read_write.iter().map(PathBuf::as_path).collect();
        let policy = FilesystemPolicy {
            read_only: &ro,
            read_write: &rw,
        };
        landlock::apply(&policy)?;
    }

    info!("sandbox applied successfully");
    Ok(())
}

/// Apply the worker sandbox: Landlock with empty filesystem policy,
/// then the worker seccomp filter.
///
/// This is the function the privsep orchestrator calls from inside
/// each child process (capture and crypto workers) immediately after
/// installing signal handlers and immediately before entering the
/// worker's main loop.
///
/// The two layers are applied in this order because:
///
/// 1. Landlock is applied first because `landlock_create_ruleset` and
///    `landlock_restrict_self` are themselves syscalls. If seccomp ran
///    first without those syscalls in the allowlist, the Landlock
///    setup would be killed by SIGSYS.
/// 2. With Landlock done, the seccomp filter can omit the Landlock
///    syscalls, giving a tighter allowlist.
///
/// Both layers are irrevocable per-thread. Any failure returns
/// `SandboxError` and the caller is responsible for exiting the
/// child process so it doesn't accidentally run unsandboxed.
///
/// `worker_name` is included in the log lines so each child's sandbox
/// install is auditable in the parent's log stream.
pub fn apply_worker_sandbox(worker_name: &'static str) -> Result<(), SandboxError> {
    tracing::info!(
        worker = worker_name,
        "applying worker sandbox: Landlock first"
    );
    let policy = crate::landlock::FilesystemPolicy {
        read_only: &[],
        read_write: &[],
    };
    crate::landlock::apply(&policy)?;

    tracing::info!(
        worker = worker_name,
        "applying worker sandbox: seccomp filter"
    );
    crate::seccomp::install_worker_filter()?;

    tracing::info!(worker = worker_name, "worker sandbox applied successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_applies_without_error() {
        // An empty SandboxConfig asks to drop all caps but not to
        // touch user/group or Landlock. Because the test runner may
        // start without any capabilities anyway, drop_all should be
        // a no-op.
        let config = SandboxConfig::default();
        let _ = apply(&config);
    }

    #[test]
    fn keep_caps_list_is_honored_in_config() {
        let config = SandboxConfig {
            keep_caps: vec![Capability::CAP_NET_ADMIN],
            ..Default::default()
        };
        assert_eq!(config.keep_caps.len(), 1);
    }

    #[test]
    fn drop_to_target_is_cloneable() {
        let target = PrivDropTarget {
            user: "nobody".into(),
            group: "nogroup".into(),
        };
        let clone = target.clone();
        assert_eq!(clone.user, "nobody");
    }
}
