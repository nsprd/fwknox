// SPDX-License-Identifier: AGPL-3.0-or-later

//! seccomp-bpf filters built with the `seccompiler` crate.
//!
//! Two profiles are provided:
//!
//! - [`worker_filter`]: the tight whitelist for both workers
//!   (capture and crypto). Allows only the syscalls a worker actually
//!   needs to read from a socket, write to another socket, and exit.
//!   The default action for everything else is `KillProcess`, so any
//!   unexpected syscall terminates the worker immediately.
//!
//! A future version may add a separate filter for the capture worker
//! if it ever needs pcap (which requires `CAP_NET_RAW` and a larger
//! syscall set). For now both workers use the same filter because the
//! UDP capture path and the crypto path share the same syscall
//! requirements: recv, send, read, write, futex, brk, mmap, clock,
//! and exit.

use std::collections::BTreeMap;

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
};
use tracing::info;

use crate::error::SandboxError;

/// Target architecture for seccomp filter compilation. We select at
/// compile time based on `cfg(target_arch)`. Only `x86_64` and `aarch64`
/// are supported in Phase 5; other Linux architectures return
/// `SandboxError::Configuration` at filter-build time.
#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;

#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// Build the tight syscall filter used by both the capture and crypto
/// workers. The filter allows:
///
/// - `read`, `write`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg` — for
///   socket I/O (both the UDP socket and the `UnixDatagram` socketpair)
/// - `futex` — for any internal mutex/RwLock that might be entered
/// - `brk`, `mmap`, `munmap` — for the allocator
/// - `clock_gettime`, `clock_nanosleep`, `nanosleep` — for time
/// - `close` — for dropping file descriptors
/// - `exit`, `exit_group`, `rt_sigreturn` — for graceful exit and
///   signal delivery
/// - `getpid`, `gettid`, `rt_sigaction`, `rt_sigprocmask` — for
///   signal-hook's own internals
/// - `poll`, `ppoll`, `epoll_wait`, `epoll_ctl` — the standard library
///   uses these for `set_read_timeout` even though we're doing blocking
///   reads
///
/// Everything else triggers `SeccompAction::KillProcess`.
pub fn worker_filter() -> Result<BpfProgram, SandboxError> {
    // Allow list: each syscall maps to an empty rule vec, which means
    // "allow with any arguments".
    let rules: BTreeMap<i64, Vec<SeccompRule>> = [
        // I/O
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_close,
        // fcntl is needed to set socket read timeouts via setsockopt
        libc::SYS_fcntl,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        // Poll/timeout plumbing
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_create1,
        // Allocator + mutexes
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_futex,
        // Time
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        // Signal handling + process identity
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_tgkill,
        // Exit paths
        libc::SYS_exit,
        libc::SYS_exit_group,
    ]
    .into_iter()
    .map(|syscall_number| (syscall_number, Vec::new()))
    .collect();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        TARGET_ARCH,
    )
    .map_err(|e| SandboxError::Configuration(format!("seccomp filter build: {e}")))?;

    BpfProgram::try_from(filter)
        .map_err(|e| SandboxError::Configuration(format!("seccomp filter compile: {e}")))
}

/// Install the worker filter on the current thread. This call is
/// irrevocable — once installed, the filter stays active until the
/// process exits.
pub fn install_worker_filter() -> Result<(), SandboxError> {
    info!("installing worker seccomp filter");
    let program = worker_filter()?;
    apply_filter(&program)
        .map_err(|e| SandboxError::Configuration(format!("seccomp apply: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_filter_compiles_without_error() {
        let program = worker_filter().expect("filter should compile");
        // The compiled BPF program should have some instructions.
        // seccompiler doesn't expose the instruction count directly
        // in the public API, but TryFrom<SeccompFilter> returning Ok
        // is sufficient evidence the filter is valid.
        drop(program);
    }

    // Note: we deliberately do NOT call `install_worker_filter()` from
    // a test because it's irrevocable and would break the rest of the
    // test runner. Integration tests in tests/integration can exercise
    // the filter in a subprocess (Phase 6 or later).
}
