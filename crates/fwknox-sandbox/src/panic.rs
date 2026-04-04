// SPDX-License-Identifier: AGPL-3.0-or-later

//! Panic hook for sandboxed worker processes.
//!
//! The default Rust panic hook tries to resolve symbols for a
//! backtrace, which requires `readlink`, `open`, and `pread64` —
//! syscalls the worker seccomp filter does not allow. A panic in a
//! sandboxed worker therefore produces a silent SIGSYS kill with no
//! useful diagnostic.
//!
//! [`install_worker_panic_hook`] replaces the default hook with a
//! minimal handler that writes the panic location and message to
//! stderr (via a plain `write` syscall, which IS in the allow-list)
//! and then calls [`std::process::abort`] to terminate with SIGABRT
//! so the parent's SIGCHLD handler notices immediately.
//!
//! Call this BEFORE `apply_worker_sandbox` so the hook is in place
//! by the time any code can possibly panic under the sandbox.

/// Install a minimal panic hook suitable for a worker running under
/// a strict seccomp filter. The hook:
///
/// 1. Writes `"<worker>: panicked: <info>\n"` to stderr via a single
///    `write(2)` syscall (fd 2).
/// 2. Calls `std::process::abort()` which raises `SIGABRT` — the
///    parent's SIGCHLD handler will notice.
///
/// `worker_name` is baked into the closure so multiple workers running
/// in the same process (in tests) produce distinguishable output.
pub fn install_worker_panic_hook(worker_name: &'static str) {
    std::panic::set_hook(Box::new(move |info| {
        use std::io::Write as _;
        let mut stderr = std::io::stderr().lock();
        // Best-effort: if stderr is closed or broken, we still abort.
        let _ = writeln!(stderr, "{worker_name}: panicked: {info}");
        let _ = stderr.flush();
        std::process::abort();
    }));
}
