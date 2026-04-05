// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression test for Phase 7 Task 8: a panicking worker must call
//! the installed panic hook (writing to stderr + abort) rather than
//! fall through to the default hook which would be killed by seccomp.

/// Spawn a child process via fork, install the panic hook, and panic.
/// Assert the child exits via SIGABRT (signal 6), not normal exit 0
/// or a different signal.
#[test]
fn worker_panic_hook_aborts_cleanly() {
    // Compile-time proof the hook exists.
    #[allow(clippy::no_effect_underscore_binding)]
    let _hook: fn(&'static str) = fwknox_sandbox::install_worker_panic_hook;

    // Runtime proof via `fork + panic in child`.
    // Safety: fork in a test is fine as long as the child only calls
    // async-signal-safe operations before exiting.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // Child.
        fwknox_sandbox::install_worker_panic_hook("test-worker");
        panic!("deliberate test panic");
    }

    let mut status: libc::c_int = 0;
    // Safety: waitpid on a known child pid.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid);

    // We expect the child to be killed by SIGABRT (signal 6) from
    // std::process::abort(). Check that it was signal-terminated
    // (not normal exit), and that the signal is SIGABRT.
    assert!(
        libc::WIFSIGNALED(status),
        "child did not exit via signal (status = {status})"
    );
    let sig = libc::WTERMSIG(status);
    assert_eq!(
        sig,
        libc::SIGABRT,
        "child exited on signal {sig}, expected SIGABRT ({})",
        libc::SIGABRT
    );
}
