// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper binary driven by `tests/real_seccomp.rs`.
//!
//! Installs the worker seccomp filter on the current thread, then issues
//! either an allow-listed syscall (to prove the baseline) or a syscall
//! that is **not** on the allow-list (to prove the filter actually kills
//! the process with SIGSYS). The parent test reads our exit status to
//! decide pass/fail.
//!
//! Invocation: `seccomp-victim allowed | forbidden`.
//!
//! Kept in its own binary because `install_worker_filter` is irrevocable
//! — once applied to a thread the filter stays active until process
//! exit, which would poison the rest of the test runner if invoked
//! in-process.

use std::process::ExitCode;

use fwknox_sandbox::seccomp::install_worker_filter;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();

    // Any printing happens **before** the filter is installed so it
    // cannot itself trip the filter via an un-listed syscall.
    eprintln!("seccomp-victim: mode={mode}, installing filter");

    if let Err(e) = install_worker_filter() {
        eprintln!("seccomp-victim: install failed: {e}");
        return ExitCode::from(2);
    }

    match mode.as_str() {
        "allowed" => {
            // getpid is on the worker allow-list. This must succeed and
            // return normally — proves the filter isn't over-blocking.
            // Safety: getpid is an FFI call that never fails and never
            // touches memory we own.
            let pid = unsafe { libc::getpid() };
            eprintln!("seccomp-victim: getpid returned {pid}");
            ExitCode::SUCCESS
        }
        "forbidden" => {
            // openat is NOT on the worker allow-list. Under the filter's
            // default action (`SeccompAction::KillProcess`) the kernel
            // delivers SIGSYS and terminates us before the syscall
            // returns. If we somehow get past the syscall it means the
            // filter failed to install.
            //
            // Safety: direct syscall invocation; the path is a valid
            // NUL-terminated byte string and libc::syscall returns an
            // integer we ignore.
            let path = b"/dev/null\0";
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    path.as_ptr().cast::<libc::c_char>(),
                    libc::O_RDONLY,
                )
            };
            // Should be unreachable under a functioning filter.
            eprintln!("seccomp-victim: openat unexpectedly returned {ret}");
            ExitCode::from(3)
        }
        other => {
            eprintln!("seccomp-victim: unknown mode {other:?}");
            ExitCode::from(2)
        }
    }
}
