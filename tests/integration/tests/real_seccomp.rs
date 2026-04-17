// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real seccomp-bpf integration tests.
//!
//! Validates the worker syscall filter end-to-end by spawning the
//! `seccomp-victim` helper binary in two modes:
//!
//! - `allowed`: hits only on-allow-list syscalls → exits 0.
//! - `forbidden`: hits `openat` (deliberately excluded from the worker
//!   allow-list) → kernel delivers SIGSYS → helper is killed by signal.
//!
//! Filter installation is irrevocable, so we MUST run the filter in a
//! subprocess (not a test thread). The helper binary lives at
//! `tests/integration/bin/seccomp_victim.rs` and is built only when the
//! `real-net` feature is active.

#![cfg(feature = "real-net")]

use std::{
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, Stdio},
};

/// Resolve the path of the compiled `seccomp-victim` helper binary.
///
/// Cargo sets `CARGO_BIN_EXE_<name>` when compiling integration tests
/// for any target that declares a `[[bin]]` entry in the same package.
fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_seccomp-victim"))
}

#[test]
fn seccomp_filter_allows_listed_syscalls() {
    let status = Command::new(helper_path())
        .arg("allowed")
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn helper");
    assert!(
        status.success(),
        "allow-listed syscalls should let the helper exit cleanly: {status:?}"
    );
}

#[test]
fn seccomp_filter_kills_on_forbidden_syscall() {
    let status = Command::new(helper_path())
        .arg("forbidden")
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn helper");

    // `KillProcess` causes the kernel to kill the process with SIGSYS
    // *without* delivering the signal to a handler. Under Unix semantics
    // this surfaces to the parent as `WIFSIGNALED` with the SIGSYS
    // number (`31` on x86_64 Linux and aarch64 Linux).
    assert!(
        status.code().is_none(),
        "helper should NOT have exited normally — forbidden syscall should trip seccomp; got {status:?}"
    );
    let sig = status
        .signal()
        .expect("helper should have been killed by a signal");
    assert_eq!(
        sig,
        libc::SIGSYS,
        "forbidden syscall should raise SIGSYS (got {sig})"
    );
}
