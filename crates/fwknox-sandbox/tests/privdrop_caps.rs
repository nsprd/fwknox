// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression test for Phase 7 Task 2: verify that `CAP_NET_ADMIN`
//! survives an `apply()` call that drops the process from root to an
//! unprivileged user.
//!
//! This test is gated on being run as uid 0 because only root can
//! change users, and the test must actually exercise the setuid path
//! to reproduce the bug. In CI this test reports a skip; on a developer
//! box it should be run with `sudo -E cargo test -p fwknox-sandbox
//! --test privdrop_caps -- --ignored` or similar.

use caps::{CapSet, Capability};
use fwknox_sandbox::{apply, PrivDropTarget, SandboxConfig};

fn running_as_root() -> bool {
    // Safety: geteuid is always safe.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn cap_net_admin_survives_privdrop() {
    if !running_as_root() {
        eprintln!("SKIP: cap_net_admin_survives_privdrop requires root");
        return;
    }

    // Fork a child so the test runner (which needs its original caps)
    // is not itself dropped.
    // Safety: fork is safe in a test context because we only call
    // async-signal-safe operations in the child before exec-or-exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child: perform the drop and check the result.
        let config = SandboxConfig {
            keep_caps: vec![Capability::CAP_NET_ADMIN],
            drop_to: Some(PrivDropTarget {
                user: "nobody".into(),
                group: nobody_group_name().into(),
            }),
            landlock: None,
        };
        let status = match apply(&config) {
            Ok(()) => {
                // Verify we still have CAP_NET_ADMIN in the effective set.
                match caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN) {
                    Ok(true) => 0,
                    Ok(false) => 10,
                    Err(_) => 11,
                }
            }
            Err(_) => 12,
        };
        // Safety: _exit is async-signal-safe and bypasses destructors.
        unsafe {
            libc::_exit(status);
        }
    }

    // Parent: wait for the child and check its exit status.
    let mut status: libc::c_int = 0;
    // Safety: waitpid on a known child pid.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid, "waitpid returned unexpected pid");
    assert!(libc::WIFEXITED(status), "child did not exit normally");
    let code = libc::WEXITSTATUS(status);
    assert_eq!(
        code, 0,
        "child reported failure (code {code}): 10=cap_net_admin lost, 11=cap probe errored, 12=apply() errored"
    );
}

fn nobody_group_name() -> &'static str {
    // Debian/Ubuntu use "nogroup"; Arch/Fedora use "nobody".
    if std::process::Command::new("getent")
        .args(["group", "nogroup"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        "nogroup"
    } else {
        "nobody"
    }
}
