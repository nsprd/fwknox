// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-fork privsep integration tests.
//!
//! The unit tests in `fwknox-privsep` exchange IPC messages between two
//! halves of a socketpair owned by the same process. That covers the
//! serde/MessagePack plumbing but not the kernel-level semantics of
//! `fork()` + inherited file descriptors + `SOCK_DGRAM` message boundary
//! preservation across a process split. These tests do the real fork.
//!
//! Gated behind `real-net` because forking inside a `cargo test` runner
//! is safe when managed carefully but we don't want it to run on every
//! plain `cargo test` — especially on developer laptops where test
//! parallelism could surprise a process tree.

#![cfg(feature = "real-net")]

use std::{net::IpAddr, time::Duration};

use fwknox_privsep::{make_socketpair, recv_msg, send_msg, CaptureMsg, CryptoMsg};
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::{fork, ForkResult},
};

/// Read timeout on the parent side of the socketpair. Generous enough
/// to tolerate a slow CI runner but still finite — if the child never
/// sends, we fail rather than hang.
const PARENT_RECV_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn fork_child_writes_capture_msg_to_parent_over_socketpair() {
    let (parent_sock, child_sock) = make_socketpair().expect("socketpair");
    parent_sock
        .set_read_timeout(Some(PARENT_RECV_TIMEOUT))
        .expect("set parent timeout");

    // Safety: fork() is only safe in async-signal-safe contexts. The
    // child calls `send_msg` + `_exit` — both are safe to invoke from
    // a post-fork child even though the parent holds mutexes/threads
    // from the test runner.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Parent { child } => {
            // Parent keeps its end; close the child's end so that if
            // the child dies before sending, our recv returns EOF
            // rather than blocking forever.
            drop(child_sock);

            let msg: CaptureMsg = recv_msg(&parent_sock).expect("recv from child");
            let CaptureMsg::Packet { source_ip, data } = msg;
            assert_eq!(source_ip, "192.0.2.7".parse::<IpAddr>().unwrap());
            assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

            let status = waitpid(child, None).expect("reap child");
            assert!(
                matches!(status, WaitStatus::Exited(_, 0)),
                "child exited abnormally: {status:?}"
            );
        }
        ForkResult::Child => {
            drop(parent_sock);
            let msg = CaptureMsg::Packet {
                source_ip: "192.0.2.7".parse().unwrap(),
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            };
            let rc = match send_msg(&child_sock, &msg) {
                Ok(()) => 0,
                Err(_) => 1,
            };
            // Safety: _exit is async-signal-safe; skips atexit handlers
            // that could race with the test harness in the parent.
            unsafe { libc::_exit(rc) };
        }
    }
}

#[test]
fn fork_child_sends_crypto_rejected_then_parent_waits_cleanly() {
    let (parent_sock, child_sock) = make_socketpair().expect("socketpair");
    parent_sock
        .set_read_timeout(Some(PARENT_RECV_TIMEOUT))
        .expect("set parent timeout");

    match unsafe { fork() }.expect("fork") {
        ForkResult::Parent { child } => {
            drop(child_sock);

            let msg: CryptoMsg = recv_msg(&parent_sock).expect("recv from child");
            match msg {
                CryptoMsg::Rejected { source_ip, reason } => {
                    assert_eq!(source_ip, "198.51.100.42".parse::<IpAddr>().unwrap());
                    assert_eq!(reason, "timestamp too old");
                }
                other => panic!("expected Rejected, got {other:?}"),
            }

            let status = waitpid(child, None).expect("reap child");
            assert!(matches!(status, WaitStatus::Exited(_, 0)), "{status:?}");
        }
        ForkResult::Child => {
            drop(parent_sock);
            let msg = CryptoMsg::Rejected {
                source_ip: "198.51.100.42".parse().unwrap(),
                reason: "timestamp too old".into(),
            };
            let rc = match send_msg(&child_sock, &msg) {
                Ok(()) => 0,
                Err(_) => 1,
            };
            unsafe { libc::_exit(rc) };
        }
    }
}

#[test]
fn dropping_child_socketpair_end_signals_peer_closed_on_parent() {
    // Verifies the kernel delivers a zero-length recv on SOCK_DGRAM
    // after the peer closes all handles to its side — the signal our
    // parent uses to detect "worker has exited".
    let (parent_sock, child_sock) = make_socketpair().expect("socketpair");
    parent_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    match unsafe { fork() }.expect("fork") {
        ForkResult::Parent { child } => {
            drop(child_sock);
            // Child closes and exits without sending; our recv should
            // either see PeerClosed (zero-byte recv on SOCK_DGRAM) or a
            // timeout/WouldBlock. Both are legitimate kernel behaviors
            // and the privsep code tolerates either.
            let result: Result<CaptureMsg, _> = recv_msg(&parent_sock);
            assert!(
                matches!(
                    result,
                    Err(fwknox_privsep::PrivsepError::PeerClosed
                        | fwknox_privsep::PrivsepError::Io(_))
                ),
                "expected PeerClosed or Io, got {result:?}"
            );
            let status = waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)), "{status:?}");
        }
        ForkResult::Child => {
            drop(parent_sock);
            drop(child_sock);
            unsafe { libc::_exit(0) };
        }
    }
}
