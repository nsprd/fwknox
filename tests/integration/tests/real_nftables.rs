// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-kernel nftables integration tests.
//!
//! These tests drive [`NftablesBackend`] against the live kernel via the
//! `nft` binary and then query the resulting ruleset back to assert that
//! the table / set / element actually exist. They require:
//!
//! - root (`CAP_NET_ADMIN` on the host, not a user-namespace proxy)
//! - the `nft` binary on PATH
//! - a kernel with the `nf_tables` module loaded
//!
//! Gated behind the `real-net` Cargo feature so a plain
//! `cargo test --workspace` on a developer laptop stays unprivileged and
//! fast. The dedicated CI job `integration-real` turns the feature on.

#![cfg(feature = "real-net")]

use std::{net::IpAddr, time::Duration};

use fwknox_firewall::{
    AccessRule, FirewallBackend, NftablesBackend, CHAIN_NAME, SET_NAME, TABLE_NAME,
};
use fwknox_proto::{PortProto, Protocol};
use nftables::{
    helper::get_current_ruleset,
    schema::{NfListObject, NfObject, Nftables},
};

/// Skip the test (with a clear log line) when the harness isn't root.
/// `nf_tables` netlink ops require `CAP_NET_ADMIN` in the *initial* user
/// namespace — an unprivileged developer laptop will hit `EPERM` before
/// any ruleset ever leaves the process.
fn require_root_or_skip(test: &str) -> bool {
    // Safety: getuid is always safe — it reads a kernel counter and
    // cannot fail.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        eprintln!("skipping {test}: needs root (uid={uid})");
        return false;
    }
    true
}

/// Return `true` if the live ruleset contains an inet table with the
/// name fwknox-firewall manages.
fn table_present(rs: &Nftables<'_>) -> bool {
    rs.objects.iter().any(|obj| {
        matches!(
            obj,
            NfObject::ListObject(NfListObject::Table(t))
                if t.name == TABLE_NAME
        )
    })
}

/// Return the number of set elements currently installed in the
/// `fwknox_allow_v4` set. Used to confirm add/remove actually hit the
/// kernel.
fn element_count(rs: &Nftables<'_>) -> usize {
    rs.objects
        .iter()
        .filter(|obj| {
            matches!(
                obj,
                NfObject::ListObject(NfListObject::Element(e))
                    if e.name == SET_NAME
            )
        })
        .count()
}

/// Pre-flight: tear down any leftover fwknox table from a previous test
/// run. Ignores all errors — if the table doesn't exist the flush is a
/// no-op. Every real-nftables test calls this first so ordering between
/// tests doesn't matter.
fn pre_clean() {
    let mut b = NftablesBackend::new();
    let _ = b.flush();
}

#[test]
fn nftables_backend_roundtrip_against_kernel() {
    if !require_root_or_skip("nftables_backend_roundtrip_against_kernel") {
        return;
    }
    pre_clean();

    let mut backend = NftablesBackend::new();
    backend.init().expect("init should succeed as root");

    let rs = get_current_ruleset().expect("list ruleset");
    assert!(
        table_present(&rs),
        "fwknox table should exist after init(), got {:#?}",
        rs.objects
    );
    // Chain name is a compile-time constant; referencing it keeps the
    // test from silently passing if the backend renames the chain.
    let _: &str = CHAIN_NAME;

    let rule = AccessRule {
        source_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        ports: vec![PortProto::new(Protocol::Tcp, 22)],
        timeout: Duration::from_secs(30),
        comment: "real-integration".into(),
    };
    let handle = backend
        .open_access(&rule)
        .expect("open_access installs rule");

    let rs = get_current_ruleset().expect("list ruleset after open");
    assert_eq!(
        element_count(&rs),
        1,
        "exactly one element should be present after open_access"
    );

    backend.remove_rule(&handle).expect("remove_rule succeeds");
    let rs = get_current_ruleset().expect("list ruleset after remove");
    assert_eq!(
        element_count(&rs),
        0,
        "element should be gone after remove_rule"
    );

    backend.flush().expect("flush tears down table");
    let rs = get_current_ruleset().expect("list ruleset after flush");
    assert!(
        !table_present(&rs),
        "fwknox table should be gone after flush"
    );
}

#[test]
fn nftables_remove_of_already_expired_element_returns_rule_not_found() {
    if !require_root_or_skip("nftables_remove_of_already_expired_element_returns_rule_not_found") {
        return;
    }
    pre_clean();

    let mut backend = NftablesBackend::new();
    backend.init().unwrap();

    // Install with a 1s timeout, then sleep long enough for the kernel
    // to garbage-collect the element before we try to remove it.
    let rule = AccessRule {
        source_ip: "127.0.0.2".parse::<IpAddr>().unwrap(),
        ports: vec![PortProto::new(Protocol::Tcp, 80)],
        timeout: Duration::from_secs(1),
        comment: "expire-me".into(),
    };
    let handle = backend.open_access(&rule).unwrap();
    std::thread::sleep(Duration::from_millis(2500));

    let err = backend.remove_rule(&handle).unwrap_err();
    assert!(
        matches!(err, fwknox_firewall::FirewallError::RuleNotFound(_)),
        "kernel ENOENT path should map to RuleNotFound, got {err:?}"
    );

    backend.flush().unwrap();
}

#[test]
fn nftables_open_access_with_multiple_ports_installs_one_element_per_port() {
    if !require_root_or_skip(
        "nftables_open_access_with_multiple_ports_installs_one_element_per_port",
    ) {
        return;
    }
    pre_clean();

    let mut backend = NftablesBackend::new();
    backend.init().unwrap();

    let rule = AccessRule {
        source_ip: "127.0.0.3".parse::<IpAddr>().unwrap(),
        ports: vec![
            PortProto::new(Protocol::Tcp, 22),
            PortProto::new(Protocol::Tcp, 443),
            PortProto::new(Protocol::Udp, 53),
        ],
        timeout: Duration::from_secs(30),
        comment: "multi-port".into(),
    };
    backend.open_access(&rule).unwrap();

    let rs = get_current_ruleset().unwrap();
    assert_eq!(element_count(&rs), 3);

    backend.flush().unwrap();
}
