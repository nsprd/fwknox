// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test that exercises every Phase 1 and Phase 2 crate
//! together: capture a packet, parse + validate it, check the replay
//! cache, look up the access stanza, and install a rule via the mock
//! firewall backend.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fwknox_capture::{CaptureBackend, UdpCapture};
use fwknox_config::{load_daemon_config, AccessStanza, DaemonConfig};
use fwknox_firewall::{AccessRule, FirewallBackend, MockBackend};
use fwknox_proto::{
    build_packet, parse_packet, validate_against_clock, PortProto, Protocol, SpaMessage,
    SpaPayload, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_SKEW_SECS,
};
use fwknox_replay::ReplayCache;

#[allow(clippy::cast_possible_wrap)]
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn write_test_config(dir: &std::path::Path, master_key: &[u8]) -> std::path::PathBuf {
    let path = dir.join("fwknoxd.toml");
    let body = format!(
        r#"
[daemon]
[replay]

[[access]]
name = "ssh-admin"
source = ["127.0.0.1/32"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
require_source_match = true
"#,
        k = B64.encode(master_key),
    );
    fs::write(&path, body).unwrap();
    path
}

fn build_test_payload(nonce: [u8; 16]) -> SpaPayload {
    SpaPayload {
        nonce,
        timestamp: now_unix(),
        username: "alice".into(),
        message: SpaMessage::Access {
            source_ip: "127.0.0.1".parse().unwrap(),
            ports: vec![PortProto::new(Protocol::Tcp, 22)],
        },
        client_timeout: Some(60),
    }
}

#[test]
fn end_to_end_capture_validate_replay_install() {
    let master_key = [0x42u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = write_test_config(dir.path(), &master_key);
    let cfg: DaemonConfig = load_daemon_config(&cfg_path).expect("config loads");

    // Bind a capture socket on an ephemeral loopback port.
    let server =
        UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Build and send the SPA packet.
    let payload = build_test_payload([0xAB; 16]);
    let wire = build_packet(&payload, &master_key).unwrap();
    let client =
        UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
    client.send_to(&wire, server_addr).unwrap();

    // Daemon side: receive, parse, validate, replay-check, stanza-match, install.
    let captured = server
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .expect("packet should arrive");
    let parsed = parse_packet(&captured.data, &master_key).expect("parse succeeds");
    validate_against_clock(
        &parsed,
        now_unix(),
        DEFAULT_MAX_AGE_SECS,
        DEFAULT_MAX_SKEW_SECS,
    )
    .expect("validation succeeds");

    let replay = ReplayCache::new();
    assert!(
        replay.check_and_insert(parsed.nonce).unwrap(),
        "fresh nonce should be accepted"
    );

    let stanza: &AccessStanza = cfg
        .find_by_master_key(&master_key)
        .expect("stanza found by master key");
    assert!(stanza.require_source_match);
    assert!(stanza.source.iter().any(|s| s.matches(captured.source_ip)));

    let mut firewall = MockBackend::new();
    firewall.init().unwrap();

    // For Phase 2, the daemon-side logic just turns the parsed payload
    // into an AccessRule and installs it.
    let SpaMessage::Access { source_ip, ports } = &parsed.message else {
        panic!("expected Access message");
    };
    let rule = AccessRule {
        source_ip: *source_ip,
        ports: ports.clone(),
        timeout: Duration::from_secs(60),
        comment: format!("fwknox:{}:{}", parsed.username, parsed.timestamp),
    };
    let handle = firewall.open_access(&rule).unwrap();

    let installed = firewall.installed_rules();
    assert_eq!(installed.len(), 1);
    let stored = installed.values().next().unwrap();
    assert_eq!(
        stored.source_ip,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(stored.ports.len(), 1);
    assert_eq!(stored.ports[0], PortProto::new(Protocol::Tcp, 22));

    // A second send of the same nonce should be detected as a replay.
    assert!(
        !replay.check_and_insert(parsed.nonce).unwrap(),
        "second insertion should fail"
    );

    // Removing the rule cleans up the mock state.
    firewall.remove_rule(&handle).unwrap();
    assert!(firewall.installed_rules().is_empty());
}

#[test]
fn replay_cache_persists_across_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.cache");
    {
        let cache = ReplayCache::new();
        cache.check_and_insert([0x77; 16]).unwrap();
        cache.save_to_file(&path).unwrap();
    }
    let loaded = ReplayCache::load_from_file(&path).unwrap();
    assert!(
        !loaded.check_and_insert([0x77; 16]).unwrap(),
        "should detect prior replay"
    );
}
