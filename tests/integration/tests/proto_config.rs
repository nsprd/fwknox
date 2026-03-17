// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test: load a config, build an SPA packet using the stanza's
//! master key, parse it back, and validate it against the wall-clock time.

use std::{
    fs,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fwknox_config::{load_daemon_config, AccessStanza};
use fwknox_proto::{
    build_packet, parse_packet, validate_against_clock, PortProto, Protocol, SpaMessage,
    SpaPayload, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_SKEW_SECS,
};

fn build_test_payload() -> SpaPayload {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed();
    SpaPayload {
        nonce: [0xCD; 16],
        timestamp: now,
        username: "alice".into(),
        message: SpaMessage::Access {
            source_ip: "192.168.1.5".parse().unwrap(),
            ports: vec![PortProto::new(Protocol::Tcp, 22)],
        },
        client_timeout: Some(60),
    }
}

fn write_test_config(dir: &std::path::Path, master_key: &[u8]) -> std::path::PathBuf {
    let path = dir.join("fwknoxd.toml");
    let body = format!(
        r#"
[daemon]
[replay]

[[access]]
name = "ssh-admin"
source = ["192.168.1.0/24"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
require_source_match = true
"#,
        k = B64.encode(master_key),
    );
    fs::write(&path, body).unwrap();
    path
}

#[test]
fn end_to_end_packet_roundtrip_with_loaded_config() {
    let master_key = [0x42u8; 32];

    let dir = tempfile::tempdir().unwrap();
    let cfg_path = write_test_config(dir.path(), &master_key);
    let cfg = load_daemon_config(&cfg_path).expect("config loads");

    // Build a packet from the stanza's master key.
    let payload = build_test_payload();
    let wire = build_packet(&payload, &master_key).unwrap();

    // Parse it back with the same key (HKDF on both sides yields the same subkeys).
    let decoded = parse_packet(&wire, &master_key).unwrap();
    assert_eq!(decoded, payload);

    // The stanza is findable by master key.
    let stanza: &AccessStanza = cfg
        .find_by_master_key(&master_key)
        .expect("stanza found by master key");
    assert_eq!(stanza.name, "ssh-admin");

    // Source IP is in the stanza's allowlist.
    let src: IpAddr = "192.168.1.5".parse().unwrap();
    assert!(stanza.source.iter().any(|s| s.matches(src)));

    // Timestamp is fresh.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed();
    validate_against_clock(&decoded, now, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_SKEW_SECS).unwrap();
}

#[test]
fn parse_with_wrong_key_fails_at_hmac() {
    let payload = build_test_payload();
    let wire = build_packet(&payload, &[0x42; 32]).unwrap();
    let result = parse_packet(&wire, &[0x99; 32]);
    assert!(result.is_err());
}
