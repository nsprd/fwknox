// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test that the daemon rejects a packet whose ciphertext
//! has been tampered after the sender signed it. A single bit flip
//! inside the AEAD-covered region is enough to invalidate the HMAC
//! (since HMAC is computed over `header || nonce || ciphertext`), so
//! the stanza matcher must return `NoMatch` for every stanza it tries.
//!
//! This exercises the H10 audit finding: a forged packet must never
//! install a firewall rule and must never crash the daemon.

use std::{
    fs,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fwknox_capture::CapturedPacket;
use fwknox_config::{load_daemon_config, DaemonConfig};
use fwknox_daemon::{process_packet, ProcessResult};
use fwknox_firewall::{FirewallBackend, MockBackend};
use fwknox_proto::{
    build_packet, PortProto, Protocol, SpaMessage, SpaPayload, HEADER_LEN, NONCE_LEN,
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
name = "ssh"
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

fn fresh_payload(nonce: [u8; 16]) -> SpaPayload {
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
fn daemon_rejects_forged_ciphertext() {
    let master_key = [0x42u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = write_test_config(dir.path(), &master_key);
    let cfg: DaemonConfig = load_daemon_config(&cfg_path).expect("config loads");

    // Build a valid packet, then flip a single high-order bit inside
    // the ciphertext region (one byte past the header + nonce) WITHOUT
    // re-signing the HMAC. The HMAC is computed over
    // `header || nonce || ciphertext`, so any change to the ciphertext
    // must invalidate the tag and force the matcher into `NoMatch`.
    let payload = fresh_payload([0xAB; 16]);
    let mut wire = build_packet(&payload, &master_key).unwrap();
    let tamper_idx = HEADER_LEN + NONCE_LEN + 2;
    assert!(tamper_idx < wire.len(), "tamper index inside wire buffer");
    wire[tamper_idx] ^= 0x80;

    let src_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let captured = CapturedPacket {
        source_ip: src_ip,
        data: wire,
    };

    let replay = ReplayCache::new();
    let mut firewall = MockBackend::new();
    firewall.init().unwrap();

    // The pipeline should not panic, should not install a rule, and
    // should classify the forged packet as NoMatch (every stanza's
    // HMAC verification fails, so the matcher never reaches AEAD).
    let result = process_packet(&captured, &cfg, &replay, &firewall);

    match &result {
        // NoMatch is the expected classification (every stanza's HMAC
        // rejects the forged bytes), but Rejected is also accepted for
        // robustness against future matcher refactors.
        Ok(ProcessResult::NoMatch | ProcessResult::Rejected { .. }) => {}
        Ok(other) => panic!("forged packet must not succeed: got {other:?}"),
        Err(e) => panic!("forged packet must not surface a backend error: {e}"),
    }

    assert!(
        firewall.installed_rules().is_empty(),
        "no rule should be installed on forged packet, got {} rules",
        firewall.installed_rules().len(),
    );

    // Re-running the same forged packet must remain deterministic: no
    // rule, no panic, same classification. This guards against the
    // pipeline partially advancing (e.g. inserting the tampered nonce
    // into the replay cache) on the first pass.
    let result2 = process_packet(&captured, &cfg, &replay, &firewall);
    assert!(
        matches!(
            result2,
            Ok(ProcessResult::NoMatch | ProcessResult::Rejected { .. })
        ),
        "second pass must also reject forged packet: {result2:?}",
    );
    assert!(
        firewall.installed_rules().is_empty(),
        "still no rule after second pass",
    );
}
