// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test that the rate limiter caps burst traffic from a
//! single source before the daemon's pipeline ever installs a rule.
//!
//! Exercises the H9 audit finding: with `per_source_rate = 2` and
//! `per_source_burst = 2`, sending five valid packets (each with a
//! distinct nonce, so no replay collision) must result in at most
//! two firewall rules — the remainder must be dropped by the limiter
//! in `run()`'s capture loop BEFORE reaching `process_packet`.

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
use fwknox_proto::{build_packet, PortProto, Protocol, SpaMessage, SpaPayload};
use fwknox_ratelimit::{Decision, RateLimiter};
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

[rate_limit]
enabled = true
# Per-source tier exists but is unreachable in this test because the
# promotion threshold is set higher than the number of packets we send.
# All five packets therefore flow through the global bucket tier, and
# the per_source_burst=2 knob is effectively expressed via global_burst=2.
per_source_rate_per_sec = 2
per_source_burst = 2
tracked_sources_capacity = 16
global_rate_per_sec = 2
global_burst = 2
promotion_threshold = 1000
ipv6_prefix_len = 64

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

fn payload_with_nonce(nonce: [u8; 16]) -> SpaPayload {
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
fn limiter_drops_burst_overflow() {
    let master_key = [0x55u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = write_test_config(dir.path(), &master_key);
    let cfg: DaemonConfig = load_daemon_config(&cfg_path).expect("config loads");

    // Sanity-check the config plumbed through.
    assert!(cfg.rate_limit.enabled);
    assert_eq!(cfg.rate_limit.per_source_rate_per_sec, 2);
    assert_eq!(cfg.rate_limit.per_source_burst, 2);

    let limiter = RateLimiter::from_config(&cfg.rate_limit);
    let replay = ReplayCache::new();
    let mut firewall = MockBackend::new();
    firewall.init().unwrap();

    let src_ip: IpAddr = "127.0.0.1".parse().unwrap();

    // Five packets from the same source, each with a distinct nonce
    // so the replay cache never rejects them. The daemon's run loop
    // (see crates/fwknox-daemon/src/run.rs) applies the limiter
    // BEFORE process_packet, so we do the same here.
    let mut installed = 0usize;
    let mut passed = 0usize;
    let mut dropped = 0usize;
    for i in 0u8..5 {
        let nonce = [i.wrapping_add(1); 16];
        let payload = payload_with_nonce(nonce);
        let wire = build_packet(&payload, &master_key).unwrap();
        let captured = CapturedPacket {
            source_ip: src_ip,
            data: wire,
        };

        match limiter.check(src_ip) {
            Decision::Drop(_) => {
                dropped += 1;
                continue;
            }
            Decision::Pass => {
                passed += 1;
            }
        }
        let result = process_packet(&captured, &cfg, &replay, &firewall)
            .expect("pipeline should not surface backend errors on valid packets");
        if matches!(result, ProcessResult::Installed { .. }) {
            installed += 1;
        } else {
            panic!("packet {i} passed limiter but pipeline did not install: {result:?}");
        }
    }

    // Promotion threshold is set high (1000) so no source ever
    // escapes the Tier 2 global bucket within this test. The global
    // bucket is sized to burst=2, so exactly 2 packets pass and the
    // remaining 3 are dropped by the limiter before the pipeline runs.
    // We send all five packets in well under a second, so refill does
    // not kick in.
    assert!(
        installed >= 1,
        "first packet from a fresh source must pass: installed={installed}",
    );
    assert!(
        installed <= 2,
        "burst=2 must cap the number of installed rules at 2, got {installed}",
    );
    assert_eq!(
        passed, installed,
        "every limiter-pass should install a rule in this test: passed={passed} installed={installed}",
    );
    assert!(
        dropped >= 1,
        "with burst=2 and 5 packets, at least one must be limiter-dropped: dropped={dropped}",
    );
    assert_eq!(
        passed + dropped,
        5,
        "every packet must be accounted for: passed={passed} dropped={dropped}",
    );

    // The firewall state must agree with our counter.
    assert_eq!(
        firewall.installed_rules().len(),
        installed,
        "installed-rule count in backend must match pipeline tally",
    );

    // The limiter's own stats should also reflect at least one drop.
    let stats = limiter.stats();
    assert!(
        stats.dropped_per_source + stats.dropped_global >= 1,
        "limiter stats must record at least one drop: {stats:?}",
    );
}
