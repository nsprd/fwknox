// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-packet processing pipeline.
//!
//! The daemon's main loop hands every captured packet to
//! [`process_packet`], which runs the standard sequence:
//!
//! 1. Match the packet against an access stanza (HMAC iteration).
//! 2. Validate the timestamp against the wall clock.
//! 3. Check the nonce against the replay cache.
//! 4. Enforce the stanza's source-IP policy.
//! 5. Build an `AccessRule` and install it via the firewall backend.
//!
//! Each path returns a [`ProcessResult`] variant so the caller can log
//! the outcome at the appropriate level.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fwknox_capture::CapturedPacket;
use fwknox_config::DaemonConfig;
use fwknox_firewall::{AccessRule, FirewallBackend, RuleHandle};
use fwknox_proto::{
    validate_against_clock, SpaMessage, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_SKEW_SECS,
};
use fwknox_replay::ReplayCache;

use crate::matcher::{match_packet, MatchResult};

/// Outcome of running [`process_packet`] on a single packet.
#[derive(Debug)]
pub enum ProcessResult {
    /// A stanza matched and a firewall rule was installed.
    Installed {
        /// Name of the stanza that authorized the packet.
        stanza_name: String,
        /// Backend handle for the installed rule.
        handle: RuleHandle,
    },
    /// A stanza matched but the packet was a replay (nonce already seen).
    Replay {
        /// Name of the stanza the replay belongs to.
        stanza_name: String,
    },
    /// No stanza's HMAC matched the packet.
    NoMatch,
    /// A stanza matched but the packet was rejected for policy reasons
    /// (expired timestamp, source IP mismatch, ports outside `open_ports`,
    /// AEAD failure, etc).
    Rejected {
        /// Name of the matching stanza.
        stanza_name: String,
        /// Human-readable rejection reason.
        reason: String,
    },
}

#[allow(clippy::cast_possible_wrap)]
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as i64
}

/// Run the full per-packet processing pipeline.
///
/// Returns `Ok(ProcessResult)` for every outcome that the daemon can
/// recover from (the main loop logs and continues). Returns `Err` only
/// when the firewall backend itself fails — that's a fatal condition
/// because subsequent rule installations will also fail.
pub fn process_packet(
    captured: &CapturedPacket,
    config: &DaemonConfig,
    replay: &ReplayCache,
    firewall: &dyn FirewallBackend,
) -> Result<ProcessResult, fwknox_firewall::FirewallError> {
    // Step 1: stanza matching.
    let (stanza_name, payload) = match match_packet(&captured.data, &config.access) {
        MatchResult::Matched { stanza_name, payload } => (stanza_name, payload),
        MatchResult::NoMatch => return Ok(ProcessResult::NoMatch),
        MatchResult::Rejected { stanza_name, reason } => {
            return Ok(ProcessResult::Rejected {
                stanza_name,
                reason: reason.to_string(),
            });
        }
    };

    let stanza = config
        .access
        .iter()
        .find(|s| s.name == stanza_name)
        .expect("stanza name returned by matcher must exist in config");

    // Step 2: timestamp validation.
    if let Err(e) = validate_against_clock(
        &payload,
        now_unix(),
        DEFAULT_MAX_AGE_SECS,
        DEFAULT_MAX_SKEW_SECS,
    ) {
        return Ok(ProcessResult::Rejected {
            stanza_name,
            reason: e.to_string(),
        });
    }

    // Step 3: replay check.
    if !replay.check_and_insert(payload.nonce) {
        return Ok(ProcessResult::Replay { stanza_name });
    }

    // Step 4: source IP allowlist + require_source_match.
    let SpaMessage::Access { source_ip, ports } = &payload.message else {
        // Phase 3 only handles Access. NAT/Command/LocalNat are deferred.
        return Ok(ProcessResult::Rejected {
            stanza_name,
            reason: "unsupported message variant in Phase 3".into(),
        });
    };
    if stanza.require_source_match && *source_ip != captured.source_ip {
        return Ok(ProcessResult::Rejected {
            stanza_name,
            reason: format!(
                "source mismatch: payload says {}, packet from {}",
                source_ip, captured.source_ip
            ),
        });
    }
    if !stanza.source.iter().any(|s| s.matches(captured.source_ip)) {
        return Ok(ProcessResult::Rejected {
            stanza_name,
            reason: format!("source {} not in stanza allowlist", captured.source_ip),
        });
    }

    // Step 5: requested ports must be a subset of open_ports.
    let allowed = &stanza.open_ports.0;
    for pp in ports {
        if !allowed.iter().any(|a| a == pp) {
            return Ok(ProcessResult::Rejected {
                stanza_name,
                reason: format!("requested port {pp} not in stanza open_ports"),
            });
        }
    }

    // Step 6: install the rule.
    let timeout = stanza
        .fw_timeout
        .unwrap_or(config.daemon.default_fw_timeout);
    let timeout = clamp_timeout(timeout, config.daemon.max_fw_timeout);
    let rule = AccessRule {
        source_ip: *source_ip,
        ports: ports.clone(),
        timeout,
        comment: format!("fwknox:{}:{}", payload.username, payload.timestamp),
    };
    let handle = firewall.open_access(&rule)?;
    Ok(ProcessResult::Installed {
        stanza_name,
        handle,
    })
}

fn clamp_timeout(requested: Duration, max: Duration) -> Duration {
    if requested > max {
        max
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use fwknox_config::load_daemon_config;
    use fwknox_firewall::MockBackend;
    use fwknox_proto::{build_packet, PortProto, Protocol, SpaMessage, SpaPayload};

    #[allow(clippy::cast_possible_wrap)]
    fn ts_now() -> i64 {
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
        std::fs::write(&path, body).unwrap();
        path
    }

    fn build_packet_with(payload: &SpaPayload, key: &[u8]) -> Vec<u8> {
        build_packet(payload, key).unwrap()
    }

    fn captured(data: Vec<u8>, src: &str) -> CapturedPacket {
        CapturedPacket {
            source_ip: src.parse().unwrap(),
            data,
        }
    }

    fn fresh_payload(nonce: [u8; 16]) -> SpaPayload {
        SpaPayload {
            nonce,
            timestamp: ts_now(),
            username: "alice".into(),
            message: SpaMessage::Access {
                source_ip: "127.0.0.1".parse().unwrap(),
                ports: vec![PortProto::new(Protocol::Tcp, 22)],
            },
            client_timeout: Some(60),
        }
    }

    #[test]
    fn happy_path_installs_rule() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();
        let replay = ReplayCache::new();
        let mut firewall = MockBackend::new();
        firewall.init().unwrap();

        let wire = build_packet_with(&fresh_payload([1; 16]), &key);
        let pkt = captured(wire, "127.0.0.1");

        let result = process_packet(&pkt, &cfg, &replay, &firewall).unwrap();
        match result {
            ProcessResult::Installed { stanza_name, .. } => {
                assert_eq!(stanza_name, "ssh");
                assert_eq!(firewall.installed_rules().len(), 1);
            }
            other => panic!("expected Installed, got {other:?}"),
        }
    }

    #[test]
    fn replay_is_detected() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();
        let replay = ReplayCache::new();
        let mut firewall = MockBackend::new();
        firewall.init().unwrap();

        let wire = build_packet_with(&fresh_payload([2; 16]), &key);
        let pkt = captured(wire, "127.0.0.1");

        // First call installs the rule.
        let _ = process_packet(&pkt, &cfg, &replay, &firewall).unwrap();
        // Second call must detect the replay.
        let result = process_packet(&pkt, &cfg, &replay, &firewall).unwrap();
        assert!(matches!(result, ProcessResult::Replay { .. }));
        // Only one rule was installed.
        assert_eq!(firewall.installed_rules().len(), 1);
    }

    #[test]
    fn unknown_key_returns_no_match() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();
        let replay = ReplayCache::new();
        let mut firewall = MockBackend::new();
        firewall.init().unwrap();

        let unknown = [0x99u8; 32];
        let wire = build_packet_with(&fresh_payload([3; 16]), &unknown);
        let pkt = captured(wire, "127.0.0.1");

        let result = process_packet(&pkt, &cfg, &replay, &firewall).unwrap();
        assert!(matches!(result, ProcessResult::NoMatch));
        assert!(firewall.installed_rules().is_empty());
    }

    #[test]
    fn require_source_match_rejects_mismatched_packet_source() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();
        let replay = ReplayCache::new();
        let mut firewall = MockBackend::new();
        firewall.init().unwrap();

        let wire = build_packet_with(&fresh_payload([4; 16]), &key);
        // Packet arrives from a different IP than the payload claims.
        let pkt = captured(wire, "10.0.0.1");

        let result = process_packet(&pkt, &cfg, &replay, &firewall).unwrap();
        match result {
            ProcessResult::Rejected { reason, .. } => {
                assert!(reason.contains("source mismatch"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn requested_port_outside_open_ports_is_rejected() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();
        let replay = ReplayCache::new();
        let mut firewall = MockBackend::new();
        firewall.init().unwrap();

        let mut payload = fresh_payload([5; 16]);
        payload.message = SpaMessage::Access {
            source_ip: "127.0.0.1".parse().unwrap(),
            ports: vec![PortProto::new(Protocol::Tcp, 80)], // Not in open_ports.
        };
        let wire = build_packet_with(&payload, &key);
        let pkt = captured(wire, "127.0.0.1");

        let result = process_packet(&pkt, &cfg, &replay, &firewall).unwrap();
        match result {
            ProcessResult::Rejected { reason, .. } => {
                assert!(reason.contains("not in stanza open_ports"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
