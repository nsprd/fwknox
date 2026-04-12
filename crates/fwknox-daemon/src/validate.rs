// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure validation helper for the crypto worker.
//!
//! [`validate_capture_msg`] takes a raw [`CaptureMsg`] + daemon config
//! and returns the corresponding [`CryptoMsg`]. It runs the matcher,
//! timestamp validation, source-IP policy, and port allowlist, but
//! NOT the replay cache check or the firewall install (those stay in
//! the parent).

use std::time::{SystemTime, UNIX_EPOCH};

use fwknox_config::DaemonConfig;
use fwknox_privsep::{CaptureMsg, CryptoMsg};
use fwknox_proto::{validate_against_clock, SpaMessage, DEFAULT_MAX_SKEW_SECS};

use crate::{
    matcher::{match_packet, MatchResult},
    pipeline::find_stanza,
};

#[allow(clippy::cast_possible_wrap)]
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as i64
}

/// Validate a `CaptureMsg` against the daemon config.
///
/// Returns the [`CryptoMsg`] that the crypto worker should forward to
/// the parent: `ValidRequest` if the packet passes every non-replay
/// check, `Rejected` with a reason string if a stanza matched but the
/// packet failed policy, or `NoMatch` if no stanza's HMAC verified.
#[must_use]
pub fn validate_capture_msg(msg: CaptureMsg, config: &DaemonConfig) -> CryptoMsg {
    let CaptureMsg::Packet { source_ip, data } = msg;

    // Stanza match (HMAC iteration, decrypt, decode).
    let (stanza_name, payload) = match match_packet(&data, &config.access) {
        MatchResult::Matched {
            stanza_name,
            payload,
        } => (stanza_name, payload),
        MatchResult::NoMatch => return CryptoMsg::NoMatch { source_ip },
        MatchResult::Rejected {
            stanza_name: _,
            reason,
        } => {
            return CryptoMsg::Rejected {
                source_ip,
                reason: reason.to_string(),
            };
        }
    };

    let stanza = match find_stanza(config, &stanza_name) {
        Ok(s) => s,
        Err(e) => {
            // Should-never-happen: the matcher returned a stanza name
            // that is not in `config.access`. We prefer to log and
            // reject the packet rather than panic the crypto worker.
            tracing::error!(error = %e, stanza = %stanza_name, "stanza lookup invariant violated");
            return CryptoMsg::Rejected {
                source_ip,
                reason: e.to_string(),
            };
        }
    };

    // Timestamp.
    let max_age = i64::try_from(config.daemon.max_spa_packet_age.as_secs()).unwrap_or(i64::MAX);
    if let Err(e) = validate_against_clock(&payload, now_unix(), max_age, DEFAULT_MAX_SKEW_SECS) {
        return CryptoMsg::Rejected {
            source_ip,
            reason: e.to_string(),
        };
    }

    // Source IP and ports.
    let SpaMessage::Access {
        source_ip: payload_source,
        ports,
    } = &payload.message
    else {
        return CryptoMsg::Rejected {
            source_ip,
            reason: "unsupported message variant".into(),
        };
    };
    if stanza.require_source_match && *payload_source != source_ip {
        return CryptoMsg::Rejected {
            source_ip,
            reason: format!(
                "source mismatch: payload says {payload_source}, packet from {source_ip}"
            ),
        };
    }
    if !stanza.source.iter().any(|s| s.matches(source_ip)) {
        return CryptoMsg::Rejected {
            source_ip,
            reason: format!("source {source_ip} not in stanza allowlist"),
        };
    }
    for pp in ports {
        if !stanza.open_ports.0.iter().any(|a| a == pp) {
            return CryptoMsg::Rejected {
                source_ip,
                reason: format!("requested port {pp} not in stanza open_ports"),
            };
        }
    }

    CryptoMsg::ValidRequest {
        stanza_name,
        source_ip,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use fwknox_config::load_daemon_config;
    use fwknox_proto::{build_packet, PortProto, Protocol, SpaMessage, SpaPayload};

    use super::*;

    #[allow(clippy::cast_possible_wrap)]
    fn ts_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn write_config(dir: &std::path::Path, master_key: &[u8]) -> std::path::PathBuf {
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

    fn fresh_payload() -> SpaPayload {
        SpaPayload {
            nonce: [0xAA; 16],
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
    fn happy_path_returns_valid_request() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_config(dir.path(), &key)).unwrap();
        let wire = build_packet(&fresh_payload(), &key).unwrap();
        let msg = CaptureMsg::Packet {
            source_ip: "127.0.0.1".parse().unwrap(),
            data: wire,
        };
        let reply = validate_capture_msg(msg, &cfg);
        match reply {
            CryptoMsg::ValidRequest { stanza_name, .. } => {
                assert_eq!(stanza_name, "ssh");
            }
            other => panic!("expected ValidRequest, got {other:?}"),
        }
    }

    #[test]
    fn unknown_key_returns_no_match() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_config(dir.path(), &key)).unwrap();
        let wire = build_packet(&fresh_payload(), &[0x99; 32]).unwrap();
        let msg = CaptureMsg::Packet {
            source_ip: "127.0.0.1".parse().unwrap(),
            data: wire,
        };
        let reply = validate_capture_msg(msg, &cfg);
        assert!(matches!(reply, CryptoMsg::NoMatch { .. }));
    }

    #[test]
    fn missing_stanza_lookup_yields_invariant_error() {
        // Exercises the lookup helper used by `validate_capture_msg`.
        // If the matcher ever returned a name not in `config.access`
        // (e.g. after a config reload race), the helper surfaces the
        // violation as an error instead of panicking the crypto
        // worker.
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_config(dir.path(), &key)).unwrap();
        let err = find_stanza(&cfg, "does-not-exist").unwrap_err();
        assert!(
            matches!(err, crate::error::DaemonError::InvariantViolation(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn source_mismatch_returns_rejected() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_config(dir.path(), &key)).unwrap();
        let wire = build_packet(&fresh_payload(), &key).unwrap();
        let msg = CaptureMsg::Packet {
            source_ip: "10.0.0.1".parse().unwrap(), // Different from payload.
            data: wire,
        };
        let reply = validate_capture_msg(msg, &cfg);
        match reply {
            CryptoMsg::Rejected { reason, .. } => {
                assert!(reason.contains("source mismatch"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
