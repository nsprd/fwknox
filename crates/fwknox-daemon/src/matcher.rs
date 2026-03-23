// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stanza matching for incoming SPA packets.
//!
//! The daemon doesn't know which `[[access]]` stanza an incoming packet
//! belongs to until it tries each stanza's master key. We rely on the
//! protocol crate's HMAC-then-decrypt design: a wrong master key fails
//! at HMAC verification (cheap), and only the correct key proceeds to
//! decryption.

use fwknox_config::AccessStanza;
use fwknox_proto::{parse_packet, ProtoError, SpaPayload};

/// Result of matching a wire packet against the daemon's access stanzas.
#[derive(Debug)]
pub enum MatchResult {
    /// A stanza's HMAC verified and the packet decoded successfully.
    Matched {
        /// Name of the matching stanza.
        stanza_name: String,
        /// The decoded payload.
        payload: SpaPayload,
    },
    /// No stanza's HMAC matched. The packet is silently dropped (logged
    /// at debug level only) — this is the common case for random
    /// internet noise.
    NoMatch,
    /// A stanza's HMAC matched but a later step (AEAD, decode, structural
    /// validation) failed. This is suspicious and should be logged.
    Rejected {
        /// Name of the stanza whose HMAC matched.
        stanza_name: String,
        /// Underlying parse error.
        reason: ProtoError,
    },
}

/// Try each stanza's master key against `wire`. Returns at the first
/// stanza whose HMAC verifies; subsequent stanzas are not tried.
#[must_use]
pub fn match_packet(wire: &[u8], stanzas: &[AccessStanza]) -> MatchResult {
    for stanza in stanzas {
        match parse_packet(wire, stanza.master_key_base64.as_bytes()) {
            Ok(payload) => {
                return MatchResult::Matched {
                    stanza_name: stanza.name.clone(),
                    payload,
                };
            }
            Err(ProtoError::HmacFailed) => {
                // Not our stanza — try the next one.
            }
            Err(other) => {
                // HMAC matched, but something else failed. The packet
                // belongs to this stanza but is invalid for some other
                // reason (corrupted ciphertext, oversized, etc).
                return MatchResult::Rejected {
                    stanza_name: stanza.name.clone(),
                    reason: other,
                };
            }
        }
    }
    MatchResult::NoMatch
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use fwknox_config::{load_daemon_config, DaemonConfig};
    use fwknox_proto::{build_packet, PortProto, Protocol, SpaMessage, SpaPayload};

    use super::*;

    #[allow(clippy::cast_possible_wrap)]
    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn write_two_stanza_config(
        dir: &std::path::Path,
        key_a: &[u8],
        key_b: &[u8],
    ) -> std::path::PathBuf {
        let path = dir.join("fwknoxd.toml");
        let body = format!(
            r#"
[daemon]
[replay]

[[access]]
name = "stanza-a"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{a}"

[[access]]
name = "stanza-b"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{b}"
"#,
            a = B64.encode(key_a),
            b = B64.encode(key_b),
        );
        std::fs::write(&path, body).unwrap();
        path
    }

    fn sample_payload() -> SpaPayload {
        SpaPayload {
            nonce: [0xCD; 16],
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
    fn matches_first_stanza_when_first_key_is_used() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let path = write_two_stanza_config(dir.path(), &key_a, &key_b);
        let cfg: DaemonConfig = load_daemon_config(&path).unwrap();

        let wire = build_packet(&sample_payload(), &key_a).unwrap();
        match match_packet(&wire, &cfg.access) {
            MatchResult::Matched { stanza_name, .. } => {
                assert_eq!(stanza_name, "stanza-a");
            }
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn matches_second_stanza_when_second_key_is_used() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let path = write_two_stanza_config(dir.path(), &key_a, &key_b);
        let cfg: DaemonConfig = load_daemon_config(&path).unwrap();

        let wire = build_packet(&sample_payload(), &key_b).unwrap();
        match match_packet(&wire, &cfg.access) {
            MatchResult::Matched { stanza_name, .. } => {
                assert_eq!(stanza_name, "stanza-b");
            }
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn no_match_for_unknown_key() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let path = write_two_stanza_config(dir.path(), &key_a, &key_b);
        let cfg: DaemonConfig = load_daemon_config(&path).unwrap();

        let unknown = [0x99u8; 32];
        let wire = build_packet(&sample_payload(), &unknown).unwrap();
        match match_packet(&wire, &cfg.access) {
            MatchResult::NoMatch => {}
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn rejected_when_hmac_matches_but_packet_is_corrupt() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let path = write_two_stanza_config(dir.path(), &key_a, &key_b);
        let cfg: DaemonConfig = load_daemon_config(&path).unwrap();

        // Build a valid packet then flip a byte inside the ciphertext
        // region (between header+nonce and the trailing HMAC) and
        // re-sign the HMAC so the matcher gets past the HMAC gate.
        let mut wire = build_packet(&sample_payload(), &key_a).unwrap();
        // header is 4 bytes, nonce is 12 bytes, ciphertext starts at 16.
        wire[20] ^= 0x80;
        // Re-sign the HMAC with the right hmac subkey by recomputing.
        let keys = fwknox_proto::DerivedKeys::derive(&key_a).unwrap();
        let signed_len = wire.len() - fwknox_proto::HMAC_LEN;
        let new_tag = fwknox_proto::hmac_sign(keys.hmac.as_bytes(), &wire[..signed_len]);
        wire[signed_len..].copy_from_slice(&new_tag);

        match match_packet(&wire, &cfg.access) {
            MatchResult::Rejected {
                stanza_name,
                reason,
            } => {
                assert_eq!(stanza_name, "stanza-a");
                // The corrupted ciphertext fails AEAD decryption.
                assert!(matches!(reason, ProtoError::AeadFailed));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
