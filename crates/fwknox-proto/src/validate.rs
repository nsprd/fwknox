// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time-based and contextual validation of decoded SPA payloads.

use crate::{error::ProtoError, payload::SpaPayload};

/// Default maximum packet age in seconds.
pub const DEFAULT_MAX_AGE_SECS: i64 = 120;

/// Default maximum allowed clock skew in seconds (packets in the future).
pub const DEFAULT_MAX_SKEW_SECS: i64 = 30;

/// Marker returned when a payload passes validation, kept simple for now.
#[derive(Debug, Clone, Copy)]
pub struct Validated;

/// Validate a payload against the wall-clock time `now_unix`.
pub fn validate_against_clock(
    payload: &SpaPayload,
    now_unix: i64,
    max_age_secs: i64,
    max_skew_secs: i64,
) -> Result<Validated, ProtoError> {
    let delta = now_unix - payload.timestamp;
    if delta < -max_skew_secs {
        return Err(ProtoError::PacketInFuture { skew_secs: -delta });
    }
    if delta > max_age_secs {
        return Err(ProtoError::PacketTooOld {
            age_secs: delta,
            max_secs: max_age_secs,
        });
    }
    Ok(Validated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PortProto, Protocol, SpaMessage};

    fn payload_at(ts: i64) -> SpaPayload {
        SpaPayload {
            nonce: [0u8; 16],
            timestamp: ts,
            username: "u".into(),
            message: SpaMessage::Access {
                source_ip: "10.0.0.1".parse().unwrap(),
                ports: vec![PortProto::new(Protocol::Tcp, 22)],
            },
            client_timeout: None,
        }
    }

    #[test]
    fn accepts_fresh_packet() {
        let p = payload_at(1_000_000);
        validate_against_clock(&p, 1_000_001, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_SKEW_SECS).unwrap();
    }

    #[test]
    fn accepts_packet_within_skew_window() {
        let p = payload_at(1_000_010);
        // packet is 10s in the future; skew window is 30s
        validate_against_clock(&p, 1_000_000, DEFAULT_MAX_AGE_SECS, DEFAULT_MAX_SKEW_SECS).unwrap();
    }

    #[test]
    fn rejects_old_packet() {
        let p = payload_at(1_000_000);
        let err = validate_against_clock(
            &p,
            1_000_000 + DEFAULT_MAX_AGE_SECS + 1,
            DEFAULT_MAX_AGE_SECS,
            DEFAULT_MAX_SKEW_SECS,
        )
        .unwrap_err();
        match err {
            ProtoError::PacketTooOld { age_secs, max_secs } => {
                assert_eq!(age_secs, DEFAULT_MAX_AGE_SECS + 1);
                assert_eq!(max_secs, DEFAULT_MAX_AGE_SECS);
            }
            other => panic!("expected PacketTooOld, got {other:?}"),
        }
    }

    #[test]
    fn rejects_packet_too_far_in_future() {
        let p = payload_at(2_000_000);
        let err = validate_against_clock(
            &p,
            2_000_000 - DEFAULT_MAX_SKEW_SECS - 1,
            DEFAULT_MAX_AGE_SECS,
            DEFAULT_MAX_SKEW_SECS,
        )
        .unwrap_err();
        assert!(matches!(err, ProtoError::PacketInFuture { .. }));
    }
}
