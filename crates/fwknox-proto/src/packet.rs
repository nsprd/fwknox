// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPA packet construction and parsing.
//!
//! Wire format:
//!
//! ```text
//! [Header(4)] [GCM nonce(12)] [GCM ciphertext + tag(N+16)] [HMAC-SHA256(32)]
//! ```
//!
//! `build_packet` runs encrypt-then-MAC; `parse_packet` runs MAC-then-decrypt
//! and short-circuits on the cheap HMAC check before attempting AEAD.

use crate::{
    aead::{self, NONCE_LEN, TAG_LEN},
    error::ProtoError,
    header::{Flags, Header, HEADER_LEN},
    hmac::{self, HMAC_LEN},
    kdf::DerivedKeys,
    payload::SpaPayload,
    types::SpaMessage,
};

/// Maximum SPA packet length (UDP-friendly).
pub const MAX_PACKET_LEN: usize = 1500;

/// Minimum SPA packet length: header + nonce + at least one AEAD block + tag + HMAC.
pub const MIN_PACKET_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN + HMAC_LEN;

/// Build a complete SPA packet from a payload and a master key.
///
/// The flag bits are computed automatically from the payload's `message`
/// variant and the presence of `client_timeout`.
pub fn build_packet(payload: &SpaPayload, master_key: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let plaintext = payload.encode()?;
    let nonce = aead::generate_nonce()?;
    let flags = derive_flags(&payload.message, payload.client_timeout.is_some());
    let payload_len_after_aead =
        u16::try_from(plaintext.len() + TAG_LEN).map_err(|_| ProtoError::PacketTooLong {
            got: plaintext.len() + TAG_LEN,
            max: u16::MAX as usize,
        })?;
    let header = Header::new(flags, payload_len_after_aead);
    let header_bytes = header.encode();

    let keys = DerivedKeys::derive(master_key)?;
    let ciphertext = aead::seal(keys.enc.as_bytes(), &nonce, &header_bytes, &plaintext)?;

    // packet = header || nonce || ciphertext_with_tag
    let mut packet = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len() + HMAC_LEN);
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);

    // hmac over header || nonce || ciphertext (everything before the HMAC)
    let tag = hmac::sign(keys.hmac.as_bytes(), &packet);
    packet.extend_from_slice(&tag);

    if packet.len() > MAX_PACKET_LEN {
        return Err(ProtoError::PacketTooLong {
            got: packet.len(),
            max: MAX_PACKET_LEN,
        });
    }
    Ok(packet)
}

/// Parse and verify an SPA packet, returning the decoded payload.
///
/// Performs HMAC verification *before* decryption to short-circuit invalid
/// packets cheaply.
pub fn parse_packet(wire: &[u8], master_key: &[u8]) -> Result<SpaPayload, ProtoError> {
    if wire.len() < MIN_PACKET_LEN {
        return Err(ProtoError::PacketTooShort {
            got: wire.len(),
            need: MIN_PACKET_LEN,
        });
    }
    if wire.len() > MAX_PACKET_LEN {
        return Err(ProtoError::PacketTooLong {
            got: wire.len(),
            max: MAX_PACKET_LEN,
        });
    }

    // Split off the trailing HMAC tag.
    let (signed, tag) = wire.split_at(wire.len() - HMAC_LEN);

    let keys = DerivedKeys::derive(master_key)?;
    hmac::verify(keys.hmac.as_bytes(), signed, tag)?;

    // After HMAC: parse header, extract nonce, decrypt the rest.
    let header = Header::decode(&signed[..HEADER_LEN])?;
    let header_bytes = &signed[..HEADER_LEN];
    let nonce_bytes = &signed[HEADER_LEN..HEADER_LEN + NONCE_LEN];
    let ciphertext = &signed[HEADER_LEN + NONCE_LEN..];

    if ciphertext.len() != header.payload_len as usize {
        return Err(ProtoError::InvalidField("payload_len mismatch"));
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    let plaintext = aead::open(keys.enc.as_bytes(), &nonce, header_bytes, ciphertext)?;
    let payload = SpaPayload::decode(&plaintext)?;

    // Cross-check the payload variant against the header flag bits.
    check_flags_match_payload(header.flags, &payload)?;

    Ok(payload)
}

fn derive_flags(message: &SpaMessage, has_client_timeout: bool) -> Flags {
    let mut flags = Flags::new();
    match message {
        SpaMessage::Access { .. } => {}
        SpaMessage::Nat { .. } | SpaMessage::LocalNat { .. } => flags.set(Flags::NAT),
        SpaMessage::Command { .. } => flags.set(Flags::COMMAND),
    }
    if has_client_timeout {
        flags.set(Flags::CLIENT_TIMEOUT);
    }
    flags
}

fn check_flags_match_payload(flags: Flags, payload: &SpaPayload) -> Result<(), ProtoError> {
    let expected = derive_flags(&payload.message, payload.client_timeout.is_some());
    if flags.raw() != expected.raw() {
        return Err(ProtoError::InvalidField("flag/payload mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PortProto, Protocol};

    fn sample_payload() -> SpaPayload {
        SpaPayload {
            nonce: [0xCDu8; 16],
            timestamp: 1_700_000_000,
            username: "alice".into(),
            message: SpaMessage::Access {
                source_ip: "192.168.1.5".parse().unwrap(),
                ports: vec![PortProto::new(Protocol::Tcp, 22)],
            },
            client_timeout: Some(60),
        }
    }

    fn nat_payload() -> SpaPayload {
        SpaPayload {
            nonce: [0xCDu8; 16],
            timestamp: 1_700_000_000,
            username: "alice".into(),
            message: SpaMessage::Nat {
                source_ip: "10.0.0.1".parse().unwrap(),
                ports: vec![PortProto::new(Protocol::Tcp, 443)],
                nat_dest: "192.168.1.100:8443".parse().unwrap(),
            },
            client_timeout: None,
        }
    }

    #[test]
    fn build_then_parse_roundtrip() {
        let key = [0x42u8; 32];
        let payload = sample_payload();
        let wire = build_packet(&payload, &key).unwrap();
        let back = parse_packet(&wire, &key).unwrap();
        assert_eq!(payload, back);
    }

    #[test]
    fn build_sets_correct_flags_for_nat() {
        let key = [0x42u8; 32];
        let wire = build_packet(&nat_payload(), &key).unwrap();
        let header = Header::decode(&wire[..HEADER_LEN]).unwrap();
        assert!(header.flags.contains(Flags::NAT));
        assert!(!header.flags.contains(Flags::CLIENT_TIMEOUT));
    }

    #[test]
    fn parse_with_wrong_key_fails_on_hmac() {
        let payload = sample_payload();
        let wire = build_packet(&payload, &[0x42; 32]).unwrap();
        let err = parse_packet(&wire, &[0x00; 32]).unwrap_err();
        assert!(matches!(err, ProtoError::HmacFailed));
    }

    #[test]
    fn parse_rejects_truncated_packet() {
        let payload = sample_payload();
        let wire = build_packet(&payload, &[0x42; 32]).unwrap();
        let truncated = &wire[..wire.len() - 1];
        let err = parse_packet(truncated, &[0x42; 32]).unwrap_err();
        assert!(matches!(err, ProtoError::HmacFailed));
    }

    #[test]
    fn parse_rejects_tampered_header_via_aad() {
        let payload = sample_payload();
        let mut wire = build_packet(&payload, &[0x42; 32]).unwrap();
        // Recompute the HMAC after flipping a header bit, so we get past the
        // HMAC gate and prove the AAD binding catches the tampering.
        wire[1] ^= Flags::COMMAND; // flip an unrelated flag
        let keys = DerivedKeys::derive(&[0x42; 32]).unwrap();
        let signed_len = wire.len() - HMAC_LEN;
        let new_tag = hmac::sign(keys.hmac.as_bytes(), &wire[..signed_len]);
        wire[signed_len..].copy_from_slice(&new_tag);
        let err = parse_packet(&wire, &[0x42; 32]).unwrap_err();
        // The deterministic outcome: flipping the flags byte changes the AAD
        // that was bound into AES-GCM, so decryption fails *before* the
        // flag/payload cross-check ever runs. Asserting AeadFailed exactly
        // means a future regression that broke AAD binding cannot quietly
        // pass via the (also-correct) InvalidField path.
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn parse_rejects_tampered_ciphertext_at_hmac() {
        // Build a valid packet, then flip a byte deep inside the ciphertext
        // region (after the header + nonce). Do NOT re-sign the HMAC. The
        // HMAC is over header || nonce || ciphertext_with_tag, so any change
        // to the ciphertext bytes must invalidate the HMAC tag. This proves
        // encrypt-then-MAC ordering: if the HMAC were mistakenly computed
        // over the *plaintext* instead, this tampering would slip past HMAC
        // and only be caught at AEAD, returning AeadFailed instead of
        // HmacFailed.
        let payload = sample_payload();
        let mut wire = build_packet(&payload, &[0x42; 32]).unwrap();
        // Flip a bit inside the ciphertext region (one byte past the nonce).
        let ct_byte_index = HEADER_LEN + NONCE_LEN;
        wire[ct_byte_index] ^= 0x80;
        let err = parse_packet(&wire, &[0x42; 32]).unwrap_err();
        assert!(
            matches!(err, ProtoError::HmacFailed),
            "expected HmacFailed (proves HMAC covers ciphertext), got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_oversize_packet() {
        let mut wire = vec![0u8; MAX_PACKET_LEN + 1];
        wire[0] = 0x01;
        let err = parse_packet(&wire, &[0x42; 32]).unwrap_err();
        assert!(matches!(err, ProtoError::PacketTooLong { .. }));
    }

    #[test]
    fn parse_rejects_short_packet() {
        let err = parse_packet(&[0u8; 10], &[0x42; 32]).unwrap_err();
        assert!(matches!(err, ProtoError::PacketTooShort { .. }));
    }

    #[test]
    fn nat_payload_roundtrip() {
        let key = [0x99u8; 32];
        let p = nat_payload();
        let wire = build_packet(&p, &key).unwrap();
        let back = parse_packet(&wire, &key).unwrap();
        assert_eq!(p, back);
    }
}
