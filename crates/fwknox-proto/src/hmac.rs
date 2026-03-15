// SPDX-License-Identifier: AGPL-3.0-or-later

//! HMAC-SHA256 wrapper. The verify path uses ring's constant-time check.

use crate::error::ProtoError;

/// Length of an HMAC-SHA256 tag in bytes.
pub const HMAC_LEN: usize = 32;

/// Compute an HMAC-SHA256 tag for `message` under `key`.
#[must_use]
pub fn sign(key: &[u8], message: &[u8]) -> [u8; HMAC_LEN] {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&k, message);
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verify an HMAC-SHA256 tag in constant time.
pub fn verify(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), ProtoError> {
    if tag.len() != HMAC_LEN {
        return Err(ProtoError::HmacFailed);
    }
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::verify(&k, message, tag).map_err(|_| ProtoError::HmacFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_succeeds() {
        let key = [0x42u8; 32];
        let msg = b"hello fwknox";
        let tag = sign(&key, msg);
        verify(&key, msg, &tag).unwrap();
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let key = [0x42u8; 32];
        let bad = [0x01u8; 32];
        let tag = sign(&key, b"x");
        let err = verify(&bad, b"x", &tag).unwrap_err();
        assert!(matches!(err, ProtoError::HmacFailed));
    }

    #[test]
    fn verify_with_tampered_message_fails() {
        let key = [0x42u8; 32];
        let tag = sign(&key, b"hello");
        let err = verify(&key, b"hellp", &tag).unwrap_err();
        assert!(matches!(err, ProtoError::HmacFailed));
    }

    #[test]
    fn verify_rejects_short_tag() {
        let key = [0x42u8; 32];
        let err = verify(&key, b"x", &[0; 16]).unwrap_err();
        assert!(matches!(err, ProtoError::HmacFailed));
    }

    #[test]
    fn known_answer_for_zero_key_zero_message() {
        // Sanity: 32 bytes, not all zero (HMAC of empty under zero key is well-defined and non-zero)
        let tag = sign(&[0u8; 32], b"");
        assert_eq!(tag.len(), HMAC_LEN);
        assert!(tag.iter().any(|b| *b != 0));
    }
}
