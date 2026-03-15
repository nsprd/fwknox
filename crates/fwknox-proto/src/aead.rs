// SPDX-License-Identifier: AGPL-3.0-or-later

//! AES-256-GCM authenticated encryption with associated data.
//!
//! This wrapper hides ring's `LessSafeKey` API behind a simple
//! `seal` / `open` pair that uses an explicit caller-supplied nonce.

use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};

use crate::error::ProtoError;

/// Length of the AES-256-GCM key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the AES-256-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of the AES-256-GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Generate a fresh 12-byte nonce from the system CSPRNG.
pub fn generate_nonce() -> Result<[u8; NONCE_LEN], ProtoError> {
    let rng = SystemRandom::new();
    let mut out = [0u8; NONCE_LEN];
    rng.fill(&mut out).map_err(|_| ProtoError::AeadFailed)?;
    Ok(out)
}

/// Encrypt `plaintext` under `key` and `nonce`, binding `aad`.
///
/// Returns ciphertext with the GCM tag appended (length = `plaintext.len()` + 16).
pub fn seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    if key.len() != KEY_LEN {
        return Err(ProtoError::AeadFailed);
    }
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| ProtoError::AeadFailed)?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let aad = aead::Aad::from(aad);

    let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buf.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(nonce, aad, &mut buf)
        .map_err(|_| ProtoError::AeadFailed)?;
    Ok(buf)
}

/// Decrypt `ciphertext_and_tag` under `key`, `nonce`, and `aad`. The input
/// must be ciphertext followed by the 16-byte GCM tag. On success returns
/// the plaintext bytes.
pub fn open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    if key.len() != KEY_LEN {
        return Err(ProtoError::AeadFailed);
    }
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(ProtoError::AeadFailed);
    }
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| ProtoError::AeadFailed)?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let aad = aead::Aad::from(aad);

    let mut buf = ciphertext_and_tag.to_vec();
    let plaintext = key
        .open_in_place(nonce, aad, &mut buf)
        .map_err(|_| ProtoError::AeadFailed)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_roundtrip() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let aad = b"header bytes";
        let pt = b"top secret message";
        let ct = seal(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let pt2 = open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let nonce = [0u8; NONCE_LEN];
        let ct = seal(&[0x11; KEY_LEN], &nonce, b"", b"hello").unwrap();
        let err = open(&[0x22; KEY_LEN], &nonce, b"", &ct).unwrap_err();
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn open_with_wrong_nonce_fails() {
        let key = [0x11; KEY_LEN];
        let ct = seal(&key, &[0u8; NONCE_LEN], b"", b"hello").unwrap();
        let err = open(&key, &[1u8; NONCE_LEN], b"", &ct).unwrap_err();
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn open_with_wrong_aad_fails() {
        let key = [0x11; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"hdr1", b"hello").unwrap();
        let err = open(&key, &nonce, b"hdr2", &ct).unwrap_err();
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn open_with_tampered_ciphertext_fails() {
        let key = [0x11; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let mut ct = seal(&key, &nonce, b"", b"hello").unwrap();
        ct[0] ^= 0x80;
        let err = open(&key, &nonce, b"", &ct).unwrap_err();
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn rejects_wrong_key_length() {
        let nonce = [0u8; NONCE_LEN];
        let err = seal(&[0u8; 16], &nonce, b"", b"x").unwrap_err();
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn open_rejects_short_input() {
        let key = [0x11; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let err = open(&key, &nonce, b"", &[0u8; 8]).unwrap_err();
        assert!(matches!(err, ProtoError::AeadFailed));
    }

    #[test]
    fn generate_nonce_is_nonzero_and_correct_length() {
        let n = generate_nonce().unwrap();
        assert_eq!(n.len(), NONCE_LEN);
        // Vanishingly unlikely to be all zero
        assert!(n.iter().any(|b| *b != 0));
    }
}
