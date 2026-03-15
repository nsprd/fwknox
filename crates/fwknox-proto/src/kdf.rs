// SPDX-License-Identifier: AGPL-3.0-or-later

//! HKDF-SHA256 key derivation for the fwknox protocol.
//!
//! Two subkeys are derived from a single 32-byte master key:
//!
//! - `enc_key`  — used as the AES-256-GCM key
//! - `hmac_key` — used as the HMAC-SHA256 key
//!
//! Domain separation is enforced through the HKDF salt (per-key) and the
//! info string (per-purpose).

use ring::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ProtoError;

const ENC_SALT: &[u8] = b"fwknox-enc-v1";
const HMAC_SALT: &[u8] = b"fwknox-hmac-v1";
const ENC_INFO: &[u8] = b"encryption";
const HMAC_INFO: &[u8] = b"authentication";

/// Length of a derived subkey in bytes.
pub const SUBKEY_LEN: usize = 32;

/// A 32-byte derived subkey, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubKey([u8; SUBKEY_LEN]);

impl SubKey {
    /// Borrow the subkey as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SubKey(<redacted>)")
    }
}

/// Type wrapper used to satisfy ring's `KeyType` trait for an arbitrary
/// length of OKM.
struct OutputLen(usize);

impl hkdf::KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// The pair of subkeys derived from a master key.
pub struct DerivedKeys {
    /// Encryption subkey (AES-256-GCM key).
    pub enc: SubKey,
    /// HMAC subkey (HMAC-SHA256 key).
    pub hmac: SubKey,
}

impl DerivedKeys {
    /// Derive `enc` and `hmac` subkeys from a master key.
    pub fn derive(master_key: &[u8]) -> Result<Self, ProtoError> {
        let enc = derive_one(master_key, ENC_SALT, ENC_INFO)?;
        let hmac = derive_one(master_key, HMAC_SALT, HMAC_INFO)?;
        Ok(Self { enc, hmac })
    }
}

fn derive_one(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SubKey, ProtoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_slice = [info];
    let okm = prk
        .expand(&info_slice, OutputLen(SUBKEY_LEN))
        .map_err(|_| ProtoError::HkdfFailed)?;
    let mut out = [0u8; SUBKEY_LEN];
    okm.fill(&mut out).map_err(|_| ProtoError::HkdfFailed)?;
    Ok(SubKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_two_distinct_subkeys() {
        let master = [0x42u8; 32];
        let keys = DerivedKeys::derive(&master).unwrap();
        assert_eq!(keys.enc.as_bytes().len(), SUBKEY_LEN);
        assert_eq!(keys.hmac.as_bytes().len(), SUBKEY_LEN);
        assert_ne!(keys.enc.as_bytes(), keys.hmac.as_bytes());
    }

    #[test]
    fn deterministic_for_same_master() {
        let master = [0x11u8; 32];
        let a = DerivedKeys::derive(&master).unwrap();
        let b = DerivedKeys::derive(&master).unwrap();
        assert_eq!(a.enc.as_bytes(), b.enc.as_bytes());
        assert_eq!(a.hmac.as_bytes(), b.hmac.as_bytes());
    }

    #[test]
    fn different_masters_give_different_keys() {
        let a = DerivedKeys::derive(&[0x00u8; 32]).unwrap();
        let b = DerivedKeys::derive(&[0xFFu8; 32]).unwrap();
        assert_ne!(a.enc.as_bytes(), b.enc.as_bytes());
        assert_ne!(a.hmac.as_bytes(), b.hmac.as_bytes());
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        let key = SubKey([0xAB; SUBKEY_LEN]);
        let s = format!("{key:?}");
        assert!(!s.contains("ab"));
        assert!(s.contains("redacted"));
    }
}
