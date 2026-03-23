// SPDX-License-Identifier: AGPL-3.0-or-later

//! Master-key generation helper.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::ClientError;

/// Length of the master key in bytes (32 = 256 bits).
pub const MASTER_KEY_LEN: usize = 32;

/// Generate a fresh 32-byte master key from the system CSPRNG.
pub fn generate_master_key() -> Result<[u8; MASTER_KEY_LEN], ClientError> {
    let rng = SystemRandom::new();
    let mut out = [0u8; MASTER_KEY_LEN];
    rng.fill(&mut out)
        .map_err(|_| ClientError::InvalidArgument {
            field: "csprng",
            reason: "system random number generator failed".into(),
        })?;
    Ok(out)
}

/// Convenience: generate a master key and return it base64-encoded.
pub fn generate_master_key_base64() -> Result<String, ClientError> {
    Ok(B64.encode(generate_master_key()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_is_correct_length() {
        let key = generate_master_key().unwrap();
        assert_eq!(key.len(), MASTER_KEY_LEN);
    }

    #[test]
    fn generated_key_is_nonzero() {
        let key = generate_master_key().unwrap();
        assert!(key.iter().any(|b| *b != 0));
    }

    #[test]
    fn two_generated_keys_are_distinct() {
        let a = generate_master_key().unwrap();
        let b = generate_master_key().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn base64_form_decodes_to_32_bytes() {
        let s = generate_master_key_base64().unwrap();
        let bytes = B64.decode(s).unwrap();
        assert_eq!(bytes.len(), MASTER_KEY_LEN);
    }
}
