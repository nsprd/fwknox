// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for the fwknox protocol crate.

use thiserror::Error;

/// All errors that can be produced by the fwknox protocol crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The packet was shorter than the minimum valid SPA packet size.
    #[error("packet too short: got {got} bytes, need at least {need}")]
    PacketTooShort {
        /// Number of bytes actually received.
        got: usize,
        /// Minimum number of bytes required.
        need: usize,
    },

    /// The packet was longer than the maximum allowed SPA packet size.
    #[error("packet too long: got {got} bytes, max {max}")]
    PacketTooLong {
        /// Number of bytes actually received.
        got: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// The header version byte does not match a supported protocol version.
    #[error("unsupported protocol version: {0:#x}")]
    UnsupportedVersion(u8),

    /// A reserved bit in the flags byte was set.
    #[error("reserved flag bit set: {0:#x}")]
    ReservedFlag(u8),

    /// The HMAC tag did not verify.
    #[error("HMAC verification failed")]
    HmacFailed,

    /// AEAD decryption failed (tag mismatch or tampered ciphertext).
    #[error("AEAD decryption failed")]
    AeadFailed,

    /// The MessagePack-encoded SPA payload could not be decoded.
    #[error("payload decode error: {0}")]
    PayloadDecode(String),

    /// The MessagePack-encoded SPA payload could not be encoded.
    #[error("payload encode error: {0}")]
    PayloadEncode(String),

    /// HKDF expand failed (length out of range).
    #[error("HKDF expand failed")]
    HkdfFailed,

    /// A field in the decoded payload failed validation.
    #[error("invalid field: {0}")]
    InvalidField(&'static str),

    /// The SPA packet's timestamp is older than the allowed window.
    #[error("packet age {age_secs}s exceeds maximum {max_secs}s")]
    PacketTooOld {
        /// How many seconds old the packet is.
        age_secs: i64,
        /// Maximum allowed age.
        max_secs: i64,
    },

    /// The SPA packet's timestamp is in the future beyond the allowed skew.
    #[error("packet timestamp is {skew_secs}s in the future")]
    PacketInFuture {
        /// How many seconds in the future the packet is.
        skew_secs: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_byte_counts() {
        let err = ProtoError::PacketTooShort { got: 10, need: 64 };
        let s = err.to_string();
        assert!(s.contains("10"));
        assert!(s.contains("64"));
    }

    #[test]
    fn display_includes_version() {
        let err = ProtoError::UnsupportedVersion(0xFF);
        assert!(err.to_string().contains("0xff"));
    }
}
