// SPDX-License-Identifier: AGPL-3.0-or-later

//! The 4-byte fwknox SPA header: version | flags | length (BE u16).

use crate::error::ProtoError;

/// Current fwknox SPA protocol version.
pub const PROTO_VERSION: u8 = 0x01;

/// Length of the wire-format header in bytes.
pub const HEADER_LEN: usize = 4;

/// Flag bits for the second byte of the SPA header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// Bit set when the payload is `SpaMessage::Nat` or `SpaMessage::LocalNat`.
    pub const NAT: u8 = 0b0000_0001;
    /// Bit set when `SpaPayload::client_timeout` is `Some`.
    pub const CLIENT_TIMEOUT: u8 = 0b0000_0010;
    /// Bit set when the payload is `SpaMessage::Command`.
    pub const COMMAND: u8 = 0b0000_0100;
    /// Bit set when the packet uses asymmetric (Ed25519 + X25519) mode.
    pub const ASYMMETRIC: u8 = 0b0000_1000;

    /// Mask of all currently-defined flag bits. Any bit set outside this
    /// mask must be rejected by receivers.
    pub const ALL_DEFINED: u8 = Self::NAT | Self::CLIENT_TIMEOUT | Self::COMMAND | Self::ASYMMETRIC;

    /// Construct an empty `Flags` value with no bits set.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Return the raw byte representation of the flags.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Construct a `Flags` from a raw byte without checking reserved bits.
    /// Useful for tests and round-tripping; production code should prefer
    /// `from_raw`.
    #[inline]
    #[must_use]
    pub const fn from_raw_unchecked(byte: u8) -> Self {
        Self(byte)
    }

    /// Construct a `Flags` from a raw byte, rejecting any reserved bits.
    pub fn from_raw(byte: u8) -> Result<Self, ProtoError> {
        let reserved = byte & !Self::ALL_DEFINED;
        if reserved != 0 {
            return Err(ProtoError::ReservedFlag(reserved));
        }
        Ok(Self(byte))
    }

    /// Return `true` if any of the bits in `mask` are set.
    #[inline]
    #[must_use]
    pub const fn contains(self, mask: u8) -> bool {
        self.0 & mask != 0
    }

    /// Set the bits in `mask`.
    #[inline]
    pub fn set(&mut self, mask: u8) {
        self.0 |= mask;
    }
}

/// The SPA wire-format header (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Protocol version byte.
    pub version: u8,
    /// Flag bits.
    pub flags: Flags,
    /// Length of the encrypted payload (ciphertext + GCM tag) in bytes.
    pub payload_len: u16,
}

impl Header {
    /// Build a header for the current protocol version.
    #[must_use]
    pub fn new(flags: Flags, payload_len: u16) -> Self {
        Self {
            version: PROTO_VERSION,
            flags,
            payload_len,
        }
    }

    /// Encode the header to a fixed-size byte array.
    #[must_use]
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let len = self.payload_len.to_be_bytes();
        [self.version, self.flags.raw(), len[0], len[1]]
    }

    /// Decode a header from the start of a byte slice. Rejects unsupported
    /// versions and reserved flag bits.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtoError::PacketTooShort {
                got: bytes.len(),
                need: HEADER_LEN,
            });
        }
        let version = bytes[0];
        if version != PROTO_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }
        let flags = Flags::from_raw(bytes[1])?;
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        Ok(Self {
            version,
            flags,
            payload_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encode_decode_roundtrip() {
        let mut flags = Flags::new();
        flags.set(Flags::NAT);
        flags.set(Flags::CLIENT_TIMEOUT);
        let h = Header::new(flags, 184);
        let bytes = h.encode();
        assert_eq!(bytes[0], PROTO_VERSION);
        assert_eq!(bytes[1], Flags::NAT | Flags::CLIENT_TIMEOUT);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 184);
        let decoded = Header::decode(&bytes).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn rejects_short_header() {
        let err = Header::decode(&[0x01, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, ProtoError::PacketTooShort { .. }));
    }

    #[test]
    fn rejects_unknown_version() {
        let err = Header::decode(&[0xFF, 0x00, 0x00, 0x10]).unwrap_err();
        assert!(matches!(err, ProtoError::UnsupportedVersion(0xFF)));
    }

    #[test]
    fn rejects_reserved_flag_bits() {
        let err = Header::decode(&[0x01, 0xF0, 0x00, 0x10]).unwrap_err();
        match err {
            ProtoError::ReservedFlag(b) => assert_eq!(b, 0xF0),
            other => panic!("expected ReservedFlag, got {other:?}"),
        }
    }

    #[test]
    fn flags_contains_works() {
        let mut f = Flags::new();
        f.set(Flags::NAT);
        assert!(f.contains(Flags::NAT));
        assert!(!f.contains(Flags::COMMAND));
    }
}
