// SPDX-License-Identifier: AGPL-3.0-or-later

//! The plaintext SPA payload, encoded as `MessagePack` inside the encrypted
//! portion of the SPA packet.

use serde::{Deserialize, Serialize};

use crate::{error::ProtoError, types::SpaMessage};

/// The plaintext payload carried inside an SPA packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaPayload {
    /// 16-byte random nonce, primary key for replay detection.
    pub nonce: [u8; 16],
    /// Unix epoch seconds at which the client created the packet.
    pub timestamp: i64,
    /// Username embedded by the client (max 64 bytes).
    pub username: String,
    /// The actual access request.
    pub message: SpaMessage,
    /// Optional client-requested firewall rule timeout (seconds).
    pub client_timeout: Option<u32>,
}

impl SpaPayload {
    /// Maximum length of the username field, in bytes.
    pub const MAX_USERNAME_LEN: usize = 64;

    /// Maximum encoded payload size before encryption.
    pub const MAX_ENCODED_LEN: usize = 1024;

    /// Encode this payload to a `MessagePack` byte vector.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let bytes =
            rmp_serde::to_vec(self).map_err(|e| ProtoError::PayloadEncode(e.to_string()))?;
        if bytes.len() > Self::MAX_ENCODED_LEN {
            return Err(ProtoError::InvalidField("payload too large"));
        }
        Ok(bytes)
    }

    /// Decode a `MessagePack` byte slice into a payload, also performing
    /// structural validation (username length, etc).
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let payload: Self =
            rmp_serde::from_slice(bytes).map_err(|e| ProtoError::PayloadDecode(e.to_string()))?;
        payload.validate_structure()?;
        Ok(payload)
    }

    /// Internal: structural validation (no time / no key checks).
    fn validate_structure(&self) -> Result<(), ProtoError> {
        if self.username.len() > Self::MAX_USERNAME_LEN {
            return Err(ProtoError::InvalidField("username too long"));
        }
        if !self
            .username
            .chars()
            .all(|c| c.is_ascii_graphic() || c == ' ')
        {
            return Err(ProtoError::InvalidField("username contains control bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PortProto, Protocol};

    fn sample_payload() -> SpaPayload {
        SpaPayload {
            nonce: [0xAB; 16],
            timestamp: 1_700_000_000,
            username: "alice".to_string(),
            message: SpaMessage::Access {
                source_ip: "192.168.1.5".parse().unwrap(),
                ports: vec![PortProto::new(Protocol::Tcp, 22)],
            },
            client_timeout: Some(60),
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let payload = sample_payload();
        let bytes = payload.encode().unwrap();
        let decoded = SpaPayload::decode(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn rejects_long_username() {
        let mut p = sample_payload();
        p.username = "a".repeat(SpaPayload::MAX_USERNAME_LEN + 1);
        let bytes = rmp_serde::to_vec(&p).unwrap();
        let err = SpaPayload::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::InvalidField("username too long")));
    }

    #[test]
    fn rejects_username_with_control_bytes() {
        let mut p = sample_payload();
        p.username = "alice\u{0007}".to_string();
        let bytes = rmp_serde::to_vec(&p).unwrap();
        let err = SpaPayload::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::InvalidField(_)));
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = SpaPayload::decode(&[0xFF, 0xFE, 0xFD]).unwrap_err();
        assert!(matches!(err, ProtoError::PayloadDecode(_)));
    }

    #[test]
    fn encoded_size_under_budget() {
        let bytes = sample_payload().encode().unwrap();
        // Reasonable upper bound for the sample payload (well under MAX_ENCODED_LEN)
        assert!(bytes.len() < 200, "encoded len = {}", bytes.len());
    }
}
