// SPDX-License-Identifier: AGPL-3.0-or-later

//! IPC message types exchanged between the three fwknox processes.

use std::net::IpAddr;

use fwknox_proto::SpaPayload;
use serde::{Deserialize, Serialize};

/// Serde helpers that encode `IpAddr` as a UTF-8 string.
///
/// `IpAddr`'s built-in serde impl is format-sensitive: on human-readable
/// formats it writes a string, on binary formats (like `MessagePack`) it
/// writes an enum map. The map form cannot be decoded back because the
/// standard library's `Deserialize` for `IpAddr` always expects a string.
/// Serialising as a string is portable across all serde formats and is
/// still compact enough for the IPC use-case.
mod serde_ip {
    use std::net::IpAddr;

    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ip.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IpAddr, D::Error> {
        let raw = <&str as serde::Deserialize>::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Message sent from the capture worker to the crypto worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureMsg {
    /// A UDP datagram arrived on the capture socket.
    Packet {
        /// IP address the packet came from.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// Raw datagram bytes.
        data: Vec<u8>,
    },
}

/// Message sent from the crypto worker to the parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CryptoMsg {
    /// The crypto worker authenticated and validated a packet. The
    /// parent must still run the replay check and install the firewall
    /// rule.
    ValidRequest {
        /// Name of the matching access stanza.
        stanza_name: String,
        /// IP address the packet arrived from.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// Full decoded SPA payload.
        payload: SpaPayload,
    },
    /// The crypto worker authenticated a stanza but rejected the packet
    /// for policy reasons (timestamp, source mismatch, port outside
    /// `open_ports`, AEAD failure after HMAC match, etc).
    Rejected {
        /// IP address the packet arrived from.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// Human-readable rejection reason.
        reason: String,
    },
    /// The crypto worker couldn't match any stanza (common noise case).
    NoMatch {
        /// IP address the packet arrived from.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
    },
}
