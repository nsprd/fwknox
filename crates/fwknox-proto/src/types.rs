// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core protocol value types: protocol families, port-protocol pairs, SPA
//! message variants.

use core::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Serde helpers that encode `IpAddr` as a UTF-8 string.
///
/// `IpAddr`'s built-in serde impl is format-sensitive: on human-readable
/// formats it writes a string, on binary formats (like `MessagePack`) it writes
/// an enum map. The map form cannot be decoded back because the standard
/// library's `Deserialize` for `IpAddr` always expects a string.  Serialising
/// as a string is portable across all serde formats and is still compact
/// enough for the SPA use-case.
mod serde_ip {
    use core::net::IpAddr;

    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ip.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IpAddr, D::Error> {
        let raw = <&str as serde::Deserialize>::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Serde helpers that encode `SocketAddr` as a UTF-8 string.
///
/// See [`serde_ip`] for the rationale; the same format-sensitivity applies to
/// `SocketAddr`.
mod serde_sock {
    use core::net::SocketAddr;

    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(addr: &SocketAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&addr.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SocketAddr, D::Error> {
        let raw = <&str as serde::Deserialize>::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Layer-4 protocol used for an SPA access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl core::fmt::Display for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
        }
    }
}

/// A `protocol/port` pair (e.g. `tcp/22`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortProto {
    /// The layer-4 protocol.
    pub proto: Protocol,
    /// The TCP or UDP port number.
    pub port: u16,
}

impl PortProto {
    /// Construct a new [`PortProto`] from a protocol and port.
    #[must_use]
    pub const fn new(proto: Protocol, port: u16) -> Self {
        Self { proto, port }
    }
}

impl core::fmt::Display for PortProto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.proto, self.port)
    }
}

/// The SPA message payload, after authentication and decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpaMessage {
    /// Standard access request: open `ports` from `source_ip`.
    Access {
        /// IP address that should be permitted by the firewall rule.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// Ports to open for the source.
        ports: Vec<PortProto>,
    },
    /// NAT (forwarding) request: open `ports`, DNAT to `nat_dest`.
    Nat {
        /// IP address that should be permitted by the firewall rule.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// External ports to open.
        ports: Vec<PortProto>,
        /// Internal destination to DNAT into.
        #[serde(with = "serde_sock")]
        nat_dest: SocketAddr,
    },
    /// Local NAT (loopback) request.
    LocalNat {
        /// IP address that should be permitted by the firewall rule.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// External ports to open.
        ports: Vec<PortProto>,
        /// Local-loopback destination to DNAT into.
        #[serde(with = "serde_sock")]
        nat_dest: SocketAddr,
    },
    /// Server-side command execution request.
    Command {
        /// IP address that should be permitted by the firewall rule.
        #[serde(with = "serde_ip")]
        source_ip: IpAddr,
        /// Command line to execute on the server.
        command: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
    }

    #[test]
    fn portproto_display() {
        assert_eq!(PortProto::new(Protocol::Tcp, 22).to_string(), "tcp/22");
    }

    #[test]
    fn spa_message_access_serializes() {
        let msg = SpaMessage::Access {
            source_ip: "192.168.1.5".parse().unwrap(),
            ports: vec![PortProto::new(Protocol::Tcp, 22)],
        };
        let bytes = rmp_serde::to_vec(&msg).expect("serialize");
        let back: SpaMessage = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(msg, back);
    }

    #[test]
    fn spa_message_nat_roundtrip() {
        let msg = SpaMessage::Nat {
            source_ip: "10.0.0.1".parse().unwrap(),
            ports: vec![PortProto::new(Protocol::Tcp, 443)],
            nat_dest: "192.168.1.100:8443".parse().unwrap(),
        };
        let bytes = rmp_serde::to_vec(&msg).unwrap();
        let back: SpaMessage = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn spa_message_command_roundtrip() {
        let msg = SpaMessage::Command {
            source_ip: "10.0.0.1".parse().unwrap(),
            command: "/bin/true".to_string(),
        };
        let bytes = rmp_serde::to_vec(&msg).unwrap();
        let back: SpaMessage = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(msg, back);
    }
}
