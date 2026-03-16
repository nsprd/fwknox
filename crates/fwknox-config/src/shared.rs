// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper types shared between daemon and client config.

use std::{net::IpAddr, str::FromStr};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fwknox_proto::{PortProto, Protocol};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ConfigError;

/// A "source" entry in an access stanza: either a CIDR, a single IP, or
/// the literal `"any"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSpec {
    /// Match any IP address (IPv4 or IPv6).
    Any,
    /// Match any IP within the given CIDR network.
    Cidr(IpNet),
    /// Match exactly one IP address.
    Single(IpAddr),
}

impl SourceSpec {
    /// Returns `true` if `ip` is matched by this source spec.
    #[must_use]
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Cidr(net) => net.contains(&ip),
            Self::Single(addr) => *addr == ip,
        }
    }
}

impl FromStr for SourceSpec {
    type Err = ConfigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("any") {
            return Ok(Self::Any);
        }
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(Self::Cidr(net));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Single(ip));
        }
        Err(ConfigError::Invalid(format!(
            "could not parse source spec: {s:?}"
        )))
    }
}

impl Serialize for SourceSpec {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let s = match self {
            Self::Any => "any".to_string(),
            Self::Cidr(net) => net.to_string(),
            Self::Single(ip) => ip.to_string(),
        };
        ser.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SourceSpec {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Parse a `proto/port` string (e.g. `"tcp/22"`).
pub fn parse_port_proto(s: &str) -> Result<PortProto, ConfigError> {
    let (proto, port) = s
        .split_once('/')
        .ok_or_else(|| ConfigError::Invalid(format!("expected proto/port, got {s:?}")))?;
    let proto = match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => return Err(ConfigError::Invalid(format!("unknown protocol: {other:?}"))),
    };
    let port: u16 = port
        .trim()
        .parse()
        .map_err(|e| ConfigError::Invalid(format!("invalid port: {e}")))?;
    if port == 0 {
        return Err(ConfigError::Invalid("port must be > 0".into()));
    }
    Ok(PortProto::new(proto, port))
}

/// A list of `proto/port` strings, deserialized from a `Vec<String>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PortProtoList(
    /// The decoded list of protocol/port pairs.
    pub Vec<PortProto>,
);

impl<'de> Deserialize<'de> for PortProtoList {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let strings: Vec<String> = Vec::deserialize(de)?;
        let mut out = Vec::with_capacity(strings.len());
        for s in strings {
            out.push(parse_port_proto(&s).map_err(serde::de::Error::custom)?);
        }
        Ok(Self(out))
    }
}

/// A base64-encoded 32-byte key, validated on deserialize.
#[derive(Clone, PartialEq, Eq)]
pub struct Base64Key(
    /// The decoded 32-byte key material.
    pub [u8; 32],
);

impl Base64Key {
    /// Borrow the underlying 32-byte key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Base64Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Base64Key(<redacted>)")
    }
}

impl Serialize for Base64Key {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&B64.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Key {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let bytes = B64.decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32-byte key, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_port() {
        let p = parse_port_proto("tcp/22").unwrap();
        assert_eq!(p, PortProto::new(Protocol::Tcp, 22));
    }

    #[test]
    fn parse_udp_port() {
        let p = parse_port_proto("udp/53").unwrap();
        assert_eq!(p, PortProto::new(Protocol::Udp, 53));
    }

    #[test]
    fn rejects_unknown_protocol() {
        assert!(parse_port_proto("sctp/22").is_err());
    }

    #[test]
    fn rejects_zero_port() {
        assert!(parse_port_proto("tcp/0").is_err());
    }

    #[test]
    fn rejects_missing_slash() {
        assert!(parse_port_proto("tcp22").is_err());
    }

    #[test]
    fn source_spec_any() {
        let s: SourceSpec = "any".parse().unwrap();
        assert!(s.matches("1.2.3.4".parse().unwrap()));
        assert!(s.matches("::1".parse().unwrap()));
    }

    #[test]
    fn source_spec_cidr_v4() {
        let s: SourceSpec = "192.168.1.0/24".parse().unwrap();
        assert!(s.matches("192.168.1.50".parse().unwrap()));
        assert!(!s.matches("192.168.2.50".parse().unwrap()));
    }

    #[test]
    fn source_spec_single() {
        let s: SourceSpec = "10.0.0.1".parse().unwrap();
        assert!(s.matches("10.0.0.1".parse().unwrap()));
        assert!(!s.matches("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn base64_key_roundtrip_via_toml() {
        // Encode/decode through a tiny TOML wrapper.
        #[derive(Serialize, Deserialize)]
        struct Wrap {
            k: Base64Key,
        }
        let w = Wrap {
            k: Base64Key([0xAB; 32]),
        };
        let s = toml::to_string(&w).unwrap();
        let back: Wrap = toml::from_str(&s).unwrap();
        assert_eq!(back.k.as_bytes(), w.k.as_bytes());
    }

    #[test]
    fn base64_key_rejects_wrong_length() {
        #[derive(Deserialize)]
        struct Wrap {
            #[allow(dead_code)]
            k: Base64Key,
        }
        let bad = B64.encode([0u8; 16]);
        let toml_str = format!("k = \"{bad}\"\n");
        let result: Result<Wrap, _> = toml::from_str(&toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn base64_key_debug_does_not_leak() {
        let key = Base64Key([0xAB; 32]);
        let s = format!("{key:?}");
        assert!(!s.contains("ab"));
        assert!(s.contains("redacted"));
    }
}
