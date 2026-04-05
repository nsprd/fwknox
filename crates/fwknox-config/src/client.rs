// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client-side configuration: defaults + named server entries.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    error::ConfigError,
    shared::{Base64Key, PortProtoList},
};

/// Top-level structure of `fwknox.toml` (client side).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// `[defaults]` section.
    #[serde(default)]
    pub defaults: DefaultsSection,
    /// `[[server]]` entries.
    #[serde(default, rename = "server")]
    pub servers: Vec<ServerEntry>,
}

/// The `[defaults]` section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DefaultsSection {
    /// Default transport for outbound SPA packets.
    #[serde(default)]
    pub transport: ClientTransport,
    /// Whether to resolve the client's external IP via HTTPS by default.
    #[serde(default)]
    pub resolve_ip: bool,
    /// Whether the client logs verbosely by default.
    #[serde(default)]
    pub verbose: bool,
}

/// One `[[server]]` entry: a named connection to a fwknox daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerEntry {
    /// Human-readable name (used by `fwknox -n <name>`).
    pub name: String,
    /// Server hostname or IP.
    pub destination: String,
    /// Server port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Ports to request access to.
    pub access: PortProtoList,
    /// 32-byte master key. The protocol crate's HKDF derives separate
    /// `enc` and `hmac` subkeys from this value.
    pub master_key_base64: Base64Key,
    /// Optional firewall timeout to request from the daemon.
    #[serde(default, with = "humantime_serde::option")]
    pub fw_timeout: Option<Duration>,
    /// Source IP to embed in the SPA packet (`"auto"` resolves at send time).
    #[serde(default = "default_source_ip")]
    pub source_ip: String,
}

/// Transport used by the client to send the SPA packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientTransport {
    /// Plain UDP datagram (default; no privileges required).
    #[default]
    Udp,
    /// TCP connection — open, send the SPA bytes, close.
    Tcp,
    /// HTTP `GET` with the SPA payload base64url-encoded into the path.
    Http,
}

fn default_port() -> u16 {
    62201
}

fn default_source_ip() -> String {
    "auto".into()
}

impl ClientConfig {
    /// Validate semantic constraints not enforced by serde.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = std::collections::HashSet::new();
        for s in &self.servers {
            if !seen.insert(s.name.as_str()) {
                return Err(ConfigError::invalid(format!(
                    "duplicate server name: {}",
                    s.name
                )));
            }
            if s.access.0.is_empty() {
                return Err(ConfigError::invalid(format!(
                    "server {} has empty access list",
                    s.name
                )));
            }
        }
        Ok(())
    }

    /// Find a server entry by its `name`.
    #[must_use]
    pub fn find_server(&self, name: &str) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.name == name)
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    use super::*;

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    fn sample_toml() -> String {
        format!(
            r#"
[defaults]
transport = "udp"

[[server]]
name = "home"
destination = "my.server.com"
access = ["tcp/22"]
master_key_base64 = "{k}"
fw_timeout = "30s"
"#,
            k = b64(&[0x11; 32]),
        )
    }

    #[test]
    fn parses_sample_client_config() {
        let cfg: ClientConfig = toml::from_str(&sample_toml()).unwrap();
        assert_eq!(cfg.defaults.transport, ClientTransport::Udp);
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].port, 62201);
        assert_eq!(cfg.servers[0].fw_timeout, Some(Duration::from_secs(30)));
        cfg.validate().unwrap();
    }

    #[test]
    fn find_server_by_name() {
        let cfg: ClientConfig = toml::from_str(&sample_toml()).unwrap();
        assert!(cfg.find_server("home").is_some());
        assert!(cfg.find_server("nonexistent").is_none());
    }

    #[test]
    fn rejects_duplicate_server_names() {
        let body = format!(
            r#"
[[server]]
name = "dup"
destination = "a"
access = ["tcp/22"]
master_key_base64 = "{k}"

[[server]]
name = "dup"
destination = "b"
access = ["tcp/22"]
master_key_base64 = "{k}"
"#,
            k = b64(&[0x11; 32]),
        );
        let cfg: ClientConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn defaults_section_optional() {
        let body = format!(
            r#"
[[server]]
name = "x"
destination = "x"
access = ["tcp/22"]
master_key_base64 = "{k}"
"#,
            k = b64(&[0x11; 32]),
        );
        let cfg: ClientConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg.defaults.transport, ClientTransport::Udp);
    }

    #[test]
    fn unknown_defaults_field_is_rejected() {
        let body = format!(
            r#"
[defaults]
bogus_flag = true

[[server]]
name = "x"
destination = "x"
access = ["tcp/22"]
master_key_base64 = "{k}"
"#,
            k = b64(&[0x11; 32]),
        );
        let err = toml::from_str::<ClientConfig>(&body).unwrap_err();
        assert!(
            err.to_string().contains("bogus_flag") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }

    #[test]
    fn unknown_server_field_is_rejected() {
        let body = format!(
            r#"
[[server]]
name = "x"
destination = "x"
access = ["tcp/22"]
master_key_base64 = "{k}"
typo_field = 42
"#,
            k = b64(&[0x11; 32]),
        );
        let err = toml::from_str::<ClientConfig>(&body).unwrap_err();
        assert!(
            err.to_string().contains("typo_field") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }
}
