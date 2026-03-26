// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-side configuration: daemon settings + access stanzas.

use std::{net::IpAddr, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    error::ConfigError,
    shared::{Base64Key, PortProtoList, SourceSpec},
};

/// Top-level structure of `fwknoxd.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// `[daemon]` section.
    #[serde(default)]
    pub daemon: DaemonSection,
    /// `[replay]` section.
    #[serde(default)]
    pub replay: ReplaySection,
    /// `[[access]]` stanzas.
    #[serde(default, rename = "access")]
    pub access: Vec<AccessStanza>,
}

/// The `[daemon]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DaemonSection {
    /// IP address the daemon binds to.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    /// UDP/TCP port the daemon listens on.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Packet capture backend (UDP listener vs libpcap sniffer).
    #[serde(default = "default_capture_mode")]
    pub capture_mode: CaptureMode,
    /// Network interface for pcap mode.
    #[serde(default)]
    pub pcap_interface: Option<String>,
    /// Berkeley packet filter expression for pcap mode.
    #[serde(default = "default_pcap_filter")]
    pub pcap_filter: String,
    /// Firewall backend used for opening rules.
    #[serde(default = "default_firewall_backend")]
    pub firewall_backend: FirewallBackend,
    /// Path to the daemon's PID file.
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,
    /// Unix user the daemon drops privileges to.
    #[serde(default = "default_run_user")]
    pub run_user: String,
    /// Unix group the daemon drops privileges to.
    #[serde(default = "default_run_group")]
    pub run_group: String,
    /// Maximum age of an SPA packet timestamp before it is rejected.
    #[serde(default = "default_max_age", with = "humantime_serde")]
    pub max_spa_packet_age: Duration,
    /// Whether to flush firewall rules at daemon startup.
    #[serde(default = "yes")]
    pub flush_rules_at_init: bool,
    /// Whether to flush firewall rules on graceful shutdown.
    #[serde(default = "yes")]
    pub flush_rules_at_exit: bool,
    /// Default firewall rule timeout when the SPA packet does not specify one.
    #[serde(default = "default_fw_timeout", with = "humantime_serde")]
    pub default_fw_timeout: Duration,
    /// Maximum firewall rule timeout the daemon will accept.
    #[serde(default = "default_max_fw_timeout", with = "humantime_serde")]
    pub max_fw_timeout: Duration,
    /// Whether to send `sd_notify(READY=1)` and watchdog heartbeats.
    #[serde(default = "yes")]
    pub enable_systemd: bool,
    /// Log level: error/warn/info/debug/trace.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Whether to drop capabilities and privileges on startup.
    #[serde(default = "yes")]
    pub enable_sandbox: bool,
    /// Whether to install a Landlock filesystem ruleset.
    #[serde(default = "yes")]
    pub landlock_enabled: bool,
}

impl Default for DaemonSection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            capture_mode: default_capture_mode(),
            pcap_interface: None,
            pcap_filter: default_pcap_filter(),
            firewall_backend: default_firewall_backend(),
            pid_file: default_pid_file(),
            run_user: default_run_user(),
            run_group: default_run_group(),
            max_spa_packet_age: default_max_age(),
            flush_rules_at_init: true,
            flush_rules_at_exit: true,
            default_fw_timeout: default_fw_timeout(),
            max_fw_timeout: default_max_fw_timeout(),
            enable_systemd: true,
            log_level: default_log_level(),
            enable_sandbox: true,
            landlock_enabled: true,
        }
    }
}

/// The `[replay]` section: replay-detection cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySection {
    /// Path to the persistent replay-detection cache file.
    #[serde(default = "default_replay_path")]
    pub cache_path: PathBuf,
    /// Maximum age of cache entries before they are pruned.
    #[serde(default = "default_replay_max_age", with = "humantime_serde")]
    pub max_age: Duration,
}

impl Default for ReplaySection {
    fn default() -> Self {
        Self {
            cache_path: default_replay_path(),
            max_age: default_replay_max_age(),
        }
    }
}

/// One `[[access]]` stanza, defining a key + the policy that key authorizes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessStanza {
    /// Human-readable name for this stanza (must be unique within the config).
    pub name: String,
    /// List of allowed source specs (`any`, CIDR, or single IP).
    pub source: Vec<SourceSpec>,
    /// Allowed `proto/port` pairs the client may request.
    pub open_ports: PortProtoList,
    /// 32-byte master key. The protocol crate's HKDF derives separate
    /// `enc` and `hmac` subkeys from this value.
    pub master_key_base64: Base64Key,
    /// Optional override for the daemon's default firewall timeout.
    #[serde(default, with = "humantime_serde::option")]
    pub fw_timeout: Option<Duration>,
    /// Optional override for the daemon's max firewall timeout.
    #[serde(default, with = "humantime_serde::option")]
    pub max_fw_timeout: Option<Duration>,
    /// If `true`, the SPA packet's payload `source_ip` must match the
    /// packet's actual source IP. Defaults to `true`.
    #[serde(default = "yes")]
    pub require_source_match: bool,
    /// If set, the SPA packet's `username` field must equal this value.
    #[serde(default)]
    pub require_username: Option<String>,
    /// Whether NAT (DNAT/forwarding) rules are allowed for this stanza.
    #[serde(default)]
    pub enable_nat: bool,
    /// NAT destination `ip:port` (required when `enable_nat` is `true`).
    #[serde(default)]
    pub nat_destination: Option<String>,
    /// Whether SPA `Command` messages are allowed for this stanza.
    #[serde(default)]
    pub enable_cmd_exec: bool,
    /// Unix user that command-exec processes run as.
    #[serde(default)]
    pub cmd_exec_user: Option<String>,
    /// Optional `MM/DD/YYYY` expiration date after which this stanza is rejected.
    #[serde(default)]
    pub expiration_date: Option<String>,
}

/// Packet capture mode used by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMode {
    /// Plain UDP listener (no special privileges).
    Udp,
    /// libpcap-based packet sniffer (requires `CAP_NET_RAW`).
    Pcap,
}

/// Firewall backend used by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    /// Pure-Rust nftables via netlink (preferred).
    Nftables,
    /// Legacy iptables shell wrapper.
    Iptables,
}

fn default_listen_addr() -> IpAddr {
    "0.0.0.0".parse().unwrap()
}
fn default_listen_port() -> u16 {
    62201
}
fn default_capture_mode() -> CaptureMode {
    CaptureMode::Udp
}
fn default_pcap_filter() -> String {
    "udp port 62201".into()
}
fn default_firewall_backend() -> FirewallBackend {
    FirewallBackend::Nftables
}
fn default_pid_file() -> PathBuf {
    PathBuf::from("/run/fwknox/fwknoxd.pid")
}
fn default_run_user() -> String {
    "fwknox".into()
}
fn default_run_group() -> String {
    "fwknox".into()
}
#[allow(clippy::duration_suboptimal_units)]
fn default_max_age() -> Duration {
    Duration::from_secs(120)
}
fn default_fw_timeout() -> Duration {
    Duration::from_secs(30)
}
#[allow(clippy::duration_suboptimal_units)]
fn default_max_fw_timeout() -> Duration {
    Duration::from_secs(300)
}
fn default_log_level() -> String {
    "info".into()
}
fn default_replay_path() -> PathBuf {
    PathBuf::from("/var/lib/fwknox/replay.cache")
}
#[allow(clippy::duration_suboptimal_units)]
fn default_replay_max_age() -> Duration {
    Duration::from_secs(86_400)
}
fn yes() -> bool {
    true
}

impl DaemonConfig {
    /// Validate semantic constraints not enforced by serde.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.access.is_empty() {
            return Err(ConfigError::invalid(
                "at least one [[access]] stanza is required",
            ));
        }
        let mut seen_names = std::collections::HashSet::new();
        for stanza in &self.access {
            if !seen_names.insert(stanza.name.as_str()) {
                return Err(ConfigError::invalid(format!(
                    "duplicate access stanza name: {}",
                    stanza.name
                )));
            }
            if stanza.open_ports.0.is_empty() {
                return Err(ConfigError::invalid(format!(
                    "access stanza {} has empty open_ports",
                    stanza.name
                )));
            }
            if stanza.enable_nat && stanza.nat_destination.is_none() {
                return Err(ConfigError::invalid(format!(
                    "access stanza {} has enable_nat=true but no nat_destination",
                    stanza.name
                )));
            }
        }
        if self.daemon.default_fw_timeout > self.daemon.max_fw_timeout {
            return Err(ConfigError::invalid(
                "default_fw_timeout must be <= max_fw_timeout",
            ));
        }
        Ok(())
    }

    /// Find the first access stanza with a matching master key. Used by
    /// tests in this phase; the daemon will use HMAC-based matching in
    /// Phase 2.
    #[must_use]
    pub fn find_by_master_key(&self, key: &[u8; 32]) -> Option<&AccessStanza> {
        self.access
            .iter()
            .find(|s| s.master_key_base64.as_bytes() == key)
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    use super::*;

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    fn minimal_config_toml() -> String {
        format!(
            r#"
[daemon]

[replay]

[[access]]
name = "test"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{}"
"#,
            b64(&[0x11; 32]),
        )
    }

    #[test]
    fn parses_minimal_config_with_defaults() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert_eq!(cfg.daemon.listen_port, 62201);
        assert_eq!(cfg.daemon.firewall_backend, FirewallBackend::Nftables);
        assert_eq!(cfg.access.len(), 1);
        assert_eq!(cfg.access[0].name, "test");
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_empty_access_list() {
        let toml_str = r"
[daemon]
[replay]
";
        let cfg: DaemonConfig = toml::from_str(toml_str).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn rejects_duplicate_access_names() {
        let body = format!(
            r#"
[daemon]
[replay]

[[access]]
name = "dup"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"

[[access]]
name = "dup"
source = ["any"]
open_ports = ["tcp/23"]
master_key_base64 = "{k}"
"#,
            k = b64(&[0x11; 32]),
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_nat_without_destination() {
        let body = format!(
            r#"
[daemon]
[replay]

[[access]]
name = "n"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
enable_nat = true
"#,
            k = b64(&[0x11; 32]),
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("nat_destination"));
    }

    #[test]
    fn find_by_master_key_works() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        let key = [0x11u8; 32];
        let stanza = cfg.find_by_master_key(&key).expect("should find stanza");
        assert_eq!(stanza.name, "test");
        let bad = [0x99u8; 32];
        assert!(cfg.find_by_master_key(&bad).is_none());
    }

    #[test]
    fn require_source_match_default_is_true() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert!(cfg.access[0].require_source_match);
    }

    #[test]
    fn sandbox_fields_can_be_disabled_via_toml() {
        let body = format!(
            r#"
[daemon]
enable_sandbox = false
landlock_enabled = false

[replay]

[[access]]
name = "t"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{}"
"#,
            b64(&[0x11; 32]),
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        assert!(!cfg.daemon.enable_sandbox);
        assert!(!cfg.daemon.landlock_enabled);
    }

    #[test]
    fn sandbox_fields_default_to_true() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert!(cfg.daemon.enable_sandbox);
        assert!(cfg.daemon.landlock_enabled);
    }
}
