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
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// `[daemon]` section.
    #[serde(default)]
    pub daemon: DaemonSection,
    /// `[replay]` section.
    #[serde(default)]
    pub replay: ReplaySection,
    /// `[rate_limit]` section.
    #[serde(default)]
    pub rate_limit: RateLimitSection,
    /// `[[access]]` stanzas.
    #[serde(default, rename = "access")]
    pub access: Vec<AccessStanza>,
}

/// The `[daemon]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct DaemonSection {
    /// IP address the daemon binds to.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    /// UDP/TCP port the daemon listens on.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Firewall backend used for opening rules.
    #[serde(default = "default_firewall_backend")]
    pub firewall_backend: FirewallBackend,
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
    /// Whether to drop capabilities and privileges on startup.
    #[serde(default = "yes")]
    pub enable_sandbox: bool,
    /// Whether to run in privilege-separated mode (three processes).
    ///
    /// When `true` the daemon forks a capture worker and a crypto
    /// worker at startup and runs the main loop in the parent
    /// process, receiving authenticated requests from the crypto
    /// worker over a Unix socketpair. When `false` the daemon runs
    /// as a single process (Phase 3/4 fallback mode).
    #[serde(default = "yes")]
    pub enable_privsep: bool,
    /// Whether to install a Landlock filesystem ruleset.
    ///
    /// Defaults to `false` in Phase 4 because the current
    /// `nftables-rs` firewall backend spawns `nft` as a subprocess
    /// on every rule operation, and a Landlock ruleset covering
    /// the daemon would block that spawn. Phase 5's privilege
    /// separation will move firewall ops to a separate process
    /// that doesn't need Landlock, at which point the default
    /// will flip back to `true`.
    #[serde(default)]
    pub landlock_enabled: bool,
}

impl Default for DaemonSection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            firewall_backend: default_firewall_backend(),
            run_user: default_run_user(),
            run_group: default_run_group(),
            max_spa_packet_age: default_max_age(),
            flush_rules_at_init: true,
            flush_rules_at_exit: true,
            default_fw_timeout: default_fw_timeout(),
            max_fw_timeout: default_max_fw_timeout(),
            enable_systemd: true,
            enable_sandbox: true,
            enable_privsep: true,
            landlock_enabled: false,
        }
    }
}

/// The `[replay]` section: replay-detection cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySection {
    /// Path to the persistent replay-detection cache file.
    #[serde(default = "default_replay_path")]
    pub cache_path: PathBuf,
    /// Maximum age of cache entries before they are pruned.
    #[serde(default = "default_replay_max_age", with = "humantime_serde")]
    pub max_age: Duration,
    /// Maximum number of in-memory entries. When the cache is full,
    /// the least-recently-used entry is evicted to make room for a
    /// new nonce. This bounds the memory footprint against adversarial
    /// packet floods.
    #[serde(default = "default_replay_max_entries")]
    pub max_entries: usize,
}

impl Default for ReplaySection {
    fn default() -> Self {
        Self {
            cache_path: default_replay_path(),
            max_age: default_replay_max_age(),
            max_entries: default_replay_max_entries(),
        }
    }
}

/// The `[rate_limit]` section: per-source packet rate limiting.
///
/// Defaults are tuned for a typical fwknox deployment with dozens of
/// legitimate clients and no upstream rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSection {
    /// Master switch. Set to `false` to disable rate limiting entirely.
    #[serde(default = "yes")]
    pub enabled: bool,

    /// Per-source token refill rate (tokens per second) for sources
    /// that have been promoted into exact tracking.
    #[serde(default = "default_per_source_rate_per_sec")]
    pub per_source_rate_per_sec: u64,

    /// Per-source burst capacity (max tokens a per-source bucket holds).
    #[serde(default = "default_per_source_burst")]
    pub per_source_burst: u64,

    /// Maximum number of exact-tracked sources in the LRU.
    #[serde(default = "default_tracked_sources_capacity")]
    pub tracked_sources_capacity: usize,

    /// Global fallback bucket refill rate (tokens per second).
    #[serde(default = "default_global_rate_per_sec")]
    pub global_rate_per_sec: u64,

    /// Global fallback bucket burst capacity.
    #[serde(default = "default_global_burst")]
    pub global_burst: u64,

    /// Number of successful global-bucket consumptions before a source
    /// is promoted into exact tracking. Rejected traffic does not count.
    #[serde(default = "default_promotion_threshold")]
    pub promotion_threshold: u32,

    /// IPv6 source addresses are masked to this prefix length before
    /// keying. Valid range: 1..=128. Default 64 is the IETF-standard
    /// end-site allocation boundary.
    #[serde(default = "default_ipv6_prefix_len")]
    pub ipv6_prefix_len: u8,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            enabled: true,
            per_source_rate_per_sec: default_per_source_rate_per_sec(),
            per_source_burst: default_per_source_burst(),
            tracked_sources_capacity: default_tracked_sources_capacity(),
            global_rate_per_sec: default_global_rate_per_sec(),
            global_burst: default_global_burst(),
            promotion_threshold: default_promotion_threshold(),
            ipv6_prefix_len: default_ipv6_prefix_len(),
        }
    }
}

/// One `[[access]]` stanza, defining a key + the policy that key authorizes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
fn default_firewall_backend() -> FirewallBackend {
    FirewallBackend::Nftables
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
fn default_replay_path() -> PathBuf {
    PathBuf::from("/var/lib/fwknox/replay.cache")
}
#[allow(clippy::duration_suboptimal_units)]
fn default_replay_max_age() -> Duration {
    Duration::from_secs(86_400)
}
fn default_replay_max_entries() -> usize {
    10_000
}
fn default_per_source_rate_per_sec() -> u64 {
    10
}
fn default_per_source_burst() -> u64 {
    20
}
fn default_tracked_sources_capacity() -> usize {
    1024
}
fn default_global_rate_per_sec() -> u64 {
    500
}
fn default_global_burst() -> u64 {
    1000
}
fn default_promotion_threshold() -> u32 {
    5
}
fn default_ipv6_prefix_len() -> u8 {
    64
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
            if stanza.master_key_base64.is_all_zero() {
                return Err(ConfigError::invalid(format!(
                    "access stanza {:?} uses the all-zero example placeholder key; \
                     generate a real one with `head -c 32 /dev/urandom | base64`",
                    stanza.name
                )));
            }
            if stanza.expiration_date.is_some() {
                return Err(ConfigError::invalid(format!(
                    "access stanza {:?} sets expiration_date, which is not yet \
                     implemented — remove the field or wait for a future release",
                    stanza.name
                )));
            }
            if stanza.enable_nat {
                return Err(ConfigError::invalid(format!(
                    "access stanza {:?} sets enable_nat, which is not yet \
                     implemented — remove the field or wait for a future release",
                    stanza.name
                )));
            }
            if stanza.enable_cmd_exec {
                return Err(ConfigError::invalid(format!(
                    "access stanza {:?} sets enable_cmd_exec, which is not yet \
                     implemented — remove the field or wait for a future release",
                    stanza.name
                )));
            }
        }
        if self.daemon.default_fw_timeout > self.daemon.max_fw_timeout {
            return Err(ConfigError::invalid(
                "default_fw_timeout must be <= max_fw_timeout",
            ));
        }
        // Rate limit validation. Only enforce when enabled — if the operator
        // set enabled=false they've opted out explicitly and the numeric
        // values are ignored.
        if self.rate_limit.enabled {
            if self.rate_limit.per_source_rate_per_sec < 1 {
                return Err(ConfigError::invalid(
                    "per_source_rate_per_sec must be >= 1 when rate limiting is enabled",
                ));
            }
            if self.rate_limit.global_rate_per_sec < 1 {
                return Err(ConfigError::invalid(
                    "global_rate_per_sec must be >= 1 when rate limiting is enabled",
                ));
            }
            if self.rate_limit.per_source_burst < self.rate_limit.per_source_rate_per_sec {
                return Err(ConfigError::invalid(
                    "per_source_burst must be >= per_source_rate_per_sec",
                ));
            }
            if self.rate_limit.global_burst < self.rate_limit.global_rate_per_sec {
                return Err(ConfigError::invalid(
                    "global_burst must be >= global_rate_per_sec",
                ));
            }
            if self.rate_limit.tracked_sources_capacity == 0 {
                return Err(ConfigError::invalid(
                    "tracked_sources_capacity must be >= 1",
                ));
            }
            if self.rate_limit.promotion_threshold == 0 {
                return Err(ConfigError::invalid("promotion_threshold must be >= 1"));
            }
            if !(1..=128).contains(&self.rate_limit.ipv6_prefix_len) {
                return Err(ConfigError::invalid("ipv6_prefix_len must be in 1..=128"));
            }
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

    fn config_with_rate_limit_override(rate_limit_toml: &str) -> String {
        format!(
            r#"
[daemon]
[replay]

{rate_limit_toml}

[[access]]
name = "t"
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
    fn enable_sandbox_defaults_to_true_landlock_defaults_to_false() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert!(cfg.daemon.enable_sandbox);
        // Landlock defaults to false in Phase 4 because the current
        // nftables-rs backend spawns nft as a subprocess. Phase 5
        // will re-enable it by default after privsep lands.
        assert!(!cfg.daemon.landlock_enabled);
    }

    #[test]
    fn enable_privsep_defaults_to_true() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert!(cfg.daemon.enable_privsep);
    }

    #[test]
    fn default_config_has_rate_limit_section_with_defaults() {
        let cfg: DaemonConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert!(cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.per_source_rate_per_sec, 10);
        assert_eq!(cfg.rate_limit.per_source_burst, 20);
        assert_eq!(cfg.rate_limit.tracked_sources_capacity, 1024);
        assert_eq!(cfg.rate_limit.global_rate_per_sec, 500);
        assert_eq!(cfg.rate_limit.global_burst, 1000);
        assert_eq!(cfg.rate_limit.promotion_threshold, 5);
        assert_eq!(cfg.rate_limit.ipv6_prefix_len, 64);
    }

    #[test]
    fn partial_rate_limit_section_fills_missing_fields() {
        let body = format!(
            r#"
[daemon]
[replay]

[rate_limit]
per_source_rate_per_sec = 50

[[access]]
name = "t"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{}"
"#,
            b64(&[0x11; 32]),
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg.rate_limit.per_source_rate_per_sec, 50);
        assert_eq!(cfg.rate_limit.per_source_burst, 20); // default
        assert!(cfg.rate_limit.enabled); // default
    }

    #[test]
    fn rate_limit_section_rejects_unknown_fields() {
        let body = format!(
            r#"
[daemon]
[replay]

[rate_limit]
unknown_field = true

[[access]]
name = "t"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{}"
"#,
            b64(&[0x11; 32]),
        );
        let err = toml::from_str::<DaemonConfig>(&body).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn rate_limit_can_be_disabled_via_toml() {
        let body = format!(
            r#"
[daemon]
[replay]

[rate_limit]
enabled = false

[[access]]
name = "t"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{}"
"#,
            b64(&[0x11; 32]),
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        assert!(!cfg.rate_limit.enabled);
        cfg.validate().unwrap();
    }

    #[test]
    fn enable_privsep_can_be_disabled_via_toml() {
        let body = format!(
            r#"
[daemon]
enable_privsep = false

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
        assert!(!cfg.daemon.enable_privsep);
    }

    #[test]
    fn rate_limit_rejects_burst_less_than_rate() {
        let body = config_with_rate_limit_override(
            "[rate_limit]\nper_source_rate_per_sec = 10\nper_source_burst = 5\n",
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("per_source_burst"));
    }

    #[test]
    fn rate_limit_rejects_global_burst_less_than_global_rate() {
        let body = config_with_rate_limit_override(
            "[rate_limit]\nglobal_rate_per_sec = 500\nglobal_burst = 100\n",
        );
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("global_burst"));
    }

    #[test]
    fn rate_limit_rejects_zero_tracked_capacity() {
        let body = config_with_rate_limit_override("[rate_limit]\ntracked_sources_capacity = 0\n");
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("tracked_sources_capacity"));
    }

    #[test]
    fn rate_limit_rejects_ipv6_prefix_zero() {
        let body = config_with_rate_limit_override("[rate_limit]\nipv6_prefix_len = 0\n");
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("ipv6_prefix_len"));
    }

    #[test]
    fn rate_limit_rejects_ipv6_prefix_over_128() {
        let body = config_with_rate_limit_override("[rate_limit]\nipv6_prefix_len = 129\n");
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("ipv6_prefix_len"));
    }

    #[test]
    fn rate_limit_rejects_promotion_threshold_zero() {
        let body = config_with_rate_limit_override("[rate_limit]\npromotion_threshold = 0\n");
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("promotion_threshold"));
    }

    #[test]
    fn rate_limit_rejects_zero_rates_while_enabled() {
        let body = config_with_rate_limit_override("[rate_limit]\nper_source_rate_per_sec = 0\n");
        let cfg: DaemonConfig = toml::from_str(&body).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("per_source_rate_per_sec"));
    }

    #[test]
    fn rate_limit_accepts_ipv6_prefix_at_boundary() {
        // Both 1 and 128 must be accepted (inclusive range).
        for len in [1u8, 128u8] {
            let body = config_with_rate_limit_override(&format!(
                "[rate_limit]\nipv6_prefix_len = {len}\n"
            ));
            let cfg: DaemonConfig = toml::from_str(&body).unwrap();
            cfg.validate().expect("boundary value should be accepted");
        }
    }
}
