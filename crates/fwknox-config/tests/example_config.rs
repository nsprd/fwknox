// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifies that the shipped `config/fwknoxd.toml.example` file parses
//! against the current `DaemonConfig` schema. Guards against the example
//! drifting from the code.

use std::path::PathBuf;

#[test]
fn example_daemon_config_parses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("config")
        .join("fwknoxd.toml.example");
    let cfg = fwknox_config::load_daemon_config(&path).expect("example config must parse");

    // Sanity: the [daemon] section parsed.
    assert_eq!(cfg.daemon.listen_port, 62201);
    assert!(cfg.daemon.enable_privsep);

    // Access stanza: these are required serde fields with no default, so
    // if any is renamed or removed from the struct, the example will fail
    // to parse and this test will fail loudly.
    assert_eq!(cfg.access.len(), 1);
    let stanza = &cfg.access[0];
    assert_eq!(stanza.name, "ssh-from-anywhere");
    assert_eq!(stanza.source.len(), 1);
    assert_eq!(stanza.open_ports.0.len(), 1);

    // [rate_limit]: the example documents every knob and its value must
    // match the current defaults. If a default drifts without updating
    // the example, this assertion fires loudly.
    assert!(cfg.rate_limit.enabled);
    assert_eq!(cfg.rate_limit.per_source_rate_per_sec, 10);
    assert_eq!(cfg.rate_limit.per_source_burst, 20);
    assert_eq!(cfg.rate_limit.tracked_sources_capacity, 1024);
    assert_eq!(cfg.rate_limit.global_rate_per_sec, 500);
    assert_eq!(cfg.rate_limit.global_burst, 1000);
    assert_eq!(cfg.rate_limit.promotion_threshold, 5);
    assert_eq!(cfg.rate_limit.ipv6_prefix_len, 64);
}
