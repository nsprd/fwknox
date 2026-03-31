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
}
