// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifies that the shipped `config/fwknoxd.toml.example` file parses
//! against the current `DaemonConfig` schema. Guards against the example
//! drifting from the code.

use std::path::PathBuf;

#[test]
fn example_daemon_config_parses() {
    // CARGO_MANIFEST_DIR is .../fwknox/crates/fwknox-config.
    // The example lives at .../fwknox/config/fwknoxd.toml.example.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("config")
        .join("fwknoxd.toml.example");
    let cfg =
        fwknox_config::load_daemon_config(&path).expect("example config must parse");
    assert_eq!(cfg.daemon.listen_port, 62201);
    assert_eq!(cfg.access.len(), 1);
    assert_eq!(cfg.access[0].name, "ssh-from-anywhere");
}
