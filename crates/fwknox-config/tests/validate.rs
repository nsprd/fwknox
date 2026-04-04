// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for `DaemonConfig::validate` rejection paths.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

fn toml_with_stanza_extras(extras: &str, key_bytes: [u8; 32]) -> String {
    format!(
        r#"
[daemon]
[replay]

[[access]]
name = "t"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
{extras}
"#,
        k = B64.encode(key_bytes),
    )
}

fn load(body: &str) -> Result<fwknox_config::DaemonConfig, fwknox_config::ConfigError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fwknoxd.toml");
    std::fs::write(&path, body).unwrap();
    fwknox_config::load_daemon_config(&path)
}

#[test]
fn all_zero_master_key_is_rejected() {
    let body = toml_with_stanza_extras("", [0u8; 32]);
    let err = load(&body).expect_err("all-zero key must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("all-zero") || msg.contains("example placeholder"),
        "unexpected error for zero key: {msg}"
    );
}

#[test]
fn expiration_date_is_rejected() {
    let body = toml_with_stanza_extras(r#"expiration_date = "01/01/2024""#, [0x11; 32]);
    let err = load(&body).expect_err("expiration_date must be rejected as unimplemented");
    assert!(
        err.to_string().contains("expiration_date"),
        "unexpected error: {err}"
    );
}

#[test]
fn enable_nat_is_rejected() {
    let body = toml_with_stanza_extras(
        r#"enable_nat = true
nat_destination = "10.0.0.5:22""#,
        [0x11; 32],
    );
    let err = load(&body).expect_err("enable_nat must be rejected as unimplemented");
    assert!(err.to_string().contains("enable_nat"), "unexpected error: {err}");
}

#[test]
fn enable_cmd_exec_is_rejected() {
    let body = toml_with_stanza_extras(
        r#"enable_cmd_exec = true
cmd_exec_user = "root""#,
        [0x11; 32],
    );
    let err = load(&body).expect_err("enable_cmd_exec must be rejected");
    assert!(
        err.to_string().contains("enable_cmd_exec"),
        "unexpected error: {err}"
    );
}

#[test]
fn valid_stanza_loads_clean() {
    let body = toml_with_stanza_extras("", [0x11; 32]);
    let cfg = load(&body).expect("valid stanza must load");
    assert_eq!(cfg.access.len(), 1);
}
