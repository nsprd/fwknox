// SPDX-License-Identifier: AGPL-3.0-or-later

//! Drift guard: parse the `[[server]]` TOML block embedded in the
//! repository `README.md` through the real `ClientConfig` schema, so
//! the README cannot silently go out of sync with the struct.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// Extract the first fenced code block between the "```toml" and "```"
/// markers that comes after the string "fwknox.toml" in the README.
/// Panics if the marker can't be found — that's what we want: if
/// somebody deletes the quickstart, the test fails loudly.
fn extract_client_toml_from_readme(readme: &str) -> String {
    let anchor = "fwknox.toml";
    let anchor_pos = readme
        .find(anchor)
        .expect("README: missing 'fwknox.toml' anchor near the client quickstart");
    let after = &readme[anchor_pos..];
    let start_fence = "```toml";
    let start = after
        .find(start_fence)
        .expect("README: missing ```toml fence after 'fwknox.toml' anchor");
    let body_start = start + start_fence.len();
    let rest = &after[body_start..];
    let end = rest
        .find("```")
        .expect("README: ```toml block has no closing ``` fence");
    // Strip any leading newline after ```toml.
    rest[..end].trim_start_matches('\n').to_string()
}

#[test]
fn readme_client_toml_parses_against_real_schema() {
    let readme_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("README.md");
    let readme = std::fs::read_to_string(&readme_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", readme_path.display()));

    let mut toml_body = extract_client_toml_from_readme(&readme);

    // The README example uses a placeholder "<same key as server>" that
    // is not valid base64. Replace it with 32 bytes of 0x11 base64-encoded
    // so the parser can validate the rest of the schema.
    let real_key = B64.encode([0x11u8; 32]);
    toml_body = toml_body.replace("\"<same key as server>\"", &format!("\"{real_key}\""));

    let cfg: fwknox_config::ClientConfig =
        toml::from_str(&toml_body).expect("README client TOML must parse");
    cfg.validate().expect("README client TOML must validate");

    // Verify the example has the expected shape so reviewers notice
    // if somebody trims the example to something trivial.
    assert_eq!(
        cfg.servers.len(),
        1,
        "README example should have one server"
    );
    let server = &cfg.servers[0];
    assert_eq!(server.name, "home");
    assert_eq!(server.destination, "203.0.113.42");
    assert_eq!(server.port, 62201);
    assert_eq!(
        server.access.0.len(),
        1,
        "README example should request exactly one port"
    );
}

#[test]
fn readme_mentions_real_cli_flags() {
    // Belt-and-suspenders: fail the test if the README still references
    // the fictional `send` subcommand or `--open`/`--duration`/`--server`
    // flags, which were removed in Phase 7.
    let readme_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("README.md");
    let readme = std::fs::read_to_string(&readme_path).unwrap();

    let forbidden = [
        "fwknox send",
        "--open ",
        "--duration ",
        "--server ",
        "[[servers]]",
        "address = ",
    ];
    for term in &forbidden {
        assert!(
            !readme.contains(term),
            "README contains fictional CLI/schema element: {term:?}"
        );
    }

    let required = [
        "fwknox -n home",
        "[[server]]",
        "destination = ",
        "access = ",
    ];
    for term in &required {
        assert!(
            readme.contains(term),
            "README is missing required CLI/schema element: {term:?}"
        );
    }
}
