// SPDX-License-Identifier: AGPL-3.0-or-later

//! File loaders for daemon and client config.

use std::{fs, path::Path};

use crate::{client::ClientConfig, daemon::DaemonConfig, error::ConfigError};

/// Read, parse, and validate a daemon TOML config file.
pub fn load_daemon_config(path: impl AsRef<Path>) -> Result<DaemonConfig, ConfigError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let cfg: DaemonConfig = toml::from_str(&text).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    cfg.validate()?;
    Ok(cfg)
}

/// Read, parse, and validate a client TOML config file.
pub fn load_client_config(path: impl AsRef<Path>) -> Result<ClientConfig, ConfigError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let cfg: ClientConfig = toml::from_str(&text).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    use super::*;

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    #[test]
    fn loads_daemon_config_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwknoxd.toml");
        let body = format!(
            r#"
[daemon]
[replay]

[[access]]
name = "test"
source = ["any"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
"#,
            k = b64(&[0x11; 32]),
        );
        fs::write(&path, body).unwrap();
        let cfg = load_daemon_config(&path).unwrap();
        assert_eq!(cfg.access.len(), 1);
    }

    #[test]
    fn missing_file_returns_io_error() {
        let err = load_daemon_config("/nonexistent/file.toml").unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn invalid_toml_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        fs::write(&path, "not = valid = toml").unwrap();
        let err = load_daemon_config(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Toml { .. }));
    }

    #[test]
    fn loads_client_config_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwknox.toml");
        let body = format!(
            r#"
[[server]]
name = "x"
destination = "x.com"
access = ["tcp/22"]
master_key_base64 = "{k}"
"#,
            k = b64(&[0x11; 32]),
        );
        fs::write(&path, body).unwrap();
        let cfg = load_client_config(&path).unwrap();
        assert_eq!(cfg.servers.len(), 1);
    }
}
