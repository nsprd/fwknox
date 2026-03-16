// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-config
//!
//! TOML configuration parsing for the fwknox daemon and client. Defines
//! the `DaemonConfig`, `AccessStanza`, `ClientConfig`, and `ServerEntry`
//! types used by the binaries.
//!
//! This crate is the schema for `/etc/fwknox/fwknoxd.toml` (server) and
//! `~/.config/fwknox/fwknox.toml` (client). Subsequent tasks add the
//! individual modules.

mod error;

pub use error::ConfigError;
