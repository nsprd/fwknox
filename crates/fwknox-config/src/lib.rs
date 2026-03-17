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

mod client;
mod daemon;
mod error;
mod shared;

pub use client::{ClientConfig, ClientTransport, DefaultsSection, ServerEntry};
pub use daemon::{
    AccessStanza, CaptureMode, DaemonConfig, DaemonSection, FirewallBackend, ReplaySection,
};
pub use error::ConfigError;
pub use shared::{parse_port_proto, Base64Key, PortProtoList, SourceSpec};
