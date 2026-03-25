// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-sandbox
//!
//! Security hardening for the fwknox daemon. Exposes:
//!
//! - `capabilities`: drop all capabilities except `CAP_NET_ADMIN`
//! - `privdrop`: switch the process to an unprivileged user/group
//! - `landlock`: install a Landlock ruleset restricting filesystem access
//! - `notify`: `sd_notify` wrappers for systemd integration
//!
//! The `apply` module glues these together into a single call the
//! daemon makes after binding sockets and initialising the firewall.

pub mod capabilities;
mod error;
pub mod privdrop;

pub use error::SandboxError;
