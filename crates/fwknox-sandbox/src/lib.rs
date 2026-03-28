// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-sandbox
//!
//! Security hardening for the fwknox daemon. Exposes:
//!
//! - `capabilities`: drop all capabilities except `CAP_NET_ADMIN`
//! - `privdrop`: switch the process to an unprivileged user/group
//! - `landlock`: install a Landlock ruleset restricting filesystem access
//! - `seccomp`: install a tight seccomp-bpf filter for workers
//! - `notify`: `sd_notify` wrappers for systemd integration
//! - `apply`: high-level orchestrator that runs all layers in order

mod apply;
pub mod capabilities;
mod error;
pub mod landlock;
pub mod notify;
pub mod privdrop;
pub mod seccomp;

pub use apply::{apply, LandlockConfig, PrivDropTarget, SandboxConfig};
pub use error::SandboxError;
