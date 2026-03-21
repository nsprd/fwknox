// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-daemon
//!
//! Library half of the fwknox daemon. Holds the packet-processing
//! pipeline, the stanza matcher, the shutdown signal, and the main
//! event loop. The `fwknoxd` binary in `src/bin/fwknoxd.rs` is just
//! config loading + real-backend instantiation + a single call into
//! `run`.

mod error;

pub use error::DaemonError;
