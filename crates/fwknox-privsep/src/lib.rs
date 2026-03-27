// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-privsep
//!
//! Privilege separation primitives for the fwknox daemon: IPC framing,
//! fork + socketpair helpers, and generic worker run loops. The
//! `fwknoxd` binary in `fwknox-daemon` glues these primitives together
//! into the parent + capture worker + crypto worker architecture.

mod error;

pub use error::PrivsepError;
