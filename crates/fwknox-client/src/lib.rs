// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-client
//!
//! Library half of the fwknox client. Holds the CLI definition, the
//! SPA payload builder, the UDP send routine, and the master-key
//! generator. The `fwknox` binary in `src/bin/fwknox.rs` is a thin
//! wrapper that parses CLI args, loads the config, and calls into
//! this library.

mod error;

pub use error::ClientError;
