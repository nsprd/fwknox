// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-daemon
//!
//! Library half of the fwknox daemon. Holds the packet-processing
//! pipeline, the stanza matcher, the shutdown signal, the main event
//! loop, and the pure validation helper for the privsep crypto worker.

mod cli;
mod error;
mod matcher;
mod pipeline;
mod privsep_run;
mod run;
mod shutdown;
mod validate;

pub use cli::Cli;
pub use error::DaemonError;
pub use matcher::{match_packet, MatchResult};
pub use pipeline::{process_packet, ProcessResult};
pub use run::run;
pub use shutdown::ShutdownSignal;
pub use validate::validate_capture_msg;

/// Entry points for the three-process privsep architecture.
pub mod privsep {
    /// Run the privsep daemon (capture + crypto workers + parent loop).
    pub use crate::privsep_run::run;
}
