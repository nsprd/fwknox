// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command-line interface for `fwknoxd`.

use std::path::PathBuf;

use clap::Parser;

/// fwknox SPA daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Path to the daemon TOML config file.
    #[arg(short = 'c', long, default_value = "/etc/fwknox/fwknoxd.toml")]
    pub config: PathBuf,

    /// Increase log verbosity (`-v` for debug, `-vv` for trace).
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}
