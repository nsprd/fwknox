// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command-line interface for `fwknox`.

use std::path::PathBuf;

use clap::Parser;

/// fwknox SPA client.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Use the named server entry from the config file.
    #[arg(short = 'n', long)]
    pub name: Option<String>,

    /// Server hostname or IP address (overrides --name).
    #[arg(short = 'D', long)]
    pub destination: Option<String>,

    /// Server port.
    #[arg(short = 'p', long, default_value_t = 62201)]
    pub port: u16,

    /// Requested ports as a comma-separated list of `proto/port`
    /// (e.g. `tcp/22,udp/53`).
    #[arg(short = 'A', long)]
    pub access: Option<String>,

    /// Source IP to embed in the SPA payload (defaults to the address
    /// the config or `--name` server entry specifies).
    #[arg(short = 'a', long)]
    pub source_ip: Option<String>,

    /// Username to embed in the SPA payload (defaults to `$USER`).
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// Requested firewall rule timeout in seconds.
    #[arg(short = 't', long)]
    pub timeout: Option<u64>,

    /// Master key (base64-encoded 32 bytes). Prefer storing this in the
    /// config file rather than passing it on the CLI.
    #[arg(short = 'k', long)]
    pub master_key_base64: Option<String>,

    /// Path to the client TOML config file.
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// Build the packet and print it as base64 instead of sending.
    #[arg(short = 'T', long)]
    pub test: bool,

    /// Generate a random 32-byte master key, print it as base64, and exit.
    #[arg(long)]
    pub generate_key: bool,

    /// Increase log verbosity.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}
