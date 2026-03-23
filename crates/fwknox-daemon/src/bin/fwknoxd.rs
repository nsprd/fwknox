// SPDX-License-Identifier: AGPL-3.0-or-later

//! `fwknoxd` daemon binary entrypoint.

use std::{
    net::{IpAddr, SocketAddr},
    process::ExitCode,
};

use clap::Parser;
use fwknox_capture::UdpCapture;
use fwknox_config::{load_daemon_config, FirewallBackend as ConfigBackend};
use fwknox_daemon::{run, Cli, DaemonError, ShutdownSignal};
use fwknox_firewall::{FirewallBackend, NftablesBackend};
use fwknox_replay::ReplayCache;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match real_main(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "fwknoxd failed");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("fwknox={level},fwknoxd={level}")));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn real_main(cli: &Cli) -> Result<(), DaemonError> {
    info!(config = %cli.config.display(), "loading daemon config");
    let config = load_daemon_config(&cli.config)?;

    // Phase 3 only ships the nftables backend; iptables is deferred.
    let mut firewall: Box<dyn FirewallBackend> = match config.daemon.firewall_backend {
        ConfigBackend::Nftables => Box::new(NftablesBackend::new()),
        ConfigBackend::Iptables => {
            return Err(DaemonError::Firewall(
                fwknox_firewall::FirewallError::Unsupported(
                    "iptables backend (Phase 3 ships only nftables)",
                ),
            ));
        }
    };

    let bind_addr: IpAddr = config.daemon.listen_addr;
    let listen_addr = SocketAddr::new(bind_addr, config.daemon.listen_port);
    info!(addr = %listen_addr, "binding capture socket");
    let capture = UdpCapture::bind(listen_addr)?;

    let replay = ReplayCache::load_from_file(&config.replay.cache_path)?;

    let shutdown = ShutdownSignal::new();
    shutdown.install_handlers()?;

    run(&config, &capture, firewall.as_mut(), &replay, &shutdown)
}
