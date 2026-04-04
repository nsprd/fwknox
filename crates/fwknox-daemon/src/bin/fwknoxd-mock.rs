// SPDX-License-Identifier: AGPL-3.0-or-later

//! `fwknoxd-mock` — test-only daemon binary that uses
//! [`fwknox_firewall::MockBackend`] instead of `NftablesBackend`.
//!
//! This binary is identical to `fwknoxd` in every way except the
//! firewall backend. It's used by the subprocess integration test in
//! `crates/fwknox-daemon/tests/privsep_subprocess.rs` so the test can
//! run the daemon end-to-end (privsep, sandbox, full pipeline)
//! without needing `CAP_NET_ADMIN` or actually touching nftables.
//!
//! Production deployments should use `fwknoxd`, not this binary.

use std::process::ExitCode;

use clap::Parser;
use fwknox_capture::UdpCapture;
use fwknox_config::load_daemon_config;
use fwknox_daemon::{run, Cli, DaemonError, ShutdownSignal};
use fwknox_firewall::{FirewallBackend, MockBackend};
use fwknox_replay::ReplayCache;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match real_main(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "fwknoxd-mock failed");
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
        .unwrap_or_else(|_| EnvFilter::new(format!("fwknox={level},fwknoxd_mock={level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn real_main(cli: &Cli) -> Result<(), DaemonError> {
    info!(config = %cli.config.display(), "loading daemon config (mock backend)");
    let config = load_daemon_config(&cli.config)?;

    // Mock firewall backend — no CAP_NET_ADMIN required.
    let mut firewall: Box<dyn FirewallBackend> = Box::new(MockBackend::new());

    let bind_addr: std::net::IpAddr = config.daemon.listen_addr;
    let listen_addr = std::net::SocketAddr::new(bind_addr, config.daemon.listen_port);
    info!(addr = %listen_addr, "binding capture socket");
    let udp_socket = std::net::UdpSocket::bind(listen_addr)?;

    let cap = std::num::NonZeroUsize::new(config.replay.max_entries)
        .unwrap_or_else(|| std::num::NonZeroUsize::new(1).expect("1 > 0"));
    let mut replay = if config.replay.cache_path.exists() {
        ReplayCache::load_from_file(&config.replay.cache_path)?
    } else {
        ReplayCache::with_capacity(cap)
    };
    replay.set_persist_path(config.replay.cache_path.clone());
    let replay = replay; // freeze into an immutable binding for the rest of the run

    let shutdown = ShutdownSignal::new();
    shutdown.install_handlers()?;

    // We deliberately do NOT call apply_sandbox here, because the
    // fwknoxd-mock binary is used in tests where we don't want to
    // drop privileges or capabilities (the test runs as a normal
    // user). The privsep mode still applies the WORKER sandbox in
    // each fork child (Phase 6a Task 3), which is the actual thing
    // the integration test wants to validate.

    if config.daemon.enable_privsep {
        info!("running in privsep mode (mock backend)");
        fwknox_daemon::privsep::run(&config, udp_socket, firewall.as_mut(), &replay, &shutdown)
    } else {
        info!("running in single-process mode (mock backend)");
        let capture = UdpCapture::from_socket(udp_socket);
        run(&config, &capture, firewall.as_mut(), &replay, &shutdown)
    }
}
