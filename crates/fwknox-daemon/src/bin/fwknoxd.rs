// SPDX-License-Identifier: AGPL-3.0-or-later

//! `fwknoxd` daemon binary entrypoint.

use std::process::ExitCode;

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

    // Phase 4: apply the sandbox AFTER initialising the firewall and
    // binding sockets (those need root/netlink) but BEFORE entering
    // the main loop.

    // Step 1: firewall backend (needs CAP_NET_ADMIN).
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

    // Step 2: capture socket (binds before sandbox so we don't need
    // the CAP_NET_BIND_SERVICE capability after the drop).
    let bind_addr: std::net::IpAddr = config.daemon.listen_addr;
    let listen_addr = std::net::SocketAddr::new(bind_addr, config.daemon.listen_port);
    info!(addr = %listen_addr, "binding capture socket");
    let capture = UdpCapture::bind(listen_addr)?;

    // Step 3: replay cache.
    let replay = ReplayCache::load_from_file(&config.replay.cache_path)?;

    // Step 4: signal handlers.
    let shutdown = ShutdownSignal::new();
    shutdown.install_handlers()?;

    // Step 5: sandbox.
    if config.daemon.enable_sandbox {
        apply_sandbox(&config)?;
    } else {
        info!("sandbox disabled in config");
    }

    run(&config, &capture, firewall.as_mut(), &replay, &shutdown)
}

fn apply_sandbox(config: &fwknox_config::DaemonConfig) -> Result<(), DaemonError> {
    use caps::Capability;
    use fwknox_sandbox::{apply, LandlockConfig, PrivDropTarget, SandboxConfig};

    let drop_to = if fwknox_sandbox::privdrop::is_root() {
        Some(PrivDropTarget {
            user: config.daemon.run_user.clone(),
            group: config.daemon.run_group.clone(),
        })
    } else {
        info!("not running as root; skipping user/group drop");
        None
    };

    let landlock = if config.daemon.landlock_enabled {
        Some(LandlockConfig {
            read_only: vec![config.daemon.pid_file.clone()],
            read_write: vec![
                config.replay.cache_path.clone(),
                parent_or_current(&config.replay.cache_path),
                parent_or_current(&config.daemon.pid_file),
            ],
        })
    } else {
        info!("Landlock disabled in config");
        None
    };

    let sandbox_config = SandboxConfig {
        keep_caps: vec![Capability::CAP_NET_ADMIN],
        drop_to,
        landlock,
    };

    apply(&sandbox_config).map_err(DaemonError::from)
}

fn parent_or_current(path: &std::path::Path) -> std::path::PathBuf {
    path.parent()
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf)
}
