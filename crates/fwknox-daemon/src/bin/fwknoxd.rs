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
    // Log to stderr so systemd/journald captures everything correctly
    // and stdout stays clean for any future structured output.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn real_main(cli: &Cli) -> Result<(), DaemonError> {
    info!(config = %cli.config.display(), "loading daemon config");
    let config = load_daemon_config(&cli.config)?;

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

    // Step 2: bind the capture socket / UDP listener.
    let bind_addr: std::net::IpAddr = config.daemon.listen_addr;
    let listen_addr = std::net::SocketAddr::new(bind_addr, config.daemon.listen_port);
    info!(addr = %listen_addr, "binding capture socket");
    let udp_socket = std::net::UdpSocket::bind(listen_addr)?;

    // Step 3: replay cache.
    let cap = std::num::NonZeroUsize::new(config.replay.max_entries)
        .unwrap_or_else(|| std::num::NonZeroUsize::new(1).expect("1 > 0"));
    let mut replay = if config.replay.cache_path.exists() {
        ReplayCache::load_from_file(&config.replay.cache_path)?
    } else {
        ReplayCache::with_capacity(cap)
    };
    replay.set_persist_path(config.replay.cache_path.clone());
    let replay = replay; // freeze into an immutable binding for the rest of the run

    // Step 4: signal handlers.
    let shutdown = ShutdownSignal::new();
    shutdown.install_handlers()?;

    // Step 5: sandbox (capability drop + privdrop; Landlock only
    // activates if explicitly configured — see Phase 4 rationale).
    if config.daemon.enable_sandbox {
        apply_sandbox(&config)?;
    } else {
        info!("sandbox disabled in config");
    }

    // Step 6: dispatch to privsep or single-process mode.
    if config.daemon.enable_privsep {
        info!("running in privsep mode");
        fwknox_daemon::privsep::run(&config, udp_socket, firewall.as_mut(), &replay, &shutdown)
    } else {
        info!("running in single-process mode (privsep disabled in config)");
        // Wrap udp_socket in a UdpCapture for the single-process run loop.
        let capture = UdpCapture::from_socket(udp_socket);
        run(&config, &capture, firewall.as_mut(), &replay, &shutdown)
    }
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
        // Operators who opt into Landlock must understand the
        // current nftables backend spawns `nft` as a subprocess
        // and will fail under Landlock. We warn loudly and still
        // install the policy the operator asked for.
        tracing::warn!(
            "Landlock is enabled but the current nftables backend spawns nft as a subprocess; \
             rule installation may fail. Phase 5 will fix this by moving firewall ops behind privsep."
        );
        // Landlock policy covers only the replay-cache parent
        // directory. We no longer reference the pid file (which the
        // daemon doesn't write) or the cache file (which may not
        // exist on first start). The parent directory is the stable
        // unit of Landlock access.
        Some(LandlockConfig {
            read_only: vec![],
            read_write: vec![parent_or_current(&config.replay.cache_path)],
        })
    } else {
        info!("Landlock disabled (Phase 4 default; see config docs for rationale)");
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
    path.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    )
}
