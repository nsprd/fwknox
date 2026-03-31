// SPDX-License-Identifier: AGPL-3.0-or-later

//! Privsep run loop for the fwknox daemon.
//!
//! This is the parent-side orchestrator. It:
//!
//! 1. Creates two `UnixDatagram` socketpairs (capture→crypto and
//!    crypto→parent).
//! 2. Forks the capture worker, passing it the UDP socket and the
//!    capture→crypto socket.
//! 3. Forks the crypto worker, passing it both socketpair ends.
//! 4. Closes the socket ends the parent doesn't own.
//! 5. Installs signal handlers.
//! 6. Sends `sd_notify(READY=1)`.
//! 7. Loops: `recv_msg::<CryptoMsg>` → replay check → firewall install
//!    → repeat until shutdown.
//! 8. On shutdown: signals both workers, waitpids them, flushes the
//!    firewall, saves the replay cache.
//!
//! The worker processes do NOT return from this function. After fork
//! they each call their own `run_*_worker` and then `exit()`.

use std::{net::UdpSocket, os::unix::net::UnixDatagram, time::Duration};

use fwknox_config::DaemonConfig;
use fwknox_firewall::{AccessRule, FirewallBackend};
use fwknox_privsep::{
    make_socketpair, recv_msg, run_capture_worker, run_crypto_worker, CryptoMsg, ForkedWorker,
    PrivsepError,
};
use fwknox_proto::SpaMessage;
use fwknox_replay::ReplayCache;
use nix::unistd::{fork, ForkResult};
use tracing::{debug, error, info, warn};

use crate::{error::DaemonError, shutdown::ShutdownSignal, validate::validate_capture_msg};

/// How often the parent's main loop wakes up to check its shutdown flag.
const PARENT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Run the three-process privsep daemon.
///
/// On success, returns when a shutdown signal has been fully handled
/// (both workers reaped, firewall flushed, replay cache saved). On
/// error, returns immediately with the worker PIDs potentially still
/// running — the caller should call [`ShutdownSignal::trigger`] and
/// wait briefly for a cleanup pass.
#[allow(clippy::too_many_arguments)] // Mirrors the single-process `run`.
pub fn run(
    config: &DaemonConfig,
    udp_socket: UdpSocket,
    firewall: &mut dyn FirewallBackend,
    replay: &ReplayCache,
    shutdown: &ShutdownSignal,
) -> Result<(), DaemonError> {
    info!(
        listen_addr = %config.daemon.listen_addr,
        listen_port = config.daemon.listen_port,
        "fwknox daemon starting in privsep mode"
    );

    firewall.init()?;

    // Create the two socketpairs BEFORE fork so every process inherits
    // both ends.
    let (capture_writer, crypto_reader) = make_socketpair()?;
    let (crypto_writer, parent_reader) = make_socketpair()?;

    // Fork capture worker first.
    let capture_pid = unsafe { fork() }.map_err(|source| {
        DaemonError::from(PrivsepError::Syscall {
            syscall: "fork",
            source,
        })
    })?;
    match capture_pid {
        ForkResult::Child => {
            // In capture worker: we only need udp_socket and
            // capture_writer. Close every other fd we inherited.
            drop(crypto_reader);
            drop(crypto_writer);
            drop(parent_reader);
            let local_shutdown = ShutdownSignal::new();
            if let Err(e) = local_shutdown.install_handlers() {
                eprintln!("capture worker: install_handlers failed: {e}");
                std::process::exit(1);
            }
            // Apply Landlock + seccomp sandbox AFTER signal handlers
            // are in place but BEFORE entering the worker loop. From
            // this point forward the worker has no filesystem access
            // and only the syscalls in the worker_filter allowlist.
            if let Err(e) = fwknox_sandbox::apply_worker_sandbox("capture") {
                eprintln!("capture worker: apply_worker_sandbox failed: {e}");
                std::process::exit(1);
            }
            let result = run_capture_worker(&udp_socket, &capture_writer, || {
                local_shutdown.is_shutdown()
            });
            if let Err(e) = result {
                eprintln!("capture worker: {e}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            debug!(pid = child.as_raw(), "forked capture worker");
            // Parent does NOT keep the capture_writer or udp_socket;
            // close them so the worker is the sole owner.
            drop(capture_writer);
            drop(udp_socket);
            // Fork the crypto worker.
            run_parent_after_capture_fork(
                config,
                firewall,
                replay,
                shutdown,
                crypto_reader,
                crypto_writer,
                parent_reader,
                child,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_parent_after_capture_fork(
    config: &DaemonConfig,
    firewall: &mut dyn FirewallBackend,
    replay: &ReplayCache,
    shutdown: &ShutdownSignal,
    crypto_reader: UnixDatagram,
    crypto_writer: UnixDatagram,
    parent_reader: UnixDatagram,
    capture_pid: nix::unistd::Pid,
) -> Result<(), DaemonError> {
    let capture_handle = ForkedWorker {
        pid: capture_pid,
        name: "capture",
    };

    // Clone the config for the crypto worker's closure (it needs a
    // static copy because it's captured by a closure that crosses the
    // fork boundary).
    let crypto_config = config.clone();

    let crypto_pid = unsafe { fork() }.map_err(|source| {
        DaemonError::from(PrivsepError::Syscall {
            syscall: "fork",
            source,
        })
    })?;
    match crypto_pid {
        ForkResult::Child => {
            // In crypto worker: we need crypto_reader and crypto_writer.
            // Close parent_reader.
            drop(parent_reader);
            let local_shutdown = ShutdownSignal::new();
            if let Err(e) = local_shutdown.install_handlers() {
                eprintln!("crypto worker: install_handlers failed: {e}");
                std::process::exit(1);
            }
            // Apply Landlock + seccomp sandbox AFTER signal handlers
            // are in place but BEFORE entering the worker loop. The
            // crypto worker is the most security-critical process in
            // fwknox: it processes untrusted internet input from the
            // capture worker, decrypts it, and only sends the result
            // to the parent if it passes every validation step. Any
            // bug in fwknox-proto's parser would otherwise be a
            // remote attack surface; the sandbox makes that surface
            // moot.
            if let Err(e) = fwknox_sandbox::apply_worker_sandbox("crypto") {
                eprintln!("crypto worker: apply_worker_sandbox failed: {e}");
                std::process::exit(1);
            }
            let validate = move |msg| validate_capture_msg(msg, &crypto_config);
            let result = run_crypto_worker(&crypto_reader, &crypto_writer, validate, || {
                local_shutdown.is_shutdown()
            });
            if let Err(e) = result {
                eprintln!("crypto worker: {e}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            debug!(pid = child.as_raw(), "forked crypto worker");
            let crypto_handle = ForkedWorker {
                pid: child,
                name: "crypto",
            };
            // Parent doesn't need these any more.
            drop(crypto_reader);
            drop(crypto_writer);
            run_parent_loop(
                config,
                firewall,
                replay,
                shutdown,
                &parent_reader,
                &capture_handle,
                &crypto_handle,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_parent_loop(
    config: &DaemonConfig,
    firewall: &mut dyn FirewallBackend,
    replay: &ReplayCache,
    shutdown: &ShutdownSignal,
    parent_reader: &UnixDatagram,
    capture_handle: &ForkedWorker,
    crypto_handle: &ForkedWorker,
) -> Result<(), DaemonError> {
    parent_reader
        .set_read_timeout(Some(PARENT_POLL_INTERVAL))
        .map_err(|e| DaemonError::from(PrivsepError::Io(e)))?;

    // Install a SIGCHLD handler that flips our shutdown flag, so the
    // parent fails closed when either worker dies. systemd's
    // Restart=on-failure will bring us back fresh.
    if let Err(e) = signal_hook::flag::register(
        signal_hook::consts::SIGCHLD,
        std::sync::Arc::clone(shutdown.flag_arc()),
    ) {
        warn!(error = %e, "failed to install SIGCHLD handler; dead workers will not be detected");
    }

    if let Err(e) = fwknox_sandbox::notify::ready() {
        warn!(error = %e, "sd_notify(READY=1) failed");
    }

    info!("parent: entering main loop");

    let mut tick: u64 = 0;
    while !shutdown.is_shutdown() {
        match recv_msg::<CryptoMsg>(parent_reader) {
            Ok(msg) => handle_crypto_msg(msg, config, replay, firewall),
            Err(PrivsepError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Tick timeout: fall through to the shutdown / prune check.
            }
            Err(e) => {
                warn!(error = %e, "recv from crypto worker failed");
            }
        }
        let _ = fwknox_sandbox::notify::watchdog();
        tick = tick.wrapping_add(1);
        if tick.is_multiple_of(crate::run::PRUNE_EVERY_TICKS) {
            let pruned = replay.prune_older_than(config.replay.max_age);
            if pruned > 0 {
                debug!(pruned, "pruned expired replay cache entries");
            }
        }
    }

    info!(
        shutdown = shutdown.is_shutdown(),
        "parent: shutting down workers"
    );
    let _ = fwknox_sandbox::notify::stopping();

    if let Err(e) = capture_handle.terminate_and_wait() {
        warn!(error = %e, "capture worker reap failed");
    }
    if let Err(e) = crypto_handle.terminate_and_wait() {
        warn!(error = %e, "crypto worker reap failed");
    }

    if let Err(e) = firewall.flush() {
        error!(error = %e, "firewall flush failed during shutdown");
    }
    if let Err(e) = replay.save_to_file(&config.replay.cache_path) {
        warn!(error = %e, "replay cache save failed during shutdown");
    }
    Ok(())
}

fn handle_crypto_msg(
    msg: CryptoMsg,
    config: &DaemonConfig,
    replay: &ReplayCache,
    firewall: &mut dyn FirewallBackend,
) {
    match msg {
        CryptoMsg::NoMatch { source_ip } => {
            debug!(source = %source_ip, "parent: no-match packet");
        }
        CryptoMsg::Rejected { source_ip, reason } => {
            warn!(source = %source_ip, reason = %reason, "parent: rejected packet");
        }
        CryptoMsg::ValidRequest {
            stanza_name,
            source_ip,
            payload,
        } => {
            // Replay check happens in the parent.
            if !replay.check_and_insert(payload.nonce) {
                warn!(
                    stanza = %stanza_name,
                    source = %source_ip,
                    "parent: replay detected"
                );
                return;
            }

            let SpaMessage::Access {
                source_ip: payload_src,
                ports,
            } = &payload.message
            else {
                warn!(
                    stanza = %stanza_name,
                    "parent: unsupported message variant in ValidRequest"
                );
                return;
            };

            let stanza = config.access.iter().find(|s| s.name == stanza_name);
            let Some(stanza) = stanza else {
                error!(stanza = %stanza_name, "parent: stanza name not found in config");
                return;
            };

            let timeout = stanza
                .fw_timeout
                .unwrap_or(config.daemon.default_fw_timeout);
            let timeout = timeout.min(config.daemon.max_fw_timeout);

            let rule = AccessRule {
                source_ip: *payload_src,
                ports: ports.clone(),
                timeout,
                comment: format!("fwknox:{}:{}", payload.username, payload.timestamp),
            };

            match firewall.open_access(&rule) {
                Ok(_handle) => {
                    info!(
                        stanza = %stanza_name,
                        source = %source_ip,
                        "parent: rule installed"
                    );
                }
                Err(e) => {
                    error!(error = %e, "parent: firewall.open_access failed");
                }
            }
        }
    }
}
