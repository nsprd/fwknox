// SPDX-License-Identifier: AGPL-3.0-or-later

//! The fwknox daemon main loop.

use std::time::Duration;

use fwknox_capture::CaptureBackend;
use fwknox_config::DaemonConfig;
use fwknox_firewall::FirewallBackend;
use fwknox_replay::ReplayCache;
use tracing::{debug, error, info, warn};

use crate::{
    error::DaemonError,
    pipeline::{process_packet, ProcessResult},
    shutdown::ShutdownSignal,
};

/// How often the main loop wakes up to check the shutdown flag.
pub(crate) const LOOP_TICK: Duration = Duration::from_millis(500);

/// How often (in loop ticks) the main loop prunes expired entries from
/// the replay cache.
pub(crate) const PRUNE_EVERY_TICKS: u64 = 600; // ~5 minutes at 500 ms ticks

/// Run the daemon main loop until `shutdown` is tripped.
///
/// This function is generic over the capture and firewall backends via
/// `&dyn` so unit tests can drive it with `MockBackend`.
///
/// On entry, the firewall backend is initialised. On exit (whether via
/// shutdown signal or fatal error), the firewall is flushed and the
/// replay cache is saved to disk.
pub fn run(
    config: &DaemonConfig,
    capture: &dyn CaptureBackend,
    firewall: &mut dyn FirewallBackend,
    replay: &ReplayCache,
    shutdown: &ShutdownSignal,
) -> Result<(), DaemonError> {
    info!(
        listen_addr = %config.daemon.listen_addr,
        listen_port = config.daemon.listen_port,
        "fwknox daemon starting"
    );
    firewall.init()?;

    let mut tick: u64 = 0;
    let result = loop {
        if shutdown.is_shutdown() {
            info!("shutdown signal received");
            break Ok(());
        }
        match capture.recv_timeout(LOOP_TICK) {
            Ok(None) => {} // tick timeout — fall through to pruning + loop
            Ok(Some(pkt)) => {
                handle_packet(&pkt, config, replay, &*firewall);
            }
            Err(e) => {
                warn!(error = %e, "capture recv failed; continuing");
            }
        }
        tick = tick.wrapping_add(1);
        if tick.is_multiple_of(PRUNE_EVERY_TICKS) {
            let pruned = replay.prune_older_than(config.replay.max_age);
            if pruned > 0 {
                debug!(pruned, "pruned expired replay cache entries");
            }
        }
    };

    info!("fwknox daemon shutting down");
    if let Err(e) = firewall.flush() {
        error!(error = %e, "firewall flush failed during shutdown");
    }
    if let Err(e) = replay.save_to_file(&config.replay.cache_path) {
        warn!(error = %e, "replay cache save failed during shutdown");
    }
    result
}

fn handle_packet(
    pkt: &fwknox_capture::CapturedPacket,
    config: &DaemonConfig,
    replay: &ReplayCache,
    firewall: &dyn FirewallBackend,
) {
    match process_packet(pkt, config, replay, firewall) {
        Ok(ProcessResult::Installed { stanza_name, .. }) => {
            info!(
                stanza = %stanza_name,
                source = %pkt.source_ip,
                "rule installed"
            );
        }
        Ok(ProcessResult::Replay { stanza_name }) => {
            warn!(
                stanza = %stanza_name,
                source = %pkt.source_ip,
                "replay detected"
            );
        }
        Ok(ProcessResult::NoMatch) => {
            debug!(source = %pkt.source_ip, "no stanza matched (dropped)");
        }
        Ok(ProcessResult::Rejected {
            stanza_name,
            reason,
        }) => {
            warn!(
                stanza = %stanza_name,
                source = %pkt.source_ip,
                reason = %reason,
                "packet rejected"
            );
        }
        Err(e) => {
            error!(
                source = %pkt.source_ip,
                error = %e,
                "firewall backend failure during packet processing"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Mutex,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use fwknox_capture::{CaptureError, CapturedPacket};
    use fwknox_config::load_daemon_config;
    use fwknox_firewall::MockBackend;
    use fwknox_proto::{build_packet, PortProto, Protocol, SpaMessage, SpaPayload};

    use super::*;

    /// In-memory capture that hands out a queue of pre-built packets.
    #[derive(Debug)]
    struct ScriptedCapture {
        queue: Mutex<Vec<CapturedPacket>>,
    }

    impl ScriptedCapture {
        fn new(packets: Vec<CapturedPacket>) -> Self {
            Self {
                queue: Mutex::new(packets.into_iter().rev().collect()),
            }
        }
    }

    impl CaptureBackend for ScriptedCapture {
        fn recv(&self) -> Result<CapturedPacket, CaptureError> {
            // Not used in these tests — only recv_timeout matters.
            unreachable!()
        }

        fn recv_timeout(&self, _timeout: Duration) -> Result<Option<CapturedPacket>, CaptureError> {
            Ok(self.queue.lock().unwrap().pop())
        }
    }

    #[allow(clippy::cast_possible_wrap)]
    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn write_test_config(dir: &std::path::Path, master_key: &[u8]) -> std::path::PathBuf {
        let path = dir.join("fwknoxd.toml");
        let body = format!(
            r#"
[daemon]
[replay]
cache_path = "{cache}"

[[access]]
name = "ssh"
source = ["127.0.0.1/32"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
require_source_match = true
"#,
            cache = dir.join("replay.cache").display(),
            k = B64.encode(master_key),
        );
        std::fs::write(&path, body).unwrap();
        path
    }

    fn payload(nonce: [u8; 16]) -> SpaPayload {
        SpaPayload {
            nonce,
            timestamp: now_unix(),
            username: "alice".into(),
            message: SpaMessage::Access {
                source_ip: "127.0.0.1".parse().unwrap(),
                ports: vec![PortProto::new(Protocol::Tcp, 22)],
            },
            client_timeout: Some(60),
        }
    }

    fn captured(data: Vec<u8>) -> CapturedPacket {
        CapturedPacket {
            source_ip: "127.0.0.1".parse().unwrap(),
            data,
        }
    }

    #[test]
    fn run_processes_one_packet_then_shuts_down() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();

        let wire = build_packet(&payload([1; 16]), &key).unwrap();
        let capture = ScriptedCapture::new(vec![captured(wire)]);
        let mut firewall = MockBackend::new();
        let replay = ReplayCache::new();
        let shutdown = ShutdownSignal::new();

        // Trigger shutdown after a moment so the main loop has time to
        // process the queued packet and then exit.
        let trigger = shutdown.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            trigger.trigger();
        });

        run(&cfg, &capture, &mut firewall, &replay, &shutdown).unwrap();

        // After run() returns, the firewall has been flushed (so the
        // mock's installed_rules() reports empty), but the rule was
        // installed during the loop. To assert installation happened,
        // check that the replay cache picked up the nonce.
        assert_eq!(replay.len(), 1);
    }

    #[test]
    fn run_with_no_packets_just_idles_until_shutdown() {
        let key = [0x42u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_daemon_config(write_test_config(dir.path(), &key)).unwrap();

        let capture = ScriptedCapture::new(vec![]);
        let mut firewall = MockBackend::new();
        let replay = ReplayCache::new();
        let shutdown = ShutdownSignal::new();

        let trigger = shutdown.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            trigger.trigger();
        });

        run(&cfg, &capture, &mut firewall, &replay, &shutdown).unwrap();
        assert_eq!(replay.len(), 0);
    }
}
