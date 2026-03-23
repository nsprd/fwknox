// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test that runs the daemon library against a client-built
//! SPA packet over real loopback UDP.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use fwknox_capture::UdpCapture;
use fwknox_client::{build_spa_packet, send_udp_packet, Cli as ClientCli};
use fwknox_config::load_daemon_config;
use fwknox_daemon::{run, ShutdownSignal};
use fwknox_firewall::{AccessRule, FirewallBackend, FirewallError, MockBackend, RuleHandle};
use fwknox_replay::ReplayCache;

/// A `FirewallBackend` wrapper that delegates to an inner `MockBackend`
/// while also recording every installed rule into a separate
/// "permanent" log so that we can observe what was installed even
/// after shutdown calls `flush()` on the inner backend.
#[derive(Debug, Default)]
struct RecordingFirewall {
    inner: MockBackend,
    installed_log: Arc<Mutex<Vec<AccessRule>>>,
}

impl RecordingFirewall {
    fn new() -> Self {
        Self::default()
    }
    fn log_handle(&self) -> Arc<Mutex<Vec<AccessRule>>> {
        Arc::clone(&self.installed_log)
    }
}

impl FirewallBackend for RecordingFirewall {
    fn init(&mut self) -> Result<(), FirewallError> {
        self.inner.init()
    }
    fn open_access(&self, rule: &AccessRule) -> Result<RuleHandle, FirewallError> {
        let handle = self.inner.open_access(rule)?;
        self.installed_log.lock().unwrap().push(rule.clone());
        Ok(handle)
    }
    fn remove_rule(&self, handle: &RuleHandle) -> Result<(), FirewallError> {
        self.inner.remove_rule(handle)
    }
    fn flush(&mut self) -> Result<(), FirewallError> {
        self.inner.flush()
    }
}

fn write_test_config(dir: &std::path::Path, master_key: &[u8], port: u16) -> std::path::PathBuf {
    let path = dir.join("fwknoxd.toml");
    let body = format!(
        r#"
[daemon]
listen_addr = "127.0.0.1"
listen_port = {port}

[replay]
cache_path = "{cache}"

[[access]]
name = "ssh"
source = ["127.0.0.1/32"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
require_source_match = true
"#,
        port = port,
        cache = dir.join("replay.cache").display(),
        k = B64.encode(master_key),
    );
    fs::write(&path, body).unwrap();
    path
}

#[test]
fn client_sends_packet_daemon_installs_rule() {
    let key = [0x99u8; 32];
    let dir = tempfile::tempdir().unwrap();

    // Pre-bind a UDP socket on an ephemeral port so we know the port
    // before starting the daemon. We then drop it and re-bind from
    // inside UdpCapture::bind. There is a tiny TOCTOU window here
    // (another process could grab the port) but on a CI box running
    // a single test it is reliable.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let cfg_path = write_test_config(dir.path(), &key, port);
    let cfg = load_daemon_config(&cfg_path).unwrap();

    let capture =
        UdpCapture::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))).unwrap();
    let mut firewall = RecordingFirewall::new();
    let installed_log = firewall.log_handle();
    let replay = ReplayCache::new();
    let shutdown = ShutdownSignal::new();

    // Run the daemon in a worker thread.
    let cfg_for_thread = cfg.clone();
    let shutdown_for_thread = shutdown.clone();
    let daemon_thread = thread::spawn(move || {
        run(
            &cfg_for_thread,
            &capture,
            &mut firewall,
            &replay,
            &shutdown_for_thread,
        )
    });

    // Build a packet via the client library and send it.
    let cli = ClientCli::parse_from([
        "fwknox",
        "--destination",
        "127.0.0.1",
        "--source-ip",
        "127.0.0.1",
        "--access",
        "tcp/22",
        "--master-key-base64",
        &B64.encode(key),
    ]);
    // Allow the daemon a moment to enter its loop and bind.
    thread::sleep(Duration::from_millis(50));
    let wire = build_spa_packet(&cli, None).unwrap();
    send_udp_packet(&wire, "127.0.0.1", port).unwrap();

    // Wait for the daemon to process the packet.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if !installed_log.lock().unwrap().is_empty() {
            break;
        }
        if std::time::Instant::now() > deadline {
            shutdown.trigger();
            let _ = daemon_thread.join();
            panic!("daemon never recorded the installation");
        }
        thread::sleep(Duration::from_millis(20));
    }

    shutdown.trigger();
    let result = daemon_thread.join().unwrap();
    result.expect("daemon should exit cleanly");

    let installed = installed_log.lock().unwrap();
    assert_eq!(installed.len(), 1);
    let rule = &installed[0];
    assert_eq!(
        rule.source_ip,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(rule.ports.len(), 1);
}
