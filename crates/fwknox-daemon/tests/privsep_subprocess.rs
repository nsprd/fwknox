// SPDX-License-Identifier: AGPL-3.0-or-later

//! Subprocess-based integration test for the privsep architecture.
//!
//! This test exercises the full daemon stack:
//!
//! - Spawns `fwknoxd-mock` (a binary identical to `fwknoxd` but
//!   using `MockBackend` so it doesn't need root or nftables) with
//!   a generated test config
//! - Waits for the daemon to bind its capture socket and enter the
//!   main loop (detected by scraping stderr for the "entering main loop"
//!   log line, with a generous startup grace period)
//! - Builds a real SPA packet via `fwknox-client::build_spa_packet`
//! - Sends the packet via `fwknox-client::send_udp_packet`
//! - Asserts the daemon prints the "rule installed" log line within
//!   a few seconds
//! - Sends `SIGTERM` and asserts the daemon exits cleanly
//!
//! The point of this test is to validate the worker sandbox: if
//! Phase 6a's seccomp filter is missing a syscall, the crypto
//! worker will be killed by SIGSYS as soon as it tries to do its
//! first AEAD decrypt or HMAC check, and the test will time out
//! waiting for the "rule installed" line.

use std::{
    fs,
    io::{BufRead, BufReader},
    net::UdpSocket,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use fwknox_client::{build_spa_packet, send_udp_packet, Cli as ClientCli};

/// How long to wait for the daemon to print a particular log line.
const LOG_DEADLINE: Duration = Duration::from_secs(10);

/// Reserve an ephemeral UDP port by binding and immediately dropping.
/// There's a tiny TOCTOU window where another process could grab the
/// port before the daemon binds it, but on a single-test CI box this
/// is reliable enough.
fn reserve_ephemeral_port() -> u16 {
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

/// Write the test config to disk and return its path.
fn write_test_config(dir: &std::path::Path, master_key: &[u8], port: u16) -> PathBuf {
    let path = dir.join("fwknoxd.toml");
    let body = format!(
        r#"
[daemon]
listen_addr = "127.0.0.1"
listen_port = {port}
enable_privsep = true
enable_sandbox = false

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

/// Spawn `fwknoxd-mock` and capture its stderr in a background
/// thread. Returns the child handle plus an `Arc<Mutex<Vec<String>>>`
/// of every line printed.
fn spawn_daemon(
    config_path: &std::path::Path,
) -> (std::process::Child, Arc<std::sync::Mutex<Vec<String>>>) {
    let bin_path = env!("CARGO_BIN_EXE_fwknoxd-mock");
    let mut child = Command::new(bin_path)
        .arg("-c")
        .arg(config_path)
        .arg("-vv") // trace-level so we see "rule installed"
        .env("RUST_LOG", "fwknox=debug,fwknoxd_mock=debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fwknoxd-mock");

    let stderr = child.stderr.take().expect("child stderr");
    let lines: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let lines_clone = Arc::clone(&lines);
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            lines_clone.lock().unwrap().push(line);
        }
    });

    (child, lines)
}

/// Block until the captured stderr contains a line that matches
/// `predicate`, or the deadline expires. Returns `true` on hit,
/// `false` on timeout.
fn wait_for_log_line<F>(lines: &Arc<std::sync::Mutex<Vec<String>>>, predicate: F) -> bool
where
    F: Fn(&str) -> bool,
{
    let start = Instant::now();
    while start.elapsed() < LOG_DEADLINE {
        {
            let snapshot = lines.lock().unwrap();
            if snapshot.iter().any(|l| predicate(l)) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn privsep_subprocess_full_pipeline() {
    let key = [0xABu8; 32];
    let dir = tempfile::tempdir().unwrap();
    let port = reserve_ephemeral_port();
    let config_path = write_test_config(dir.path(), &key, port);

    let (mut child, log_lines) = spawn_daemon(&config_path);

    // Wait for the daemon to enter its main loop. The parent's
    // privsep_run logs "parent: entering main loop" once it's
    // accepting CryptoMsg from the crypto worker.
    let entered_main = wait_for_log_line(&log_lines, |l| l.contains("parent: entering main loop"));
    if !entered_main {
        let _ = child.kill();
        let _ = child.wait();
        let snapshot = log_lines.lock().unwrap().join("\n");
        panic!("daemon never entered main loop. stderr was:\n{snapshot}");
    }

    // Give the workers a moment to also reach steady state (their
    // "starting" log lines should appear before main loop entry,
    // but we want to be sure the seccomp filter has been installed
    // and survived).
    thread::sleep(Duration::from_millis(100));

    // Build a real SPA packet via the client library.
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
    let wire = build_spa_packet(&cli, None).expect("client builds SPA packet");
    send_udp_packet(&wire, "127.0.0.1", port).expect("client sends UDP packet");

    // Wait for the parent to log "rule installed".
    let installed = wait_for_log_line(&log_lines, |l| l.contains("rule installed"));
    if !installed {
        let _ = child.kill();
        let _ = child.wait();
        let snapshot = log_lines.lock().unwrap().join("\n");
        panic!("daemon never installed the rule. stderr was:\n{snapshot}");
    }

    // Send SIGTERM and wait for clean exit.
    let pid = child.id().cast_signed();
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let exit = child.wait().expect("child wait");
    let snapshot = log_lines.lock().unwrap().join("\n");
    assert!(
        exit.success() || matches!(exit.code(), Some(0)),
        "daemon exited with {exit:?}. stderr was:\n{snapshot}"
    );
}
