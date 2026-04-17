// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-binary end-to-end test.
//!
//! Spawns the production `fwknoxd` binary against the live kernel and
//! shoots a SPA packet at it with the production `fwknox` client binary.
//! Verifies the rule actually lands in nftables.
//!
//! Requires:
//!
//! - root (to manipulate the inet fwknox table)
//! - `nft` binary on PATH (used by `NftablesBackend`'s applier)
//! - the two workspace binaries to have been built first — the CI job
//!   runs `cargo build --bin fwknoxd --bin fwknox` before this test.
//!
//! Gated behind `real-net`.

#![cfg(feature = "real-net")]

use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nftables::{
    helper::get_current_ruleset,
    schema::{NfListObject, NfObject},
};

const BIND_PORT_ENV: &str = "FWKNOX_TEST_BIND_PORT";

/// Resolve a workspace binary path. Tests in this crate can't use
/// `CARGO_BIN_EXE_<name>` for binaries in sibling crates, so we fall
/// back to `<workspace>/target/<profile>/<name>`. Honors
/// `CARGO_TARGET_DIR` if set.
fn workspace_bin(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // tests/integration → repo root
    let repo = manifest
        .ancestors()
        .nth(2)
        .expect("manifest has grandparent");
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo.join("target"), Into::into);
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    target.join(profile).join(name)
}

fn require_root_or_skip(test: &str) -> bool {
    // Safety: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        eprintln!("skipping {test}: needs root (uid={uid})");
        return false;
    }
    true
}

/// Clear any stale fwknox table from a prior run.
fn pre_clean() {
    use fwknox_firewall::{FirewallBackend, NftablesBackend};
    let mut b = NftablesBackend::new();
    let _ = b.flush();
}

/// Allocate an ephemeral UDP port by binding then releasing. TOCTOU
/// window is tolerable on a single-test CI runner.
fn pick_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

fn write_daemon_config(dir: &Path, key: &[u8], port: u16) -> PathBuf {
    let path = dir.join("fwknoxd.toml");
    let body = format!(
        r#"
[daemon]
listen_addr = "127.0.0.1"
listen_port = {port}
firewall_backend = "nftables"
enable_sandbox = false
enable_privsep = false
flush_rules_at_init = true
flush_rules_at_exit = true
default_fw_timeout = "30s"
max_fw_timeout = "5m"

[replay]
cache_path = "{cache}"

[rate_limit]
enabled = false

[[access]]
name = "ssh-real"
source = ["127.0.0.1/32"]
open_ports = ["tcp/22"]
master_key_base64 = "{k}"
require_source_match = true
"#,
        port = port,
        cache = dir.join("replay.cache").display(),
        k = B64.encode(key),
    );
    fs::write(&path, body).expect("write config");
    path
}

/// Count the number of set elements live in the fwknox allow set.
///
/// `nft list ruleset -j` reports elements nested inside the owning
/// `Set` object (`set.elem`); top-level `Element` objects only appear
/// on the add/delete write path. Walk sets and sum their `elem` len.
fn installed_element_count() -> usize {
    let rs = get_current_ruleset().expect("list ruleset");
    rs.objects
        .iter()
        .filter_map(|obj| match obj {
            NfObject::ListObject(NfListObject::Set(s)) if s.name == fwknox_firewall::SET_NAME => {
                Some(s.elem.as_ref().map_or(0, |e| e.len()))
            }
            _ => None,
        })
        .sum()
}

#[test]
fn fwknoxd_installs_nftables_rule_after_fwknox_client_sends_packet() {
    if !require_root_or_skip("fwknoxd_installs_nftables_rule_after_fwknox_client_sends_packet") {
        return;
    }

    let daemon = workspace_bin("fwknoxd");
    let client = workspace_bin("fwknox");
    assert!(
        daemon.exists(),
        "fwknoxd binary not found at {}. Run `cargo build --bin fwknoxd` first.",
        daemon.display()
    );
    assert!(
        client.exists(),
        "fwknox binary not found at {}. Run `cargo build --bin fwknox` first.",
        client.display()
    );

    pre_clean();

    let key = [0x5Au8; 32];
    let dir = tempfile::tempdir().expect("tempdir");
    let port = std::env::var(BIND_PORT_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(pick_udp_port);
    let cfg_path = write_daemon_config(dir.path(), &key, port);

    // Spawn the daemon. Inherit stderr so its tracing output lands in
    // the test log if something goes wrong.
    let mut daemon_proc = Command::new(&daemon)
        .arg("-c")
        .arg(&cfg_path)
        .arg("-v")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fwknoxd");

    // Tee daemon stderr into the test log via a worker thread. Keeps
    // the pipe drained so the daemon doesn't block on a full buffer.
    if let Some(stderr) = daemon_proc.stderr.take() {
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("fwknoxd: {line}");
            }
        });
    }

    // Wait for the daemon to bind. We retry a TCP-style probe by
    // sending a no-op UDP packet and checking the port is live via
    // `connect` + `write` on a transient socket. A simple sleep is
    // tolerable here since the daemon starts fast and we only need
    // coarse synchronization.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut listening = false;
    while Instant::now() < deadline {
        if std::net::UdpSocket::bind(format!("127.0.0.1:{port}")).is_err() {
            listening = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(listening, "daemon never bound port {port}");

    // Shoot the SPA packet with the client binary.
    let client_status = Command::new(&client)
        .arg("--destination")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--source-ip")
        .arg("127.0.0.1")
        .arg("--access")
        .arg("tcp/22")
        .arg("--master-key-base64")
        .arg(B64.encode(key))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn client");
    assert!(client_status.success(), "client exited nonzero");

    // Poll the kernel ruleset for up to 5s waiting for the rule to land.
    let rule_deadline = Instant::now() + Duration::from_secs(5);
    let mut installed = 0usize;
    while Instant::now() < rule_deadline {
        installed = installed_element_count();
        if installed > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Clean up the daemon before asserting so we always tear down.
    // SIGTERM gives the daemon a chance to run its shutdown path
    // (including flush_rules_at_exit).
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(daemon_proc.id().to_string())
        .status();
    let _ = daemon_proc.wait();
    pre_clean();

    assert_eq!(
        installed, 1,
        "expected exactly one set element after client packet, got {installed}"
    );
}
