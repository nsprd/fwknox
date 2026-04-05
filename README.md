# fwknox

**Single Packet Authorization (SPA) firewall daemon — a clean-room Rust port of [fwknop](https://github.com/mrash/fwknop).**

fwknox keeps network services invisible to port scanners and opens them only to clients that can prove knowledge of a shared secret — by sending a single authenticated, encrypted UDP packet. Once the packet is validated, the daemon installs a short-lived nftables rule that allows the sender's source IP to reach the protected port. No open port, no rule; no rule, no attack surface.

> [!WARNING]
> fwknox is pre-1.0 software. The wire format is stable within 0.x releases but may change before 1.0. There is **no wire compatibility with C fwknop** — this is a clean-break re-implementation.

## Table of contents

- [Why SPA](#why-spa)
- [Features](#features)
- [Threat model](#threat-model)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security hardening](#security-hardening)
- [Contributing](#contributing)
- [License](#license)

## Why SPA

Port knocking hides services but uses a fragile sequence of connection attempts. SPA solves the same problem with one cryptographically authenticated UDP packet. An attacker without the key sees an unresponsive host; an attacker with the key looks like any other user. SPA is *not* authentication for the protected service — it is a gate that decides whether the service is worth attacking at all.

## Features

- **Authenticated encryption.** AES-256-GCM + HMAC-SHA256, keys derived via HKDF-SHA256 from a single master key per access stanza.
- **Replay protection.** Packet HMACs are cached on disk (`replay.cache`) and pruned on a timer.
- **Clock-skew tolerant.** Packets carry a timestamp; old packets are rejected (`max_spa_packet_age`).
- **Three-process privilege separation.** Unauthenticated packets are parsed by a sandboxed worker; authenticated requests are processed by a second sandboxed worker; only the parent touches the firewall. See [Architecture](#architecture).
- **Sandboxed workers.** Both workers run under Landlock + seccomp-bpf. The seccomp filter allow-lists only the syscalls `libstd` needs for socket I/O.
- **nftables backend.** Typed JSON ruleset via the `nftables-rs` crate — no shell-out to `nft` from security-sensitive code paths.
- **systemd native.** `sd_notify` READY/WATCHDOG/STOPPING, plus full unit hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies`, capability bounding, runtime/state directories).
- **TOML config.** Human-editable, comments welcome, schema documented in this README.
- **AGPL-3.0.** See [License](#license).

## Threat model

fwknox is designed to resist the following adversaries:

| Adversary | Resistance | How |
|-----------|-----------|-----|
| Passive network observer | Packet contents opaque | AES-256-GCM ciphertext with random nonce |
| Active MITM | Packet integrity protected | Encrypt-then-MAC with HMAC-SHA256 over the full header + ciphertext |
| Replay attacker | One-shot packets | HMAC cached in the replay cache; duplicates dropped |
| Portscanner | Invisible host | No port open until a valid SPA packet is received |
| Timing attacker | Constant-time HMAC compare | `ring`'s HMAC verify |
| Local attacker on the daemon host | Worker compromise contained | Three-process privsep: crypto worker can only talk to the parent via a socketpair, cannot touch the firewall, cannot read the filesystem (Landlock empty policy), cannot call most syscalls (seccomp allow-list) |
| Compromised fwknox master key | **Full break** — attacker can open any port the stanza permits | You must rotate the key. There is no forward secrecy. |

fwknox does **not** defend against:
- Kernel exploits against nftables or the netlink socket
- Side channels in the firewall backend or libc
- Physical attacks on the daemon host
- DoS via packet floods (rate limiting is a future phase)

The master key is the crown jewel. Treat it like an SSH host key.

## Installation

### Arch Linux (AUR)

```bash
# Once the AUR package is published:
yay -S fwknox
```

Or build locally from `dist/PKGBUILD`:

```bash
cd dist && makepkg -si
```

### Docker

```bash
docker pull ghcr.io/nsprd/fwknox:latest     # once published
# Or build locally:
docker build -t fwknox:local .
```

### From source

```bash
git clone https://github.com/nsprd/fwknox.git
cd fwknox
cargo build --release --workspace --bins
sudo install -Dm755 target/release/fwknox  /usr/bin/fwknox
sudo install -Dm755 target/release/fwknoxd /usr/bin/fwknoxd
sudo install -Dm644 dist/fwknoxd.service   /etc/systemd/system/fwknoxd.service
sudo install -Dm640 config/fwknoxd.toml.example /etc/fwknox/fwknoxd.toml
```

Requires nightly Rust (pinned in `rust-toolchain.toml`) and nftables at runtime.

## Quickstart

1. **Generate a master key:**
   ```bash
   head -c 32 /dev/urandom | base64
   ```

2. **Write the daemon config.** Start from `config/fwknoxd.toml.example`, paste your master key into the `[[access]]` stanza's `master_key_base64` field, and save as `/etc/fwknox/fwknoxd.toml`.

3. **Start the daemon:**
   ```bash
   sudo systemctl enable --now fwknoxd
   sudo systemctl status fwknoxd
   ```

4. **From a client host, write `~/.config/fwknox/fwknox.toml`:**
   ```toml
   [defaults]
   transport = "udp"

   [[server]]
   name = "home"
   destination = "203.0.113.42"
   port = 62201
   access = ["tcp/22"]
   master_key_base64 = "<same key as server>"
   fw_timeout = "30s"
   ```

5. **Send a packet to open SSH:**
   ```bash
   fwknox -n home                       # use the "home" entry above
   ssh user@203.0.113.42
   ```

   Or, with everything on the command line (no config file):

   ```bash
   fwknox -D 203.0.113.42 \
          -A tcp/22 \
          -t 30 \
          -k "<your 32-byte base64 master key>"
   ```

   The rule self-expires after `fw_timeout` / `-t` seconds — established
   connections survive, but no new ones.

## Configuration

The daemon reads `/etc/fwknox/fwknoxd.toml` by default. See `config/fwknoxd.toml.example` for every field with comments. Key sections:

- `[daemon]` — listen address, firewall backend, timeouts, privsep/sandbox toggles.
- `[replay]` — replay cache location, pruning interval.
- `[[access]]` — one stanza per master key / source / port set. You can define many stanzas for different clients.

Field schemas are the source of truth: see `crates/fwknox-config/src/daemon.rs` and `crates/fwknox-config/src/client.rs`.

## Architecture

fwknox runs as three processes when `enable_privsep = true` (the default):

```
┌────────────────────────────────────────────────────────────┐
│ parent (root → CAP_NET_ADMIN)                              │
│  • binds UDP socket                                        │
│  • owns nftables netlink handle                            │
│  • receives crypto-worker decisions, installs rules        │
│  • reaps children on SIGCHLD, prunes replay cache          │
└──────┬─────────────────────────────────────────┬───────────┘
       │ socketpair(SOCK_DGRAM)                  │ socketpair(SOCK_DGRAM)
       │ CaptureMsg::Packet                      │ CryptoMsg::{Valid,Rejected,NoMatch}
       ▼                                         ▼
┌──────────────────────────┐        ┌───────────────────────────────┐
│ capture worker (nobody)  │        │ crypto worker (nobody)        │
│  • Landlock: no FS       │        │  • Landlock: no FS            │
│  • seccomp: read/write/  │        │  • seccomp: read/write/recv/  │
│    recv/send only        │        │    send only                  │
│  • reads UDP, forwards   │        │  • HKDF + HMAC verify + AEAD  │
│    opaque bytes          │        │    decrypt, timestamp check   │
└──────────────────────────┘        └───────────────────────────────┘
```

If `enable_privsep = false`, everything runs in a single process and the workers become function calls. Privsep is strongly recommended in production.

## Security hardening

The daemon layers multiple hardening mechanisms:

1. **systemd unit** — `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, `CapabilityBoundingSet=CAP_NET_ADMIN`.
2. **Capability drop** — the parent keeps only `CAP_NET_ADMIN`; the children drop everything.
3. **User/group drop** — both workers run as the `fwknox` user after fork.
4. **Landlock** — worker filesystem view is empty (`read_only = []`, `read_write = []`). The parent's Landlock policy is deferred to a future phase because `nftables-rs` spawns `nft` in one code path that Landlock would kill.
5. **seccomp-bpf** — worker syscall allow-list; any other syscall kills the process (`SECCOMP_RET_KILL_PROCESS`).

See `crates/fwknox-sandbox/` for the implementation.

## Contributing

- Nightly Rust only (enforced by `rust-toolchain.toml`).
- `cargo fmt` + `cargo clippy --workspace --all-targets -- -D warnings` on every PR.
- TDD: write the test first, watch it fail, then implement.
- Every source file carries the `SPDX-License-Identifier: AGPL-3.0-or-later` header.
- Issues and PRs welcome at [github.com/nsprd/fwknox](https://github.com/nsprd/fwknox).

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).

AGPL is an OSI-approved open-source license that lets the community freely use, study, modify, and contribute, while preventing enterprises from taking the code proprietary or offering it as a managed service without releasing their changes. For a security tool, these transparency requirements are appropriate.
