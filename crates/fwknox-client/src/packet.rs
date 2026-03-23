// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build an SPA packet from CLI args + optional client config.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fwknox_config::{parse_port_proto, ServerEntry};
use fwknox_proto::{build_packet, PortProto, SpaMessage, SpaPayload};
use ring::rand::{SecureRandom, SystemRandom};

use crate::cli::Cli;
use crate::error::ClientError;

/// Build the SPA packet wire bytes from CLI args + an optional `ServerEntry`.
///
/// Resolution order:
///
/// - If `--master-key-base64` is set, use it; otherwise fall back to
///   `server.master_key_base64`.
/// - If `--access` is set, parse it; otherwise use `server.access`.
/// - If `--source-ip` is set, use it; otherwise use the local loopback
///   address (Phase 3 doesn't do `--resolve-ip` HTTPS resolution).
/// - If `--username` is set, use it; otherwise read `$USER` (or default
///   to `"fwknox"` if `$USER` is unset).
pub fn build_spa_packet(
    cli: &Cli,
    server: Option<&ServerEntry>,
) -> Result<Vec<u8>, ClientError> {
    let master_key = resolve_master_key(cli, server)?;
    let ports = resolve_ports(cli, server)?;
    let source_ip = resolve_source_ip(cli)?;
    let username = resolve_username(cli);
    let timestamp = current_unix();
    let nonce = random_nonce()?;
    let client_timeout = cli.timeout.and_then(|t| u32::try_from(t).ok());

    let payload = SpaPayload {
        nonce,
        timestamp,
        username,
        message: SpaMessage::Access {
            source_ip,
            ports,
        },
        client_timeout,
    };

    let wire = build_packet(&payload, &master_key)?;
    Ok(wire)
}

fn resolve_master_key(
    cli: &Cli,
    server: Option<&ServerEntry>,
) -> Result<[u8; 32], ClientError> {
    if let Some(b64) = &cli.master_key_base64 {
        return decode_master_key(b64);
    }
    if let Some(s) = server {
        return Ok(*s.master_key_base64.as_bytes());
    }
    Err(ClientError::MissingArgument(
        "master_key (-k or via -n / --name)",
    ))
}

fn decode_master_key(b64: &str) -> Result<[u8; 32], ClientError> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| ClientError::InvalidArgument {
            field: "master-key-base64",
            reason: e.to_string(),
        })?;
    if bytes.len() != 32 {
        return Err(ClientError::InvalidArgument {
            field: "master-key-base64",
            reason: format!("expected 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_ports(
    cli: &Cli,
    server: Option<&ServerEntry>,
) -> Result<Vec<PortProto>, ClientError> {
    if let Some(s) = &cli.access {
        return parse_access_string(s);
    }
    if let Some(server) = server {
        return Ok(server.access.0.clone());
    }
    Err(ClientError::MissingArgument(
        "access (-A or via -n / --name)",
    ))
}

fn parse_access_string(s: &str) -> Result<Vec<PortProto>, ClientError> {
    let mut out = Vec::new();
    for token in s.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let pp = parse_port_proto(token).map_err(|e| ClientError::InvalidArgument {
            field: "access",
            reason: e.to_string(),
        })?;
        out.push(pp);
    }
    if out.is_empty() {
        return Err(ClientError::InvalidArgument {
            field: "access",
            reason: "empty list".into(),
        });
    }
    Ok(out)
}

fn resolve_source_ip(cli: &Cli) -> Result<IpAddr, ClientError> {
    if let Some(s) = &cli.source_ip {
        return s.parse().map_err(|e: std::net::AddrParseError| {
            ClientError::InvalidArgument {
                field: "source-ip",
                reason: e.to_string(),
            }
        });
    }
    // Phase 3 default: assume the user is on the same host or behind
    // a NAT that exposes 127.0.0.1. Phase 4 will add --resolve-ip.
    Ok("127.0.0.1".parse().unwrap())
}

fn resolve_username(cli: &Cli) -> String {
    if let Some(u) = &cli.username {
        return u.clone();
    }
    std::env::var("USER").unwrap_or_else(|_| "fwknox".into())
}

#[allow(clippy::cast_possible_wrap)]
fn current_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as i64
}

fn random_nonce() -> Result<[u8; 16], ClientError> {
    let rng = SystemRandom::new();
    let mut out = [0u8; 16];
    rng.fill(&mut out).map_err(|_| ClientError::InvalidArgument {
        field: "csprng",
        reason: "system random number generator failed".into(),
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use clap::Parser;
    use fwknox_proto::{parse_packet, Protocol};

    fn cli_with_inline_args() -> Cli {
        Cli::parse_from([
            "fwknox",
            "--destination", "127.0.0.1",
            "--access", "tcp/22",
            "--master-key-base64", &B64.encode([0x42u8; 32]),
        ])
    }

    #[test]
    fn build_packet_from_inline_cli_args() {
        let cli = cli_with_inline_args();
        let wire = build_spa_packet(&cli, None).unwrap();
        // The packet must be parseable by the protocol crate using the
        // same key, and yield an Access message with tcp/22.
        let payload = parse_packet(&wire, &[0x42u8; 32]).unwrap();
        match payload.message {
            SpaMessage::Access { ports, .. } => {
                assert_eq!(ports, vec![PortProto::new(Protocol::Tcp, 22)]);
            }
            other => panic!("expected Access, got {other:?}"),
        }
    }

    #[test]
    fn missing_master_key_returns_missing_argument() {
        let cli = Cli::parse_from(["fwknox", "--access", "tcp/22"]);
        let err = build_spa_packet(&cli, None).unwrap_err();
        assert!(matches!(err, ClientError::MissingArgument(_)));
    }

    #[test]
    fn missing_access_returns_missing_argument() {
        let cli = Cli::parse_from([
            "fwknox",
            "--master-key-base64", &B64.encode([0u8; 32]),
        ]);
        let err = build_spa_packet(&cli, None).unwrap_err();
        assert!(matches!(err, ClientError::MissingArgument(_)));
    }

    #[test]
    fn invalid_master_key_length_is_rejected() {
        let cli = Cli::parse_from([
            "fwknox",
            "--access", "tcp/22",
            "--master-key-base64", &B64.encode([0u8; 16]), // wrong length
        ]);
        let err = build_spa_packet(&cli, None).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument { .. }));
    }

    #[test]
    fn parse_access_handles_multiple_ports() {
        let parsed = parse_access_string("tcp/22, udp/53,tcp/443").unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn parse_access_rejects_empty_string() {
        let err = parse_access_string("").unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument { .. }));
    }
}
