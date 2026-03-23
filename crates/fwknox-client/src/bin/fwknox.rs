// SPDX-License-Identifier: AGPL-3.0-or-later

//! `fwknox` client binary entrypoint.

use std::process::ExitCode;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use fwknox_client::{
    build_spa_packet, generate_master_key_base64, send_udp_packet, Cli, ClientError,
};
use fwknox_config::{load_client_config, ServerEntry};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match real_main(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "fwknox failed");
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
        .unwrap_or_else(|_| EnvFilter::new(format!("fwknox={level}")));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn real_main(cli: &Cli) -> Result<(), ClientError> {
    if cli.generate_key {
        let key = generate_master_key_base64()?;
        println!("{key}");
        return Ok(());
    }

    let server = load_server_entry(cli)?;
    let destination = resolve_destination(cli, server.as_ref())?;
    let port = resolve_port(cli, server.as_ref());

    let wire = build_spa_packet(cli, server.as_ref())?;

    if cli.test {
        println!("{}", B64.encode(&wire));
        info!(bytes = wire.len(), "test mode: packet built but not sent");
        return Ok(());
    }

    info!(
        destination = %destination,
        port,
        bytes = wire.len(),
        "sending SPA packet"
    );
    send_udp_packet(&wire, &destination, port)?;
    info!("packet sent");
    Ok(())
}

fn load_server_entry(cli: &Cli) -> Result<Option<ServerEntry>, ClientError> {
    let Some(name) = &cli.name else {
        return Ok(None);
    };
    let path = cli
        .config
        .clone()
        .unwrap_or_else(default_client_config_path);
    let cfg = load_client_config(&path)?;
    cfg.find_server(name)
        .cloned()
        .map(Some)
        .ok_or_else(|| ClientError::UnknownServer(name.clone()))
}

fn default_client_config_path() -> std::path::PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = std::path::PathBuf::from(home);
        p.push(".config/fwknox/fwknox.toml");
        p
    } else {
        std::path::PathBuf::from("fwknox.toml")
    }
}

fn resolve_destination(cli: &Cli, server: Option<&ServerEntry>) -> Result<String, ClientError> {
    if let Some(d) = &cli.destination {
        return Ok(d.clone());
    }
    if let Some(s) = server {
        return Ok(s.destination.clone());
    }
    Err(ClientError::MissingArgument(
        "destination (-D or via -n / --name)",
    ))
}

fn resolve_port(cli: &Cli, server: Option<&ServerEntry>) -> u16 {
    // Clap default is 62201. If the user passed an explicit port that
    // matches the default, that's fine; if a server entry exists, prefer
    // its port unless the CLI overrode it.
    if cli.port != 62201 {
        return cli.port;
    }
    if let Some(s) = server {
        return s.port;
    }
    cli.port
}
