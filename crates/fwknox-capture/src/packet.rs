// SPDX-License-Identifier: AGPL-3.0-or-later

//! `CapturedPacket` — a single packet handed up by a capture backend.

use std::net::IpAddr;

/// A single packet received by a capture backend.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// IP address of the sender.
    pub source_ip: IpAddr,
    /// Raw payload bytes (for UDP, the datagram body).
    pub data: Vec<u8>,
}
