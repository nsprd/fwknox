// SPDX-License-Identifier: AGPL-3.0-or-later

//! IPC message types exchanged between the three fwknox processes.

use std::net::IpAddr;

use fwknox_proto::SpaPayload;
use serde::{Deserialize, Serialize};

/// Message sent from the capture worker to the crypto worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureMsg {
    /// A UDP datagram arrived on the capture socket.
    Packet {
        /// IP address the packet came from.
        source_ip: IpAddr,
        /// Raw datagram bytes.
        data: Vec<u8>,
    },
}

/// Message sent from the crypto worker to the parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CryptoMsg {
    /// The crypto worker authenticated and validated a packet. The
    /// parent must still run the replay check and install the firewall
    /// rule.
    ValidRequest {
        /// Name of the matching access stanza.
        stanza_name: String,
        /// IP address the packet arrived from.
        source_ip: IpAddr,
        /// Full decoded SPA payload.
        payload: SpaPayload,
    },
    /// The crypto worker authenticated a stanza but rejected the packet
    /// for policy reasons (timestamp, source mismatch, port outside
    /// `open_ports`, AEAD failure after HMAC match, etc).
    Rejected {
        /// IP address the packet arrived from.
        source_ip: IpAddr,
        /// Human-readable rejection reason.
        reason: String,
    },
    /// The crypto worker couldn't match any stanza (common noise case).
    NoMatch {
        /// IP address the packet arrived from.
        source_ip: IpAddr,
    },
}
