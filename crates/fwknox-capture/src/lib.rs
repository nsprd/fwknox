// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-capture
//!
//! Packet capture abstraction for the fwknox daemon. Phase 2 ships only
//! the [`UdpCapture`] backend (a plain `UdpSocket` listener); pcap
//! support is deferred to a later phase.

mod backend;
mod error;
mod packet;
mod udp;

pub use backend::CaptureBackend;
pub use error::CaptureError;
pub use packet::CapturedPacket;
pub use udp::{UdpCapture, MAX_DATAGRAM_LEN};
