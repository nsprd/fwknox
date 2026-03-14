// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-proto
//!
//! SPA packet format, authenticated encryption, HMAC verification, and
//! encoding for the fwknox project. This crate has no I/O dependencies and
//! is the security-critical core of fwknox.
//!
//! ## Wire format
//!
//! ```text
//! [Header (4 bytes)] [GCM Nonce (12 bytes)] [Encrypted Payload + GCM Tag] [HMAC (32 bytes)]
//! ```

mod error;
mod payload;
mod types;

pub use error::ProtoError;
pub use payload::SpaPayload;
pub use types::{PortProto, Protocol, SpaMessage};
