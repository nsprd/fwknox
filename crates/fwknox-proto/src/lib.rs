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

mod aead;
mod error;
mod header;
mod hmac;
mod kdf;
mod payload;
mod types;

pub use aead::{
    generate_nonce, open as aead_open, seal as aead_seal, KEY_LEN as AEAD_KEY_LEN, NONCE_LEN,
    TAG_LEN,
};
pub use error::ProtoError;
pub use header::{Flags, Header, HEADER_LEN, PROTO_VERSION};
pub use hmac::{sign as hmac_sign, verify as hmac_verify, HMAC_LEN};
pub use kdf::{DerivedKeys, SubKey, SUBKEY_LEN};
pub use payload::SpaPayload;
pub use types::{PortProto, Protocol, SpaMessage};
