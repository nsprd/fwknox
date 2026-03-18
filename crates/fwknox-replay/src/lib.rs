// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-replay
//!
//! In-memory + file-backed replay-detection cache for the fwknox daemon.
//!
//! Each entry is keyed by the SPA payload's 16-byte nonce. Insert returns
//! `true` for fresh nonces and `false` for replays. The cache periodically
//! prunes entries older than a configured maximum age and persists itself
//! to disk via atomic file replacement (write to temp + rename).

mod error;

pub use error::ReplayError;
