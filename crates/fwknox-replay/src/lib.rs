// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-replay
//!
//! In-memory + file-backed replay-detection cache for the fwknox daemon.

mod cache;
mod error;
mod persist;

pub use cache::{Nonce, ReplayCache, DEFAULT_MAX_ENTRIES};
pub use error::ReplayError;
