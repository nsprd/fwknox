// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-ratelimit
//!
//! Per-source UDP packet rate limiter for the fwknox daemon. Implements
//! a two-tier token-bucket scheme with hot-source promotion: recently
//! active sources get exact per-source accounting in an LRU-bounded
//! map, and all other traffic shares a single global fallback bucket.
//! Enforced in the capture path before any packet reaches the crypto
//! pipeline.

pub mod clock;
pub mod key;

pub use clock::{Clock, MockClock, SystemClock};
pub use key::SourceKey;
