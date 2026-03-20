// SPDX-License-Identifier: AGPL-3.0-or-later

//! # fwknox-firewall
//!
//! Firewall backend abstraction for the fwknox daemon.
//!
//! This crate defines the [`FirewallBackend`] trait and ships two
//! implementations:
//!
//! - [`MockBackend`]: an in-memory implementation used by tests.
//! - [`NftablesBackend`]: a Linux nftables backend that uses the
//!   [`nftables`](https://docs.rs/nftables) Rust crate to construct
//!   typed rulesets and apply them via the kernel's netlink interface
//!   (the crate invokes `nft` internally as its transport but the API
//!   is fully strongly typed — no string interpolation, no command
//!   injection surface).

mod backend;
mod error;
mod mock;
mod nftables;
mod rule;

pub use backend::FirewallBackend;
pub use error::FirewallError;
pub use mock::MockBackend;
pub use nftables::{
    NftablesBackend, RulesetApplier, SystemApplier, CHAIN_NAME, SET_NAME, TABLE_NAME,
};
pub use rule::{AccessRule, RuleHandle};
