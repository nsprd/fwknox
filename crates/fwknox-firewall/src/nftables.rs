// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nftables` backend for the fwknox daemon.
//!
//! This backend uses the [`nftables`](https://docs.rs/nftables) Rust
//! crate to construct strongly-typed `Nftables` rulesets and apply them
//! via the kernel's netlink interface (the crate uses `nft` internally
//! as its transport but the Rust API is fully strongly typed — there is
//! no string interpolation, no shell parsing, and no command-injection
//! surface).
//!
//! ## Layout
//!
//! The backend creates one inet table named `fwknox` containing one
//! ipv4 set and an `input` chain that accepts packets matching the set.
//! The conceptual nft equivalent is:
//!
//! ```text
//! table inet fwknox {
//!     set fwknox_allow_v4 {
//!         type ipv4_addr . inet_proto . inet_service
//!         flags timeout
//!     }
//!     chain input {
//!         type filter hook input priority 0; policy accept;
//!         ip saddr . meta l4proto . th dport @fwknox_allow_v4 accept
//!     }
//! }
//! ```
//!
//! Each call to [`FirewallBackend::open_access`] inserts an element into
//! `fwknox_allow_v4` with a per-element timeout. The kernel removes
//! elements automatically when their timeout expires, so the daemon
//! does not need to track or poll them.

use std::{borrow::Cow, collections::HashSet, sync::Mutex};

use nftables::{
    batch::Batch,
    expr::{Elem, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    helper,
    schema::{
        Chain, Element, NfListObject, Nftables, Rule, Set, SetFlag, SetType, SetTypeValue, Table,
    },
    stmt::{Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use tracing::debug;

use crate::{
    backend::FirewallBackend,
    error::FirewallError,
    rule::{AccessRule, RuleHandle},
};

/// Name of the inet table this backend manages.
pub const TABLE_NAME: &str = "fwknox";

/// Name of the timeout-aware set inside the table.
pub const SET_NAME: &str = "fwknox_allow_v4";

/// Name of the input chain that consults the set.
pub const CHAIN_NAME: &str = "input";

/// Trait abstracting "apply this `Nftables` ruleset". Production code
/// uses [`SystemApplier`] which delegates to
/// [`nftables::helper::apply_ruleset`]; tests inject a recording double.
pub trait RulesetApplier: Send + Sync + std::fmt::Debug {
    /// Apply a typed nftables ruleset to the kernel (or to a test sink).
    fn apply(&self, ruleset: &Nftables<'_>) -> Result<(), FirewallError>;
}

/// Production applier that calls `nftables::helper::apply_ruleset`.
#[derive(Debug, Default)]
pub struct SystemApplier;

impl RulesetApplier for SystemApplier {
    fn apply(&self, ruleset: &Nftables<'_>) -> Result<(), FirewallError> {
        helper::apply_ruleset(ruleset).map_err(|e| FirewallError::Backend(e.to_string()))
    }
}

/// nftables backend that builds typed `Nftables` rulesets and dispatches
/// them through a [`RulesetApplier`].
#[derive(Debug)]
pub struct NftablesBackend {
    applier: Box<dyn RulesetApplier>,
    state: Mutex<NftState>,
}

#[derive(Debug, Default)]
struct NftState {
    initialized: bool,
}

impl NftablesBackend {
    /// Construct a backend that uses the real system `nft` interface.
    #[must_use]
    pub fn new() -> Self {
        Self::with_applier(Box::new(SystemApplier))
    }

    /// Construct a backend with a custom ruleset applier (used by tests).
    #[must_use]
    pub fn with_applier(applier: Box<dyn RulesetApplier>) -> Self {
        Self {
            applier,
            state: Mutex::new(NftState::default()),
        }
    }

    fn assert_initialized(&self, op: &'static str) -> Result<(), FirewallError> {
        if !self.state.lock().expect("nft backend poisoned").initialized {
            return Err(FirewallError::InconsistentState(format!(
                "{op} called before init"
            )));
        }
        Ok(())
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallBackend for NftablesBackend {
    // The function body is long because the typed-builder API requires each
    // of the four nftables objects to be spelled out in full.
    #[allow(clippy::too_many_lines)]
    fn init(&mut self) -> Result<(), FirewallError> {
        debug!("initialising nftables backend");
        let mut batch = Batch::new();

        // 1. Create the inet table.
        batch.add(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(TABLE_NAME),
            handle: None,
        }));

        // 2. Create the timeout-aware set.
        let mut flags = HashSet::new();
        flags.insert(SetFlag::Timeout);
        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE_NAME),
            name: Cow::Borrowed(SET_NAME),
            handle: None,
            set_type: SetTypeValue::Concatenated(Cow::Owned(vec![
                SetType::Ipv4Addr,
                SetType::InetProto,
                SetType::InetService,
            ])),
            policy: None,
            flags: Some(flags),
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        })));

        // 3. Create the input chain.
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE_NAME),
            name: Cow::Borrowed(CHAIN_NAME),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(0),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // 4. Create the lookup rule that consults the set.
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE_NAME),
            chain: Cow::Borrowed(CHAIN_NAME),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Concat(vec![
                        Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("ip"),
                                field: Cow::Borrowed("saddr"),
                            },
                        ))),
                        Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::L4proto,
                        })),
                        Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("th"),
                                field: Cow::Borrowed("dport"),
                            },
                        ))),
                    ])),
                    right: Expression::String(Cow::Owned(format!("@{SET_NAME}"))),
                    op: Operator::IN,
                }),
                Statement::Accept(None),
            ]),
            handle: None,
            index: None,
            comment: None,
        }));

        let ruleset = batch.to_nftables();
        self.applier.apply(&ruleset)?;
        self.state.lock().expect("nft backend poisoned").initialized = true;
        Ok(())
    }

    fn open_access(&self, rule: &AccessRule) -> Result<RuleHandle, FirewallError> {
        self.assert_initialized("open_access")?;
        // Phase 2 only supports IPv4.
        let ipv4 = match rule.source_ip {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => {
                return Err(FirewallError::Unsupported(
                    "IPv6 source addresses (Phase 2 nftables backend is IPv4-only)",
                ));
            }
        };

        let timeout_secs = u32::try_from(rule.timeout.as_secs()).unwrap_or(u32::MAX);

        let mut batch = Batch::new();
        let mut handle_parts = Vec::with_capacity(rule.ports.len());
        for pp in &rule.ports {
            let proto_str = pp.proto.to_string();
            let elem_expr = Expression::Named(NamedExpression::Elem(Elem {
                val: Box::new(Expression::Named(NamedExpression::Concat(vec![
                    Expression::String(Cow::Owned(ipv4.to_string())),
                    Expression::String(Cow::Owned(proto_str.clone())),
                    Expression::Number(u32::from(pp.port)),
                ]))),
                timeout: Some(timeout_secs),
                expires: None,
                comment: None,
                counter: None,
            }));
            batch.add(NfListObject::Element(Element {
                family: NfFamily::INet,
                table: Cow::Borrowed(TABLE_NAME),
                name: Cow::Borrowed(SET_NAME),
                elem: Cow::Owned(vec![elem_expr]),
            }));
            handle_parts.push(format!("{ipv4}/{proto_str}/{}", pp.port));
        }

        let ruleset = batch.to_nftables();
        self.applier.apply(&ruleset)?;
        Ok(RuleHandle::new(handle_parts.join(",")))
    }

    fn remove_rule(&self, handle: &RuleHandle) -> Result<(), FirewallError> {
        self.assert_initialized("remove_rule")?;
        let mut batch = Batch::new();
        for entry in handle.as_str().split(',') {
            let parts: Vec<&str> = entry.split('/').collect();
            if parts.len() != 3 {
                return Err(FirewallError::RuleNotFound(handle.as_str().into()));
            }
            let port: u16 = parts[2]
                .parse()
                .map_err(|_| FirewallError::RuleNotFound(handle.as_str().into()))?;
            let elem_expr = Expression::Named(NamedExpression::Concat(vec![
                Expression::String(Cow::Owned(parts[0].to_string())),
                Expression::String(Cow::Owned(parts[1].to_string())),
                Expression::Number(u32::from(port)),
            ]));
            batch.delete(NfListObject::Element(Element {
                family: NfFamily::INet,
                table: Cow::Borrowed(TABLE_NAME),
                name: Cow::Borrowed(SET_NAME),
                elem: Cow::Owned(vec![elem_expr]),
            }));
        }
        let ruleset = batch.to_nftables();
        self.applier.apply(&ruleset)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), FirewallError> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(TABLE_NAME),
            handle: None,
        }));
        let ruleset = batch.to_nftables();
        // Ignore errors so flush is idempotent — a missing table on
        // shutdown is the common case.
        if let Err(e) = self.applier.apply(&ruleset) {
            debug!(error = %e, "flush ignored backend error (likely missing table)");
        }
        self.state.lock().expect("nft backend poisoned").initialized = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use fwknox_proto::{PortProto, Protocol};
    use nftables::schema::{NfCmd, NfObject};

    use super::*;

    /// Recording applier used by the unit tests. Captures every typed
    /// `Nftables` value submitted to `apply`. Optionally returns a
    /// canned error.
    #[derive(Debug, Default)]
    struct RecordingApplier {
        // We snapshot each call as a JSON string because Nftables<'_>
        // borrows from owned data and is awkward to clone-store directly.
        calls: Mutex<Vec<String>>,
        // Counts of object kinds per call so tests can assert without
        // depending on JSON formatting details.
        summaries: Mutex<Vec<CallSummary>>,
        fail_with: Mutex<Option<String>>,
    }

    #[derive(Debug, Default, Clone)]
    struct CallSummary {
        adds: Vec<&'static str>,
        deletes: Vec<&'static str>,
    }

    impl RecordingApplier {
        fn snapshot_summaries(&self) -> Vec<CallSummary> {
            self.summaries.lock().unwrap().clone()
        }
        fn snapshot_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn record(&self, ruleset: &Nftables<'_>) {
            let json = serde_json::to_string(ruleset).expect("ruleset serializes");
            self.calls.lock().unwrap().push(json);
            let mut summary = CallSummary::default();
            for obj in ruleset.objects.iter() {
                if let NfObject::CmdObject(cmd) = obj {
                    match cmd {
                        NfCmd::Add(o) => summary.adds.push(object_kind(o)),
                        NfCmd::Delete(o) => summary.deletes.push(object_kind(o)),
                        _ => {}
                    }
                }
            }
            self.summaries.lock().unwrap().push(summary);
        }
    }

    fn object_kind(o: &NfListObject<'_>) -> &'static str {
        match o {
            NfListObject::Table(_) => "table",
            NfListObject::Chain(_) => "chain",
            NfListObject::Set(_) => "set",
            NfListObject::Rule(_) => "rule",
            NfListObject::Element(_) => "element",
            _ => "other",
        }
    }

    impl RulesetApplier for RecordingApplier {
        fn apply(&self, ruleset: &Nftables<'_>) -> Result<(), FirewallError> {
            self.record(ruleset);
            if let Some(msg) = self.fail_with.lock().unwrap().clone() {
                return Err(FirewallError::Backend(msg));
            }
            Ok(())
        }
    }

    /// Wrapper that lets `Box<dyn RulesetApplier>` share state with the test
    /// (the test holds an Arc; the box delegates to the same Arc).
    #[derive(Debug)]
    struct ApplierHandle(Arc<RecordingApplier>);
    impl RulesetApplier for ApplierHandle {
        fn apply(&self, ruleset: &Nftables<'_>) -> Result<(), FirewallError> {
            self.0.apply(ruleset)
        }
    }

    fn make_backend() -> (NftablesBackend, Arc<RecordingApplier>) {
        let applier = Arc::new(RecordingApplier::default());
        let backend = NftablesBackend::with_applier(Box::new(ApplierHandle(applier.clone())));
        (backend, applier)
    }

    fn rule() -> AccessRule {
        AccessRule {
            source_ip: "192.168.1.5".parse().unwrap(),
            ports: vec![
                PortProto::new(Protocol::Tcp, 22),
                PortProto::new(Protocol::Udp, 53),
            ],
            timeout: Duration::from_secs(30),
            comment: "test".into(),
        }
    }

    #[test]
    fn init_submits_one_batch_with_table_set_chain_rule() {
        let (mut b, applier) = make_backend();
        b.init().unwrap();
        let summaries = applier.snapshot_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].adds, vec!["table", "set", "chain", "rule"]);
        assert!(summaries[0].deletes.is_empty());
    }

    #[test]
    fn init_ruleset_json_mentions_table_and_set_names() {
        let (mut b, applier) = make_backend();
        b.init().unwrap();
        let calls = applier.snapshot_calls();
        assert_eq!(calls.len(), 1);
        let json = &calls[0];
        assert!(
            json.contains("\"fwknox\""),
            "expected table name in JSON: {json}"
        );
        assert!(
            json.contains("\"fwknox_allow_v4\""),
            "expected set name in JSON: {json}"
        );
        assert!(
            json.contains("\"timeout\""),
            "expected timeout flag in JSON: {json}"
        );
    }

    #[test]
    fn open_access_submits_one_element_per_port_in_a_single_batch() {
        let (mut b, applier) = make_backend();
        b.init().unwrap();
        let handle = b.open_access(&rule()).unwrap();
        // 1 init batch + 1 open_access batch.
        let summaries = applier.snapshot_summaries();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[1].adds, vec!["element", "element"]);
        assert!(summaries[1].deletes.is_empty());
        assert_eq!(handle.as_str(), "192.168.1.5/tcp/22,192.168.1.5/udp/53");
    }

    #[test]
    fn open_access_element_json_includes_per_element_timeout() {
        let (mut b, applier) = make_backend();
        b.init().unwrap();
        b.open_access(&rule()).unwrap();
        let calls = applier.snapshot_calls();
        let element_json = &calls[1];
        assert!(element_json.contains("192.168.1.5"));
        assert!(element_json.contains("\"tcp\""));
        // Timeout is encoded as JSON number 30 inside an "elem" object.
        assert!(element_json.contains("\"timeout\":30"));
    }

    #[test]
    fn open_access_before_init_returns_inconsistent_state() {
        let (b, _) = make_backend();
        let err = b.open_access(&rule()).unwrap_err();
        assert!(matches!(err, FirewallError::InconsistentState(_)));
    }

    #[test]
    fn ipv6_access_returns_unsupported() {
        let (mut b, _) = make_backend();
        b.init().unwrap();
        let mut r = rule();
        r.source_ip = "2001:db8::1".parse().unwrap();
        let err = b.open_access(&r).unwrap_err();
        assert!(matches!(err, FirewallError::Unsupported(_)));
    }

    #[test]
    fn remove_rule_submits_delete_per_handle_segment() {
        let (mut b, applier) = make_backend();
        b.init().unwrap();
        let handle = b.open_access(&rule()).unwrap();
        b.remove_rule(&handle).unwrap();
        let summaries = applier.snapshot_summaries();
        // init + open_access + remove_rule.
        assert_eq!(summaries.len(), 3);
        assert!(summaries[2].adds.is_empty());
        assert_eq!(summaries[2].deletes, vec!["element", "element"]);
    }

    #[test]
    fn remove_rule_rejects_malformed_handle() {
        let (mut b, _) = make_backend();
        b.init().unwrap();
        let err = b
            .remove_rule(&RuleHandle::new("not/well/formed/extra"))
            .unwrap_err();
        assert!(matches!(err, FirewallError::RuleNotFound(_)));
    }

    #[test]
    fn flush_submits_table_delete_and_clears_initialized() {
        let (mut b, applier) = make_backend();
        b.init().unwrap();
        b.flush().unwrap();
        let summaries = applier.snapshot_summaries();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[1].deletes, vec!["table"]);
    }

    #[test]
    fn flush_swallows_backend_errors() {
        let (mut b, applier) = make_backend();
        // Simulate a missing table from the kernel.
        *applier.fail_with.lock().unwrap() = Some("nft delete table failed: not found".into());
        b.flush().unwrap(); // Must not propagate.
    }

    #[test]
    fn init_propagates_backend_errors() {
        let (mut b, applier) = make_backend();
        *applier.fail_with.lock().unwrap() = Some("permission denied".into());
        let err = b.init().unwrap_err();
        assert!(matches!(err, FirewallError::Backend(_)));
    }
}
