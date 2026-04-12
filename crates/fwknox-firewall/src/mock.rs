// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory `FirewallBackend` implementation used by tests.

use std::{collections::BTreeMap, sync::Mutex};

use crate::{
    backend::FirewallBackend,
    error::FirewallError,
    rule::{AccessRule, RuleHandle},
};

/// In-memory `FirewallBackend` that records every operation.
///
/// Tests can use [`MockBackend::installed_rules`] to read the current set
/// of "installed" rules without touching a real firewall.
#[derive(Debug, Default)]
pub struct MockBackend {
    state: Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    initialized: bool,
    next_id: u64,
    rules: BTreeMap<String, AccessRule>,
}

impl MockBackend {
    /// Construct a fresh, uninitialised mock backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `init` has been called and `flush` has not.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.state
            .lock()
            .expect("mock backend poisoned")
            .initialized
    }

    /// Snapshot of the currently-installed rules, keyed by handle.
    #[must_use]
    pub fn installed_rules(&self) -> BTreeMap<String, AccessRule> {
        self.state
            .lock()
            .expect("mock backend poisoned")
            .rules
            .clone()
    }
}

impl FirewallBackend for MockBackend {
    fn init(&mut self) -> Result<(), FirewallError> {
        let mut s = self.state.lock().expect("mock backend poisoned");
        s.initialized = true;
        Ok(())
    }

    fn open_access(&self, rule: &AccessRule) -> Result<RuleHandle, FirewallError> {
        let mut s = self.state.lock().expect("mock backend poisoned");
        if !s.initialized {
            return Err(FirewallError::InconsistentState(
                "open_access called before init".into(),
            ));
        }
        let id = format!("mock-{}", s.next_id);
        s.next_id += 1;
        s.rules.insert(id.clone(), rule.clone());
        Ok(RuleHandle::new(id))
    }

    fn remove_rule(&self, handle: &RuleHandle) -> Result<(), FirewallError> {
        let mut s = self.state.lock().expect("mock backend poisoned");
        if s.rules.remove(handle.as_str()).is_none() {
            return Err(FirewallError::RuleNotFound(handle.as_str().to_string()));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), FirewallError> {
        let mut s = self.state.lock().expect("mock backend poisoned");
        s.rules.clear();
        s.initialized = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fwknox_proto::{PortProto, Protocol};

    use super::*;

    fn rule() -> AccessRule {
        AccessRule {
            source_ip: "192.168.1.5".parse().unwrap(),
            ports: vec![PortProto::new(Protocol::Tcp, 22)],
            timeout: Duration::from_secs(30),
            comment: "test".into(),
        }
    }

    #[test]
    fn open_then_remove_roundtrip() {
        let mut b = MockBackend::new();
        b.init().unwrap();
        let handle = b.open_access(&rule()).unwrap();
        assert_eq!(b.installed_rules().len(), 1);
        b.remove_rule(&handle).unwrap();
        assert!(b.installed_rules().is_empty());
    }

    #[test]
    fn open_before_init_fails() {
        let b = MockBackend::new();
        let err = b.open_access(&rule()).unwrap_err();
        assert!(matches!(err, FirewallError::InconsistentState(_)));
    }

    #[test]
    fn double_remove_fails_with_not_found() {
        let mut b = MockBackend::new();
        b.init().unwrap();
        let handle = b.open_access(&rule()).unwrap();
        b.remove_rule(&handle).unwrap();
        let err = b.remove_rule(&handle).unwrap_err();
        assert!(matches!(err, FirewallError::RuleNotFound(_)));
    }

    #[test]
    fn flush_clears_rules_and_initialized_flag() {
        let mut b = MockBackend::new();
        b.init().unwrap();
        b.open_access(&rule()).unwrap();
        assert!(b.is_initialized());
        b.flush().unwrap();
        assert!(!b.is_initialized());
        assert!(b.installed_rules().is_empty());
    }

    #[test]
    fn removing_unknown_rule_returns_rulenotfound() {
        // Audit task 7.1: simulate a stale handle whose underlying
        // element has already been removed (kernel timeout, admin
        // flush, etc). The mock should return `RuleNotFound` rather
        // than silently succeeding.
        let mut fw = MockBackend::new();
        fw.init().unwrap();
        let handle = RuleHandle::new("mock-never-installed");
        let err = fw.remove_rule(&handle).unwrap_err();
        assert!(matches!(err, FirewallError::RuleNotFound(_)));
    }

    #[test]
    fn handles_are_unique() {
        let mut b = MockBackend::new();
        b.init().unwrap();
        let h1 = b.open_access(&rule()).unwrap();
        let h2 = b.open_access(&rule()).unwrap();
        assert_ne!(h1, h2);
    }
}
