// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory replay-detection cache.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// A 16-byte SPA nonce used as the cache key.
pub type Nonce = [u8; 16];

/// In-memory replay cache. Thread-safe via an internal `Mutex`.
#[derive(Debug, Default)]
pub struct ReplayCache {
    pub(crate) inner: Mutex<HashMap<Nonce, u64>>,
}

impl ReplayCache {
    /// Construct a new, empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to insert `nonce` with the current Unix-epoch second timestamp.
    /// Returns `true` if the nonce is fresh (newly inserted) or `false` if
    /// it was already present (a replay).
    pub fn check_and_insert(&self, nonce: Nonce) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut guard = self.inner.lock().expect("replay cache poisoned");
        if guard.contains_key(&nonce) {
            return false;
        }
        guard.insert(nonce, now);
        true
    }

    /// Number of entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("replay cache poisoned").len()
    }

    /// `true` if the cache holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove entries older than `max_age` from the cache. Returns the
    /// number of entries pruned.
    pub fn prune_older_than(&self, max_age: Duration) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let cutoff = now.saturating_sub(max_age.as_secs());
        let mut guard = self.inner.lock().expect("replay cache poisoned");
        let before = guard.len();
        guard.retain(|_, ts| *ts >= cutoff);
        before - guard.len()
    }

    /// Load a cache from a file. Missing files produce an empty cache.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, crate::error::ReplayError> {
        let entries = crate::persist::read_cache_file(path)?;
        Ok(Self {
            inner: Mutex::new(entries),
        })
    }

    /// Atomically save the cache to a file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), crate::error::ReplayError> {
        let guard = self.inner.lock().expect("replay cache poisoned");
        crate::persist::write_cache_file(path, &guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonce_is_accepted() {
        let cache = ReplayCache::new();
        assert!(cache.check_and_insert([1u8; 16]));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_is_rejected() {
        let cache = ReplayCache::new();
        let n = [2u8; 16];
        assert!(cache.check_and_insert(n));
        assert!(!cache.check_and_insert(n));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn distinct_nonces_independent() {
        let cache = ReplayCache::new();
        assert!(cache.check_and_insert([0; 16]));
        assert!(cache.check_and_insert([1; 16]));
        assert!(cache.check_and_insert([2; 16]));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn prune_with_generous_max_age_keeps_everything() {
        let cache = ReplayCache::new();
        cache.check_and_insert([1; 16]);
        cache.check_and_insert([2; 16]);
        // Anything less than an hour old should survive.
        let pruned = cache.prune_older_than(Duration::from_secs(3600));
        assert_eq!(pruned, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn prune_with_synthetic_old_entries_evicts() {
        // We test the eviction path by reaching into the lock with a known
        // stale timestamp instead of sleeping (which would slow tests).
        let cache = ReplayCache::new();
        cache.check_and_insert([3; 16]);
        {
            let mut guard = cache.inner.lock().unwrap();
            // Backdate the entry to 1970.
            for ts in guard.values_mut() {
                *ts = 0;
            }
        }
        let pruned = cache.prune_older_than(Duration::from_secs(60));
        assert_eq!(pruned, 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn empty_cache_is_empty() {
        let cache = ReplayCache::new();
        assert!(cache.is_empty());
        cache.check_and_insert([0; 16]);
        assert!(!cache.is_empty());
    }

    #[test]
    fn cache_persists_across_load_and_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.cache");
        {
            let cache = ReplayCache::new();
            cache.check_and_insert([0x11; 16]);
            cache.check_and_insert([0x22; 16]);
            cache.save_to_file(&path).unwrap();
        }
        let loaded = ReplayCache::load_from_file(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        // Re-inserting the same nonces is detected as a replay.
        assert!(!loaded.check_and_insert([0x11; 16]));
    }
}
