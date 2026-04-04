// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded replay-detection cache with optional auto-persistence.
//!
//! The cache is an LRU with a configurable maximum entry count. On
//! insert, if the cache is full, the least-recently-used nonce is
//! evicted. An optional persistence path makes every successful
//! insert durable before the function returns.

use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lru::LruCache;

use crate::error::ReplayError;

/// A 16-byte SPA nonce used as the cache key.
pub type Nonce = [u8; 16];

/// Default maximum number of in-memory nonce entries. Chosen to keep
/// memory bounded (~320 KiB for key+timestamp+LRU overhead) while still
/// tolerating a high SPA request rate.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// In-memory replay cache with a bounded LRU backing store. Thread-safe.
#[derive(Debug)]
pub struct ReplayCache {
    inner: Mutex<LruCache<Nonce, u64>>,
    persist_path: Option<PathBuf>,
}

impl ReplayCache {
    /// Construct a new, empty cache with [`DEFAULT_MAX_ENTRIES`] capacity
    /// and no persistence path.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(
            NonZeroUsize::new(DEFAULT_MAX_ENTRIES).expect("DEFAULT_MAX_ENTRIES > 0"),
        )
    }

    /// Construct an empty cache with an explicit capacity.
    #[must_use]
    pub fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            persist_path: None,
        }
    }

    /// Attach a persistence path. When set, [`Self::check_and_insert`]
    /// writes the full cache atomically after every successful insert.
    pub fn set_persist_path(&mut self, path: PathBuf) {
        self.persist_path = Some(path);
    }

    /// Try to insert `nonce` with the current Unix-epoch second timestamp.
    ///
    /// Returns `true` if the nonce was fresh and newly inserted,
    /// or `false` if it was already present (a replay).
    ///
    /// If the cache is over capacity, the LRU entry is evicted before
    /// insertion. If a persistence path is set, the new state is saved
    /// atomically before returning.
    pub fn check_and_insert(&self, nonce: Nonce) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let inserted = {
            let mut guard = self.inner.lock().expect("replay cache poisoned");
            if guard.contains(&nonce) {
                return false;
            }
            guard.put(nonce, now);
            true
        };
        // Auto-save outside the lock to avoid holding it during disk I/O.
        if let Some(path) = &self.persist_path {
            if let Err(e) = self.save_to_file(path) {
                tracing::warn!(
                    error = %e,
                    "replay cache auto-save failed (nonce is still in memory)"
                );
            }
        }
        inserted
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

    /// Maximum number of entries this cache will hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner
            .lock()
            .expect("replay cache poisoned")
            .cap()
            .get()
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
        let stale: Vec<Nonce> = guard
            .iter()
            .filter_map(|(k, ts)| (*ts < cutoff).then_some(*k))
            .collect();
        for k in stale {
            guard.pop(&k);
        }
        before - guard.len()
    }

    /// Load a cache from a file. Missing files produce an empty cache.
    /// The loaded cache uses the default capacity.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, ReplayError> {
        let entries = crate::persist::read_cache_file(path)?;
        let mut lru = LruCache::new(
            NonZeroUsize::new(DEFAULT_MAX_ENTRIES).expect("DEFAULT_MAX_ENTRIES > 0"),
        );
        for (k, v) in entries {
            lru.put(k, v);
        }
        Ok(Self {
            inner: Mutex::new(lru),
            persist_path: None,
        })
    }

    /// Atomically save the cache to a file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), ReplayError> {
        let guard = self.inner.lock().expect("replay cache poisoned");
        let map: std::collections::HashMap<Nonce, u64> =
            guard.iter().map(|(k, v)| (*k, *v)).collect();
        drop(guard);
        crate::persist::write_cache_file(path, &map)
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
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
    fn capacity_cap_evicts_oldest() {
        let cap = NonZeroUsize::new(3).unwrap();
        let cache = ReplayCache::with_capacity(cap);
        assert!(cache.check_and_insert([0; 16]));
        assert!(cache.check_and_insert([1; 16]));
        assert!(cache.check_and_insert([2; 16]));
        assert_eq!(cache.len(), 3);
        // This inserts a new nonce and evicts the oldest ([0; 16]).
        assert!(cache.check_and_insert([3; 16]));
        assert_eq!(cache.len(), 3);
        // [0; 16] should now be fresh again because it was evicted.
        // This demonstrates the DoS-resistance trade-off: bounded
        // memory means an attacker who floods new nonces can evict
        // real ones, but the daemon will NOT OOM.
        assert!(cache.check_and_insert([0; 16]));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn prune_with_generous_max_age_keeps_everything() {
        let cache = ReplayCache::new();
        cache.check_and_insert([1; 16]);
        cache.check_and_insert([2; 16]);
        let pruned = cache.prune_older_than(Duration::from_secs(3600));
        assert_eq!(pruned, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn prune_with_synthetic_old_entries_evicts() {
        let cache = ReplayCache::new();
        cache.check_and_insert([3; 16]);
        // Backdate the entry to 1970 by rewriting through the lock.
        {
            let mut guard = cache.inner.lock().unwrap();
            let nonces: Vec<Nonce> = guard.iter().map(|(k, _)| *k).collect();
            for n in nonces {
                guard.put(n, 0);
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
        assert!(!loaded.check_and_insert([0x11; 16]));
    }

    #[test]
    fn auto_save_persists_after_insert() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auto.cache");
        let mut cache = ReplayCache::new();
        cache.set_persist_path(path.clone());

        // Insert; the file should now exist.
        cache.check_and_insert([0x33; 16]);
        assert!(path.exists(), "auto-save should create the cache file");

        // Load from disk and verify the nonce made it.
        let reloaded = ReplayCache::load_from_file(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(!reloaded.check_and_insert([0x33; 16]));
    }
}
