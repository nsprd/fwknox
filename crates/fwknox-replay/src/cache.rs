// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded replay-detection cache with optional auto-persistence.
//!
//! The cache is an LRU with a configurable maximum entry count. On
//! insert, if the cache is full, the least-recently-used nonce is
//! evicted. An optional persistence path makes every successful
//! insert durable before the function returns.
//!
//! # Clock semantics
//!
//! Entry timestamps are wall-clock `SystemTime` values stored as Unix
//! epoch seconds, so they survive process restarts and on-disk reloads.
//! NTP steps are handled defensively: backward steps are absorbed by
//! `saturating_sub` inside [`ReplayCache::prune_older_than`] (the prune
//! cutoff clamps to 0 rather than underflowing), and forward steps cause
//! at most earlier-than-expected pruning, which is safe because a pruned
//! nonce cannot produce a false acceptance -- only the window shortens.
//! Callers that require strict monotonicity should run the host with a
//! slewing time source (e.g. `chronyd` with `makestep` disabled) rather
//! than one that steps the clock.

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
    /// Returns `Ok(true)` if the nonce was fresh and newly inserted,
    /// `Ok(false)` if it was already present (a replay), or `Err` if a
    /// persistence path is set and writing the cache to disk failed.
    ///
    /// If the cache is over capacity, the LRU entry is evicted before
    /// insertion. If a persistence path is set, the new state is saved
    /// atomically before returning — on persist failure, the in-memory
    /// entry is rolled back so that a crash cannot leave the daemon with
    /// a nonce that exists only in RAM and would be re-accepted after
    /// restart. Callers MUST fail closed (reject the packet, do not
    /// install a firewall rule) on `Err`.
    pub fn check_and_insert(&self, nonce: Nonce) -> Result<bool, ReplayError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        {
            let mut guard = self.inner.lock().expect("replay cache poisoned");
            if guard.contains(&nonce) {
                return Ok(false);
            }
            guard.put(nonce, now);
        }
        // Auto-save outside the lock to avoid holding it during disk I/O.
        if let Some(path) = self.persist_path.clone() {
            if let Err(e) = self.save_to_file(&path) {
                let mut guard = self.inner.lock().expect("replay cache poisoned");
                guard.pop(&nonce);
                return Err(e);
            }
        }
        Ok(true)
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
    ///
    /// When a persistence path is set, the cache is saved atomically
    /// after any eviction so that on-disk state reflects the prune and
    /// pruned nonces do not return after a crash/restart. On persist
    /// failure an `Err` is returned; the in-memory eviction stands
    /// (stale nonces cannot cause false replays) but callers should
    /// log the error so operators know disk state is lagging.
    pub fn prune_older_than(&self, max_age: Duration) -> Result<usize, ReplayError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let cutoff = now.saturating_sub(max_age.as_secs());
        let pruned = {
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
        };
        if pruned > 0 {
            if let Some(path) = self.persist_path.clone() {
                self.save_to_file(&path)?;
            }
        }
        Ok(pruned)
    }

    /// Load a cache from a file. Missing files produce an empty cache.
    /// The loaded cache uses the default capacity.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, ReplayError> {
        let entries = crate::persist::read_cache_file(path)?;
        let mut lru =
            LruCache::new(NonZeroUsize::new(DEFAULT_MAX_ENTRIES).expect("DEFAULT_MAX_ENTRIES > 0"));
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
        assert!(cache.check_and_insert([1u8; 16]).unwrap());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_is_rejected() {
        let cache = ReplayCache::new();
        let n = [2u8; 16];
        assert!(cache.check_and_insert(n).unwrap());
        assert!(!cache.check_and_insert(n).unwrap());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn distinct_nonces_independent() {
        let cache = ReplayCache::new();
        assert!(cache.check_and_insert([0; 16]).unwrap());
        assert!(cache.check_and_insert([1; 16]).unwrap());
        assert!(cache.check_and_insert([2; 16]).unwrap());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn capacity_cap_evicts_oldest() {
        let cap = NonZeroUsize::new(3).unwrap();
        let cache = ReplayCache::with_capacity(cap);
        assert!(cache.check_and_insert([0; 16]).unwrap());
        assert!(cache.check_and_insert([1; 16]).unwrap());
        assert!(cache.check_and_insert([2; 16]).unwrap());
        assert_eq!(cache.len(), 3);
        // This inserts a new nonce and evicts the oldest ([0; 16]).
        assert!(cache.check_and_insert([3; 16]).unwrap());
        assert_eq!(cache.len(), 3);
        // [0; 16] should now be fresh again because it was evicted.
        // This demonstrates the DoS-resistance trade-off: bounded
        // memory means an attacker who floods new nonces can evict
        // real ones, but the daemon will NOT OOM.
        assert!(cache.check_and_insert([0; 16]).unwrap());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn prune_with_generous_max_age_keeps_everything() {
        let cache = ReplayCache::new();
        cache.check_and_insert([1; 16]).unwrap();
        cache.check_and_insert([2; 16]).unwrap();
        let pruned = cache.prune_older_than(Duration::from_secs(3600)).unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn prune_with_synthetic_old_entries_evicts() {
        let cache = ReplayCache::new();
        cache.check_and_insert([3; 16]).unwrap();
        // Backdate the entry to 1970 by rewriting through the lock.
        {
            let mut guard = cache.inner.lock().unwrap();
            let nonces: Vec<Nonce> = guard.iter().map(|(k, _)| *k).collect();
            for n in nonces {
                guard.put(n, 0);
            }
        }
        let pruned = cache.prune_older_than(Duration::from_secs(60)).unwrap();
        assert_eq!(pruned, 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn empty_cache_is_empty() {
        let cache = ReplayCache::new();
        assert!(cache.is_empty());
        cache.check_and_insert([0; 16]).unwrap();
        assert!(!cache.is_empty());
    }

    #[test]
    fn cache_persists_across_load_and_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.cache");
        {
            let cache = ReplayCache::new();
            cache.check_and_insert([0x11; 16]).unwrap();
            cache.check_and_insert([0x22; 16]).unwrap();
            cache.save_to_file(&path).unwrap();
        }
        let loaded = ReplayCache::load_from_file(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(!loaded.check_and_insert([0x11; 16]).unwrap());
    }

    #[test]
    fn persist_failure_rolls_back_in_memory_entry() {
        let dir = tempfile::tempdir().unwrap();
        // Force persist to fail by nesting under a regular file.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"regular file").unwrap();
        let bad_path = blocker.join("child.cache");
        let mut cache = ReplayCache::new();
        cache.set_persist_path(bad_path);
        // With today's API this returns `bool`; after the fix it returns
        // Result<bool, ReplayError>. The test uses the post-fix shape so it
        // compiles only after the change — when you see the compile error
        // naming `Result`, that IS the reproduction evidence.
        let result = cache.check_and_insert([0x77; 16]);
        assert!(result.is_err(), "persist failure must propagate");
        assert_eq!(
            cache.len(),
            0,
            "failed insert must not leave nonce in memory"
        );
    }

    #[test]
    fn prune_persists_evictions_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prune.cache");
        let mut cache = ReplayCache::new();
        cache.set_persist_path(path.clone());
        cache.check_and_insert([0x01; 16]).unwrap();
        {
            let mut g = cache.inner.lock().unwrap();
            g.put([0x01; 16], 0);
        }
        let n = cache.prune_older_than(Duration::from_secs(60)).unwrap();
        assert_eq!(n, 1);
        let reloaded = ReplayCache::load_from_file(&path).unwrap();
        assert_eq!(reloaded.len(), 0, "disk cache must reflect the prune");
    }

    #[test]
    fn auto_save_persists_after_insert() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auto.cache");
        let mut cache = ReplayCache::new();
        cache.set_persist_path(path.clone());

        // Insert; the file should now exist.
        cache.check_and_insert([0x33; 16]).unwrap();
        assert!(path.exists(), "auto-save should create the cache file");

        // Load from disk and verify the nonce made it.
        let reloaded = ReplayCache::load_from_file(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(!reloaded.check_and_insert([0x33; 16]).unwrap());
    }
}
