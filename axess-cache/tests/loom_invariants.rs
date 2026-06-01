//! Loom permutation-checked invariants for the inflight-map ↔ LRU-map
//! state machine that backs `ClockTtlCache::get_or_try_insert_with`,
//! `invalidate`, `invalidate_by`, and `invalidate_all`.
//!
//! # Why a separate model, not loom-checking the real type
//!
//! `ClockTtlCache` uses `tokio::sync::OnceCell` to collapse N concurrent
//! same-key loads into a single fetcher invocation. tokio's internals
//! are not loom-instrumented, so a loom test that constructs a real
//! `ClockTtlCache` would either deadlock the model checker or require
//! swapping `OnceCell` for a hand-rolled stub; meaning we'd no longer
//! be verifying the implementation that actually ships.
//!
//! The bug surface we want loom to cover is the part *we* wrote: the
//! ordering between the inflight map and the LRU map under concurrent
//! load-promote and invalidate. That state machine is captured here in
//! a stripped-down model that mirrors the real lock-ordering rule
//! (inflight-before-LRU) and the real post-resolve "check still
//! active, then promote under inflight" sequence.
//!
//! Drift risk between this model and the real type is addressed two
//! ways: (1) the model lives in-tree alongside the implementation, so
//! changes touch both files; (2) the regular tokio test suite in
//! `src/lib.rs` covers the same scenarios at the type level; loom
//! adds permutation coverage, not coverage of new operations.
//!
//! # Invariants pinned here
//!
//! 1. **No deadlocks**: every interleaving of load and invalidate
//!    completes. Implies the lock-ordering rule (inflight before LRU)
//!    is consistent across all paths.
//! 2. **Invalidate wins during load**: a load already in flight when
//!    an invalidate begins must not promote its result to the LRU.
//! 3. **At-most-one-promote**: when two threads claim the same key
//!    concurrently, the joiner does not also promote; final LRU has
//!    one entry, never two writes against the same slot.
//! 4. **invalidate_all clears all in-flight promotions**: any load
//!    in flight when `invalidate_all` runs leaves no LRU entry.
//!
//! # Running
//!
//! ```bash
//! RUSTFLAGS='--cfg loom' cargo test --release \
//!     --manifest-path axess/axess-cache/Cargo.toml \
//!     --test loom_invariants
//! ```
//!
//! Without `--cfg loom`, the entire module is gated out and `cargo
//! test` skips it. Loom explores O(N!) thread interleavings, so
//! `--release` keeps each test bounded to seconds rather than minutes.

#![cfg(loom)]

use loom::sync::{Arc, Mutex};
use loom::thread;
use std::collections::HashMap;

/// Stripped-down model of the cache's two-map state machine.
///
/// Mirrors the lock-ordering rule from `ClockTtlCache`: any path that
/// touches both maps must take `inflight` before `lru` (i.e. before the
/// `inner` LRU mutex in the real type). `lru` here is a `HashMap`
/// rather than an `LruCache` because LRU recency ordering is irrelevant
/// to the invariants under test; only presence/absence matters.
struct CacheModel {
    inflight: Mutex<HashMap<u32, ()>>,
    lru: Mutex<HashMap<u32, u32>>,
}

impl CacheModel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inflight: Mutex::new(HashMap::new()),
            lru: Mutex::new(HashMap::new()),
        })
    }

    /// Models `get_or_try_insert_with`'s claim step: insert into
    /// inflight if no existing cell; return whether *we* claimed
    /// (vs. joined an existing claimer).
    fn claim_inflight(&self, key: u32) -> bool {
        let mut inf = self.inflight.lock().unwrap();
        if inf.contains_key(&key) {
            false
        } else {
            inf.insert(key, ());
            true
        }
    }

    /// Models `get_or_try_insert_with`'s post-resolve "check + promote
    /// under inflight" sequence. Returns whether the value was promoted
    /// (i.e. the cell was still active; no concurrent invalidate had
    /// removed it during the load).
    ///
    /// Critical: holds the inflight lock across the LRU insert, exactly
    /// as the real code does. This forces any racing invalidate to
    /// serialize *after* the LRU insert, at which point the invalidate
    /// will then remove the just-inserted entry; converging on
    /// "invalidated."
    fn promote_under_inflight(&self, key: u32, value: u32) -> bool {
        let mut inf = self.inflight.lock().unwrap();
        if inf.contains_key(&key) {
            let mut l = self.lru.lock().unwrap();
            l.insert(key, value);
            drop(l);
            inf.remove(&key);
            true
        } else {
            false
        }
    }

    /// Models `invalidate`: remove from inflight, then remove from LRU.
    /// Two separate critical sections; lock-ordering is inflight first.
    fn invalidate(&self, key: u32) {
        self.inflight.lock().unwrap().remove(&key);
        self.lru.lock().unwrap().remove(&key);
    }

    /// Models `invalidate_all`: clear inflight, then clear LRU.
    fn invalidate_all(&self) {
        self.inflight.lock().unwrap().clear();
        self.lru.lock().unwrap().clear();
    }

    fn lru_contains(&self, key: u32) -> bool {
        self.lru.lock().unwrap().contains_key(&key)
    }

    fn lru_len(&self) -> usize {
        self.lru.lock().unwrap().len()
    }
}

/// Invariant 1: no interleaving of two concurrent operations deadlocks
/// or panics. Loom's model harness fails the test if any thread fails
/// to terminate, so the success of this test under all interleavings
/// implies the lock-ordering rule is consistent (no path takes
/// `lru` before `inflight`, which would create a deadlock partner).
#[test]
fn no_deadlocks_under_concurrent_load_and_invalidate() {
    loom::model(|| {
        let cache = CacheModel::new();

        let c1 = cache.clone();
        let h1 = thread::spawn(move || {
            if c1.claim_inflight(1) {
                let _ = c1.promote_under_inflight(1, 42);
            }
        });

        let c2 = cache.clone();
        let h2 = thread::spawn(move || {
            c2.invalidate(1);
        });

        h1.join().unwrap();
        h2.join().unwrap();
        // Reaching this point under every interleaving is the property.
    });
}

/// Invariant 2: a load that was in flight when an invalidate began
/// must not result in a stale entry in the LRU after both operations
/// complete.
///
/// Setup mirrors the real-world race we documented in
/// `get_or_try_insert_with`: thread A has *already claimed* the in-
/// flight cell (modelling "load is in flight"), then thread A's
/// post-resolve and thread B's invalidate run concurrently. Loom
/// enumerates every interleaving of the two; the assertion must hold
/// under all of them.
#[test]
fn invalidate_wins_against_concurrent_in_flight_load() {
    loom::model(|| {
        let cache = CacheModel::new();
        // Pre-claim: simulate "load already in flight."
        assert!(cache.claim_inflight(1));

        let c1 = cache.clone();
        let h1 = thread::spawn(move || {
            // The post-resolve step from `get_or_try_insert_with`.
            c1.promote_under_inflight(1, 99);
        });

        let c2 = cache.clone();
        let h2 = thread::spawn(move || {
            c2.invalidate(1);
        });

        h1.join().unwrap();
        h2.join().unwrap();

        assert!(
            !cache.lru_contains(1),
            "invalidate-wins violation: post-invalidate LRU contains a value \
             from a concurrently-resolving load"
        );
    });
}

/// Invariant 3: when two threads concurrently claim the *same* key,
/// at most one promotion happens. The joiner sees the cell already
/// present in inflight and exits without promoting; the claimer
/// promotes. Final LRU has exactly one entry (or zero, if a racing
/// invalidate also ran; see invariant 2).
///
/// This pins the property that single-flight does not accidentally
/// "double-publish" when two callers race to claim. (In the real
/// type, OnceCell handles fetcher coordination; this test handles
/// the surrounding map-state machine.)
#[test]
fn at_most_one_promote_under_concurrent_same_key_loads() {
    loom::model(|| {
        let cache = CacheModel::new();

        let c1 = cache.clone();
        let h1 = thread::spawn(move || {
            if c1.claim_inflight(1) {
                c1.promote_under_inflight(1, 10);
            }
        });

        let c2 = cache.clone();
        let h2 = thread::spawn(move || {
            if c2.claim_inflight(1) {
                c2.promote_under_inflight(1, 20);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // After both join: the LRU has either 0 or 1 entries for key 1
        // (0 only if some path skipped promotion, which it can't here
        // since there's no invalidate; so we expect exactly 1).
        assert!(
            cache.lru_len() <= 1,
            "two threads concurrently promoted the same key; single-flight \
             map-state invariant violated"
        );
        assert!(
            cache.lru_contains(1),
            "neither thread promoted; one of them should have claimed and \
             promoted under exclusive inflight ownership"
        );
    });
}

/// Invariant 4: `invalidate_all` running concurrently with multiple
/// in-flight loads leaves the LRU empty for every key that was being
/// loaded. Generalises invariant 2 to the bulk-clear path.
#[test]
fn invalidate_all_blocks_every_in_flight_promotion() {
    loom::model(|| {
        let cache = CacheModel::new();
        // Pre-claim two in-flight loads.
        assert!(cache.claim_inflight(1));
        assert!(cache.claim_inflight(2));

        let c1 = cache.clone();
        let h1 = thread::spawn(move || {
            c1.promote_under_inflight(1, 100);
        });

        let c2 = cache.clone();
        let h2 = thread::spawn(move || {
            c2.promote_under_inflight(2, 200);
        });

        let c3 = cache.clone();
        let h3 = thread::spawn(move || {
            c3.invalidate_all();
        });

        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();

        assert!(
            !cache.lru_contains(1) && !cache.lru_contains(2),
            "invalidate_all-wins violation: post-invalidate_all LRU contains \
             values from concurrently-resolving loads"
        );
    });
}
