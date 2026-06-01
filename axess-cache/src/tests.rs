//! Unit + integration tests for the cache + stats modules.

#![cfg(test)]

use crate::{CacheStats, ClockTtlCache};
use axess_clock::Clock;
use axess_clock::testing::MockClock;
use chrono::{TimeZone, Utc};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn fixed_clock() -> Arc<MockClock> {
    Arc::new(MockClock::at(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ))
}

fn cache(capacity: usize, ttl_secs: u64, clock: Arc<MockClock>) -> ClockTtlCache<String, u32> {
    ClockTtlCache::new(
        NonZeroUsize::new(capacity).unwrap(),
        Duration::from_secs(ttl_secs),
        clock as Arc<dyn Clock>,
    )
}

#[test]
fn miss_returns_none() {
    let c = cache(8, 60, fixed_clock());
    assert_eq!(c.get(&"absent".to_string()), None);
}

#[test]
fn insert_then_get_roundtrip() {
    let c = cache(8, 60, fixed_clock());
    c.insert("k".into(), 42);
    assert_eq!(c.get(&"k".into()), Some(42));
}

#[test]
fn entry_evicted_after_ttl_expiry() {
    let clk = fixed_clock();
    let c = cache(8, 60, clk.clone());
    c.insert("k".into(), 1);
    assert_eq!(c.get(&"k".into()), Some(1));
    clk.advance_secs(61);
    assert_eq!(
        c.get(&"k".into()),
        None,
        "entry must expire once Clock advances past TTL"
    );
}

#[test]
fn entry_survives_until_ttl_boundary() {
    let clk = fixed_clock();
    let c = cache(8, 60, clk.clone());
    c.insert("k".into(), 1);
    // Within TTL; still present.
    clk.advance_secs(59);
    assert_eq!(c.get(&"k".into()), Some(1));
}

#[test]
fn invalidate_removes_single_key() {
    let c = cache(8, 60, fixed_clock());
    c.insert("k".into(), 1);
    c.insert("other".into(), 2);
    assert!(c.invalidate(&"k".into()));
    assert_eq!(c.get(&"k".into()), None);
    assert_eq!(c.get(&"other".into()), Some(2));
}

#[test]
fn invalidate_returns_false_for_absent_key() {
    let c = cache(8, 60, fixed_clock());
    assert!(!c.invalidate(&"absent".into()));
}

#[test]
fn invalidate_by_removes_matching() {
    let c = cache(16, 60, fixed_clock());
    c.insert("user:alice:1".into(), 1);
    c.insert("user:alice:2".into(), 2);
    c.insert("user:bob:1".into(), 3);
    let removed = c.invalidate_by(|k| k.starts_with("user:alice:"));
    assert_eq!(removed, 2);
    assert_eq!(c.get(&"user:alice:1".into()), None);
    assert_eq!(c.get(&"user:alice:2".into()), None);
    assert_eq!(c.get(&"user:bob:1".into()), Some(3));
}

#[test]
fn invalidate_all_clears_everything() {
    let c = cache(8, 60, fixed_clock());
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    c.invalidate_all();
    assert_eq!(c.len(), 0);
    assert_eq!(c.get(&"a".into()), None);
    assert_eq!(c.get(&"b".into()), None);
}

#[test]
fn capacity_eviction_drops_lru_entry() {
    let c = cache(2, 60, fixed_clock());
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    // Touch "a" so "b" becomes the LRU.
    let _ = c.get(&"a".into());
    c.insert("c".into(), 3);
    assert_eq!(
        c.get(&"b".into()),
        None,
        "LRU entry must be evicted when inserting at capacity"
    );
    assert_eq!(c.get(&"a".into()), Some(1));
    assert_eq!(c.get(&"c".into()), Some(3));
}

#[test]
fn cleanup_expired_reclaims_only_expired() {
    let clk = fixed_clock();
    let c = cache(8, 60, clk.clone());
    c.insert("old".into(), 1);
    clk.advance_secs(30);
    c.insert("new".into(), 2);
    clk.advance_secs(31); // "old" is now 61s old; "new" is 31s old.
    let reclaimed = c.cleanup_expired();
    assert_eq!(reclaimed, 1);
    assert_eq!(c.get(&"old".into()), None);
    assert_eq!(c.get(&"new".into()), Some(2));
}

#[test]
fn insert_replaces_existing_value_and_resets_ttl() {
    let clk = fixed_clock();
    let c = cache(8, 60, clk.clone());
    c.insert("k".into(), 1);
    clk.advance_secs(59);
    c.insert("k".into(), 2);
    // Second insert resets TTL; should still be alive 30s after first
    // would have expired.
    clk.advance_secs(30);
    assert_eq!(c.get(&"k".into()), Some(2));
}

#[test]
fn deterministic_under_mock_clock() {
    // Pin the property the entire crate exists for: identical Clock
    // sequences produce identical cache state. If this test ever fails
    // it means a wall-clock leak crept into the implementation.
    let clk_a = fixed_clock();
    let clk_b = fixed_clock();
    let a = cache(8, 60, clk_a.clone());
    let b = cache(8, 60, clk_b.clone());

    for clk in [&clk_a, &clk_b] {
        // shared timeline
        let _ = clk;
    }

    a.insert("k".into(), 1);
    b.insert("k".into(), 1);
    clk_a.advance_secs(30);
    clk_b.advance_secs(30);
    assert_eq!(a.get(&"k".into()), b.get(&"k".into()));
    clk_a.advance_secs(31);
    clk_b.advance_secs(31);
    assert_eq!(a.get(&"k".into()), b.get(&"k".into()));
    assert_eq!(a.get(&"k".into()), None);
}

// ── Observability counters ──────────────────────────────────────────

#[test]
fn stats_starts_zeroed() {
    let c = cache(8, 60, fixed_clock());
    assert_eq!(c.stats(), CacheStats::default());
}

#[test]
fn stats_count_hits_and_misses() {
    let c = cache(8, 60, fixed_clock());
    let _ = c.get(&"absent".into()); // miss
    c.insert("k".into(), 1);
    let _ = c.get(&"k".into()); // hit
    let _ = c.get(&"k".into()); // hit
    let _ = c.get(&"other".into()); // miss
    let s = c.stats();
    assert_eq!(s.hits, 2);
    assert_eq!(s.misses, 2);
    assert_eq!(s.inserts, 1);
}

#[test]
fn stats_count_ttl_expired_as_miss() {
    let clk = fixed_clock();
    let c = cache(8, 60, clk.clone());
    c.insert("k".into(), 1);
    clk.advance_secs(61);
    let _ = c.get(&"k".into()); // TTL-expired → miss + invalidation (lazy sweep)
    let s = c.stats();
    assert_eq!(s.hits, 0);
    assert_eq!(s.misses, 1);
}

#[test]
fn stats_count_capacity_evictions() {
    let c = cache(2, 60, fixed_clock());
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    // No eviction yet; at capacity but not over.
    assert_eq!(c.stats().capacity_evictions, 0);
    c.insert("c".into(), 3); // displaces LRU
    assert_eq!(c.stats().capacity_evictions, 1);
}

#[test]
fn stats_count_invalidations() {
    let c = cache(8, 60, fixed_clock());
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    c.insert("user:alice:1".into(), 3);
    c.insert("user:alice:2".into(), 4);

    c.invalidate(&"a".into()); // +1
    c.invalidate(&"absent".into()); // +0 (no-op)
    let removed = c.invalidate_by(|k| k.starts_with("user:alice:")); // +2
    assert_eq!(removed, 2);
    c.invalidate_all(); // +1 (just "b" left)
    assert_eq!(c.stats().invalidations, 4);
}

#[test]
fn stats_cleanup_expired_counted_as_invalidations() {
    let clk = fixed_clock();
    let c = cache(8, 60, clk.clone());
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    clk.advance_secs(61);
    let n = c.cleanup_expired();
    assert_eq!(n, 2);
    assert_eq!(c.stats().invalidations, 2);
}

#[test]
fn reset_stats_zeroes_all_counters() {
    let c = cache(8, 60, fixed_clock());
    c.insert("k".into(), 1);
    let _ = c.get(&"k".into());
    let _ = c.get(&"absent".into());
    assert_ne!(c.stats(), CacheStats::default());
    c.reset_stats();
    assert_eq!(c.stats(), CacheStats::default());
}

// ── Single-flight (get_or_try_insert_with) ──────────────────────────

#[tokio::test]
async fn single_flight_first_call_runs_fetcher_and_caches() {
    let c = cache(8, 60, fixed_clock());
    let calls = Arc::new(AtomicU64::new(0));
    let v = c
        .get_or_try_insert_with::<_, _, std::convert::Infallible>("k".into(), {
            let calls = calls.clone();
            || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(99)
            }
        })
        .await
        .unwrap();
    assert_eq!(v, 99);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Second call hits the cache, not the fetcher.
    let v2 = c
        .get_or_try_insert_with::<_, _, std::convert::Infallible>("k".into(), {
            let calls = calls.clone();
            || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }
        })
        .await
        .unwrap();
    assert_eq!(v2, 99);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second call must not invoke fetcher"
    );
}

#[tokio::test]
async fn single_flight_concurrent_callers_share_one_fetch() {
    let c: Arc<ClockTtlCache<String, u32>> = Arc::new(cache(8, 60, fixed_clock()));
    let calls = Arc::new(AtomicU64::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());

    // Spawn N concurrent callers, all asking for the same key.
    // The fetcher waits on `proceed` so all N have time to enter
    // their respective `get_or_try_insert_with` calls before any
    // one resolves.
    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let c = c.clone();
        let calls = calls.clone();
        let started = started.clone();
        let proceed = proceed.clone();
        handles.push(tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>("k".into(), || {
                let calls = calls.clone();
                let started = started.clone();
                let proceed = proceed.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    started.notify_one();
                    proceed.notified().await;
                    Ok(7)
                }
            })
            .await
        }));
    }

    // Wait for the winning fetcher to start, then release it.
    started.notified().await;
    // Give the other N-1 callers a moment to join the in-flight cell.
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    proceed.notify_waiters();

    for h in handles {
        assert_eq!(h.await.unwrap().unwrap(), 7);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "single-flight must collapse N concurrent fetches into 1"
    );
    let s = c.stats();
    assert_eq!(s.single_flight_joins, (N - 1) as u64);
    assert_eq!(s.single_flight_errors, 0);
}

#[tokio::test]
async fn single_flight_concurrent_callers_distinct_keys_all_run() {
    let c: Arc<ClockTtlCache<String, u32>> = Arc::new(cache(8, 60, fixed_clock()));
    let calls = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for i in 0..4 {
        let c = c.clone();
        let calls = calls.clone();
        handles.push(tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>(
                format!("k{i}"),
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(i)
                },
            )
            .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "distinct keys must run distinct fetchers"
    );
    assert_eq!(c.stats().single_flight_joins, 0);
}

#[tokio::test]
async fn single_flight_error_removes_cell_so_retries_get_fresh_fetcher() {
    let c = cache(8, 60, fixed_clock());
    let attempts = Arc::new(AtomicU64::new(0));

    let r1: Result<u32, &'static str> = c
        .get_or_try_insert_with("k".into(), {
            let attempts = attempts.clone();
            || async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err("boom")
            }
        })
        .await;
    assert!(r1.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(c.stats().single_flight_errors, 1);

    // Second call must invoke a fresh fetcher (cell was cleaned up
    // on error). Returns Ok this time.
    let r2: Result<u32, &'static str> = c
        .get_or_try_insert_with("k".into(), {
            let attempts = attempts.clone();
            || async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            }
        })
        .await;
    assert_eq!(r2.unwrap(), 42);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "error must not pin the cell; retry must call fetcher again"
    );
}

#[tokio::test]
async fn single_flight_promotes_to_cache_after_load() {
    let c = cache(8, 60, fixed_clock());
    let _: Result<u32, std::convert::Infallible> = c
        .get_or_try_insert_with("k".into(), || async { Ok(123) })
        .await;
    // Plain `get` must hit (without invoking single-flight).
    assert_eq!(c.get(&"k".into()), Some(123));
    assert_eq!(c.stats().hits, 1);
}

#[tokio::test]
async fn pending_loads_count_reflects_in_flight_state() {
    let c = Arc::new(cache(8, 60, fixed_clock()));
    assert_eq!(c.pending_loads_count(), 0);

    // Park a fetcher mid-flight so we can observe the count.
    let started = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());
    let h = {
        let c = c.clone();
        let started = started.clone();
        let proceed = proceed.clone();
        tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>("k".into(), || async {
                started.notify_one();
                proceed.notified().await;
                Ok(7u32)
            })
            .await
        })
    };

    // Wait until the fetcher is actually mid-flight.
    started.notified().await;
    assert_eq!(
        c.pending_loads_count(),
        1,
        "exactly one in-flight load should be visible"
    );

    // Release the fetcher; verify the count drops to zero after resolution.
    proceed.notify_waiters();
    h.await.unwrap().unwrap();
    assert_eq!(
        c.pending_loads_count(),
        0,
        "guard must clean up after successful resolution"
    );
}

// ── Invalidate-wins-during-load ─────────────────────────────────────
//
// Pin the property: any of `invalidate`, `invalidate_by`,
// `invalidate_all` running during a single-flight load must prevent
// the loaded value from being re-cached. The caller that triggered
// the load still receives the value (we didn't abort the future);
// only the cache state must reflect post-invalidate semantics.

#[tokio::test]
async fn invalidate_during_load_blocks_cache_promotion() {
    let c: Arc<ClockTtlCache<String, u32>> = Arc::new(cache(8, 60, fixed_clock()));
    let started = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());

    let h = {
        let c = c.clone();
        let started = started.clone();
        let proceed = proceed.clone();
        tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>("k".into(), || async {
                started.notify_one();
                proceed.notified().await;
                Ok(99u32)
            })
            .await
        })
    };

    // Wait until the fetcher is mid-flight, then invalidate.
    started.notified().await;
    assert!(
        c.invalidate(&"k".into()),
        "invalidate must remove the in-flight cell"
    );
    // Release the fetcher; it completes successfully but must not
    // re-cache its result because the cell was removed.
    proceed.notify_waiters();
    assert_eq!(
        h.await.unwrap().unwrap(),
        99,
        "caller still receives the loaded value"
    );

    // Cache must reflect post-invalidate state; empty for "k".
    assert_eq!(
        c.get(&"k".into()),
        None,
        "post-invalidate cache must NOT contain the loaded value"
    );
}

#[tokio::test]
async fn invalidate_by_clears_matching_inflight_cells() {
    let c: Arc<ClockTtlCache<String, u32>> = Arc::new(cache(8, 60, fixed_clock()));
    let started = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());

    // Load for "user:alice:1"; should be invalidated.
    let h_alice = {
        let c = c.clone();
        let started = started.clone();
        let proceed = proceed.clone();
        tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>(
                "user:alice:1".into(),
                || async {
                    started.notify_one();
                    proceed.notified().await;
                    Ok(1u32)
                },
            )
            .await
        })
    };
    started.notified().await;

    // Load for "user:bob:1"; should NOT be invalidated.
    let started_bob = Arc::new(tokio::sync::Notify::new());
    let proceed_bob = Arc::new(tokio::sync::Notify::new());
    let h_bob = {
        let c = c.clone();
        let started = started_bob.clone();
        let proceed = proceed_bob.clone();
        tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>(
                "user:bob:1".into(),
                || async {
                    started.notify_one();
                    proceed.notified().await;
                    Ok(2u32)
                },
            )
            .await
        })
    };
    started_bob.notified().await;

    // Invalidate every alice key; bob unaffected.
    c.invalidate_by(|k| k.starts_with("user:alice:"));

    // Resolve both loads.
    proceed.notify_waiters();
    proceed_bob.notify_waiters();
    h_alice.await.unwrap().unwrap();
    h_bob.await.unwrap().unwrap();

    assert_eq!(
        c.get(&"user:alice:1".into()),
        None,
        "alice's invalidated load must not be re-cached"
    );
    assert_eq!(
        c.get(&"user:bob:1".into()),
        Some(2),
        "bob's load was not invalidated and should be cached"
    );
}

#[tokio::test]
async fn invalidate_all_blocks_all_in_flight_promotions() {
    let c: Arc<ClockTtlCache<String, u32>> = Arc::new(cache(8, 60, fixed_clock()));
    let started = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());

    const N: usize = 4;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let c = c.clone();
        let started = started.clone();
        let proceed = proceed.clone();
        handles.push(tokio::spawn(async move {
            c.get_or_try_insert_with::<_, _, std::convert::Infallible>(
                format!("k{i}"),
                || async move {
                    started.notify_one();
                    proceed.notified().await;
                    Ok(i as u32)
                },
            )
            .await
        }));
    }
    // Wait for at least one to start; in practice all N start before
    // any resolve because they all block on `proceed`.
    started.notified().await;
    // Give the others a moment to register.
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    c.invalidate_all();
    proceed.notify_waiters();
    for h in handles {
        h.await.unwrap().unwrap();
    }

    for i in 0..N {
        assert_eq!(
            c.get(&format!("k{i}")),
            None,
            "invalidate_all must block every in-flight promotion"
        );
    }
}

/// Pin the panic-safety property the RAII guard exists for: a fetcher
/// that panics while in flight must NOT leave its cell in the pending-
/// loads map. Without the guard, the `Arc<OnceCell<V>>` would be
/// pinned to the map for the rest of the process's lifetime; small
/// per-key, unbounded over time across distinct panicking keys.
#[tokio::test]
async fn fetcher_panic_cleans_up_inflight_cell() {
    let c: Arc<ClockTtlCache<String, u32>> = Arc::new(cache(8, 60, fixed_clock()));

    // Spawn a task whose fetcher panics; `tokio::spawn` catches the
    // panic and surfaces it via the JoinHandle.
    let c_clone = c.clone();
    let panic_handle = tokio::spawn(async move {
        c_clone
            .get_or_try_insert_with::<_, _, std::convert::Infallible>("k".into(), || async {
                panic!("intentional test panic; exercises RAII cleanup");
            })
            .await
    });
    let join = panic_handle.await;
    assert!(
        join.is_err() && join.unwrap_err().is_panic(),
        "fetcher panic must propagate via JoinError"
    );

    // The whole point: the in-flight cell must have been removed by
    // the guard's Drop during unwinding. Without the guard, this
    // assertion would fail (cell still parked in the map).
    assert_eq!(
        c.pending_loads_count(),
        0,
        "RAII guard must clear the in-flight cell on panic-unwind"
    );

    // Bonus check: a subsequent successful call must work cleanly.
    let v: Result<u32, std::convert::Infallible> = c
        .get_or_try_insert_with("k".into(), || async { Ok(42) })
        .await;
    assert_eq!(v.unwrap(), 42);
}

/// `len()` reflects inserted entries and `is_empty()` reports
/// `true` only at zero. Kills body-`0`, body-`true`/`false`, and
/// the `== → !=` mutations on the boundary in one suite.
#[test]
fn len_and_is_empty_track_insertions() {
    let clock = fixed_clock();
    let c = cache(8, 60, clock);
    assert_eq!(c.len(), 0);
    assert!(c.is_empty());

    c.insert("a".into(), 1);
    assert_eq!(c.len(), 1);
    assert!(!c.is_empty());

    c.insert("b".into(), 2);
    assert_eq!(c.len(), 2);
    assert!(!c.is_empty());

    c.invalidate_all();
    assert_eq!(c.len(), 0);
    assert!(c.is_empty());
}

/// `capacity()` returns the configured cap. Mutation `-> 1` would
/// fix the response at 1 regardless of construction.
#[test]
fn capacity_returns_configured_value() {
    let clock = fixed_clock();
    let c = cache(7, 60, clock);
    assert_eq!(c.capacity().get(), 7);
}

/// `cleanup_expired` uses `expires_at_micros < now_micros`. Pin the
/// strict comparison: an entry whose expiry exactly equals the
/// current time must NOT yet be evicted (it would be after the
/// next microsecond). Mutation `< → <=` would evict the boundary
/// entry.
#[test]
fn cleanup_expired_does_not_evict_at_exact_expiry() {
    let clock = fixed_clock();
    let c = cache(8, 60, clock.clone());
    c.insert("k".into(), 1);
    // advance EXACTLY to the TTL boundary; expires_at == now.
    clock.advance_secs(60);
    let reclaimed = c.cleanup_expired();
    assert_eq!(
        reclaimed, 0,
        "at expires_at == now the entry is still live (kills `< → <=`)"
    );
    // One microsecond later it's gone.
    clock.advance_secs(1);
    let reclaimed = c.cleanup_expired();
    assert_eq!(reclaimed, 1, "past the boundary the entry must be evicted");
}
