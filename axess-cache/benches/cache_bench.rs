//! Empirical baselines for `ClockTtlCache` covering the hot paths that
//! authz consumers exercise: read-on-hit, read-on-miss, insert, single-
//! flight load, parallel reads under contention.
//!
//! # Why these benches exist
//!
//! Iteration ROI for the deferred items in the queue (sharded mutex,
//! W-TinyLFU, async API, …) hinges on contention or hit-ratio data
//! that we don't have today. Committing these benches gives every
//! future iteration a regression target; both for "did my change
//! regress p50 latency on the hot path" and for "is the contention
//! actually painful enough to justify a sharded mutex."
//!
//! # Running
//!
//! ```bash
//! cargo bench -p axess-cache
//! cargo bench -p axess-cache -- get_hit          # filter by name
//! cargo bench -p axess-cache -- --save-baseline before
//! # … make a change …
//! cargo bench -p axess-cache -- --baseline before
//! ```
//!
//! Criterion writes raw samples and HTML reports to `target/criterion/`
//! (gitignored). The numbers below are *committed* documentation;
//! when an iteration moves them, update both this file and
//! `project_axess_cache_iteration_queue.md`.
//!
//! # Baseline (Apple Silicon; default criterion timings;
//! 3 s warmup + 5 s measurement per bench. Updates welcome on regression.)
//!
//! Numbers are wall-clock per single operation unless stated. Treat as
//! order-of-magnitude reference, not absolute targets; they vary by
//! 10–30% across machines and warmup. The async benches in particular
//! showed ~60% drift between runs at default timings (610 ns vs 380 ns
//! for `single_flight_cold_async` across two back-to-back runs); the
//! shape (relative ordering) is the more durable claim than absolute
//! numbers.
//!
//! | Bench                                | p50         |
//! |--------------------------------------|-------------|
//! | `get_hit`                            | ~9.3 ns     |
//! | `get_miss`                           | ~9.4 ns     |
//! | `insert_under_capacity` *            | ~216 ns     |
//! | `insert_with_eviction`               | ~26 ns      |
//! | `invalidate_present`                 | ~81 ns      |
//! | `parallel_hits_8_threads` (per op)   | ~77 ns      |
//! | `single_flight_cached_async`         | ~17 ns      |
//! | `single_flight_cold_async`           | ~610 ns     |
//!
//! \* `insert_under_capacity` is anomalously slow vs `insert_with_eviction`
//!    because the underlying `lru::LruCache` grows its HashMap
//!    incrementally during the bench (resize amortisation cost is
//!    measured here); the eviction bench runs against a pre-filled
//!    cache, so no resizing happens. Steady-state insert cost is closer
//!    to the eviction number.
//!
//! ## What the parallel number teaches us
//!
//! `parallel_hits_8_threads` clocks ~72 ns/op (per-thread average)
//! against `get_hit`'s ~10 ns/op single-threaded. That's a ~7x per-
//! thread slowdown, and total throughput across 8 threads (~14M
//! ops/s) is *worse* than single-threaded (~103M ops/s). The single
//! `parking_lot::Mutex` serializes every read.
//!
//! Implication for the deferred sharded-mutex iteration: the
//! contention bottleneck is real and quantified. **But** the gating
//! question is unchanged; does any current axess-cache consumer
//! sustain enough concurrent read pressure to feel this? Authz
//! entity caches in Gnomes today are read-heavy but not at 8-thread
//! sustained per-key contention. Defer until profiling shows it
//! mattering in practice.
//!
//! Numbers will be re-pinned by the iteration that runs them; treat
//! the *shape* (hit ≈ miss < invalidate < single-flight cold; mutex
//! contention is the dominant scaling cost) as the more durable claim.

use axess_cache::ClockTtlCache;
use axess_clock::Clock;
use axess_clock::testing::MockClock;
use chrono::{TimeZone, Utc};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::cell::Cell;
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Construct a fresh DST-pure clock anchored at a fixed wall-clock
/// instant. Benches don't advance time; TTL eviction is irrelevant
/// for performance characterisation, which is about the lock + LRU
/// + atomics overhead, not the expiry math.
fn fixed_clock() -> Arc<dyn Clock> {
    Arc::new(MockClock::at(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ))
}

fn build_cache(capacity: usize) -> ClockTtlCache<u64, u64> {
    ClockTtlCache::new(
        NonZeroUsize::new(capacity).unwrap(),
        Duration::from_secs(60),
        fixed_clock(),
    )
}

// ── Sequential micro-benchmarks ─────────────────────────────────────

fn bench_get_hit(c: &mut Criterion) {
    let cache = build_cache(1024);
    cache.insert(42, 99);
    c.bench_function("get_hit", |b| {
        b.iter(|| black_box(cache.get(black_box(&42))))
    });
}

fn bench_get_miss(c: &mut Criterion) {
    let cache = build_cache(1024);
    c.bench_function("get_miss", |b| {
        b.iter(|| black_box(cache.get(black_box(&42))))
    });
}

fn bench_insert_under_capacity(c: &mut Criterion) {
    // Capacity high enough that no eviction fires across the whole
    // bench run; isolates the insert cost from the eviction cost.
    let cache = build_cache(10_000_000);
    let counter = Cell::new(0u64);
    c.bench_function("insert_under_capacity", |b| {
        b.iter(|| {
            let k = counter.get().wrapping_add(1);
            counter.set(k);
            cache.insert(black_box(k), black_box(k));
        })
    });
}

fn bench_insert_with_eviction(c: &mut Criterion) {
    // Pre-fill to capacity so every subsequent insert displaces the
    // LRU entry; measures the "full cache" insert path that real
    // hot caches spend most of their time in.
    let cache = build_cache(64);
    for i in 0..64u64 {
        cache.insert(i, i);
    }
    let counter = Cell::new(1_000_000u64);
    c.bench_function("insert_with_eviction", |b| {
        b.iter(|| {
            let k = counter.get().wrapping_add(1);
            counter.set(k);
            cache.insert(black_box(k), black_box(k));
        })
    });
}

fn bench_invalidate_present(c: &mut Criterion) {
    // Setup pre-inserts the key per iteration; only the invalidate
    // call is timed (criterion::BatchSize::SmallInput excludes setup).
    let cache = build_cache(10_000_000);
    let counter = Cell::new(0u64);
    c.bench_function("invalidate_present", |b| {
        b.iter_batched(
            || {
                let k = counter.get().wrapping_add(1);
                counter.set(k);
                cache.insert(k, k);
                k
            },
            |k| {
                black_box(cache.invalidate(&k));
            },
            BatchSize::SmallInput,
        )
    });
}

// ── Parallel contention benchmark ──────────────────────────────────

fn bench_parallel_hits_8_threads(c: &mut Criterion) {
    let cache = Arc::new(build_cache(1024));
    cache.insert(42, 99);

    const THREADS: usize = 8;
    const OPS_PER_THREAD: usize = 1_000;
    const TOTAL_OPS: u64 = (THREADS * OPS_PER_THREAD) as u64;

    let mut group = c.benchmark_group("parallel_hits_8_threads");
    group.throughput(Throughput::Elements(TOTAL_OPS));
    // `iter_custom` lets us batch many parallel ops per bench
    // iteration. Without it, criterion would spawn 8 OS threads per
    // single-op timing; overhead dwarfs the work.
    group.bench_function("get_hit", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut handles = Vec::with_capacity(THREADS);
                for _ in 0..THREADS {
                    let cache = cache.clone();
                    handles.push(thread::spawn(move || {
                        for _ in 0..OPS_PER_THREAD {
                            black_box(cache.get(black_box(&42)));
                        }
                    }));
                }
                for h in handles {
                    h.join().unwrap();
                }
            }
            start.elapsed()
        })
    });
    group.finish();
}

// ── Single-flight async benchmarks ─────────────────────────────────

fn bench_single_flight_cached_async(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let cache = build_cache(1024);
    cache.insert(42, 99);

    c.bench_function("single_flight_cached_async", |b| {
        b.to_async(&rt).iter(|| async {
            cache
                .get_or_try_insert_with::<_, _, std::convert::Infallible>(42, || async { Ok(0u64) })
                .await
                .unwrap()
        })
    });
}

fn bench_single_flight_cold_async(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    // Capacity high enough that no eviction confounds the cold-load
    // measurement.
    let cache = build_cache(10_000_000);
    let counter = Cell::new(0u64);

    c.bench_function("single_flight_cold_async", |b| {
        // `async` (not `async move`) so `cache` and `counter` stay captured
        // by reference; `iter`'s closure is `FnMut`, can't move them.
        b.to_async(&rt).iter(|| async {
            let k = counter.get().wrapping_add(1);
            counter.set(k);
            cache
                .get_or_try_insert_with::<_, _, std::convert::Infallible>(
                    k,
                    || async move { Ok(k) },
                )
                .await
                .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_get_hit,
    bench_get_miss,
    bench_insert_under_capacity,
    bench_insert_with_eviction,
    bench_invalidate_present,
    bench_parallel_hits_8_threads,
    bench_single_flight_cached_async,
    bench_single_flight_cold_async,
);
criterion_main!(benches);
