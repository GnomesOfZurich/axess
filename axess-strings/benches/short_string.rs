//! Why this crate exists rather than a dependency on `compact_str`.
//!
//! The workload is the one real consumer: `axess_events::subject`, whose
//! `Other` variant holds a subject id constructed once, then cloned per
//! event fan-out and compared on every routing decision. Clone count
//! dominates; construction happens once per event.
//!
//! Three representations:
//!
//! - `ShortString`: 24 bytes. Up to 22 inline, `&'static str` by
//!   reference, anything longer in an `Arc<str>` shared on clone.
//! - `CompactString`: 24 bytes. Up to 24 inline, `&'static str` by
//!   reference, anything longer in a plain owned heap buffer. It is
//!   mutable and growable, and holds no refcount, so cloning a heap
//!   value allocates and copies.
//! - `Arc<str>`: 16 bytes. Always allocates for an owned value; clone is
//!   a refcount bump. The baseline for "sharing, no inline buffer".
//!
//! The case that decides the question is `spiffe_42b`: above both inline
//! caps, where `ShortString` bumps a refcount and `CompactString` runs a
//! full `String`-shaped clone. Identifiers of that shape are the common
//! case in the event pipeline, so the gap there is the gap that matters.
//!
//! `long_22b` is the opposite corner, inline for both, and exists so a
//! regression that traded the hot case for the cold one is visible
//! rather than hidden behind a single headline number.

use axess_strings::ShortString;
use compact_str::CompactString;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

const SHORT: &str = "case-42";
/// Inline for both contenders: 22 bytes is exactly `ShortString`'s cap
/// and inside `CompactString`'s 24.
const LONG: &str = "inst-aapl-20260923-001";
/// The dominant real workload: `platform/domain/messaging/core` builds a
/// subject id from a principal's SPIFFE URI. At 42 bytes it exceeds both
/// inline buffers, so this is the case the design turns on.
const SPIFFE: &str = "spiffe://gnomes.local/feed-worker/ekekrantz";

const CASES: [(&str, &str); 3] = [
    ("short_7b", SHORT),
    ("long_22b", LONG),
    ("spiffe_42b", SPIFFE),
];

fn construct(c: &mut Criterion) {
    let mut group = c.benchmark_group("construct");
    for (label, input) in CASES {
        group.bench_with_input(BenchmarkId::new("ShortString", label), input, |b, s| {
            b.iter(|| black_box(ShortString::new(black_box(s))));
        });
        group.bench_with_input(BenchmarkId::new("CompactString", label), input, |b, s| {
            b.iter(|| black_box(CompactString::new(black_box(s))));
        });
        group.bench_with_input(BenchmarkId::new("Arc<str>", label), input, |b, s| {
            b.iter(|| black_box(Arc::<str>::from(black_box(s))));
        });
    }
    group.finish();
}

fn clone_per_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("clone");
    for (label, input) in CASES {
        let ss = ShortString::new(input);
        let cs = CompactString::new(input);
        let arc: Arc<str> = Arc::from(input);
        group.bench_function(BenchmarkId::new("ShortString", label), |b| {
            b.iter(|| black_box(black_box(&ss).clone()));
        });
        group.bench_function(BenchmarkId::new("CompactString", label), |b| {
            b.iter(|| black_box(black_box(&cs).clone()));
        });
        group.bench_function(BenchmarkId::new("Arc<str>", label), |b| {
            b.iter(|| black_box(black_box(&arc).clone()));
        });
    }
    group.finish();
}

fn equality(c: &mut Criterion) {
    let mut group = c.benchmark_group("eq");
    for (label, input) in CASES {
        // Compare against a distinct allocation with the same contents:
        // the pointer-equality fast path must not be what is measured.
        let (a, b_) = (ShortString::new(input), ShortString::new(input));
        let (ca, cb) = (CompactString::new(input), CompactString::new(input));
        let (aa, ab): (Arc<str>, Arc<str>) = (Arc::from(input), Arc::from(input));
        group.bench_function(BenchmarkId::new("ShortString", label), |bench| {
            bench.iter(|| black_box(black_box(&a) == black_box(&b_)));
        });
        group.bench_function(BenchmarkId::new("CompactString", label), |bench| {
            bench.iter(|| black_box(black_box(&ca) == black_box(&cb)));
        });
        group.bench_function(BenchmarkId::new("Arc<str>", label), |bench| {
            bench.iter(|| black_box(black_box(&*aa) == black_box(&*ab)));
        });
    }
    group.finish();
}

/// The operation `Arc<str>` cannot express.
///
/// A third of the `ShortString` construction sites in axess and platform
/// are `from_static` over a compile-time-known id: actor ids, taxonomy
/// tags, the SPIFFE URIs of fixed workloads. `ShortString` stores the
/// pointer, in a `const fn`, whatever the length. `Arc<str>` has no
/// equivalent: `Arc::from(s)` allocates and copies every time, and
/// cannot appear in a `const`.
///
/// This is the case that decides `ShortString` against a bare
/// `Arc<str>`, which otherwise wins on equality and on footprint.
fn construct_static(c: &mut Criterion) {
    let mut group = c.benchmark_group("from_static");
    for (label, input) in CASES {
        // `bench_function`, not `bench_with_input`: the latter hands the
        // closure a `&str` of anonymous lifetime, and `'static` is the
        // property under test.
        group.bench_function(BenchmarkId::new("ShortString", label), |b| {
            b.iter(|| black_box(ShortString::from_static(input)));
        });
        group.bench_function(BenchmarkId::new("CompactString", label), |b| {
            b.iter(|| black_box(CompactString::const_new(input)));
        });
        group.bench_function(BenchmarkId::new("Arc<str>", label), |b| {
            b.iter(|| black_box(Arc::<str>::from(black_box(input))));
        });
    }
    group.finish();
}

/// Cloning a `from_static` value: the actual hot path at the call site
/// that drove this design.
///
/// `platform/services/capture/producer` builds its actor subject once,
/// outside the pump loop, from a `&'static str`, and then clones it into
/// every event. So what runs per message is a clone of `Repr::Static`,
/// which copies a pointer and **performs no atomic operation at all**.
/// `Arc<str>` has no such form: every clone is an atomic increment on a
/// refcount, whatever the string.
///
/// Single-threaded, that is the difference below. Across threads sharing
/// one id it is larger than this measures, because the `Arc` refcount is
/// a contended cache line and this is not a cache line at all.
fn clone_static(c: &mut Criterion) {
    let mut group = c.benchmark_group("clone_static");
    for (label, input) in CASES {
        let ss = ShortString::from_static(input);
        let arc: Arc<str> = Arc::from(input);
        group.bench_function(BenchmarkId::new("ShortString", label), |b| {
            b.iter(|| black_box(black_box(&ss).clone()));
        });
        group.bench_function(BenchmarkId::new("Arc<str>", label), |b| {
            b.iter(|| black_box(black_box(&arc).clone()));
        });
    }
    group.finish();
}

/// Equality between two `from_static` values, which is what the event
/// router actually does: a subject id compared against a fixed tag.
fn equality_static(c: &mut Criterion) {
    let mut group = c.benchmark_group("eq_static");
    for (label, input) in CASES {
        let (a, b_) = (
            ShortString::from_static(input),
            ShortString::from_static(input),
        );
        let (aa, ab): (Arc<str>, Arc<str>) = (Arc::from(input), Arc::from(input));
        group.bench_function(BenchmarkId::new("ShortString", label), |bench| {
            bench.iter(|| black_box(black_box(&a) == black_box(&b_)));
        });
        group.bench_function(BenchmarkId::new("Arc<str>", label), |bench| {
            bench.iter(|| black_box(black_box(&*aa) == black_box(&*ab)));
        });
    }
    group.finish();
}

/// What `#![forbid(unsafe_code)]` actually costs.
///
/// With `unsafe` this would be `from_utf8_unchecked` and free. Without it,
/// `as_str` on an *inline* value revalidates UTF-8 on every call: the
/// `Static` and `Shared` forms already hold a `&str` and pay nothing.
/// Equality, ordering and hashing were moved off this path onto
/// `as_bytes`, so what remains is `Deref`, `Display` and anything handing
/// the value to a `&str` API.
///
/// This is the honest price of the safe representation, and the number to
/// look at before anyone proposes bringing the union back.
fn as_str_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("as_str");
    for (label, input) in CASES {
        let ss = ShortString::new(input);
        let cs = CompactString::new(input);
        let arc: Arc<str> = Arc::from(input);
        group.bench_function(BenchmarkId::new("ShortString", label), |b| {
            b.iter(|| black_box(black_box(&ss).as_str().len()));
        });
        group.bench_function(BenchmarkId::new("CompactString", label), |b| {
            b.iter(|| black_box(black_box(&cs).as_str().len()));
        });
        group.bench_function(BenchmarkId::new("Arc<str>", label), |b| {
            b.iter(|| black_box(black_box(&arc).len()));
        });
    }
    group.finish();
}

fn footprint(c: &mut Criterion) {
    // Not a timing measurement; recorded so the size trade-off and the
    // inline/heap split appear beside the numbers rather than in a
    // comment somewhere else. If `spiffe_42b` ever reports inline for
    // either contender, the clone numbers below it mean something
    // different and the commentary above needs revisiting.
    println!(
        "\nsize_of: ShortString={} CompactString={} Arc<str>={}",
        std::mem::size_of::<ShortString>(),
        std::mem::size_of::<CompactString>(),
        std::mem::size_of::<Arc<str>>(),
    );
    for (label, input) in CASES {
        println!(
            "{label}: ShortString inline={} CompactString inline={}",
            ShortString::new(input).is_inline(),
            !CompactString::new(input).is_heap_allocated(),
        );
    }
    let mut group = c.benchmark_group("noop");
    group.bench_function("noop", |b| b.iter(|| black_box(0u8)));
    group.finish();
}

criterion_group!(
    benches,
    construct,
    construct_static,
    clone_per_fanout,
    clone_static,
    equality,
    equality_static,
    as_str_access,
    footprint
);
criterion_main!(benches);
