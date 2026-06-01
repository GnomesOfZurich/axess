# axess-cache

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-cache)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-cache) · [docs.rs](https://docs.rs/axess-cache) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

DST-friendly local hot-path cache primitives for [Axess](https://github.com/GnomesOfZurich/axess).

All time-dependent decisions go through an injected `Clock` from [`axess-clock`](https://crates.io/crates/axess-clock), so TTL eviction is reproducible under `MockClock`; the cache layer doesn't fight the rest of the workspace's deterministic-simulation posture.

The flagship type is `ClockTtlCache<K, V>`; a TTL + LRU cache that replaces [moka](https://crates.io/crates/moka) in any code path where DST or compliance forbids wall-clock background tasks. Used internally as the Cedar authz entity cache, but generic enough to wrap any adopter computation.

## Usage

```rust,no_run
use axess_cache::ClockTtlCache;
use axess_clock::SystemClock;
use std::{sync::Arc, time::Duration};

let cache: ClockTtlCache<String, Vec<u8>> = ClockTtlCache::builder()
    .capacity(10_000)
    .ttl(Duration::from_secs(60))
    .clock(Arc::new(SystemClock))
    .build();

cache.put("key".into(), vec![1, 2, 3]);
let v = cache.get(&"key".to_string());
```

## Features

- TTL + LRU with bounded capacity.
- Single-flight via `OnceCell` so concurrent misses for the same key share a single computation.
- `invalidate_by(predicate)` for scoped invalidation (per-principal,  per-tenant) without scanning the whole cache.
- Snapshotted `CacheStats` (hits, misses, evictions, invalidations) for periodic metric flush.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
