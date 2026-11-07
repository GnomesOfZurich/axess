//! Tests for [`ClockTtlCache::invalidate_entries_by`], the value-aware
//! invalidation, beside the key-only one in `tests.rs`.

use crate::ClockTtlCache;
use axess_clock::Clock;
use axess_clock::testing::MockClock;
use chrono::{TimeZone, Utc};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

fn cache() -> ClockTtlCache<String, u32> {
    let clock = Arc::new(MockClock::at(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ));
    ClockTtlCache::new(
        NonZeroUsize::new(8).unwrap(),
        Duration::from_secs(60),
        clock as Arc<dyn Clock>,
    )
}

/// The predicate sees the value, so entries go by what they hold: here
/// every entry holding an even number, whatever its key.
#[test]
fn invalidate_entries_by_removes_the_entries_whose_value_matches() {
    let c = cache();
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    c.insert("c".into(), 4);

    assert_eq!(c.invalidate_entries_by(|_, v| v % 2 == 0), 2);

    assert_eq!(c.get(&"a".into()), Some(1));
    assert_eq!(c.get(&"b".into()), None);
    assert_eq!(c.get(&"c".into()), None);
    assert_eq!(c.len(), 1);
}

/// It counts what it removed, so a predicate matching nothing reports
/// nothing and leaves the cache and the counter alone.
#[test]
fn invalidate_entries_by_matching_nothing_removes_nothing() {
    let c = cache();
    c.insert("a".into(), 1);

    assert_eq!(c.invalidate_entries_by(|_, v| *v > 100), 0);

    assert_eq!(c.len(), 1);
    assert_eq!(c.stats().invalidations, 0);
}

/// Every removal is an invalidation in the counters, as for the key-only
/// `invalidate_by`.
#[test]
fn invalidate_entries_by_counts_each_removal_as_an_invalidation() {
    let c = cache();
    c.insert("a".into(), 1);
    c.insert("b".into(), 2);
    c.insert("c".into(), 3);

    c.invalidate_entries_by(|k, _| k != "a");

    assert_eq!(c.stats().invalidations, 2);
}
