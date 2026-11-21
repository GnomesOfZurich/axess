//! The bounds of the unknown-issuer cache: how long a miss is trusted, what
//! is never remembered, and what a full cache does.

use super::*;

const TTL_SECS: i64 = 30;

fn at(secs: i64) -> Timestamp {
    Timestamp::from_unix_seconds(1_700_000_000 + secs).unwrap()
}

fn cache() -> UnknownIssuers {
    UnknownIssuers::new(Duration::from_secs(TTL_SECS.unsigned_abs()))
}

fn issuer(n: usize) -> String {
    format!("https://idp-{n}.example.com")
}

#[test]
fn a_miss_is_trusted_until_its_time_is_up_and_not_at_it() {
    let cache = cache();
    cache.remember("https://idp.example.com", at(0), 7);

    assert!(cache.is_unknown("https://idp.example.com", at(0), 7));
    assert!(cache.is_unknown("https://idp.example.com", at(TTL_SECS - 1), 7));
    assert!(
        !cache.is_unknown("https://idp.example.com", at(TTL_SECS), 7),
        "the miss ends at its time, not after it"
    );
    assert!(
        !cache.is_unknown("https://idp.example.com", at(0), 8),
        "a source that changed is asked again"
    );
    assert!(!cache.is_unknown("https://other.example.com", at(0), 7));
}

#[test]
fn a_time_to_live_of_no_time_holds_nothing() {
    let cache = UnknownIssuers::new(Duration::ZERO);
    cache.remember("https://idp.example.com", at(0), 7);
    assert!(cache.lock().is_empty());
    assert!(!cache.is_unknown("https://idp.example.com", at(0), 7));
}

#[test]
fn a_time_to_live_past_the_range_is_trusted_until_the_source_changes() {
    let cache = UnknownIssuers::new(Duration::MAX);
    cache.remember("https://idp.example.com", at(0), 7);
    assert!(cache.is_unknown("https://idp.example.com", Timestamp::MAX, 7));
    assert!(!cache.is_unknown("https://idp.example.com", at(0), 8));
}

#[test]
fn an_issuer_at_the_length_bound_is_remembered_and_a_longer_one_is_not() {
    let cache = cache();
    let longest = "i".repeat(MAX_ISSUER_BYTES);
    let too_long = "i".repeat(MAX_ISSUER_BYTES + 1);
    cache.remember(&longest, at(0), 7);
    cache.remember(&too_long, at(0), 7);

    assert!(cache.is_unknown(&longest, at(1), 7));
    assert!(!cache.is_unknown(&too_long, at(1), 7));
    assert_eq!(cache.lock().len(), 1);
}

#[test]
fn a_full_cache_of_live_misses_does_not_remember_one_more() {
    let cache = cache();
    for n in 0..MAX_ENTRIES {
        cache.remember(&issuer(n), at(0), 7);
    }
    assert_eq!(cache.lock().len(), MAX_ENTRIES);

    cache.remember("https://one-more.example.com", at(1), 7);

    assert!(!cache.is_unknown("https://one-more.example.com", at(1), 7));
    assert_eq!(cache.lock().len(), MAX_ENTRIES, "the bound holds");
    assert!(cache.is_unknown(&issuer(0), at(1), 7));
    assert!(cache.is_unknown(&issuer(MAX_ENTRIES - 1), at(1), 7));
}

/// A full cache drops the misses whose time is up, the one that ends at
/// this very instant among them, keeps the live ones, and then has room.
#[test]
fn a_full_cache_makes_room_by_dropping_the_misses_whose_time_is_up() {
    let cache = cache();
    let half = MAX_ENTRIES / 2;
    for n in 0..half {
        cache.remember(&issuer(n), at(0), 7);
    }
    for n in half..MAX_ENTRIES {
        cache.remember(&issuer(n), at(20), 7);
    }
    assert_eq!(cache.lock().len(), MAX_ENTRIES);

    // The first half ends at this instant; the second half has 20 s left.
    let now = at(TTL_SECS);
    cache.remember("https://one-more.example.com", now, 7);

    assert!(cache.is_unknown("https://one-more.example.com", now, 7));
    assert_eq!(cache.lock().len(), MAX_ENTRIES - half + 1);
    assert!(!cache.lock().contains_key(&issuer(0)));
    assert!(cache.is_unknown(&issuer(half), now, 7));
    assert!(cache.is_unknown(&issuer(MAX_ENTRIES - 1), now, 7));
}
