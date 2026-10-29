//! Key bounding: length, header sub-buckets and IPv6 prefixes.

use super::*;
use keys::{HEADER_SLOTS, bound_key, ip_bucket};

/// A key within the natural limit passes through unchanged. One between that
/// and `MAX_KEY_LEN` is cut, so no uncut key can equal a cut one.
#[test]
fn a_key_within_the_limit_is_unchanged() {
    let at_limit = "x".repeat(MAX_KEY_LEN - 70);
    assert_eq!(bound_key(at_limit.clone()), at_limit);
    let above = "x".repeat(MAX_KEY_LEN);
    assert_ne!(bound_key(above.clone()), above);
    let short = "y".repeat(100);
    assert_eq!(bound_key(short.clone()), short);
}

/// Two long identifiers that share their first 256 bytes used to share a
/// bucket, so one could drain the other's. They now differ.
#[test]
fn long_keys_sharing_a_prefix_get_different_buckets() {
    let prefix = "p".repeat(MAX_KEY_LEN);
    let a = bound_key(format!("{prefix}-victim-suffix"));
    let b = bound_key(format!("{prefix}-attacker-suffix"));
    assert_ne!(a, b);
    assert!(a.len() <= MAX_KEY_LEN && b.len() <= MAX_KEY_LEN);
    assert_eq!(a, bound_key(format!("{prefix}-victim-suffix")), "stable");
}

/// The cut lands inside a multi-byte character: the result is still valid
/// and still within the limit.
#[test]
fn a_cut_inside_a_multibyte_character_stays_valid_and_bounded() {
    let key = "a".repeat(MAX_KEY_LEN - 66) + &"🚀".repeat(20);
    let out = bound_key(key.clone());
    assert!(out.len() <= MAX_KEY_LEN, "len {}", out.len());
    assert_ne!(out, bound_key(format!("{key}x")));
}

fn user_request(user: &str, value: &str) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert("x-api-key", HeaderValue::from_str(value).unwrap());
    req.extensions_mut()
        .insert(RateLimitUserId(user.parse().unwrap()));
    req
}

const USER: &str = "00000000-0000-4000-8000-00000000000a";
const OTHER: &str = "00000000-0000-4000-8000-00000000000b";

/// One user sending thousands of distinct header values holds at most
/// `HEADER_SLOTS` keys, so the shared table cannot be filled from one
/// identity.
#[test]
fn distinct_header_values_of_one_user_map_to_a_bounded_set_of_keys() {
    let extractor = KeyExtractor::Header("x-api-key".into());
    let keys: std::collections::HashSet<String> = (0..5_000)
        .map(|i| extract_key(&user_request(USER, &format!("value-{i}")), &extractor))
        .collect();
    assert!(
        keys.len() as u64 <= HEADER_SLOTS,
        "{} keys for one user",
        keys.len()
    );
    assert!(keys.len() > 1, "values still spread over several slots");
}

/// A second user's slots are not the first user's.
#[test]
fn header_slots_are_per_user() {
    let extractor = KeyExtractor::Header("x-api-key".into());
    let a = extract_key(&user_request(USER, "v"), &extractor);
    let b = extract_key(&user_request(OTHER, "v"), &extractor);
    assert_ne!(a, b);
}

/// Spreading one user's header values cannot create more buckets in the
/// table than the slot count.
#[test]
fn a_header_flood_by_one_user_adds_at_most_the_slot_count_of_buckets() {
    let store = test_store(10, Duration::from_secs(60));
    let extractor = KeyExtractor::Header("x-api-key".into());
    for i in 0..5_000 {
        let key = extract_key(&user_request(USER, &format!("v{i}")), &extractor);
        store.try_acquire_at(&key, t_zero());
    }
    assert!(store.buckets.len() as u64 <= HEADER_SLOTS);
}

/// Every address inside one IPv6 /64 is one client; a different /64 is not.
#[test]
fn ipv6_clients_are_keyed_by_their_slash_64() {
    let a = ip_bucket("2001:db8:1:2::1".parse().unwrap());
    let b = ip_bucket("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap());
    let c = ip_bucket("2001:db8:1:3::1".parse().unwrap());
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a, "2001:db8:1:2::/64");
}

/// IPv4 is keyed as before, and an IPv4-mapped IPv6 address is the IPv4
/// client it carries.
#[test]
fn ipv4_is_unchanged_and_a_mapped_address_is_its_ipv4_client() {
    assert_eq!(ip_bucket("192.0.2.7".parse().unwrap()), "192.0.2.7");
    assert_eq!(ip_bucket("::ffff:192.0.2.7".parse().unwrap()), "192.0.2.7");
}

/// Through the real extractor: many addresses of one /64 share one bucket.
#[test]
fn the_client_ip_extractor_buckets_a_slash_64_together() {
    let extractor = KeyExtractor::ClientIp;
    let a = extract_key(&make_request_with_ip("2001:db8::1"), &extractor);
    let b = extract_key(&make_request_with_ip("2001:db8::2"), &extractor);
    assert_eq!(a, b);
}

/// The debug log carries a fingerprint, not the raw key.
#[test]
fn the_fingerprint_hides_the_key_and_is_stable() {
    let secret = [7u8; 32];
    let fp = keys::fingerprint(&secret, "alice@example.com");
    assert_eq!(fp.len(), 16);
    assert!(!fp.contains("alice"));
    assert_eq!(fp, keys::fingerprint(&secret, "alice@example.com"));
    assert_ne!(fp, keys::fingerprint(&secret, "bob@example.com"));
    assert_ne!(fp, keys::fingerprint(&[8u8; 32], "alice@example.com"));
}
