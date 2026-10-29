//! Clock steps, keyed log fingerprints, per-prefix bucket budgets, the login
//! identifier's scope and normalisation, and the remaining-requests header.

use super::*;
use axess_rng::testing::MockRng;
use keys::{GROUP_BUCKET_CAP, bound_key};

fn allowed(a: &Acquire) -> bool {
    matches!(a, Acquire::Allowed { .. })
}

fn client(ip: &str) -> keys::Target {
    resolve_target(&make_request_with_ip(ip), &KeyExtractor::ClientIp)
}

fn login_target(id: &str, peer: &str) -> keys::Target {
    let mut req = make_login_request(Some(id));
    req.extensions_mut()
        .insert(crate::client_ip::ClientIp::for_test(Some(
            peer.parse().unwrap(),
        )));
    resolve_target(&req, &KeyExtractor::LoginIdentifier)
}

/// Buckets written by a clock that then stepped back an hour are re-anchored
/// by the next sweep and aged out by the one two windows later. Before, they
/// survived every sweep until the clock caught up.
#[test]
fn buckets_dated_in_the_future_are_swept_after_the_clock_steps_back() {
    let store = test_store(5, Duration::from_secs(60));
    let t = t_zero();
    for i in 0..50 {
        store.try_acquire_at(&format!("k{i}"), t);
    }
    assert_eq!(store.len(), 50);

    let back = secs(t, -3_600);
    store.evict_expired_at(back);
    store.evict_expired_at(secs(back, 2 * 60));
    assert_eq!(store.len(), 0, "no bucket from the later clock is left");
    assert!(store.buckets.is_empty());
}

/// The logged fingerprint is keyed: it is not a plain hash of the key, and a
/// second layer instance produces a different one.
#[test]
fn the_log_fingerprint_is_keyed_per_instance() {
    use sha2::{Digest, Sha256};
    let layer = |seed| {
        RateLimitLayer::new(
            RateLimitConfig::builder()
                .key(KeyExtractor::LoginIdentifier)
                .rng(MockRng::new(seed))
                .build(),
        )
    };
    let (a, b) = (layer(1), layer(2));
    let key = "login:u:alice@example.com";
    let plain: String = Sha256::digest(key.as_bytes())
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let fa = a.log_fingerprint(key);
    assert_eq!(fa.len(), 16);
    assert_ne!(fa, plain, "a dictionary of plain hashes finds nothing");
    assert_ne!(fa, b.log_fingerprint(key), "differs between instances");
    assert_eq!(fa, a.log_fingerprint(key), "stable within an instance");
}

/// 300,000 addresses inside one /46 mint a bounded number of buckets, and a
/// client in an unrelated prefix is still admitted.
#[test]
fn one_ipv6_allocation_cannot_fill_the_table() {
    let store = test_store(100, Duration::from_secs(60));
    let now = t_zero();
    for i in 0..300_000u32 {
        // Four /48s (2001:db8:0..3::), 65,536 /64s each, a host part on top.
        let (p48, p64) = ((i % 4) as u16, ((i / 4) % 65_536) as u16);
        let ip = format!("2001:db8:{p48:x}:{p64:x}::{:x}", i % 7 + 1);
        store.try_acquire_target(&client(&ip), now);
    }
    assert!(
        store.len() <= 4 * (GROUP_BUCKET_CAP + 1),
        "{} buckets for one /46",
        store.len()
    );
    let outsider = store.try_acquire_target(&client("2001:db9::1"), now);
    assert!(allowed(&outsider), "an unrelated prefix is not locked out");
}

/// Past the group budget a new client shares the prefix's overflow bucket,
/// which is limited as one; clients that already had a bucket are unaffected.
#[test]
fn clients_past_the_group_budget_share_an_overflow_bucket() {
    let store = test_store(2, Duration::from_secs(60)).with_caps(1_000, 3);
    let now = t_zero();
    let ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"];
    for ip in &ips[..3] {
        assert!(allowed(&store.try_acquire_target(&client(ip), now)));
    }
    // Two more clients share one overflow bucket of two tokens.
    assert!(allowed(&store.try_acquire_target(&client(ips[3]), now)));
    assert!(allowed(&store.try_acquire_target(&client(ips[4]), now)));
    assert!(matches!(
        store.try_acquire_target(&client("10.0.0.6"), now),
        Acquire::Limited { .. }
    ));
    assert_eq!(store.len(), 4, "three own buckets and one overflow");
    // The first three keep their own budgets.
    assert!(allowed(&store.try_acquire_target(&client(ips[0]), now)));
    // Another /24 is unaffected.
    assert!(allowed(&store.try_acquire_target(&client("10.0.1.1"), now)));
}

/// Near the cap a new login identifier folds into its origin's overflow
/// bucket instead of taking a slot; identifiers that already had a bucket
/// keep it.
#[test]
fn new_login_identifiers_fold_into_an_overflow_bucket_near_the_cap() {
    let store = test_store(2, Duration::from_secs(60)).with_caps(100, 1024);
    let now = t_zero();
    for i in 0..75 {
        let t = login_target(&format!("user{i}@example.com"), "203.0.113.7");
        assert!(allowed(&store.try_acquire_target(&t, now)));
    }
    assert_eq!(store.len(), 75);
    for i in 0..500 {
        let t = login_target(&format!("minted{i}@example.com"), "203.0.113.7");
        store.try_acquire_target(&t, now);
    }
    assert_eq!(store.len(), 76, "all of them shared one overflow bucket");
    // A second origin has its own overflow.
    let other = login_target("minted0@example.com", "198.51.100.9");
    assert!(allowed(&store.try_acquire_target(&other, now)));
    assert_eq!(store.len(), 77);
    // An identifier that was admitted before the fold keeps its bucket.
    let first = login_target("user0@example.com", "203.0.113.7");
    assert!(allowed(&store.try_acquire_target(&first, now)));
    assert!(matches!(
        store.try_acquire_target(&first, now),
        Acquire::Limited { .. }
    ));
}

/// The same identifier in two tenants is two buckets; case variants within a
/// tenant are one; the unscoped key is different from any scoped one.
#[test]
fn login_identifiers_are_scoped_by_tenant() {
    let key = |tenant: Option<&str>, id: &str| {
        let ext = match tenant {
            Some(t) => {
                RateLimitLoginIdentifier::new_in_tenant(&axess_identity::testing::tenant(t), id)
            }
            None => RateLimitLoginIdentifier::new(id),
        }
        .unwrap();
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(ext);
        extract_key(&req, &KeyExtractor::LoginIdentifier)
    };
    assert_ne!(
        key(Some("tenant-a"), "Alice@x.com"),
        key(Some("tenant-b"), "alice@x.com")
    );
    assert_eq!(
        key(Some("tenant-a"), "Alice@x.com"),
        key(Some("tenant-a"), "alice@X.com")
    );
    assert_ne!(
        key(None, "alice@x.com"),
        key(Some("tenant-a"), "alice@x.com")
    );
}

/// Length prefixes stop one (tenant, identifier) pair spelling another.
#[test]
fn a_tenant_and_identifier_pair_cannot_spell_another() {
    let key = |tenant: &str, id: &str| {
        let ext =
            RateLimitLoginIdentifier::new_in_tenant(&axess_identity::testing::tenant(tenant), id)
                .unwrap();
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(ext);
        extract_key(&req, &KeyExtractor::LoginIdentifier)
    };
    assert_ne!(key("ab", "c:d"), key("ab:c", "d"));
}

/// A login name that spells a sentinel gets its own bucket and does not share
/// the one every request without an identifier lands in.
#[test]
fn a_login_name_spelling_a_sentinel_does_not_share_its_bucket() {
    let anonymous = extract_key(&make_login_request(None), &KeyExtractor::LoginIdentifier);
    for name in ["anon", "__anonymous__", "unknown"] {
        let named = extract_key(
            &make_login_request(Some(name)),
            &KeyExtractor::LoginIdentifier,
        );
        assert_ne!(named, anonymous, "{name}");
    }
    let unattributed = extract_key(&Request::new(Body::empty()), &KeyExtractor::PeerIp);
    let named = extract_key(
        &make_login_request(Some("unknown")),
        &KeyExtractor::LoginIdentifier,
    );
    assert_ne!(named, unattributed);
}

/// The shortened form of a long key is not a key an attacker can submit to
/// land in the long key's bucket.
#[test]
fn a_cut_key_cannot_be_submitted_as_an_uncut_one() {
    let long = "v".repeat(300);
    let cut = bound_key(long);
    assert_eq!(cut.len(), MAX_KEY_LEN);
    assert_ne!(bound_key(cut.clone()), cut, "the forged form is cut again");
}

/// Look-alike spellings of one identifier share a bucket: full-width letters,
/// and zero-width or soft-hyphen characters inserted in the middle.
#[test]
fn identifier_variants_that_a_store_may_fold_share_a_bucket() {
    let norm = |s: &str| {
        RateLimitLoginIdentifier::new(s)
            .unwrap()
            .as_str()
            .to_owned()
    };
    let plain = norm("alice@example.com");
    assert_eq!(norm("ＡＬＩＣＥ@Example.com"), plain);
    assert_eq!(norm("ali\u{200B}ce@example.com"), plain);
    assert_eq!(norm("ali\u{00AD}ce@exam\u{FEFF}ple.com"), plain);
    assert!(RateLimitLoginIdentifier::new("\u{200B}\u{200D}").is_none());
}

async fn remaining_header(svc: RateLimitService<OkService>, req: Request<Body>) -> Option<String> {
    let res = ServiceExt::oneshot(svc, req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    res.headers()
        .get("x-ratelimit-remaining")
        .map(|v| v.to_str().unwrap().to_owned())
}

/// A bucket other callers draw on does not report how much of it is left; a
/// caller's own bucket does.
#[tokio::test]
async fn the_remaining_header_is_sent_only_for_a_callers_own_bucket() {
    let login = make_login_service(10);
    assert_eq!(
        remaining_header(login, make_login_request(Some("alice"))).await,
        None,
        "an identifier bucket would tell others' attempt counts"
    );
    let own = make_service(10, Duration::from_secs(60));
    assert_eq!(
        remaining_header(own, make_request_with_ip("10.1.1.1")).await,
        Some("9".to_owned())
    );
}
