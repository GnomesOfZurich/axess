//! `tests`: extracted from `fingerprint.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use axum::http::HeaderValue;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

fn parts(ua: Option<&str>, al: Option<&str>) -> Parts {
    let mut r: Request<()> = Request::new(());
    if let Some(v) = ua {
        r.headers_mut()
            .insert(header::USER_AGENT, HeaderValue::from_str(v).unwrap());
    }
    if let Some(v) = al {
        r.headers_mut()
            .insert(header::ACCEPT_LANGUAGE, HeaderValue::from_str(v).unwrap());
    }
    r.into_parts().0
}

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("tenant-1")
}

fn fixed_pepper() -> TenantPepperResolver {
    Arc::new(|t: &TenantId| {
        t.as_uuid();
        [42u8; 32]
    })
}

fn extractor() -> DefaultFingerprintExtractor {
    DefaultFingerprintExtractor::new(fixed_pepper())
}

/// Pin: same inputs → same hash. The whole point of the type.
#[test]
fn deterministic_on_same_inputs() {
    let ext = extractor();
    let r1 = parts(Some("Mozilla/5.0"), Some("en-CH;q=0.9,en;q=0.5"));
    let r2 = parts(Some("Mozilla/5.0"), Some("en-CH;q=0.9,en;q=0.5"));
    let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
    let f1 = ext.extract(&tenant(), &r1, ip).unwrap();
    let f2 = ext.extract(&tenant(), &r2, ip).unwrap();
    assert_eq!(f1, f2);
}

/// Pin: different UA → different hash.
#[test]
fn different_user_agents_yield_different_hashes() {
    let ext = extractor();
    let r1 = parts(Some("Mozilla/5.0 (Macintosh)"), None);
    let r2 = parts(Some("Mozilla/5.0 (Windows)"), None);
    let f1 = ext.extract(&tenant(), &r1, None).unwrap();
    let f2 = ext.extract(&tenant(), &r2, None).unwrap();
    assert_ne!(f1, f2);
}

/// Pin: missing UA → None (extractor refuses to fingerprint a
/// UA-less request, mirroring the threshold in
/// `session::binding::UserAgentBinding`).
#[test]
fn missing_ua_returns_none() {
    let ext = extractor();
    let r = parts(None, Some("en"));
    assert!(ext.extract(&tenant(), &r, None).is_none());
}

/// Pin: tenant scoping. Different tenants on the same request
/// produce different hashes (cross-tenant correlation defence).
#[test]
fn different_tenants_yield_different_hashes() {
    let pepper: TenantPepperResolver = Arc::new(|t: &TenantId| {
        // Trivial differentiation: hash the tenant id as the pepper.
        // Real deployments derive via HKDF.
        let mut k = [0u8; 32];
        for (i, b) in t.as_bytes().iter().copied().enumerate().take(32) {
            k[i] = b;
        }
        k
    });
    let ext = DefaultFingerprintExtractor::new(pepper);
    let r = parts(Some("Mozilla/5.0"), None);
    let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let t1 = crate::authn::ids::testing::tenant("acme");
    let t2 = crate::authn::ids::testing::tenant("globex");
    let f1 = ext.extract(&t1, &r, ip).unwrap();
    let f2 = ext.extract(&t2, &r, ip).unwrap();
    assert_ne!(
        f1, f2,
        "same physical device under two tenants must hash differently"
    );
}

/// Pin: IPv4 truncation to /24. `10.0.0.42` and `10.0.0.7`
/// hash identically (both /24-mapped to `10.0.0.0`); but
/// `10.0.1.42` differs.
#[test]
fn ipv4_truncates_to_slash_24() {
    let ext = extractor();
    let r = parts(Some("Mozilla/5.0"), None);
    let f_a = ext
        .extract(&tenant(), &r, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))))
        .unwrap();
    let f_b = ext
        .extract(&tenant(), &r, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))))
        .unwrap();
    let f_c = ext
        .extract(&tenant(), &r, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 42))))
        .unwrap();
    assert_eq!(f_a, f_b, "/24 partners must collide");
    assert_ne!(f_a, f_c, "different /24s must produce different hashes");
}

/// Pin: IPv6 truncation to /48.
#[test]
fn ipv6_truncates_to_slash_48() {
    let ext = extractor();
    let r = parts(Some("Mozilla/5.0"), None);
    let same_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x0001, 0, 0, 0, 0x42));
    let same_b = IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb8, 0xabcd, 0x9999, 0xffff, 0xffff, 0xffff, 0x07,
    ));
    let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xfeed, 0x0001, 0, 0, 0, 0x42));
    let f_a = ext.extract(&tenant(), &r, Some(same_a)).unwrap();
    let f_b = ext.extract(&tenant(), &r, Some(same_b)).unwrap();
    let f_c = ext.extract(&tenant(), &r, Some(other)).unwrap();
    assert_eq!(f_a, f_b, "/48 partners must collide");
    assert_ne!(f_a, f_c);
}

/// Pin: Accept-Language parsing extracts the top entry only,
/// strips the q-value, and lowercases. `en-CH;q=0.9,en;q=0.5` →
/// `"en-ch"`.
#[test]
fn accept_language_takes_top_priority_only() {
    let ext = extractor();
    let r1 = parts(Some("Mozilla/5.0"), Some("en-CH;q=0.9,en;q=0.5"));
    let r2 = parts(Some("Mozilla/5.0"), Some("en-ch"));
    let f1 = ext.extract(&tenant(), &r1, None).unwrap();
    let f2 = ext.extract(&tenant(), &r2, None).unwrap();
    assert_eq!(
        f1, f2,
        "top entry of Accept-Language with q-value must equal the bare top entry"
    );
}

/// mutant kill: pins `accept_language_top` against
/// constant-replacement mutants (`-> None`, `Some("")`,
/// `Some("xyzzy")`). Each constant-replacement mutant collapses
/// every request to a single AL contribution, so requests with
/// *different* AL headers would all hash identically. That's the
/// observable difference the previous tests didn't exercise. We
/// pin (a) presence-of-AL changes the hash vs absence-of-AL, and
/// (b) two distinct AL values produce two distinct hashes.
#[test]
fn accept_language_value_actually_feeds_the_hash() {
    let ext = extractor();
    let no_al = parts(Some("Mozilla/5.0"), None);
    let with_en = parts(Some("Mozilla/5.0"), Some("en-CH"));
    let with_de = parts(Some("Mozilla/5.0"), Some("de-CH"));

    let h_none = ext.extract(&tenant(), &no_al, None).unwrap();
    let h_en = ext.extract(&tenant(), &with_en, None).unwrap();
    let h_de = ext.extract(&tenant(), &with_de, None).unwrap();

    assert_ne!(
        h_none, h_en,
        "no Accept-Language vs en-CH must hash differently; \
             a constant-`None` mutant on accept_language_top would collapse them"
    );
    assert_ne!(
        h_en, h_de,
        "two distinct Accept-Language values must hash differently; \
             a constant-`Some(\"xyzzy\")` mutant would collapse them"
    );
}

/// mutant kill: `extract_from_request` is the
/// `Request<B>`-flavoured convenience wrapper; previous tests went
/// through `extract(&Parts, …)` directly so the helper body never
/// ran. Pin its happy path: round-trips a UA-bearing request and
/// matches what `extract` produces from the same headers.
#[test]
fn extract_from_request_matches_extract_on_equivalent_inputs() {
    let ext = extractor();
    let mut req: Request<()> = Request::new(());
    req.headers_mut().insert(
        header::USER_AGENT,
        HeaderValue::from_str("Mozilla/5.0").unwrap(),
    );
    req.headers_mut().insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_str("en-CH").unwrap(),
    );
    let from_request = ext
        .extract_from_request(&tenant(), &req, None)
        .expect("UA-bearing request must produce a fingerprint");

    let p = parts(Some("Mozilla/5.0"), Some("en-CH"));
    let from_parts = ext.extract(&tenant(), &p, None).unwrap();

    assert_eq!(
        from_request, from_parts,
        "extract_from_request must agree with extract on equivalent headers"
    );
}
