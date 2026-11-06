//! Wiring mistakes the limiter can see: a missing identity extension, a
//! missing peer address, an authenticated caller without the keyed header.

use super::*;
use crate::testing::mock_tracing::TracingCapture;
use tracing::Level;

fn peer_request(ip: [u8; 4]) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    req.extensions_mut()
        .insert(std::net::SocketAddr::from((ip, 4000)));
    req
}

/// A request that names no identity is limited with its own peer, so one
/// anonymous client cannot use up a budget everyone shares.
#[test]
fn a_missing_identity_extension_is_keyed_on_the_peer() {
    for extractor in [
        KeyExtractor::UserId,
        KeyExtractor::TenantId,
        KeyExtractor::LoginIdentifier,
    ] {
        let a = extract_key(&peer_request([203, 0, 113, 1]), &extractor);
        let b = extract_key(&peer_request([203, 0, 113, 2]), &extractor);
        assert_ne!(a, b, "{extractor:?}: two peers, two buckets");
        assert!(a.starts_with("anon:"), "{a}");
    }
}

#[test]
fn a_missing_identity_extension_is_reported() {
    let capture = TracingCapture::install();
    extract_key(&peer_request([203, 0, 113, 1]), &KeyExtractor::UserId);
    assert!(
        capture.contains_at_level(Level::WARN, "UserId"),
        "{:?}",
        capture.events()
    );
}

/// With no peer address every request shares one bucket, and each request
/// says so at error level instead of the first one only, at warn level.
#[test]
fn a_missing_peer_address_is_an_error_not_a_one_off_warning() {
    let capture = TracingCapture::install();
    let key = extract_key(&Request::new(Body::empty()), &KeyExtractor::PeerIp);
    assert_eq!(key, "ip:unknown");
    assert!(
        capture.contains_at_level(Level::ERROR, "no SocketAddr"),
        "{:?}",
        capture.events()
    );
}

/// An authenticated caller who leaves out the keyed header, or sends a value
/// that is not text, holds one fixed slot of its own, not a second budget in
/// the address bucket.
#[test]
fn an_authenticated_caller_without_the_header_has_a_fixed_user_slot() {
    let extractor = KeyExtractor::Header("x-api-key".into());
    let mut absent = header_request(Some(USER_A), "ignored");
    absent.headers_mut().remove("x-api-key");
    let mut binary = header_request(Some(USER_A), "ignored");
    binary
        .headers_mut()
        .insert("x-api-key", HeaderValue::from_bytes(b"\xff\xfe").unwrap());
    let a = extract_key(&absent, &extractor);
    let b = extract_key(&binary, &extractor);
    assert_eq!(a, b, "one slot for every unusable value");
    assert!(a.starts_with(&format!("h:{USER_A}:")), "{a}");
    let other = {
        let mut r = header_request(Some("00000000-0000-4000-8000-00000000000b"), "x");
        r.headers_mut().remove("x-api-key");
        extract_key(&r, &extractor)
    };
    assert_ne!(a, other, "per user");
}

fn service_for(extractor: KeyExtractor, allow_shared: bool) -> RateLimitService<OkService> {
    let builder = RateLimitConfig::builder().key(extractor);
    let builder = if allow_shared {
        builder.allow_shared_bucket()
    } else {
        builder
    };
    RateLimitLayer::new(builder.build()).layer(OkService)
}

/// A limiter whose identity extension is missing answers 500 and says so,
/// rather than charging the request to its peer's bucket.
#[tokio::test]
async fn a_missing_identity_extension_answers_500() {
    for extractor in [
        KeyExtractor::UserId,
        KeyExtractor::TenantId,
        KeyExtractor::LoginIdentifier,
    ] {
        let capture = TracingCapture::install();
        let res = ServiceExt::oneshot(
            service_for(extractor.clone(), false),
            peer_request([203, 0, 113, 1]),
        )
        .await
        .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{extractor:?}"
        );
        assert!(
            capture.contains_at_level(Level::ERROR, "no identity"),
            "{extractor:?}: {:?}",
            capture.events()
        );
    }
}

/// A peer-keyed limiter with no peer address answers 500.
#[tokio::test]
async fn a_missing_peer_address_answers_500() {
    let res = ServiceExt::oneshot(
        service_for(KeyExtractor::PeerIp, false),
        Request::new(Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// `allow_shared_bucket` restores the earlier behaviour: per peer for a
/// missing identity, one shared bucket for a missing peer.
#[tokio::test]
async fn allow_shared_bucket_restores_the_shared_bucket() {
    let res = ServiceExt::oneshot(
        service_for(KeyExtractor::UserId, true),
        peer_request([203, 0, 113, 1]),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = ServiceExt::oneshot(
        service_for(KeyExtractor::PeerIp, true),
        Request::new(Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// A request that has what the extractor reads is untouched.
#[tokio::test]
async fn a_present_identity_or_peer_is_limited_as_before() {
    let res = ServiceExt::oneshot(
        service_for(KeyExtractor::PeerIp, false),
        peer_request([203, 0, 113, 1]),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
