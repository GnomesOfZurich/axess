//! `tests`: extracted from `request_id.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[derive(Clone)]
struct MockGenerator {
    counter: Arc<AtomicUsize>,
}

impl RequestIdGenerator for MockGenerator {
    const HEADER_NAME: HeaderName = X_REQUEST_ID;

    #[cfg(feature = "accept-client-id")]
    const ID_LENGTH: usize = 8;

    fn generate(&self) -> HeaderValue {
        let id = self.counter.fetch_add(1, Ordering::SeqCst);
        let id_str = format!("{:04}", id % 10000); // Ensures 4 digits, rolls over at 9999; enough for testing.
        let mock_id = format!("mock{}", id_str);
        HeaderValue::from_str(&mock_id).expect("Invalid header value")
    }
}

impl Default for MockGenerator {
    fn default() -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Clone)]
struct CustomHeaderGenerator;

impl RequestIdGenerator for CustomHeaderGenerator {
    const HEADER_NAME: HeaderName = HeaderName::from_static("x-custom-id");

    #[cfg(feature = "accept-client-id")]
    const ID_LENGTH: usize = 12;

    fn generate(&self) -> HeaderValue {
        // "custom-value" is ASCII-safe, use from_static to avoid Result handling/unwrapping
        HeaderValue::from_static("custom-value")
    }
}

impl Default for CustomHeaderGenerator {
    fn default() -> Self {
        Self
    }
}

#[derive(Clone)]
struct MockService;

impl Service<Request<Body>> for MockService {
    type Response = Response<Body>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Always ready; assert the reflexive waker identity so `cx`
        // is observed AND a future runtime that hands us a non-self
        // `&Waker` for `cx.waker()` would surface here.
        let waker = cx.waker();
        assert!(
            waker.will_wake(waker),
            "Waker::will_wake must hold reflexively"
        );
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        tracing::trace!(method = %req.method(), uri = %req.uri(), "mock service call");
        Box::pin(async move { Ok(Response::new(Body::empty())) })
    }
}

fn create_service() -> RequestIdService<MockService, MockGenerator> {
    RequestIdService::new(MockService, MockGenerator::default())
}

#[tokio::test]
/// Verifies that a request ID is generated when none is provided.
async fn test_request_id_generation() {
    let service = create_service();
    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");
    assert!(id.starts_with("mock"));
    assert_eq!(id.len(), 8);
}

#[tokio::test]
/// Ensures that a request ID is added to the response even if the inner service doesn't set one.
async fn test_missing_request_id_in_response() {
    let service = create_service();
    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    assert!(res.headers().contains_key(X_REQUEST_ID));
}

#[tokio::test]
/// Verifies that the service works correctly for multiple sequential requests, ensuring that
/// the generated IDs are unique.
async fn test_multiple_requests() {
    let service = create_service();
    let mut ids = Vec::new();
    for _ in 0..5 {
        let req = Request::new(Body::empty());
        let res = ServiceExt::oneshot(service.clone(), req)
            .await
            .expect("service call failed");
        let id = res
            .headers()
            .get(X_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
            .expect("response missing or contains invalid X_REQUEST_ID header")
            .to_string();
        assert!(!ids.contains(&id), "duplicate request id generated: {}", id);
        ids.push(id);
    }
}

#[cfg_attr(feature = "accept-client-id", tokio::test)]
#[cfg(feature = "accept-client-id")]
/// Feature gated check that a valid client-provided ID is accepted and preserved.
async fn test_accept_valid_client_id() {
    let service = create_service();
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("12345678"));

    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let header_value = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok());

    assert_eq!(header_value, Some("12345678"));
}

#[cfg_attr(feature = "accept-client-id", tokio::test)]
#[cfg(feature = "accept-client-id")]
/// Feature gated check to ensures that an invalid client-provided ID is rejected and replaced.
async fn test_reject_invalid_client_id() {
    let service = create_service();
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("invalid")); // Length 7, but invalid format
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");
    assert!(id.starts_with("mock"));
    assert_eq!(id.len(), 8);
}

#[cfg_attr(feature = "accept-client-id", tokio::test)]
#[cfg(feature = "accept-client-id")]
/// Feature gated with the `accept_client_id` feature. The service should generate its own ID
/// if the provided header value is badly formatted. This test ensures that the service
/// correctly rejects a client-provided ID that is too short.
async fn test_erroneous_id_length() {
    #[derive(Clone)]
    struct ErrorLengthGenerator;

    impl RequestIdGenerator for ErrorLengthGenerator {
        const HEADER_NAME: HeaderName = X_REQUEST_ID;

        #[cfg(feature = "accept-client-id")]
        const ID_LENGTH: usize = 5; // This is incorrect, should be 7

        fn generate(&self) -> HeaderValue {
            HeaderValue::from_static("12345")
        }
    }

    let service = RequestIdService::new(MockService, ErrorLengthGenerator);
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("1234567"));

    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let header_value = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");

    // The service should reject the client ID and use its own, even though it's the wrong length
    assert_eq!(header_value, "12345");
}

#[tokio::test]
#[cfg(not(feature = "accept-client-id"))]
/// Verifies that the service correctly overwrites an existing request ID if
/// the `accept_client_id` feature is disabled.
async fn test_request_id_overwrite() {
    let service = create_service();
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("existing-id"));
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");
    assert_eq!(id, "mock0000");
}

#[tokio::test]
/// Verifies that the request ID can be retrieved correctly from the request as a UUID when
/// using the default provided UUID v4 request ID generator.
async fn test_default_generator() {
    let service = RequestIdService::new(MockService, UuidGenerator);
    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");

    assert!(uuid::Uuid::parse_str(id).is_ok());
}

#[tokio::test]
/// Verifies that the request ID can be retrieved correctly from the request also when
/// using a custom header name.
async fn test_custom_header_name() {
    let service = RequestIdService::new(MockService, CustomHeaderGenerator);
    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let header_value = res
        .headers()
        .get("x-custom-id")
        .and_then(|v| v.to_str().ok());

    assert_eq!(header_value, Some("custom-value"));
}

#[tokio::test]
/// Verifies that multiple layers can be added to the service.
async fn test_multiple_layers() {
    let service = tower::ServiceBuilder::new()
        .layer(RequestIdLayer::default())
        .layer(RequestIdLayer::new(MockGenerator::default()))
        .layer(RequestIdLayer::new(CustomHeaderGenerator))
        .layer(RequestIdLayer::new(MockGenerator::default()))
        .layer(RequestIdLayer::default())
        .service(MockService);

    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let custom = res
        .headers()
        .get("x-custom-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing or invalid x-custom-id header");
    assert_eq!(custom, "custom-value");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("missing or contains invalid X_REQUEST_ID header");

    assert!(!id.starts_with("mock"));
    assert_eq!(id.len(), 36);
    assert!(uuid::Uuid::parse_str(id).is_ok());
}

#[tokio::test]
#[cfg(not(feature = "accept-client-id"))]
/// Verifies that multiple header layers can be added to the service. The second layer
/// should overwrite the first layer when `accept_client_id` feature isn't activated.
async fn test_duplicate_layers_overriden_without_accept_client_id() {
    let service = tower::ServiceBuilder::new()
        .layer(RequestIdLayer::new(MockGenerator {
            counter: Arc::new(AtomicUsize::new(2000)),
        }))
        .layer(RequestIdLayer::new(MockGenerator {
            counter: Arc::new(AtomicUsize::new(8888)),
        }))
        .service(MockService);

    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");

    assert_eq!(id, "mock8888");
}

/// (`accept_client_id` only): when an inbound request has a
/// well-formed client-supplied request ID AND a stale `RequestId`
/// extension whose inner value differs from the header, the
/// extension must be replaced so downstream handlers and logs see
/// the same ID the header carries. Pins three guard mutations on
/// `Some(ext) if ext.0 == id_str` at line 130:
/// - guard `-> true`: extension would be kept stale (skip insert).
/// - guard `-> false`: extension would be re-inserted on every
///   call (this matches the desired behaviour, but the symmetric
///   pin against `-> true` discriminates).
/// - inner `==` → `!=`: extension would be replaced when it
///   already matches and skipped when it differs.
///
/// Calls the private `ensure_request_id` directly so the test can
/// observe the post-call extension contents (axum's `oneshot`
/// consumes the request and only returns the response).
#[cfg(feature = "accept-client-id")]
#[test]
fn ensure_request_id_replaces_stale_extension_when_header_present() {
    let service = create_service();
    let mut req = Request::new(Body::empty());
    // Valid client-supplied header (length matches MockGenerator::ID_LENGTH = 8).
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("client-A"));
    // Pre-existing stale extension that differs from the header.
    req.extensions_mut()
        .insert(RequestId("STALE-VAL".to_string()));

    let returned = service.ensure_request_id(&mut req);
    assert_eq!(
        returned.to_str().unwrap(),
        "client-A",
        "must return the client-supplied ID"
    );

    // The extension MUST now match the client-supplied header value
    //; i.e., the stale extension was replaced.
    let ext = req
        .extensions()
        .get::<RequestId>()
        .expect("extension must remain present");
    assert_eq!(
        ext.0, "client-A",
        "stale extension must be replaced with the header value \
             (kills `match guard ... -> true` and `==` -> `!=` on line 130)"
    );

    // And when extension already matches the header, ensure_request_id
    // returns without changing it (sanity check the no-op path).
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("client-B"));
    req.extensions_mut()
        .insert(RequestId("client-B".to_string()));
    let returned = service.ensure_request_id(&mut req);
    assert_eq!(returned.to_str().unwrap(), "client-B");
    assert_eq!(
        req.extensions().get::<RequestId>().unwrap().0,
        "client-B",
        "matching extension must be preserved"
    );
}

/// (`accept_client_id` only): pins the length check
/// `id_str.len() == G::ID_LENGTH` against `==` → `!=` at line
/// 126:33. The mutant flips the predicate so EVERY length-mismatch
/// is accepted as a client ID, including absurdly short ones;
/// `existing_id` would be returned instead of generating a fresh
/// ID. This test sends a wrong-length client ID and asserts the
/// service replaces it with its own.
#[cfg(feature = "accept-client-id")]
#[test]
fn ensure_request_id_rejects_wrong_length_client_id() {
    let service = create_service();
    let mut req = Request::new(Body::empty());
    // Length 4; does NOT match MockGenerator::ID_LENGTH (8).
    req.headers_mut()
        .insert(X_REQUEST_ID, HeaderValue::from_static("abcd"));
    let returned = service.ensure_request_id(&mut req);
    let id = returned.to_str().unwrap();
    assert_ne!(
        id, "abcd",
        "wrong-length client ID must be rejected (kills `==` -> `!=` on line 126:33)"
    );
    assert!(
        id.starts_with("mock"),
        "rejected client ID must be replaced by the generator (got: {id})"
    );
}

/// `RequestIdExt::request_id` returns the inner string of
/// the `RequestId` extension when present, and `None` otherwise.
/// Pins the three body replacements (`-> None`, `-> Some("")`,
/// `-> Some("xyzzy")`); none of the existing tests called the
/// extension trait, so the accessor was unobserved.
#[test]
fn request_id_ext_returns_extension_value_or_none() {
    // No extension → None.
    let req = Request::new(Body::empty());
    assert!(
        req.request_id().is_none(),
        "missing extension must return None"
    );

    // Extension present → Some(inner).
    let mut req = Request::new(Body::empty());
    req.extensions_mut()
        .insert(RequestId("req-abc-123".to_string()));
    assert_eq!(
        req.request_id(),
        Some("req-abc-123"),
        "must return the exact extension value, not None / '' / 'xyzzy'"
    );
}

#[cfg_attr(feature = "accept-client-id", tokio::test)]
#[cfg(feature = "accept-client-id")]
/// Verifies that multiple header layers can be added to the service. The second layer
/// should NOT overwrite the first layer when `accept_client_id` feature is activated.
async fn test_duplicate_layers_not_overriden_with_accept_client_id() {
    let service = tower::ServiceBuilder::new()
        .layer(RequestIdLayer::new(MockGenerator {
            counter: Arc::new(AtomicUsize::new(5555)),
        }))
        .layer(RequestIdLayer::new(MockGenerator {
            counter: Arc::new(AtomicUsize::new(1000)),
        }))
        .service(MockService);

    let req = Request::new(Body::empty());
    let res = ServiceExt::oneshot(service, req)
        .await
        .expect("service call failed");

    let id = res
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .expect("response missing or contains invalid X_REQUEST_ID header");

    assert_eq!(id, "mock5555");
}
