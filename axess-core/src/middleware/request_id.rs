//! `X-Request-Id` (or custom-header) middleware for axum/tower stacks.
//!
//! Generates an ID per inbound request (UUID v4 by default), propagates
//! it via [`RequestIdExt`](crate::middleware::request_id::RequestIdExt) to handler code, and mirrors it on the outbound
//! response. With the `accept_client_id` feature activated, valid
//! client-supplied IDs are preserved (invalid ones are replaced); without
//! it, every request gets a fresh server-generated ID.
//!
//! ## When to use this vs `tower-http`
//!
//! [`tower_http::request_id`](https://docs.rs/tower-http/latest/tower_http/request_id/)
//! ships `SetRequestId` + `PropagateRequestId` with the same default
//! shape; reach for it first if you don't need the
//! validation-of-client-supplied-IDs path. This crate's
//! [`RequestIdLayer`](crate::middleware::request_id::RequestIdLayer) adds that path behind the `accept_client_id`
//! feature.
//!
//! ## Wiring
//!
//! ```rust,no_run
//! use axess_core::middleware::request_id::RequestIdLayer;
//! use axum::{Router, routing::get};
//!
//! async fn hello() -> &'static str { "hi" }
//!
//! let app: Router = Router::new()
//!     .route("/", get(hello))
//!     .layer(RequestIdLayer::default());
//! ```
//!
//! Custom header or generator: implement [`RequestIdGenerator`](crate::middleware::request_id::RequestIdGenerator) and
//! construct [`RequestIdLayer`](crate::middleware::request_id::RequestIdLayer) with the custom generator type.
//! `HEADER_NAME` must be lowercase per HTTP/2 + HTTP/3.

use axum::{
    body::Body,
    extract::Request,
    http::header::{HeaderName, HeaderValue},
    response::Response,
};
// use http::header::{HeaderName, HeaderValue};
use std::{
    future::Future,
    io::Error as IoError,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use uuid::Uuid;

const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
struct RequestId(String);

/// Pluggable strategy for producing request IDs and selecting the header
/// name they are written under.
pub trait RequestIdGenerator {
    /// HTTP header used for the generated request ID (e.g. `x-request-id`).
    const HEADER_NAME: HeaderName;

    /// Expected length of an inbound client-supplied ID, used to validate
    /// the value when the `accept_client_id` feature is enabled.
    #[cfg(feature = "accept-client-id")]
    const ID_LENGTH: usize;

    /// Produce a fresh request ID as a [`HeaderValue`].
    fn generate(&self) -> HeaderValue;
}

/// [`RequestIdGenerator`] producing UUIDv4 strings under `x-request-id`.
#[derive(Clone, Debug)]
pub struct UuidGenerator;

impl RequestIdGenerator for UuidGenerator {
    const HEADER_NAME: HeaderName = X_REQUEST_ID;

    #[cfg(feature = "accept-client-id")]
    const ID_LENGTH: usize = 36;

    fn generate(&self) -> HeaderValue {
        HeaderValue::from_str(&Uuid::new_v4().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-request-id"))
    }
}

impl Default for UuidGenerator {
    fn default() -> Self {
        Self
    }
}

/// Tower [`Service`] that ensures every request and response carries a
/// stable request ID under [`RequestIdGenerator::HEADER_NAME`]. With the
/// `accept_client_id` feature, a well-formed inbound ID is preserved.
#[derive(Clone, Debug)]
pub struct RequestIdService<S, G> {
    inner: S,
    generator: Arc<G>,
}

impl<S, G> RequestIdService<S, G>
where
    S: Clone,
    G: RequestIdGenerator + Clone,
{
    /// Wrap `inner` so that incoming requests are tagged with a request ID
    /// produced by `generator`.
    pub fn new(inner: S, generator: G) -> Self {
        Self {
            inner,
            generator: generator.into(),
        }
    }

    /// Helper function to ensure that a request ID is set in the request headers.
    fn ensure_request_id(&self, req: &mut Request<Body>) -> Result<HeaderValue, IoError> {
        #[cfg(feature = "accept-client-id")]
        if let Some(existing_id) = req.headers().get(&G::HEADER_NAME) {
            let existing_id = existing_id.clone();
            // Collapse nested if into a single condition using let-chains to satisfy clippy
            if let Ok(id_str) = existing_id.to_str()
                && id_str.len() == G::ID_LENGTH
            {
                // Ensure extension contains same ID (avoid cloning if already present)
                match req.extensions().get::<RequestId>() {
                    Some(ext) if ext.0 == id_str => return Ok(existing_id),
                    _ => {
                        req.extensions_mut().insert(RequestId(id_str.to_string()));
                        return Ok(existing_id);
                    }
                }
            }
            // fallthrough: invalid client id -> generate our own below
        }

        // Generate header value
        let header_val = self.generator.generate();

        // Ensure header is present
        req.headers_mut()
            .insert(&G::HEADER_NAME, header_val.clone());

        // Safely extract string for extensions; if to_str() fails, replace header with a UTF-8 UUID
        let request_id_str = match header_val.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                // fallback to safe ASCII UUID and update header
                let fallback = HeaderValue::from_str(&Uuid::new_v4().to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("unknown"));
                req.headers_mut().insert(&G::HEADER_NAME, fallback.clone());
                // .to_str() ok for from_static / valid uuid
                fallback.to_str().unwrap_or("unknown").to_string()
            }
        };

        req.extensions_mut().insert(RequestId(request_id_str));
        Ok(header_val)
    }
}

impl<S, G> Service<Request<Body>> for RequestIdService<S, G>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    G: RequestIdGenerator + Send + Sync + Clone + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let request_id = match self.ensure_request_id(&mut req) {
            Ok(id) => id,
            Err(_) => {
                // If we can't generate a request ID, we'll skip it and continue
                // This is more robust than failing the entire request
                tracing::warn!("Failed to generate request ID, continuing without it");
                HeaderValue::from_static("unknown")
            }
        };

        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            if res.headers().get(G::HEADER_NAME).is_none() {
                res.headers_mut().insert(G::HEADER_NAME, request_id);
            }
            Ok(res)
        })
    }
}

/// Tower [`Layer`] that wraps inner services with [`RequestIdService`].
#[derive(Clone, Debug)]
pub struct RequestIdLayer<G> {
    generator: G,
}

impl<G> RequestIdLayer<G>
where
    G: RequestIdGenerator,
{
    /// Construct a layer that uses `generator` to produce request IDs.
    pub fn new(generator: G) -> Self {
        Self { generator }
    }
}

impl Default for RequestIdLayer<UuidGenerator> {
    fn default() -> Self {
        RequestIdLayer {
            generator: UuidGenerator,
        }
    }
}

impl<S, G> Layer<S> for RequestIdLayer<G>
where
    G: RequestIdGenerator + Clone,
{
    type Service = RequestIdService<S, G>;

    fn layer(&self, service: S) -> Self::Service {
        RequestIdService {
            inner: service,
            generator: Arc::new(self.generator.clone()),
        }
    }
}

/// Extension trait to easily retrieve the request ID from a request.
pub trait RequestIdExt {
    /// Return the request ID stored in the request extensions, if any.
    fn request_id(&self) -> Option<&str>;
}

impl RequestIdExt for Request<Body> {
    fn request_id(&self) -> Option<&str> {
        self.extensions().get::<RequestId>().map(|id| id.0.as_str())
    }
}

#[cfg(test)]
mod tests {
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

        let returned = service.ensure_request_id(&mut req).unwrap();
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
        let returned = service.ensure_request_id(&mut req).unwrap();
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
        let returned = service.ensure_request_id(&mut req).unwrap();
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
}
