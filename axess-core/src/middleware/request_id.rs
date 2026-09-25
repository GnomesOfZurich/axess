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
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use uuid::Uuid;

const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// The request id this layer settled on, in the request extensions.
///
/// The layer also writes it to
/// [`RequestIdGenerator::HEADER_NAME`],
/// so a reader that knows the header name can find it there. Anything that
/// does not, such as the audit context, reads this instead: the header is
/// whatever the generator chose to call it, and `x-request-id` is only the
/// default.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

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
    ///
    /// Implementations MUST return a value whose bytes are valid ASCII
    /// (so `HeaderValue::to_str` never fails on it): the layer mirrors
    /// the generated value into a `String` extension for downstream
    /// tracing without further validation.
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
        // UUIDv4 string is ASCII by construction: `HeaderValue::from_str`
        // cannot fail. `unwrap` here would be equally safe; `expect` names
        // the invariant so a future mutation to `generate` gets flagged.
        HeaderValue::from_str(&Uuid::new_v4().to_string())
            .expect("UUIDv4 string is always valid ASCII")
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

    /// Ensure a request ID is set in the request headers and mirrored in
    /// the `RequestId` extension. Returns the header value that downstream
    /// layers should echo back on the response.
    fn ensure_request_id(&self, req: &mut Request<Body>) -> HeaderValue {
        #[cfg(feature = "accept-client-id")]
        if let Some(existing_id) = req.headers().get(&G::HEADER_NAME) {
            let existing_id = existing_id.clone();
            if let Ok(id_str) = existing_id.to_str()
                && id_str.len() == G::ID_LENGTH
            {
                match req.extensions().get::<RequestId>() {
                    Some(ext) if ext.0 == id_str => return existing_id,
                    _ => {
                        req.extensions_mut().insert(RequestId(id_str.to_string()));
                        return existing_id;
                    }
                }
            }
            // fallthrough: invalid client id -> generate our own below
        }

        let header_val = self.generator.generate();
        req.headers_mut()
            .insert(&G::HEADER_NAME, header_val.clone());
        // Generators are required to emit ASCII (see `RequestIdGenerator`
        // and `UuidGenerator::generate`), so `to_str` cannot fail.
        let request_id_str = header_val
            .to_str()
            .expect("RequestIdGenerator must produce ASCII header values")
            .to_string();
        req.extensions_mut().insert(RequestId(request_id_str));
        header_val
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
        let request_id = self.ensure_request_id(&mut req);
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
mod tests;
