//! [`DeviceResolver`]: the request-time bridge from raw HTTP requests to a
//! [`DeviceId`].
//!
//! # What an implementation does
//!
//! Per the design in [`docs/identity/device.md`](../../../../docs/identity/device.md),
//! a production `DeviceResolver` performs:
//!
//! 1. Parse the long-lived device-binding cookie from `Cookie:` header (if
//!    present) → candidate [`DeviceId`].
//! 2. Compute the keyed [`FingerprintHash`](super::types::FingerprintHash)
//!    from `User-Agent`, `Accept-Language`, `Accept`, and any other inputs
//!    configured per tenant.
//! 3. If the cookie supplied an id, [`DeviceStore::load`](super::store::DeviceStore::load) it and verify the
//!    stored fingerprint matches → emit `DeviceFingerprintMismatch
//!    Suspicious` on mismatch, return `None` (caller invalidates the
//!    session). Match → return that id and call
//!    [`DeviceStore::record_sighting`](super::store::DeviceStore::record_sighting).
//! 4. If no cookie, [`DeviceStore::find_by_fingerprint`](super::store::DeviceStore::find_by_fingerprint) on `(tenant, hash)`
//!    → return that id (and emit `DeviceFirstSeen` if newly inserted).
//! 5. If neither path resolves, [`DeviceStore::save`](super::store::DeviceStore::save) a fresh `Unknown`
//!    [`Device`](super::types::Device) and return its id, emitting
//!    `DeviceFirstSeen`.
//!
//! All of (1) through (5) is application-glue: the resolver implementation owns
//! both the [`DeviceStore`] and the per-tenant fingerprint key registry,
//! and decides how to extract tenant context from request headers /
//! routing / TLS SNI / extensions populated by upstream middleware.
//!
//! # Layer integration
//!
//! [`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver)
//! wires a `DeviceResolver` into the session middleware. On every request
//! the layer calls [`DeviceResolver::resolve`] before the inner handler
//! runs and stamps the result onto
//! [`SessionData::device_id`](crate::session::SessionData::device_id),
//! marking the session modified iff the value changed (so the new id is
//! persisted on response).
//!
//! Errors returned by `resolve` are logged and treated as `None`; device
//! resolution is best-effort and never causes the request to fail.
//!
//! [`DeviceStore`]: super::store::DeviceStore

use crate::authn::ids::DeviceId;
use axum::http::request::Parts;
use std::future::Future;
use std::pin::Pin;

/// Resolve (or create) the [`DeviceId`] associated with an inbound HTTP
/// request.
///
/// Implementors hold whatever state they need (a [`DeviceStore`], a tenant
/// fingerprint key registry, etc.) and produce a `DeviceId` per request.
///
/// # Failure semantics
///
/// `Ok(None)` means "no device could be associated with this request",
/// not an error. Reserve `Self::Error` for genuine storage / configuration
/// faults the caller should propagate. The session layer treats `Ok(None)`
/// as a no-op (leaves
/// [`SessionData::device_id`](crate::session::SessionData::device_id) at
/// `None`); it logs `Err(_)` and continues with `None`.
///
/// # Tenant context
///
/// Implementations that need tenant scoping should read the [`TenantId`]
/// from `request.extensions()` populated by an upstream tenant-resolver
/// middleware. The trait does not pass tenant explicitly because the
/// session layer that drives the resolver is itself tenant-agnostic.
///
/// [`DeviceStore`]: super::store::DeviceStore
/// [`TenantId`]: crate::authn::ids::TenantId
pub trait DeviceResolver: Send + Sync + 'static {
    /// Storage / configuration error type; typically the
    /// [`DeviceStore::Error`](super::store::DeviceStore::Error) of the
    /// underlying store.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolve the device for `parts`. Always best-effort: returning
    /// `Ok(None)` is the documented "no device" outcome; the layer never
    /// fails the request on `Err(_)`.
    ///
    /// Takes [`axum::http::request::Parts`] rather than the full
    /// `Request<Body>` because `axum::body::Body` is `!Sync`; borrowing
    /// the request across an `await` boundary is forbidden in a `Send`
    /// future. The session layer splits the request before calling and
    /// reassembles it after.
    fn resolve(
        &self,
        parts: &Parts,
    ) -> impl Future<Output = Result<Option<DeviceId>, Self::Error>> + Send;
}

/// No-op resolver used as the default plug when the `device` feature is on
/// but the application has not configured a real
/// [`DeviceResolver`].
///
/// Always returns `Ok(None)`, leaving
/// [`SessionData::device_id`](crate::session::SessionData::device_id) at
/// `None`. Applications that want device tracking must replace this with
/// an implementation backed by a [`DeviceStore`](super::store::DeviceStore).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDeviceResolver;

impl DeviceResolver for NoopDeviceResolver {
    type Error = std::convert::Infallible;

    async fn resolve(&self, parts: &Parts) -> Result<Option<DeviceId>, Self::Error> {
        tracing::trace!(
            target: "axess::device",
            method = %parts.method,
            uri = %parts.uri,
            "NoopDeviceResolver: device tracking disabled, returning None",
        );
        Ok(None)
    }
}

// ── ErasedDeviceResolver ──────────────────────────────────────────────────────

/// Internal dyn-safe wrapper around [`DeviceResolver`].
///
/// The user-facing trait uses RPITIT (`impl Future<...>`) and an associated
/// `Error` type, neither of which is dyn-compatible today. The session
/// layer needs to hold an arbitrary resolver behind `Arc<dyn ...>` so the
/// layer's type signature does not pick up an extra generic parameter that
/// would ripple through every `SessionLayer::new` call site.
///
/// This trait closes the gap: a blanket impl for every `R: DeviceResolver`
/// boxes the future and swallows the error to a `tracing::warn!` log,
/// honouring the documented best-effort contract.
pub(crate) trait ErasedDeviceResolver: Send + Sync + 'static {
    fn resolve_erased<'a>(
        &'a self,
        parts: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = Option<DeviceId>> + Send + 'a>>;
}

impl<R: DeviceResolver> ErasedDeviceResolver for R {
    fn resolve_erased<'a>(
        &'a self,
        parts: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = Option<DeviceId>> + Send + 'a>> {
        Box::pin(async move {
            match self.resolve(parts).await {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "DeviceResolver failed; continuing with device_id = None"
                    );
                    None
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    fn empty_parts() -> Parts {
        let req: Request<Body> = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.into_parts().0
    }

    #[tokio::test]
    async fn noop_resolver_always_returns_none() {
        let resolver = NoopDeviceResolver;
        let parts = empty_parts();
        let resolved = resolver.resolve(&parts).await.unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    async fn erased_resolver_swallows_errors_to_none() {
        // A resolver that always errors should appear as `None` to
        // dyn-trait callers; the warn log is fire-and-forget.
        #[derive(Debug, thiserror::Error)]
        #[error("synthetic resolver failure")]
        struct BoomError;

        #[derive(Default)]
        struct BoomResolver;

        impl DeviceResolver for BoomResolver {
            type Error = BoomError;
            async fn resolve(&self, _: &Parts) -> Result<Option<DeviceId>, Self::Error> {
                Err(BoomError)
            }
        }

        let resolver = BoomResolver;
        let parts = empty_parts();
        let outcome = resolver.resolve_erased(&parts).await;
        assert_eq!(outcome, None);
    }

    #[tokio::test]
    async fn erased_resolver_passes_through_some() {
        struct StaticResolver(DeviceId);

        impl DeviceResolver for StaticResolver {
            type Error = std::convert::Infallible;
            async fn resolve(&self, _: &Parts) -> Result<Option<DeviceId>, Self::Error> {
                Ok(Some(self.0))
            }
        }

        let id = axess_identity::testing::device("dev-static");
        let resolver = StaticResolver(id);
        let parts = empty_parts();
        let outcome = resolver.resolve_erased(&parts).await;
        assert_eq!(outcome, Some(id));
    }
}
