//! [`DeviceResolver`]: the request-time bridge from raw HTTP requests to a
//! [`DeviceId`].
//!
//! # What an implementation does
//!
//! Per the design in [`docs/identity/device.md`](../../../../docs/identity/device.md),
//! the stock resolver,
//! [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver), finds
//! a device by proof and never by its fingerprint, which a client can copy:
//!
//! 1. Read the tenant, the signed-in person (if any; see [`SessionUser`])
//!    and the device the session was last bound to from the request
//!    extensions, and the entries of the device cookie (if present): one
//!    device id and token per device the browser profile holds.
//! 2. Compute the keyed [`FingerprintHash`](super::types::FingerprintHash)
//!    of the request (`User-Agent`, the first `Accept-Language` entry and the
//!    truncated client address, under the tenant's pepper). It is stored on
//!    a new device row and selects no existing one. A request it cannot be
//!    computed for (the default extractor needs a `User-Agent`) has no
//!    device when no person is signed in, and is otherwise resolved by
//!    steps 3 to 5; step 6 creates nothing for it, and it has no device.
//! 3. An entry proves its device when it names a device of the tenant that
//!    is not revoked and whose row lists the digest of the presented token
//!    (compared in constant time). Where device keys are enforced, a device
//!    that has a key is proven only by a request that proved that key: its
//!    token alone proves nothing, and the entry counts as not presented.
//!    For a signed-in person the entries are tried newest first, and the
//!    first that proves a device the person may use (one they own, or one
//!    with no owner) is answered as [`BoundDevice::Proven`]; this records a
//!    sighting ([`DeviceStore::record_sighting`](super::store::DeviceStore::record_sighting))
//!    and claims a device that has no owner. A guest's request writes
//!    nothing, and has a device only when its entries prove exactly one:
//!    with several proven (a profile several accounts share) it has none.
//! 4. Otherwise a request with no signed-in person has no device:
//!    `Ok(None)`.
//! 5. Otherwise, if the session was already bound to a device that still
//!    exists, is not revoked and belongs to the person, keep it and answer
//!    it as [`BoundDevice::Unproven`]: recognised, not proven.
//! 6. Otherwise [`DeviceStore::save`](super::store::DeviceStore::save) a new
//!    `Unknown` [`Device`](super::types::Device) owned by the person, with
//!    the digest of a freshly minted token on its row, emit
//!    `DeviceFirstSeen`, hand the cookie that carries the token to the
//!    session layer, and answer the device as [`BoundDevice::Proven`].
//!
//! The steps are
//! [`DeviceLifecycleService::resolve_or_keep`](crate::device::DeviceLifecycleService::resolve_or_keep).
//! A resolver of your own decides the same things for itself: which store
//! and which per-tenant pepper it holds, how it reads the tenant from the
//! request (an extension an upstream middleware set, the routing, TLS SNI),
//! and what it accepts as proof. Nothing emits `DeviceFingerprintMismatch`
//! for you: the stock resolver compares no fingerprint, so the event is
//! there for a resolver that does.
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
//! Errors returned by `resolve` are logged and leave the session's
//! `device_id` as it was; device resolution is best-effort and never causes
//! the request to fail.
//!
//! [`DeviceStore`]: super::store::DeviceStore

use crate::authn::ids::{DeviceId, TenantId, UserId};
use axum::http::request::Parts;
use std::future::Future;
use std::pin::Pin;

/// The person at the browser of a signed-in session, placed in the request
/// extensions by the session layer before a [`DeviceResolver`] runs: the
/// user the session signed in, and for a session an administrator is
/// impersonating the user in, the administrator
/// ([`AuthSession::impersonator`](crate::session::extractor::AuthSession::impersonator)).
/// A session in a step-up is still the signed-in session it began from and
/// carries the same person while the step is open.
///
/// The browser of an impersonated session is the administrator's, so the
/// device of its requests is the administrator's own and never one of the
/// user's. Absent for a guest and for a session part-way through a login,
/// so a resolver that reads it never attributes a device to a user who has
/// not proved who they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser(pub UserId);

/// The tenant the session signed in to, placed in the request extensions by
/// the session layer before a [`DeviceResolver`] runs, for a signed-in
/// session (in a step-up too).
///
/// It is the tenant the login service stored when it authenticated the session, so an
/// adopter whose tenant is a property of the signed-in user needs no
/// `TenantId` request extension for device tracking: the default `tenant_fn`
/// of [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
/// falls back to it. A `TenantId` extension, when the adopter sets one, is
/// read first. Absent for a guest and for a session part-way through a login,
/// like [`SessionUser`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTenant(pub TenantId);

/// The device the session was last bound to, placed in the request
/// extensions by the session layer for a signed-in session (in a step-up
/// too) that has one.
///
/// A request that presents no device token (a cross-site navigation does not
/// send the `SameSite=Strict` device cookie) keeps this device instead of
/// being given a new one, as a device the request did not prove
/// ([`BoundDevice::Unproven`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDevice(pub DeviceId);

/// Resolve (or create) the [`DeviceId`] associated with an inbound HTTP
/// request.
///
/// Implementors hold whatever state they need (a [`DeviceStore`], a tenant
/// fingerprint key registry, etc.) and produce a [`BoundDevice`] per request:
/// the device's id, and whether the request proved it.
///
/// # Failure semantics
///
/// `Ok(None)` means "no device could be associated with this request",
/// not an error. Reserve `Self::Error` for genuine storage / configuration
/// faults the caller should propagate. The session layer stores `Ok(_)` as
/// [`SessionData::device_id`](crate::session::SessionData::device_id)
/// (so `Ok(None)` unbinds a session that had a device); it logs `Err(_)`
/// and leaves a signed-in session's `device_id` as it was, so a transient
/// fault in the device store does not strip a session of its device
/// binding. A session with nobody signed in keeps no device on `Err(_)`:
/// its device was stamped on an earlier request, and the login this
/// request completes may be another person's.
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
    /// fails the request on `Err(_)`, it keeps a signed-in session's device.
    ///
    /// Takes [`axum::http::request::Parts`] rather than the full
    /// `Request<Body>` because `axum::body::Body` is `!Sync`; borrowing
    /// the request across an `await` boundary is forbidden in a `Send`
    /// future. The session layer splits the request before calling and
    /// reassembles it after.
    fn resolve(
        &self,
        parts: &Parts,
    ) -> impl Future<Output = Result<Option<BoundDevice>, Self::Error>> + Send;
}

/// The device a [`DeviceResolver`] bound a request to, and whether the client
/// proved it.
///
/// [`Proven`](Self::Proven) is only constructible from a
/// [`ProvenDevice`](crate::device::proof::ProvenDevice), which only a resolution by
/// [`resolve_or_keep`](crate::device::DeviceLifecycleService::resolve_or_keep)
/// or [`resolve_proven`](crate::device::DeviceLifecycleService::resolve_proven)
/// yields, for a request that presented the device's token or had the device
/// created for it, so a resolver cannot claim a proof it does not hold. A bare
/// [`DeviceId`] converts to [`Unproven`](Self::Unproven): the session keeps it
/// as a label for the device, and no lockout exemption reads it. The device a
/// session keeps on a request that presents no token is one of those.
///
/// The session layer stores the device's id and nothing else: whether it was
/// proven is asked of the resolver again on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundDevice {
    /// A device the client proved it holds.
    Proven(super::proof::ProvenDevice),
    /// A device found by other means (a fingerprint, a lookup).
    Unproven(DeviceId),
}

impl BoundDevice {
    /// The device's id, proven or not.
    pub fn id(&self) -> DeviceId {
        match self {
            Self::Proven(p) => p.id(),
            Self::Unproven(id) => *id,
        }
    }
}

impl From<DeviceId> for BoundDevice {
    fn from(id: DeviceId) -> Self {
        Self::Unproven(id)
    }
}

impl From<super::proof::ProvenDevice> for BoundDevice {
    fn from(proven: super::proof::ProvenDevice) -> Self {
        Self::Proven(proven)
    }
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

    async fn resolve(&self, parts: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
        tracing::trace!(
            target: "axess::device",
            method = %parts.method,
            route = %crate::logged_route::logged_route(&parts.extensions),
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
/// boxes the future and erases the error to a `tracing::warn!` log and
/// [`DeviceResolution::Failed`], honouring the documented best-effort
/// contract.
pub(crate) trait ErasedDeviceResolver: Send + Sync + 'static {
    fn resolve_erased<'a>(
        &'a self,
        parts: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = DeviceResolution> + Send + 'a>>;
}

/// What a [`DeviceResolver`] told the session layer, with the error erased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceResolution {
    /// The resolver answered: the request's device, or none.
    Resolved(Option<BoundDevice>),
    /// The resolver failed, so nothing is known about the request's device.
    /// The layer keeps a signed-in session's device as it was: a fault in
    /// the device store must not read as "no device" and strip the session's
    /// binding. With nobody signed in, the session keeps no device.
    Failed,
}

impl<R: DeviceResolver> ErasedDeviceResolver for R {
    fn resolve_erased<'a>(
        &'a self,
        parts: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = DeviceResolution> + Send + 'a>> {
        Box::pin(async move {
            match self.resolve(parts).await {
                Ok(id) => DeviceResolution::Resolved(id),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "DeviceResolver failed; a signed-in session keeps its device"
                    );
                    DeviceResolution::Failed
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

    /// The trace line names no part of the URI: a path or a query can
    /// carry a credential.
    #[tokio::test]
    async fn the_noop_resolver_logs_no_part_of_the_uri() {
        let printed = axess_testing::mock_tracing::LineCapture::install();
        let req: Request<Body> = Request::builder()
            .uri("/reset/marker-7c1e?token=marker-7c1e")
            .body(Body::empty())
            .unwrap();
        let parts = req.into_parts().0;
        assert_eq!(NoopDeviceResolver.resolve(&parts).await.unwrap(), None);
        let text = printed.text();
        assert!(!text.contains("marker-7c1e"), "{text}");
        assert!(text.contains("route=-"), "{text}");
    }

    #[tokio::test]
    async fn noop_resolver_always_returns_none() {
        let resolver = NoopDeviceResolver;
        let parts = empty_parts();
        let resolved = resolver.resolve(&parts).await.unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    async fn erased_resolver_reports_an_error_as_a_failure() {
        // A resolver that always errors is reported as failed to dyn-trait
        // callers, never as "no device"; the warn log is fire-and-forget.
        #[derive(Debug, thiserror::Error)]
        #[error("synthetic resolver failure")]
        struct BoomError;

        #[derive(Default)]
        struct BoomResolver;

        impl DeviceResolver for BoomResolver {
            type Error = BoomError;
            async fn resolve(&self, _: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
                Err(BoomError)
            }
        }

        let resolver = BoomResolver;
        let parts = empty_parts();
        let outcome = resolver.resolve_erased(&parts).await;
        assert_eq!(outcome, DeviceResolution::Failed);
    }

    #[tokio::test]
    async fn erased_resolver_passes_through_some() {
        struct StaticResolver(DeviceId);

        impl DeviceResolver for StaticResolver {
            type Error = std::convert::Infallible;
            async fn resolve(&self, _: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
                Ok(Some(self.0.into()))
            }
        }

        let id = axess_identity::testing::device("dev-static");
        let resolver = StaticResolver(id);
        let parts = empty_parts();
        let outcome = resolver.resolve_erased(&parts).await;
        assert_eq!(outcome, DeviceResolution::Resolved(Some(id.into())));
    }
}
