//! [`LifecycleDeviceResolver`]: turn-key [`DeviceResolver`] that wires
//! a [`DeviceFingerprintExtractor`] + [`DeviceLifecycleService`] into
//! the per-request flow the
//! [`SessionLayer`](crate::session::SessionLayer) expects.
//!
//! # Why this exists
//!
//! Without this, every consumer that wants device tracking has to
//! re-implement the same glue: pull tenant, pull client IP, call the
//! extractor, read the device cookie and the session's device, resolve by
//! proof through the lifecycle
//! ([`resolve_or_keep`](DeviceLifecycleService::resolve_or_keep)), hand the
//! cookie of a new device to the session layer, and return the device with
//! whether the request proved it. That's the "SessionLayer composition
//! glue" gap.
//! `LifecycleDeviceResolver` collapses it to a single
//! [`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver)
//! call.
//!
//! # Customisation hooks
//!
//! Four small functions distinguish a deployment:
//!
//! | Hook | Default | When to override |
//! |------|---------|------------------|
//! | `tenant_fn` | a `TenantId` in the request extensions, else the tenant the session authenticated into ([`SessionTenant`](crate::device::SessionTenant)) | when tenant lives elsewhere (subdomain, JWT claim, …) |
//! | `client_ip_fn` | the address [`client_ip::layer`](crate::client_ip::layer) resolved, or `None` without it (logged once at `warn`, because the address then leaves the fingerprint) | override only where the address comes from somewhere axess cannot see, such as a platform's own header |
//! | `user_fn` | the person at the browser of an authenticated session ([`SessionUser`](crate::device::SessionUser): its user, or the administrator impersonating that user), `None` for a guest | when an upstream auth layer has already injected a `UserId` extension |
//! | `new_id_fn` | a UUID v4 drawn from the resolver's RNG (`with_rng`, default `SystemRng`) | when you have an id scheme of your own; for a deterministic UUID scheme under test, seed the RNG instead |
//!
//! # Devices are matched by proof
//!
//! The fingerprint is a hint a client can copy, so it never selects an
//! existing device. A device is found by the token in the device cookie (see
//! [`proof`](crate::device::proof)). A request with no authenticated user
//! (a guest, or a session part-way through a login) is recognised by its
//! token if it presents a valid one, so step-up can judge it, and otherwise
//! has no device; it writes nothing. The first request that carries an
//! authenticated user and no valid token creates a device for that user and
//! issues the cookie. A later request of that session that presents no
//! token (a visit arriving from another site does not send the strict
//! cookie) keeps the session's device and is answered
//! [`BoundDevice::Unproven`]: the device is recognised, and only a request
//! that presents the token, or the one the device is created on, is answered
//! [`Proven`](BoundDevice::Proven).
//!
//! # Impersonated sessions
//!
//! The browser of a session an administrator is impersonating a user in is
//! the administrator's. The session layer hands the resolver the
//! administrator as the request's user, so the request's device is found
//! among the administrator's or created as the administrator's own, and no
//! device is created, claimed or sighted for the user the session runs as.
//!
//! # Requests with no tenant or no fingerprint
//!
//! For a guest, a `tenant_fn` that returns `None` short-circuits to
//! `Ok(None)`: there is no meaningful "device" without a tenant scope
//! (see "The per-tenant pepper" in `docs/identity/device.md` on
//! cross-tenant correlation). For a request that carries a user it is
//! [`LifecycleResolveError::TenantMissing`], a fault of the deployment's
//! `tenant_fn`, and the session keeps its device.
//! A request the extractor cannot fingerprint (the default extractor needs a
//! `User-Agent`) has no device when it is a guest's, whatever it presents.
//! One that carries a user is resolved as any other, by the token it
//! presents, the key it proved or the device its session keeps, since the
//! fingerprint has no part in finding a device; it is given no new device,
//! because a new row stores the fingerprint. A client that never sends a
//! `User-Agent` therefore has no device at all.
//!
//! A guest has no tenant by the default hook and that is silent. An
//! authenticated request with no tenant is a wiring fault, and a costly one:
//! no device is created, no cookie is issued, and every later judgement of
//! "a device this account has used" has nothing to stand on. The default
//! `tenant_fn` cannot produce it, since the session layer supplies the tenant
//! the session authenticated into; a `tenant_fn` of your own can. The first
//! request that carries a user and yields no tenant is reported once at
//! `error`. The first request that carries a user, cannot be fingerprinted
//! and finds no device is reported once at `warn`: a client that sends no
//! `User-Agent` makes one, so it need not be a fault of the deployment.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axess_clock::Clock;
use axess_rng::SecureRng;
use axum::http::request::Parts;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::fingerprint::DeviceFingerprintExtractor;
use crate::device::lifecycle::{DeviceLifecycleService, DeviceRequest};
use crate::device::proof::{DeviceCookieConfig, DeviceCookieSlot, DeviceToken};
use crate::device::resolver::{BoundDevice, DeviceResolver};
use crate::device::store::DeviceStore;

/// Function shape: pull a [`TenantId`] from request [`Parts`]. Default
/// reads a `TenantId` request extension, then the
/// [`SessionTenant`](crate::device::SessionTenant) the session layer supplied.
type TenantFn = Arc<dyn Fn(&Parts) -> Option<TenantId> + Send + Sync>;

/// Function shape: pull the client IP from request [`Parts`]. Default
/// returns the address [`client_ip::layer`](crate::client_ip::layer)
/// resolved, and `None` (with one warning) when that layer is not
/// installed; see the module docs for when to override it.
type ClientIpFn = Arc<dyn Fn(&Parts) -> Option<IpAddr> + Send + Sync>;

/// Function shape: pull a [`UserId`] from request [`Parts`]. Default
/// returns the [`SessionUser`](crate::device::SessionUser) the session layer
/// supplied for an authenticated session, `None` otherwise.
type UserFn = Arc<dyn Fn(&Parts) -> Option<UserId> + Send + Sync>;

/// Function shape: mint a fresh [`DeviceId`]. Unset by default, in which
/// case the id is a UUID v4 drawn from the resolver's RNG.
type NewIdFn = Arc<dyn Fn() -> DeviceId + Send + Sync>;

/// Why [`LifecycleDeviceResolver`] could not say which device a request
/// has. The session layer treats either as a failed resolution: the session
/// keeps the device it has.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleResolveError<E: std::error::Error + Send + Sync + 'static> {
    /// The request carries an authenticated user and the tenant hook
    /// answered no tenant: a fault of the deployment's `tenant_fn`.
    #[error("the device resolver found a user and no tenant")]
    TenantMissing,
    /// The device store could not answer.
    #[error(transparent)]
    Store(#[from] E),
}

/// Built-in [`DeviceResolver`] composing
/// [`DeviceFingerprintExtractor`] + [`DeviceLifecycleService`] with
/// the four pluggable hooks documented in the module-level docs.
///
/// Cheap to clone (every field is `Arc` or `Clone`); construct once at
/// startup, hand to
/// [`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver).
pub struct LifecycleDeviceResolver<E, S, C>
where
    E: DeviceFingerprintExtractor,
    S: DeviceStore,
    C: Clock,
{
    extractor: Arc<E>,
    lifecycle: DeviceLifecycleService<S>,
    clock: Arc<C>,
    tenant_fn: TenantFn,
    client_ip_fn: ClientIpFn,
    user_fn: UserFn,
    new_id_fn: Option<NewIdFn>,
    rng: Arc<dyn SecureRng>,
    cookie: DeviceCookieConfig,
    /// Set once the default client-address hook has found no address layer.
    ip_layer_warned: Arc<AtomicBool>,
    /// Set once a request that carries a user yielded no tenant.
    tenant_missing_reported: Arc<AtomicBool>,
    /// Set once a request that carries a user yielded no fingerprint and
    /// found no device.
    fingerprint_missing_reported: Arc<AtomicBool>,
}

impl<E, S, C> Clone for LifecycleDeviceResolver<E, S, C>
where
    E: DeviceFingerprintExtractor,
    S: DeviceStore,
    C: Clock,
{
    fn clone(&self) -> Self {
        Self {
            extractor: self.extractor.clone(),
            lifecycle: self.lifecycle.clone(),
            clock: self.clock.clone(),
            tenant_fn: self.tenant_fn.clone(),
            client_ip_fn: self.client_ip_fn.clone(),
            user_fn: self.user_fn.clone(),
            new_id_fn: self.new_id_fn.clone(),
            rng: self.rng.clone(),
            cookie: self.cookie.clone(),
            ip_layer_warned: self.ip_layer_warned.clone(),
            tenant_missing_reported: self.tenant_missing_reported.clone(),
            fingerprint_missing_reported: self.fingerprint_missing_reported.clone(),
        }
    }
}

impl<E, S, C> LifecycleDeviceResolver<E, S, C>
where
    E: DeviceFingerprintExtractor,
    S: DeviceStore,
    C: Clock,
{
    /// Construct with the three required collaborators and the
    /// documented defaults for the four pluggable hooks. Override any
    /// of them with `with_tenant_fn` / `with_client_ip_fn` /
    /// `with_user_fn` / `with_new_id_fn` before passing the resolver
    /// to the session layer.
    pub fn new(extractor: E, lifecycle: DeviceLifecycleService<S>, clock: C) -> Self {
        let ip_layer_warned = Arc::new(AtomicBool::new(false));
        Self {
            extractor: Arc::new(extractor),
            lifecycle,
            clock: Arc::new(clock),
            tenant_fn: default_tenant_fn(),
            client_ip_fn: default_client_ip_fn(ip_layer_warned.clone()),
            user_fn: default_user_fn(),
            new_id_fn: None,
            rng: Arc::new(axess_rng::SystemRng),
            cookie: DeviceCookieConfig::default(),
            ip_layer_warned,
            tenant_missing_reported: Arc::new(AtomicBool::new(false)),
            fingerprint_missing_reported: Arc::new(AtomicBool::new(false)),
        }
    }

    /// `true` once a request that carried a user and yielded no tenant has
    /// been reported.
    #[cfg(test)]
    pub(crate) fn reported_missing_tenant(&self) -> bool {
        self.tenant_missing_reported.load(Ordering::Relaxed)
    }

    /// `true` once a request that carried a user, could not be fingerprinted
    /// and found no device has been reported.
    #[cfg(test)]
    pub(crate) fn reported_missing_fingerprint(&self) -> bool {
        self.fingerprint_missing_reported.load(Ordering::Relaxed)
    }

    /// `true` once the default client-address hook has logged that no
    /// [`client_ip::layer`](crate::client_ip::layer) is installed.
    #[cfg(test)]
    pub(crate) fn warned_about_missing_ip_layer(&self) -> bool {
        self.ip_layer_warned.load(Ordering::Relaxed)
    }

    /// Override the tenant-extraction strategy.
    pub fn with_tenant_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&Parts) -> Option<TenantId> + Send + Sync + 'static,
    {
        self.tenant_fn = Arc::new(f);
        self
    }

    /// Override the client-IP extraction strategy.
    pub fn with_client_ip_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&Parts) -> Option<IpAddr> + Send + Sync + 'static,
    {
        self.client_ip_fn = Arc::new(f);
        self
    }

    /// Override the user-extraction strategy. Useful when an upstream
    /// auth layer has already injected a [`UserId`] into the request
    /// extensions. The default reads the user the session layer found
    /// authenticated ([`SessionUser`](crate::device::SessionUser)), so a
    /// device is created with its owner at the first authenticated request,
    /// and a request with no user creates none. Return `Some` only for a
    /// user who has proved who they are: the user returned here owns the
    /// device that is created.
    pub fn with_user_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&Parts) -> Option<UserId> + Send + Sync + 'static,
    {
        self.user_fn = Arc::new(f);
        self
    }

    /// Override the new-id minting strategy. Without it a new device's id
    /// is a UUID v4 drawn from the resolver's RNG; see
    /// [`with_rng`](Self::with_rng).
    pub fn with_new_id_fn<F>(mut self, f: F) -> Self
    where
        F: Fn() -> DeviceId + Send + Sync + 'static,
    {
        self.new_id_fn = Some(Arc::new(f));
        self
    }

    /// Choose how the device cookie is named and sent. The default is the
    /// strict `__Host-` form; see [`DeviceCookieConfig`].
    pub fn with_cookie(mut self, cookie: DeviceCookieConfig) -> Self {
        self.cookie = cookie;
        self
    }

    /// Replace the RNG that mints new device ids (default: `SystemRng`).
    ///
    /// Ignored when [`with_new_id_fn`](Self::with_new_id_fn) is set. A seeded
    /// RNG makes the sequence of device ids reproducible.
    pub fn with_rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }
}

impl<E, S, C> DeviceResolver for LifecycleDeviceResolver<E, S, C>
where
    E: DeviceFingerprintExtractor,
    S: DeviceStore,
    C: Clock,
{
    type Error = LifecycleResolveError<S::Error>;

    async fn resolve(&self, parts: &Parts) -> Result<Option<BoundDevice>, Self::Error> {
        let user = (self.user_fn)(parts);
        // No tenant → no scoped device. Silent for a guest. For a request
        // that carries a user it is a fault of the deployment, and a
        // failure: the session keeps the device it has, where an answer of
        // "no device" would take it away. It is explained once, loudly, and
        // every such request is a failed resolution in the layer's log.
        let Some(tenant) = (self.tenant_fn)(parts) else {
            if user.is_none() {
                return Ok(None);
            }
            if !self.tenant_missing_reported.swap(true, Ordering::Relaxed) {
                tracing::error!(
                    "the device resolver found a user and no tenant: no device is created \
                     and no device cookie is issued, so nothing can recognise this user's \
                     devices; make `tenant_fn` answer for every authenticated request, or \
                     leave the default, which reads the tenant the session authenticated into"
                );
            }
            return Err(LifecycleResolveError::TenantMissing);
        };
        let client_ip = (self.client_ip_fn)(parts);
        // A request too thin to fingerprint (the default extractor needs a
        // `User-Agent`): a guest's has no device. The fingerprint only goes on
        // a new row, so one that carries a user is found by its token, its key
        // or its session's device as any other, and given no new device.
        let fingerprint = self.extractor.extract(&tenant, parts, client_ip);
        if fingerprint.is_none() && user.is_none() {
            return Ok(None);
        }
        let presented = self.cookie.presented(&parts.headers);
        let session_device = parts
            .extensions
            .get::<crate::device::SessionDevice>()
            .map(|d| d.0);
        let now = self.clock.now();
        let new_id_fn = self.new_id_fn.clone();
        let rng = self.rng.clone();
        let request = DeviceRequest {
            tenant: &tenant,
            user: user.as_ref(),
            fingerprint,
            presented: &presented,
            session_device: session_device.as_ref(),
            keys: crate::device_key::KeyEnforcement::of(parts),
        };
        let resolved = self
            .lifecycle
            .resolve_or_keep(request, now, &*self.rng, move || match new_id_fn {
                Some(f) => f(),
                None => mint_device_id(&*rng),
            })
            .await?;
        let Some(resolved) = resolved else {
            // A guest's request may find no device. One that carries a user
            // finds none only when it has no fingerprint and so cannot be
            // given a new device; the client may send no `User-Agent`, so it
            // is explained once at `warn`.
            if fingerprint.is_none()
                && !self
                    .fingerprint_missing_reported
                    .swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    "the device resolver found a user and could not fingerprint the request \
                     (the default extractor needs a `User-Agent`), and the request proved no \
                     device and its session kept none: no device is created for it"
                );
            }
            return Ok(None);
        };
        if let Some(token) = resolved.issued() {
            self.hand_over_cookie(parts, &resolved.id(), token, &presented);
        }
        // Proven for a device the request proved; recognised, and no more,
        // for the device its session kept without presenting a token.
        Ok(Some(resolved.bound()))
    }
}

impl<E, S, C> LifecycleDeviceResolver<E, S, C>
where
    E: DeviceFingerprintExtractor,
    S: DeviceStore,
    C: Clock,
{
    /// Leave the `Set-Cookie` that carries a newly issued token for the
    /// session layer to send: the new device first, then the entries the
    /// request presented for the profile's other devices.
    fn hand_over_cookie(
        &self,
        parts: &Parts,
        id: &DeviceId,
        token: &DeviceToken,
        presented: &[crate::device::proof::PresentedDevice],
    ) {
        let Some(slot) = parts.extensions.get::<DeviceCookieSlot>() else {
            tracing::warn!(
                "a device token was issued outside the session layer: nothing sends its \
                 cookie, so the device cannot be recognised again"
            );
            return;
        };
        match self.cookie.set_cookie(id, token, presented) {
            Some(value) => slot.set(value),
            None => tracing::warn!("the device cookie could not be encoded and was not sent"),
        }
    }
}

// ── Defaults ─────────────────────────────────────────────────────────

fn default_tenant_fn() -> TenantFn {
    // The extension an adopter sets is the first choice; the tenant the
    // session authenticated into is the fallback, so an adopter whose tenant
    // is a property of the signed-in user needs no extension at all.
    Arc::new(|parts: &Parts| {
        parts.extensions.get::<TenantId>().cloned().or_else(|| {
            parts
                .extensions
                .get::<crate::device::SessionTenant>()
                .map(|t| t.0)
        })
    })
}

fn default_client_ip_fn(warned: Arc<AtomicBool>) -> ClientIpFn {
    // Whatever `client_ip::layer` resolved, and nothing if it is not
    // installed. It is never read from `X-Forwarded-For` here, which is
    // the header a caller writes.
    //
    // Without the layer the address silently drops out of the fingerprint,
    // so every client with the same headers anywhere in the world has one
    // fingerprint. The first request that finds no layer says so, once.
    Arc::new(
        move |parts: &Parts| match parts.extensions.get::<crate::client_ip::ClientIp>() {
            Some(ip) => ip.get(),
            None => {
                if !warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "no client_ip layer is installed: the client address is left out of \
                         the device fingerprint, so clients with the same headers share one \
                         fingerprint from anywhere; install client_ip::layer or set \
                         with_client_ip_fn"
                    );
                }
                None
            }
        },
    )
}

fn default_user_fn() -> UserFn {
    // The person at the browser of the session the layer found
    // authenticated: its user, or the administrator impersonating that
    // user. `None` for a guest, who is recognised by a valid device token
    // and otherwise has no device; an authenticated user only ever gets a
    // device they own.
    Arc::new(|parts: &Parts| {
        parts
            .extensions
            .get::<crate::device::SessionUser>()
            .map(|u| u.0)
    })
}

fn mint_device_id(rng: &dyn SecureRng) -> DeviceId {
    // `try_new` validates against control chars / oversize; a UUID
    // string never trips either, so the expect is total.
    DeviceId::try_new(axess_identity::mint_v4(rng).to_string())
        .expect("a UUID string is always a valid DeviceId")
}

#[cfg(test)]
mod tests;
