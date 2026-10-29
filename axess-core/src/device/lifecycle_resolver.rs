//! [`LifecycleDeviceResolver`]: turn-key [`DeviceResolver`] that wires
//! a [`DeviceFingerprintExtractor`] + [`DeviceLifecycleService`] into
//! the per-request flow the
//! [`SessionLayer`](crate::session::SessionLayer) expects.
//!
//! # Why this exists
//!
//! Without this, every consumer that wants device tracking has to
//! re-implement the same six-line glue: pull tenant, pull client IP,
//! call the extractor, ensure-or-create via the lifecycle, return the
//! id. That's the "SessionLayer composition glue" gap.
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
//! | `tenant_fn` | `parts.extensions.get::<TenantId>()` | when tenant lives elsewhere (subdomain, JWT claim, …) |
//! | `client_ip_fn` | the address [`client_ip::layer`](crate::client_ip::layer) resolved, or `None` without it (logged once at `warn`, because the address then leaves the fingerprint) | override only where the address comes from somewhere axess cannot see, such as a platform's own header |
//! | `user_fn` | the user the session layer authenticated ([`SessionUser`](crate::device::SessionUser)), `None` for a guest | when an upstream auth layer has already injected a `UserId` extension |
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
//! issues the cookie.
//!
//! # Tenant-less requests
//!
//! If `tenant_fn` returns `None`, the resolver short-circuits to
//! `Ok(None)`: there is no meaningful "device" without a tenant scope
//! (see `docs/identity/device.md` §10 on cross-tenant correlation).
//! Same for fingerprint computation: if the extractor returns `None`
//! (e.g. missing `User-Agent`), we skip lifecycle entirely.

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
use crate::device::resolver::DeviceResolver;
use crate::device::store::DeviceStore;

/// Function shape: pull a [`TenantId`] from request [`Parts`]. Default
/// reads `parts.extensions.get::<TenantId>()`.
type TenantFn = Arc<dyn Fn(&Parts) -> Option<TenantId> + Send + Sync>;

/// Function shape: pull the client IP from request [`Parts`]. Default
/// returns `None`; see module docs for the recommended `ConnectInfo`
/// / `X-Forwarded-For` overrides.
type ClientIpFn = Arc<dyn Fn(&Parts) -> Option<IpAddr> + Send + Sync>;

/// Function shape: pull a [`UserId`] from request [`Parts`]. Default
/// returns the [`SessionUser`](crate::device::SessionUser) the session layer
/// supplied for an authenticated session, `None` otherwise.
type UserFn = Arc<dyn Fn(&Parts) -> Option<UserId> + Send + Sync>;

/// Function shape: mint a fresh [`DeviceId`]. Unset by default, in which
/// case the id is a UUID v4 drawn from the resolver's RNG.
type NewIdFn = Arc<dyn Fn() -> DeviceId + Send + Sync>;

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
        }
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
    /// extensions and you want the device's `user_id` field populated
    /// at creation time. (Without this, devices are created at
    /// `user_id = None` and become "owned" only when the application
    /// updates them post-authn.)
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
    type Error = S::Error;

    async fn resolve(&self, parts: &Parts) -> Result<Option<DeviceId>, Self::Error> {
        // No tenant → no scoped device. Silent no-op.
        let Some(tenant) = (self.tenant_fn)(parts) else {
            return Ok(None);
        };
        let client_ip = (self.client_ip_fn)(parts);
        // Extractor returned None → request too thin to fingerprint
        // (e.g. no User-Agent). Silent no-op per the trait contract.
        let Some(fp) = self.extractor.extract(&tenant, parts, client_ip) else {
            return Ok(None);
        };
        let user = (self.user_fn)(parts);
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
            fingerprint: fp,
            presented: presented.as_ref(),
            session_device: session_device.as_ref(),
        };
        let resolved = self
            .lifecycle
            .resolve_proven(request, now, &*self.rng, move || match new_id_fn {
                Some(f) => f(),
                None => mint_device_id(&*rng),
            })
            .await?;
        let Some(resolved) = resolved else {
            return Ok(None);
        };
        if let Some(token) = resolved.issued {
            self.hand_over_cookie(parts, &resolved.id, &token);
        }
        Ok(Some(resolved.id))
    }
}

impl<E, S, C> LifecycleDeviceResolver<E, S, C>
where
    E: DeviceFingerprintExtractor,
    S: DeviceStore,
    C: Clock,
{
    /// Leave the `Set-Cookie` that carries a newly issued token for the
    /// session layer to send.
    fn hand_over_cookie(&self, parts: &Parts, id: &DeviceId, token: &DeviceToken) {
        let Some(slot) = parts.extensions.get::<DeviceCookieSlot>() else {
            tracing::warn!(
                "a device token was issued outside the session layer: nothing sends its \
                 cookie, so the device cannot be recognised again"
            );
            return;
        };
        match self.cookie.set_cookie(id, token) {
            Some(value) => slot.set(value),
            None => tracing::warn!("the device cookie could not be encoded and was not sent"),
        }
    }
}

// ── Defaults ─────────────────────────────────────────────────────────

fn default_tenant_fn() -> TenantFn {
    Arc::new(|parts: &Parts| parts.extensions.get::<TenantId>().cloned())
}

fn default_client_ip_fn(warned: Arc<AtomicBool>) -> ClientIpFn {
    // Whatever `client_ip::layer` resolved, and nothing if it is not
    // installed. It used to be unconditionally `None`, with the module
    // table suggesting the adopter read `X-Forwarded-For` here, which is
    // the header a caller writes.
    //
    // Without the layer the address silently drops out of the fingerprint,
    // so every client with the same headers anywhere in the world matches
    // one device. The first request that finds no layer says so, once.
    Arc::new(
        move |parts: &Parts| match parts.extensions.get::<crate::client_ip::ClientIp>() {
            Some(ip) => ip.get(),
            None => {
                if !warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "no client_ip layer is installed: the client address is left out of \
                         the device fingerprint, so clients with the same headers match one \
                         device from anywhere; install client_ip::layer or set \
                         with_client_ip_fn"
                    );
                }
                None
            }
        },
    )
}

fn default_user_fn() -> UserFn {
    // The user the session layer found authenticated on this session.
    // `None` for a guest, so a guest still resolves the fingerprint's
    // device; an authenticated user only ever gets a device they own.
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
