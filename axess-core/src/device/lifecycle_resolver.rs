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
//! | `client_ip_fn` | the address [`client_ip::layer`](crate::client_ip::layer) resolved, or `None` without it | override only where the address comes from somewhere axess cannot see, such as a platform's own header |
//! | `user_fn` | always `None` | when an upstream auth layer has already injected a `UserId` extension |
//! | `new_id_fn` | `uuid::Uuid::new_v4().to_string()` | when you have a deterministic id scheme (e.g. DST tests with `MockRng`) |
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

use axess_clock::Clock;
use axum::http::request::Parts;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::fingerprint::DeviceFingerprintExtractor;
use crate::device::lifecycle::DeviceLifecycleService;
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
/// returns `None` (the resolver runs *before* authn, so no user yet).
type UserFn = Arc<dyn Fn(&Parts) -> Option<UserId> + Send + Sync>;

/// Function shape: mint a fresh [`DeviceId`]. Default uses
/// `uuid::Uuid::new_v4()`.
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
    new_id_fn: NewIdFn,
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
        Self {
            extractor: Arc::new(extractor),
            lifecycle,
            clock: Arc::new(clock),
            tenant_fn: default_tenant_fn(),
            client_ip_fn: default_client_ip_fn(),
            user_fn: default_user_fn(),
            new_id_fn: default_new_id_fn(),
        }
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

    /// Override the new-id minting strategy. Default uses
    /// `uuid::Uuid::new_v4()`. Override for DST tests to inject a
    /// deterministic generator.
    pub fn with_new_id_fn<F>(mut self, f: F) -> Self
    where
        F: Fn() -> DeviceId + Send + Sync + 'static,
    {
        self.new_id_fn = Arc::new(f);
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
        let now = self.clock.now();
        let new_id_fn = self.new_id_fn.clone();
        let id = self
            .lifecycle
            .ensure_device(&tenant, user.as_ref(), fp, now, move || (new_id_fn)())
            .await?;
        Ok(Some(id))
    }
}

// ── Defaults ─────────────────────────────────────────────────────────

fn default_tenant_fn() -> TenantFn {
    Arc::new(|parts: &Parts| parts.extensions.get::<TenantId>().cloned())
}

fn default_client_ip_fn() -> ClientIpFn {
    // Whatever `client_ip::layer` resolved, and nothing if it is not
    // installed. It used to be unconditionally `None`, with the module
    // table suggesting the adopter read `X-Forwarded-For` here, which is
    // the header a caller writes.
    Arc::new(|parts: &Parts| {
        parts
            .extensions
            .get::<crate::client_ip::ClientIp>()
            .copied()
            .unwrap_or_default()
            .get()
    })
}

fn default_user_fn() -> UserFn {
    Arc::new(|parts: &Parts| {
        parts.uri.host();
        None
    })
}

fn default_new_id_fn() -> NewIdFn {
    Arc::new(|| {
        // `try_new` validates against control chars / oversize; a UUID
        // string never trips either, so the unwrap is total.
        DeviceId::try_new(uuid::Uuid::new_v4().to_string())
            .expect("uuid::Uuid::new_v4() always produces a DeviceId-valid string")
    })
}

#[cfg(test)]
mod tests;
