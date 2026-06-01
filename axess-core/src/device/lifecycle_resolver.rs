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
//! | `client_ip_fn` | always `None` | use ``parts.extensions.get::<axum::extract::ConnectInfo<SocketAddr>>().map(\|c\| c.0.ip())`` if your app calls `into_make_service_with_connect_info`, or read `X-Forwarded-For` if behind a trusted proxy |
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
    // Default ignores request shape; observe `parts` via a cheap no-op
    // method so the closure param isn't underscore-prefixed.
    Arc::new(|parts: &Parts| {
        parts.uri.host();
        None
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
mod tests {
    use super::*;
    use crate::device::fingerprint::DefaultFingerprintExtractor;
    use crate::device::store::MemoryDeviceStore;
    use crate::device::types::DeviceTrustLevel;
    use axess_clock::testing::MockClock;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::{TimeZone, Utc};
    use std::net::{Ipv4Addr, SocketAddr};

    fn fixed_pepper() -> super::super::fingerprint::TenantPepperResolver {
        Arc::new(|t: &TenantId| {
            t.as_uuid();
            [42u8; 32]
        })
    }

    fn make_resolver()
    -> LifecycleDeviceResolver<DefaultFingerprintExtractor, MemoryDeviceStore, MockClock> {
        let store = MemoryDeviceStore::new();
        let lifecycle = DeviceLifecycleService::new(store);
        let clock = MockClock::at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
        let extractor = DefaultFingerprintExtractor::new(fixed_pepper());
        LifecycleDeviceResolver::new(extractor, lifecycle, clock)
    }

    /// Stash the client IP under a private wrapper type in extensions
    /// so a per-test `client_ip_fn` can pull it back out. Mirrors what
    /// real apps do with `ConnectInfo<SocketAddr>` (which axess-core
    /// can't depend on directly; see module docs).
    #[derive(Clone)]
    struct TestClientIp(SocketAddr);

    fn req_with(ua: Option<&str>, tenant: Option<TenantId>, ip: Option<IpAddr>) -> Parts {
        let mut req: Request<Body> = Request::new(Body::empty());
        if let Some(v) = ua {
            req.headers_mut().insert(
                axum::http::header::USER_AGENT,
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        if let Some(t) = tenant {
            req.extensions_mut().insert(t);
        }
        if let Some(ip) = ip {
            req.extensions_mut()
                .insert(TestClientIp(SocketAddr::new(ip, 8080)));
        }
        req.into_parts().0
    }

    fn ip_from_test_extension(parts: &Parts) -> Option<IpAddr> {
        parts.extensions.get::<TestClientIp>().map(|c| c.0.ip())
    }

    /// Pin: no tenant in request → resolver returns None (no device
    /// created). Devices are tenant-scoped by design.
    #[tokio::test]
    async fn missing_tenant_yields_none() {
        let resolver = make_resolver();
        let parts = req_with(Some("Mozilla/5.0"), None, None);
        let resolved = resolver.resolve(&parts).await.unwrap();
        assert_eq!(resolved, None);
    }

    /// Pin: missing User-Agent (extractor returns None) → resolver
    /// returns None without touching the store.
    #[tokio::test]
    async fn missing_user_agent_yields_none() {
        let resolver = make_resolver();
        let tenant = crate::authn::ids::testing::tenant("t1");
        let parts = req_with(None, Some(tenant), None);
        let resolved = resolver.resolve(&parts).await.unwrap();
        assert_eq!(resolved, None);
    }

    /// Pin: full happy path. UA + tenant + IP → resolver creates a
    /// device at Unknown and returns its id. Re-running the same
    /// request returns the same id (find-by-fingerprint hits).
    #[tokio::test]
    async fn happy_path_creates_then_finds() {
        let resolver = make_resolver();
        let tenant = crate::authn::ids::testing::tenant("t1");
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));

        let parts1 = req_with(Some("Mozilla/5.0"), Some(tenant), ip);
        let id1 = resolver.resolve(&parts1).await.unwrap().expect("created");

        // Same request again; must find the existing device, not create a new one.
        let parts2 = req_with(Some("Mozilla/5.0"), Some(tenant), ip);
        let id2 = resolver.resolve(&parts2).await.unwrap().expect("found");
        assert_eq!(id1, id2, "second resolve must return the same DeviceId");

        // Confirm trust level is Unknown.
        let device = resolver
            .lifecycle
            .store()
            .load(&tenant, &id1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(device.trust_level, DeviceTrustLevel::Unknown);
    }

    /// Pin: `new_id_fn` override. Swap in a deterministic id generator
    /// (the DST use case) and confirm the resolver uses it on the
    /// create path.
    #[tokio::test]
    async fn new_id_fn_override_is_honoured() {
        let resolver =
            make_resolver().with_new_id_fn(|| crate::authn::ids::testing::device("dev-fixed"));
        let tenant = crate::authn::ids::testing::tenant("t1");
        let parts = req_with(Some("Mozilla/5.0"), Some(tenant), None);
        let id = resolver.resolve(&parts).await.unwrap().expect("created");
        assert_eq!(id, crate::authn::ids::testing::device("dev-fixed"));
    }

    /// Pin: `tenant_fn` override. Read tenant from a custom location
    /// (here: a header) instead of extensions. Confirms the hook
    /// actually changes the lookup path.
    #[tokio::test]
    async fn tenant_fn_override_is_honoured() {
        let resolver = make_resolver().with_tenant_fn(|parts: &Parts| {
            parts
                .headers
                .get("x-tenant")
                .and_then(|v| v.to_str().ok())
                .map(crate::authn::ids::testing::tenant)
        });
        let mut req: Request<Body> = Request::new(Body::empty());
        req.headers_mut().insert(
            axum::http::header::USER_AGENT,
            axum::http::HeaderValue::from_static("UA"),
        );
        req.headers_mut().insert(
            "x-tenant",
            axum::http::HeaderValue::from_static("from-header"),
        );
        let parts = req.into_parts().0;
        let id = resolver
            .resolve(&parts)
            .await
            .unwrap()
            .expect("created from header tenant");
        let device = resolver
            .lifecycle
            .store()
            .load(&crate::authn::ids::testing::tenant("from-header"), &id)
            .await
            .unwrap()
            .expect("device persisted under header-derived tenant");
        assert_eq!(
            device.tenant_id,
            crate::authn::ids::testing::tenant("from-header"),
            "override must drive which tenant scope receives the device"
        );
    }

    /// Pin: `user_fn` override. When set, the created Device row
    /// carries the resolved UserId instead of None.
    #[tokio::test]
    async fn user_fn_override_populates_device_user_id() {
        let resolver = make_resolver().with_user_fn(|parts: &Parts| {
            parts.uri.host();
            Some(crate::authn::ids::testing::user("u-from-extension"))
        });
        let tenant = crate::authn::ids::testing::tenant("t1");
        let parts = req_with(Some("Mozilla/5.0"), Some(tenant), None);
        let id = resolver.resolve(&parts).await.unwrap().expect("created");
        let device = resolver
            .lifecycle
            .store()
            .load(&tenant, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            device.user_id,
            Some(crate::authn::ids::testing::user("u-from-extension")),
            "user_fn must populate device.user_id at creation time"
        );
    }

    /// Pin: a custom `client_ip_fn` (the recommended pattern when not
    /// using `ConnectInfo`) feeds the fingerprint. Two requests with
    /// the same UA but different /24s produce different devices.
    #[tokio::test]
    async fn custom_client_ip_fn_distinguishes_subnets() {
        let resolver = make_resolver().with_client_ip_fn(ip_from_test_extension);
        let tenant = crate::authn::ids::testing::tenant("t1");
        let p1 = req_with(
            Some("Mozilla/5.0"),
            Some(tenant),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        );
        let p2 = req_with(
            Some("Mozilla/5.0"),
            Some(tenant),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 99, 1))),
        );
        let id_a = resolver.resolve(&p1).await.unwrap().expect("a");
        let id_b = resolver.resolve(&p2).await.unwrap().expect("b");
        assert_ne!(
            id_a, id_b,
            "different /24s on the same UA must yield different DeviceIds"
        );
    }

    /// Pin: default `client_ip_fn` returns None: IP doesn't influence
    /// fingerprint without an explicit override. Two requests on the
    /// same UA must collide regardless of (uninspected) IP.
    #[tokio::test]
    async fn default_client_ip_fn_returns_none_so_ip_does_not_change_device() {
        let resolver = make_resolver();
        let tenant = crate::authn::ids::testing::tenant("t1");
        let p1 = req_with(
            Some("Mozilla/5.0"),
            Some(tenant),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        );
        let p2 = req_with(
            Some("Mozilla/5.0"),
            Some(tenant),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 99, 1))),
        );
        let id_a = resolver.resolve(&p1).await.unwrap().expect("a");
        let id_b = resolver.resolve(&p2).await.unwrap().expect("b");
        assert_eq!(
            id_a, id_b,
            "default extractor ignores IP unless client_ip_fn is overridden"
        );
    }

    /// Pin: clock injection. The create path uses `clock.now()` for
    /// `first_seen_at` / `last_seen_at`. Confirms DST drives time.
    #[tokio::test]
    async fn create_uses_injected_clock_for_timestamps() {
        let store = MemoryDeviceStore::new();
        let lifecycle = DeviceLifecycleService::new(store);
        let frozen = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
        let clock = MockClock::at(frozen);
        let extractor = DefaultFingerprintExtractor::new(fixed_pepper());
        let resolver = LifecycleDeviceResolver::new(extractor, lifecycle, clock);

        let tenant = crate::authn::ids::testing::tenant("t1");
        let parts = req_with(Some("Mozilla/5.0"), Some(tenant), None);
        let id = resolver.resolve(&parts).await.unwrap().expect("created");
        let device = resolver
            .lifecycle
            .store()
            .load(&tenant, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(device.first_seen_at, frozen);
        assert_eq!(device.last_seen_at, frozen);
    }
}
