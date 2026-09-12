//! `tests`: extracted from `lifecycle_resolver.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

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
