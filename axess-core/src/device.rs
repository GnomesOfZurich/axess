//! Device identity. Typed [`Device`] aggregate, three-stage assurance
//! ladder plus terminal `Revoked` state, fingerprint extraction,
//! lifecycle service, PII tokenisation, in-process cache decorator,
//! refresh-family cascade, retention sweep, and SQL / Valkey persistence
//! backends. Implements the proposal in
//! [`docs/identity/device.md`](../../../docs/identity/device.md). All
//! types are gated on the `device` feature; storage backends are
//! double-gated (`device,sqlite`, `device,postgres`, `device,valkey`).
//!
//! # Composition recipe
//!
//! Stores share the application's existing connection pool. Each
//! `Sqlite*Store` / `Postgres*Store` / `Valkey*Store` takes the pool by
//! value so one pool serves session + device stores. Typical wiring:
//!
//! ```ignore
//! // 1. shared persistence
//! let pool   = SqlitePool::connect(&db_url).await?;
//! let crypto = SessionCrypto::new(envelope_key);
//!
//! // 2. session + device stores on the same pool
//! let sessions = SqliteSessionStore::new(pool.clone(), crypto.clone());
//! let devices  = SqliteDeviceStore::new(pool.clone(), crypto);
//! sessions.init_schema().await?;
//! devices.init_schema().await?;
//!
//! // 3. opt-in: hot-path cache decorator
//! let cached_devices = CachedDeviceStore::new(devices, ttl, capacity);
//!
//! // 4. opt-in: lifecycle service (ensure-or-create + promote-on-authn)
//! let lifecycle = DeviceLifecycleService::new(cached_devices, NoopDeviceEventSink, clock);
//!
//! // 5. opt-in: Axum extractor that resolves the device per request
//! let extractor = DefaultFingerprintExtractor::new(per_tenant_pepper);
//! let resolver  = LifecycleDeviceResolver::new(lifecycle, extractor, clock);
//!
//! router.layer(SessionLayer::new(sessions, key))
//!       .layer(resolver);
//! ```

pub mod cache;
pub mod cascade;
pub mod events;
pub mod fingerprint;
pub mod lifecycle;
pub mod lifecycle_resolver;
pub mod pii;
pub mod resolver;
pub mod storage;
pub mod store;
pub mod types;

pub use cache::CachedDeviceStore;
pub use cascade::{cascade_revoke_by_refresh_family, cascade_revoke_devices};
pub use events::{DeviceEventSink, NoopDeviceEventSink};
pub use fingerprint::{
    DefaultFingerprintExtractor, DeviceFingerprintExtractor, TenantPepperResolver,
};
pub use lifecycle::DeviceLifecycleService;
pub use lifecycle_resolver::LifecycleDeviceResolver;
pub use pii::{
    DevicePiiCategory, DevicePiiMapping, DevicePiiResolver, DevicePiiStore, MemoryDevicePiiStore,
    MemoryDevicePiiStoreError, PiiToken, REDACTED_PLACEHOLDER, RedactedResolver,
};
pub use resolver::{DeviceResolver, NoopDeviceResolver};
pub use store::{
    DeviceStore, MemoryDeviceStore, MemoryDeviceStoreError, SweepConfig, SweepConfigBuilder,
    SweepCounts,
};
pub use types::{AttestationClass, Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};

// `DeviceId` is intentionally defined in `crate::authn::ids` (alongside
// `UserId` / `TenantId`) rather than here, because `SessionData` carries
// `Option<DeviceId>` ungated and must not change shape based on whether
// the `device` feature is enabled. Re-exported here for ergonomic access.
pub use crate::authn::ids::DeviceId;
