#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::redundant_explicit_links
)]
// Opt into the nightly `doc(cfg(...))` attribute so docs.rs renders an
// "available on feature `X`" badge on every feature-gated item. The
// `#[cfg_attr(docsrs, doc(cfg(...)))]` tags below are no-ops on stable
// builds; they only activate under docs.rs's `--cfg docsrs` flag (set in
// `[package.metadata.docs.rs]`).
#![cfg_attr(docsrs, feature(doc_cfg))]
//! Core implementation for the Axess authentication and authorization library.
//!
//! # Re-export strategy
//!
//! Public types have one **canonical location** (the module that defines or
//! that owns the canonical re-export from a sibling crate) and may also be
//! convenience-re-exported at the crate root. Adopters can use either path;
//! the canonical path is what `rustdoc` displays. When in doubt, prefer the
//! canonical path in import statements; it survives crate-root churn.
//!
//! | Concern | Canonical | Crate-root convenience |
//! |---------|-----------|-----------------------|
//! | Session state | [`session`]`::*` | (none; depth-2 access only) |
//! | Authn service / state machine | [`authn`]`::*` | (none) |
//! | Authn factor configs | [`authn::factor`]`::*` | (none) |
//! | Authn errors | [`authn::error`]`::*` | (none) |
//! | Authz policy / decision | [`authz`]`::*` | (none) |
//! | Identity (principal, IDs) | [`principal`]`::*` (re-exports `axess-identity`) | (none) |
//! | Clock / RNG (DST foundation) | `axess_clock::*` / `axess_rng::*` | [`Clock`], [`SecureRng`], [`SystemClock`], [`SystemRng`] |
//! | Health checks | [`health`]`::*` | [`HealthCheck`], [`HealthStatus`], [`CompositeHealthCheck`] |
//! | Authn metrics | [`metrics`]`::*` | [`AuthnMetrics`], [`NoopMetrics`] |
//! | Middleware (CSRF, rate-limit, request-id, trace-id) | [`middleware`]`::*` | [`RateLimitLayer`] + helpers; [`RequestIdLayer`] (feature-gated); [`TraceIdLayer`] + [`TraceContext`] (feature-gated) |
//! | Test fixtures | [`testing`]`::*` (gated `cfg(any(test, feature = "testing"))`) | [`MockClock`], [`MockRng`], [`MockIdentityStore`], ... |
//!
//! **Why some types have crate-root convenience and others don't:** the
//! ones promoted to the crate root are either DST primitives that every
//! adopter touches (`Clock`, `SecureRng`) or framework integration points
//! that read naturally as `axess_core::RateLimitLayer`. Authn / authz
//! types stay at depth-2 so the import line reveals *which layer* the
//! type belongs to. Useful when reading a route handler that mixes
//! authn and authz concerns.
//!
//! # Feature flags
//!
//! | Feature | What it enables |
//! |---------|----------------|
//! | `authz` | Cedar Policy authorization (RBAC + ABAC + ReBAC). **On by default.** |
//! | `device` | First-class [`device::Device`] identity with three-stage assurance ladder (`Unknown` → `Seen` → `Trusted`, plus terminal `Revoked`), per-tenant fingerprint pepper, refresh-family cascade, retention sweep, and `CachedDeviceStore` decorator. **On by default.** Pair with `sqlite` / `postgres` / `mysql` / `valkey` for persistent backends ([`SqliteDeviceStore`], [`PostgresDeviceStore`], [`MysqlDeviceStore`], [`ValkeyDeviceStore`]). See [`device`] and [`docs/identity/device.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/identity/device.md). |
//! | `memory` | In-memory session store and registry (`MemorySessionStore`, `MemorySessionRegistry`). Dev/test only, not in default features. Production builds without this flag cannot import these types. |
//! | `sqlite` | SQLite session store with AES-256-GCM encryption. |
//! | `postgres` | PostgreSQL session store with AES-256-GCM encryption. |
//! | `valkey` | Valkey/Redis session store and registry with optional encryption. |
//! | `fido2` | FIDO2/WebAuthn passkey authentication. |
//! | `oauth` | OAuth 2.0 / OIDC (AuthCode+PKCE, Client Credentials, Device Code). |
//! | `ldap` | LDAP bind authentication (Active Directory, OpenLDAP). |
//! | `request-id` | `X-Request-Id` middleware. |
//! | `trace-id` | W3C Trace Context (`traceparent`) middleware. |
//! | `default-error-response` | Built-in `IntoResponse` mapping for [`AuthnError`] (on by default). Disable to ship your own HTTP mapping; see [`authn::error`] for the recommended status-code table. |
//! | `full` | All of the above. |
//!
//! Internal features (used by the library, not intended for direct use):
//! `accept_client_id`.

// ── Session layer ──────────────────────────────────────────────────────────────

/// Custom tower session layer with HMAC-signed cookies and typed session data.
pub mod session;

pub use session::{
    AuthSession, AuthState, RefreshError, RefreshToken, RefreshTokenConfig, RefreshTokenStore,
    SameSite, SessionBinding, SessionConfig, SessionConfigBuilder, SessionData, SessionId,
    SessionLayer, SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle, SessionRevoker,
    SessionStore, UserAgentBinding,
};
#[cfg(any(test, feature = "memory"))]
pub use session::{MemorySessionRegistry, MemorySessionStore};

// ── Authentication ─────────────────────────────────────────────────────────────

/// Authentication service: identity lookup, factor verification, session management.
pub mod authn;

// ── Device identity ───────────────────────────────────────────────────────────
//
// First-class subsystem (typed `Device` aggregate, three-stage assurance
// ladder, retention sweep, refresh-family cascade, PII tokenisation) rather
// than an authn-flow submodule. Legacy `axess_core::authn::Device*` paths
// continue to resolve via the re-export shim in `authn.rs`.
/// First-class typed `Device` aggregate + three-layer assurance ladder.
#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub mod device;

pub use authn::{
    AuditContext, AuditQuery, AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType,
    AuthMethod, AuthnBackend, AuthnError, AuthnScope, AuthnService, DeviceId, EmailOtpConfig,
    EntityState, EventQueryFilter, FactorConfig, FactorCredential, FactorKind, FactorOutcome,
    FactorStep, FactorStore, FactorTemplate, FederatedProvider, Fido2Config, HotpConfig,
    IdentityAdmin, IdentityAuthnLog, IdentityLookup, IdentityStore, IpPolicy, LdapBindFactorConfig,
    LockoutPolicy, LoginOutcome, NoSessionRegistryError, NoopAuthnLog, OtpAlgorithm,
    PasswordConfig, PasswordRules, PrepareOutcome, ProvisioningError, SessionValidator,
    SignupOutcome, StatusDetail, Tenant, TenantBootstrap, TenantId, TotpConfig, User, UserId,
    ZeroizedString, create_tenant, default_catalog, extract_audit_context,
    extract_audit_context_async, require_valid_session,
};

// ── Federation; external-IdP adapters ───────────────────────────────────────
//
// External-IdP surface collected here: OAuth/OIDC, JWT, mTLS, LDAP, FIDO2,
// PKCE, back-/front-channel logout, federation adapters (K8s SA / GitHub
// Actions / generic OAuth-RS). Each submodule gated on its own per-feature
// flag.
/// External-IdP federation adapters: per-protocol + per-issuer.
pub mod federation;

// ── Authorization ──────────────────────────────────────────────────

#[cfg(feature = "authz")]
#[cfg_attr(docsrs, doc(cfg(feature = "authz")))]
pub mod authz;

#[cfg(feature = "authz")]
#[cfg_attr(docsrs, doc(cfg(feature = "authz")))]
pub use authz::{
    AuthzDecision, AuthzDenied, AuthzEntityProvider, AuthzError, AuthzSession, AuthzStore,
    BuildRequestContext, NoContext, PolicyEvaluator, PolicyStore, StandardRequestContext,
    ip_from_headers, make_action_uid, make_entity_uid,
};

// ── Storage backends (re-exports from session::storage) ────────────────────────
//
// Pluggable storage backends for [`SessionStore`] and authentication state.
// The actual modules live under [`session::storage`]; kept there because
// every backend implements `SessionStore` and/or `SessionRegistry`, both
// session-domain traits. The flat re-exports below preserve the historical
// public API (`axess_core::SqliteSessionStore`, etc.) so downstream code
// importing those types is unaffected by the layout cleanup.

// `in_memory_backend` is gated behind `cfg(any(test, feature = "testing"))`
// in `session.rs`; the re-export must match or non-testing builds fail
// (E0432: unresolved import).
#[cfg(any(test, feature = "testing"))]
pub use session::storage::in_memory_backend::InMemoryBackend;

#[cfg(feature = "sqlite")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite")))]
pub use session::storage::sqlite::SqliteSessionStore;

#[cfg(feature = "postgres")]
#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
pub use session::storage::postgres::{PostgresSessionStore, PostgresStoreError};

#[cfg(feature = "mysql")]
#[cfg_attr(docsrs, doc(cfg(feature = "mysql")))]
pub use session::storage::mysql::{MysqlSessionStore, MysqlStoreError};

#[cfg(feature = "valkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "valkey")))]
pub use session::storage::valkey::{ValkeySessionRegistry, ValkeySessionStore, ValkeyStoreError};

#[cfg(feature = "ldap")]
#[cfg_attr(docsrs, doc(cfg(feature = "ldap")))]
pub use axess_factors::ldap::{
    LdapBindResult, LdapError, LdapGroupSearch, LdapProvider, LdapProviderConfig, MockLdapProvider,
};

#[cfg(feature = "oauth")]
#[cfg_attr(docsrs, doc(cfg(feature = "oauth")))]
pub use axess_factors::oauth::{
    AuthUrlResult, MockOAuthProvider, OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProvider,
    OAuthProviderConfig, ResponseMode, UserInfoClaims, spawn_jwks_refresh,
};

#[cfg(feature = "fapi")]
#[cfg_attr(docsrs, doc(cfg(feature = "fapi")))]
pub use axess_factors::oauth::{DpopProof, FapiConfig, ParResponse, SenderConstraint};

#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub use device::{
    AttestationClass, CachedDeviceStore, DefaultFingerprintExtractor, Device, DeviceBinding,
    DeviceEventSink, DeviceFingerprintExtractor, DeviceLifecycleService, DevicePiiCategory,
    DevicePiiMapping, DevicePiiResolver, DevicePiiStore, DeviceResolver, DeviceStore,
    DeviceTrustLevel, FingerprintHash, LifecycleDeviceResolver, MemoryDevicePiiStore,
    MemoryDevicePiiStoreError, MemoryDeviceStore, MemoryDeviceStoreError, NoopDeviceEventSink,
    NoopDeviceResolver, PiiToken, REDACTED_PLACEHOLDER, RedactedResolver, SweepConfig,
    SweepConfigBuilder, SweepCounts, TenantPepperResolver, cascade_revoke_by_refresh_family,
    cascade_revoke_devices,
};

#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub use authn::service::{StepUpPolicy, StepUpPolicyBuilder, decide_step_up};

#[cfg(all(
    feature = "device",
    any(feature = "sqlite", feature = "postgres", feature = "mysql")
))]
pub use device::storage::SqlDeviceStoreError;

#[cfg(all(feature = "device", feature = "sqlite"))]
pub use device::storage::SqliteDeviceStore;

#[cfg(all(feature = "device", feature = "postgres"))]
pub use device::storage::PostgresDeviceStore;

#[cfg(all(feature = "device", feature = "mysql"))]
pub use device::storage::MysqlDeviceStore;

#[cfg(all(feature = "device", feature = "valkey"))]
pub use device::storage::{ValkeyDeviceStore, ValkeyDeviceStoreError};

// ── Principal abstraction ────────────────────────────────────────────

/// Unified identity abstraction covering humans and workloads.
/// See [`docs/workload-identity/README.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/workload-identity/README.md).
pub mod principal;

/// Workload identity hub: re-exports inbound resolvers and houses
/// outbound primitives. See [`workload`] module docs.
pub mod workload;

/// On-behalf-of (OBO) access: axess acts *as a user* at a
/// downstream service. Two flow shapes share one conceptual
/// abstraction; see [`delegated::stored`] and [`delegated::exchange`]
/// for the per-flow contracts.
#[cfg(any(feature = "delegated-stored", feature = "delegated-exchange"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "delegated-stored", feature = "delegated-exchange")))
)]
pub mod delegated;

pub use principal::{
    AuthHumanPrincipal, AuthPrincipal, AuthWorkloadPrincipal, CliResolver, CliResolverBuilder,
    HumanPrincipal, IdentityError, Issuer, Principal, PrincipalRejection, PrincipalResolver,
    SessionResolver, TrustDomain, WorkloadId, WorkloadPrincipal,
};

#[cfg(feature = "authz")]
#[cfg_attr(docsrs, doc(cfg(feature = "authz")))]
pub use principal::ToCedarEntity;

// ── Shared store abstraction ───────────────────────────────────────────────────

/// Generic key/value-with-TTL store + codec, shared across backend
/// implementations.
pub mod store;

// ── Top-level utilities ────────────────────────────────────────────────────────

/// HTTP cookie parsing helpers (`extract_named_cookie` + caps).
/// Re-exported from [`session::cookies`]; lives next to the session
/// middleware that is its primary consumer.
pub use session::cookies;
/// Composite health-check primitives.
pub mod health;
/// HMAC helpers used by the session-layer signing + CSRF middleware.
/// Re-exported from [`session::hmac`]; lives next to the session
/// middleware that is its primary consumer.
pub use session::hmac;
/// Production-grade in-process IdP: mints workload-identity JWTs
/// against an adopter-supplied [`local_idp::LocalIdpKeyStore`] and
/// exposes JWKS for verifiers. Test counterpart lives at
/// [`testing::local_idp`]. Gated on the `local-idp` feature.
#[cfg(feature = "local-idp")]
#[cfg_attr(docsrs, doc(cfg(feature = "local-idp")))]
pub mod local_idp;
/// `AuthnMetrics` trait + `NoopMetrics` default implementation.
pub mod metrics;
/// Mock authentication/identity stores, deterministic clocks/RNGs,
/// fixture builders, and other test doubles. Gated behind
/// `cfg(any(test, feature = "testing"))` so production builds cannot
/// import them; in-crate tests get them via `cfg(test)`.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
/// Identifier / e-mail / URL validation helpers.
pub mod validation;

pub use axess_clock::{Clock, SystemClock};
pub use axess_rng::{SecureRng, SystemRng};
pub use health::{CompositeHealthCheck, CompositeStatus, HealthCheck, HealthStatus};
pub use metrics::{AuthnMetrics, NoopMetrics};

#[cfg(any(test, feature = "testing"))]
pub use testing::mock_tracing::TracingCapture;

#[cfg(any(test, feature = "testing"))]
pub use testing::{
    MemoryRefreshStoreError, MemoryRefreshTokenStore, MockClock, MockFactorStore,
    MockIdentityStore, MockResolver, MockRng,
};

#[cfg(all(feature = "authz", any(test, feature = "testing")))]
pub use testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator};

// ── Middleware ─────────────────────────────────────────────────────────────────

/// Optional axum/tower middleware: request ID, W3C trace context, rate
/// limiting, CSRF. Renamed from `extras` in (the prior name was
/// meant to signal "outside the core auth flow"; `middleware` is what
/// these actually are).
pub mod middleware;

#[cfg(feature = "request-id")]
#[cfg_attr(docsrs, doc(cfg(feature = "request-id")))]
pub use middleware::request_id::RequestIdLayer;

#[cfg(feature = "trace-id")]
#[cfg_attr(docsrs, doc(cfg(feature = "trace-id")))]
pub use middleware::trace_id::{TraceContext, TraceContextLayer, TraceIdLayer};

pub use middleware::ratelimit::{
    KeyExtractor, RateLimitConfig, RateLimitConfigBuilder, RateLimitLayer,
    RateLimitLoginIdentifier, RateLimitService, RateLimitTenantId, RateLimitUserId,
};

// ── Re-export axum and tracing for macro hygiene ────────────────────────────────

#[doc(hidden)]
pub use axum;
#[doc(hidden)]
pub use tracing;
