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
//! | Authn metrics | [`metrics`]`::*` | [`MetricSinks`], [`AuthFlowMetrics`] and the other concern traits, [`NoopMetrics`] |
//! | Middleware (CSRF, rate-limit, request-id, trace context) | [`middleware`]`::*` | [`RateLimitLayer`] + helpers; [`RequestIdLayer`] (feature-gated); [`TraceContextLayer`] + [`TraceContext`] (feature-gated) |
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
//! Every feature of the crate has a row here, and
//! `scripts/check-docsrs-features.sh` holds the table to the manifest. There
//! is no umbrella over all of them: the session backends are alternatives, so
//! a deployment picks one and adds the capabilities it uses, and CI builds
//! with `--all-features`.
//!
//! | Feature | What it enables |
//! |---------|----------------|
//! | `authz` | Cedar Policy authorization (RBAC + ABAC + ReBAC). **On by default.** |
//! | `device` | First-class [`device::Device`] identity with three-stage assurance ladder (`Unknown` → `Seen` → `Trusted`, plus terminal `Revoked`), per-tenant fingerprint pepper, refresh-family cascade, retention sweep, and `CachedDeviceStore` decorator. **On by default.** Pair with `sqlite` / `postgres` / `mysql` / `valkey` for persistent backends ([`SqliteDeviceStore`], [`PostgresDeviceStore`], [`MysqlDeviceStore`], [`ValkeyDeviceStore`]). See [`device`] and [`docs/identity/device.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/identity/device.md). |
//! | `device-keys` | Device keys: sessions and devices held to a key the client cannot export ([`device_key`]). Pulls `axess-factors/key-proof` and needs a `jwt-*` backend beside it. |
//! | `default-error-response` | Built-in `IntoResponse` mapping for [`AuthnError`] (on by default). Disable to ship your own HTTP mapping; see [`authn::error`] for the recommended status-code table. |
//! | `serde` | `serde` implementations on the typed ids, forwarded to `axess-identity`. **On by default.** |
//! | `rkyv` | `rkyv` implementations on the typed ids, forwarded to `axess-identity`, and on the client-address types. |
//! | `sqlx` | `sqlx` implementations on the typed ids, forwarded to `axess-identity`. The SQL backends below switch it on. |
//! | `memory` | In-memory session store and registry (`MemorySessionStore`, `MemorySessionRegistry`). Dev/test only, not in default features. Production builds without this flag cannot import these types. |
//! | `testing` | Test doubles and fixtures: [`testing`], with the mock stores, `MockClock` and `MockRng`. Implies `memory`. A release build with it on is refused unless `allow-testing-in-release` is on too. |
//! | `allow-testing-in-release` | The named opt-out for the release-build guard on `testing`: for a benchmark, or a test run in release mode. |
//! | `sqlite` | SQLite session store with AES-256-GCM encryption. |
//! | `sqlite-unbundled` | The `sqlite` stores linked to the system's SQLite library instead of the source sqlx bundles. Enable it in place of `sqlite`. |
//! | `postgres` | PostgreSQL session store with AES-256-GCM encryption. |
//! | `mysql` | MySQL / MariaDB session store with AES-256-GCM encryption. |
//! | `valkey` | Valkey/Redis session store and registry with optional encryption. |
//! | `valkey-cache` | Valkey-backed Cedar entity cache shared across replicas, in place of the in-process `EntityCache`. Implies `authz` and `valkey`. |
//! | `audit-archive-fs` | `FilesystemAuditArchiver`, a reference `AuditArchiver` that appends JSONL records under a directory. |
//! | `fido2` | FIDO2/WebAuthn passkey authentication. |
//! | `oauth` | OAuth 2.0 / OIDC (AuthCode+PKCE, Client Credentials, Device Code). |
//! | `fapi` | An alias for `oauth`, which carries the FAPI 2.0 client profile and both halves of DPoP. |
//! | `social` | Plain OAuth 2.0 user login, whose security model is weaker than OIDC's; see `axess_factors::social`. |
//! | `ldap` | LDAP bind authentication (Active Directory, OpenLDAP). |
//! | `jwt` | JWT verification primitives (`JwtVerifier`) and the `WorkloadResolver` for workload identity from a non-SPIFFE issuer. Enable exactly one of `jwt-aws-lc` and `jwt-rust-crypto` beside it. |
//! | `jwt-aws-lc` | `jwt`, verifying with aws-lc-rs: FIPS-capable, needs a C toolchain. |
//! | `jwt-rust-crypto` | `jwt`, verifying with RustCrypto: pure Rust. |
//! | `jwt-svid` | Inbound SPIFFE JWT-SVID workload resolver. Implies `jwt`. |
//! | `mtls` | Inbound mTLS / X.509-SVID workload resolver. |
//! | `outbound-mtls` | An mTLS client identity presented to downstream services. |
//! | `outbound-oauth` | OAuth client-credential flows to downstream services. |
//! | `client-assertion-rsa` | RSA client keys for `private_key_jwt` wherever they would sign in `rsa` 0.9 (RUSTSEC-2023-0071): on `jwt-rust-crypto`, and on `jwt-aws-lc` when a crypto provider was installed before axess installed its own; refused there without it. |
//! | `workload-id` | Umbrella over `jwt`, `jwt-svid`, `mtls`, `outbound-oauth` and `outbound-mtls`. |
//! | `spire` | SPIFFE Workload API client for a local SPIRE agent: [`workload::spire`]. Fetches X.509 and JWT SVIDs and trust bundles and keeps them current on the injected clock. |
//! | `aws-sts` | A federated workload identity exchanged for AWS credentials. |
//! | `gcp-wif` | A federated workload identity exchanged for GCP credentials. |
//! | `azure-fic` | A federated workload identity exchanged for Azure credentials. |
//! | `cloud-sts` | Umbrella over `aws-sts`, `gcp-wif` and `azure-fic`. |
//! | `local-idp` | In-process IdP that mints workload JWTs against a key store, for tests and on-host issuance. |
//! | `local-idp-rsa` | RSA keys for the local IdP; compiles `rsa` 0.9 (RUSTSEC-2023-0071). `local-idp` alone has ES256 keys and no `rsa` crate. |
//! | `delegated-stored` | On-behalf-of access with a persisted refresh token (authorization code with PKCE). |
//! | `delegated-stored-encrypted` | `delegated-stored`, with a decorator that encrypts any delegated-credential store at rest (AES-256-GCM). |
//! | `delegated-exchange` | On-behalf-of access by RFC 8693 token exchange, per request. |
//! | `delegated` | Umbrella over the three `delegated-*` features. |
//! | `request-id` | `X-Request-Id` middleware. |
//! | `accept-client-id` | With `request-id`: a valid request id the client sent is kept, where otherwise every request gets one the server generated. |
//! | `trace-context` | W3C Trace Context (`traceparent`) middleware. |
//! | `service-secret` | Shared-secret check for machine callers that cannot hold a key: [`middleware::service_secret`]. The weakest machine credential; prefer `jwt` or `mtls`. |
//! | `ws` | WebSocket helpers: a connection wrapper that closes on session revocation. |

// The `testing` feature compiles deterministic clocks and random sources and
// constructors that skip key checks. A release build that links it ships
// those in a production binary, and cargo feature unification lets any one
// dependent switch it on for the whole build, so the build refuses by name.
// `allow-testing-in-release` is the named opt-out for a build that means it.
#[cfg(all(
    feature = "testing",
    not(debug_assertions),
    not(feature = "allow-testing-in-release")
))]
compile_error!(
    "the `testing` feature of axess-core is enabled in a release build; it ships test doubles in a \
     production binary. Remove the feature from the release build, or enable \
     `allow-testing-in-release` to keep it on purpose."
);

// ── Session layer ──────────────────────────────────────────────────────────────

/// Custom tower session layer with HMAC-signed cookies and typed session data.
pub mod session;

pub use session::{
    AuthFlow, AuthSession, AuthState, ConditionalUpdate, CutOff, Impersonation, MoveOutcome,
    RefreshError, RefreshToken, RefreshTokenConfig, RefreshTokenStore, RevocationError,
    SESSION_KEY_DOMAIN, SameSite, SessionBinding, SessionConfig, SessionConfigBuilder, SessionData,
    SessionId, SessionKey, SessionKeyError, SessionKeyPrefix, SessionLayer, SessionRegistry,
    SessionRegistryAdapter, SessionRegistryHandle, SessionRevoker, SessionStore, UserAgentBinding,
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
    ActiveSessionsError, Actor, AuditContext, AuditOutcome, AuditQuery, AuditTrail, AuthEvent,
    AuthEventBuilder, AuthEventStatus, AuthEventType, AuthFailureReason, AuthMethod, AuthnBackend,
    AuthnError, AuthnScope, AuthnService, AuthnServiceBuilder, BreachCheckError,
    BreachCheckUnavailable, BreachedPasswordCheck, ChosenPasswordError, CounterUnavailable,
    DeviceId, EmailOtpConfig, EntityState, EventQueryFilter, FactorConfig, FactorCredential,
    FactorKind, FactorOutcome, FactorSecret, FactorStep, FactorStore, FactorTemplate,
    FederatedProvider, Fido2Config, Fido2CredentialClaim, HotpConfig, IdentityAdmin,
    IdentityAuthnLog, IdentityLookup, IdentityPasswordHistory, IdentityPasswordReset,
    IdentityStore, IpPolicy, LdapBindFactorConfig, LockoutPolicy, LockoutPolicyError, LoginOutcome,
    NewPasswordError, NoSessionRegistryError, NoopAuthnLog, OtpAlgorithm, PasswordConfig,
    PasswordRules, PrepareOutcome, ProvisioningError, RequestAuthnService, ResolvedFactor,
    SealedFactorSecret, SessionValidator, SignupOutcome, SignupVerification, StatusCause,
    StatusDetail, Tenant, TenantBootstrap, TenantId, Throttle, ThrottleKey, ThrottleState,
    ThrottleSubject, TotpConfig, UnreadableReason, UnreadableRows, User, UserId, ZeroizedString,
    create_tenant, default_catalog, require_valid_session,
};

// ── Federation; external-IdP adapters ───────────────────────────────────────
//
// External-IdP surface collected here: OAuth/OIDC, JWT, mTLS, LDAP, FIDO2,
// PKCE, back-/front-channel logout, federation adapters (K8s SA / GitHub
// Actions / generic OAuth-RS). Each submodule gated on its own per-feature
// flag.
pub mod federation;

// ── Authorization ──────────────────────────────────────────────────

#[cfg(feature = "authz")]
#[cfg_attr(docsrs, doc(cfg(feature = "authz")))]
pub mod authz;

/// The client's address, resolved once. Ungated: the rate limiter and the
/// audit trail need this and neither should have to compile Cedar for it.
pub mod client_ip;

#[cfg(feature = "authz")]
#[cfg_attr(docsrs, doc(cfg(feature = "authz")))]
pub use authz::{
    AuthzDecision, AuthzDenied, AuthzEntityProvider, AuthzError, AuthzSession, AuthzStore,
    BuildRequestContext, NoContext, PolicyEvaluator, PolicyStore, StandardRequestContext,
    make_action_uid, make_entity_uid,
};

// Ungated, unlike the Cedar context above: a rate limiter needs the client
// address and should not compile a policy engine to get it.
pub use client_ip::{CidrParseError, ClientIp, TrustedProxies};

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

#[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "sqlite", feature = "sqlite-unbundled")))
)]
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
    LdapBindResult, LdapError, LdapGroupSearch, LdapProvider, LdapProviderConfig,
};

/// Test double for [`LdapProvider`]; compiled under `cfg(test)` or the
/// `testing` feature only.
#[cfg(all(feature = "ldap", any(test, feature = "testing")))]
pub use axess_factors::ldap::MockLdapProvider;

/// A [`BreachedPasswordCheck`] that never answers, for tests of an outage;
/// compiled under `cfg(test)` or the `testing` feature only.
#[cfg(any(test, feature = "testing"))]
pub use axess_factors::BreachCheckOutage;
/// A [`BreachedPasswordCheck`] over a fixed deny-list.
pub use axess_factors::BreachedPasswordList;

#[cfg(feature = "oauth")]
#[cfg_attr(docsrs, doc(cfg(feature = "oauth")))]
pub use axess_factors::oauth::{
    AuthUrlResult, DpopKey, DpopProof, DpopSigner, JarmResponse, OAuthClaims, OAuthError,
    OAuthLoginOptions, OAuthProvider, OAuthProviderBuilder, OAuthProviderConfig, ResponseMode,
    UserInfoClaims, spawn_jwks_refresh,
};

/// The `private_key_jwt` signer for
/// [`OAuthProviderBuilder::with_private_key_jwt`], the stored shape of its
/// settings, and why one could not be built.
#[cfg(feature = "oauth")]
#[cfg_attr(docsrs, doc(cfg(feature = "oauth")))]
pub use axess_factors::client_assertion::{
    ClientAssertionError, ClientAssertionSigner, SignerSpec,
};

#[cfg(all(feature = "oauth", any(test, feature = "testing")))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "oauth", feature = "testing"))))]
pub use axess_factors::oauth::MockOAuthProvider;

#[cfg(feature = "oauth")]
#[cfg_attr(docsrs, doc(cfg(feature = "oauth")))]
pub use axess_factors::oauth::{FapiConfig, ParResponse, SenderConstraint};

#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub use device::{
    AttestationClass, BindingsUpdate, BoundDevice, CachedDeviceStore, DefaultFingerprintExtractor,
    Device, DeviceBinding, DeviceCookieConfig, DeviceCookieSlot, DeviceEventSink,
    DeviceFingerprintExtractor, DeviceLifecycleService, DevicePiiCategory, DevicePiiMapping,
    DevicePiiResolver, DevicePiiStore, DeviceRequest, DeviceResolver, DeviceStore, DeviceToken,
    DeviceTrustLevel, FingerprintHash, LifecycleDeviceResolver, LifecycleResolveError,
    MemoryDevicePiiStore, MemoryDevicePiiStoreError, MemoryDeviceStore, MemoryDeviceStoreError,
    NoopDeviceEventSink, NoopDeviceResolver, OwnerClaim, PiiToken, PresentedDevice, ProvenDevice,
    REDACTED_PLACEHOLDER, RedactedResolver, ResolvedDevice, ResolvedOrKept, SessionDevice,
    SessionTenant, SessionUser, SweepConfig, SweepConfigBuilder, SweepConfigError, SweepCounts,
    TenantPepperResolver, TrustTransition, UserDevice, cascade_revoke_by_refresh_family_and_tokens,
    cascade_revoke_devices,
};

#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub use device::{CascadingRefreshStore, RevokeDeviceError, revoke_device};

#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub use authn::service::{
    StepUpPolicy, StepUpPolicyBuilder, decide_step_up_for_optional, decide_step_up_for_user,
};

#[cfg(all(
    feature = "device",
    any(
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql"
    )
))]
pub use device::storage::SqlDeviceStoreError;

#[cfg(all(
    feature = "device",
    any(feature = "sqlite", feature = "sqlite-unbundled")
))]
pub use device::storage::SqliteDeviceStore;

#[cfg(all(feature = "device", feature = "postgres"))]
pub use device::storage::PostgresDeviceStore;

#[cfg(all(feature = "device", feature = "mysql"))]
pub use device::storage::MysqlDeviceStore;

#[cfg(all(feature = "device", feature = "valkey"))]
pub use device::storage::{ValkeyDeviceStore, ValkeyDeviceStoreError};

// ── Principal abstraction ────────────────────────────────────────────

/// Device keys: the values a device-bound session is made of and, with the
/// `device-keys` feature, the service that registers and proves them. See
/// `docs/sessions/device-bound-sessions.md`.
pub mod device_key;

// No outer doc comment: with one, rustdoc resolves the links of the module's
// own `//!` docs in this scope and not in the module's.
#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
pub mod replay;

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
    PrincipalResolverChain, SessionResolver, TrustDomain, WorkloadId, WorkloadIdComponents,
    WorkloadPrincipal,
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
pub mod blocking;
/// Composite health-check primitives.
pub mod health;
/// HMAC helpers used by the session-layer signing + CSRF middleware.
/// Re-exported from [`session::hmac`]; lives next to the session
/// middleware that is its primary consumer.
pub use session::hmac;
#[cfg(feature = "local-idp")]
#[cfg_attr(docsrs, doc(cfg(feature = "local-idp")))]
pub mod local_idp;
/// One metrics trait per concern, [`MetricSinks`] to wire
/// them, and the `NoopMetrics` default implementation.
pub mod metrics;

pub mod reload;
/// Mock authentication/identity stores, deterministic clocks/RNGs,
/// fixture builders, and other test doubles. Gated behind
/// `cfg(any(test, feature = "testing"))` so production builds cannot
/// import them; in-crate tests get them via `cfg(test)`.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
/// Identifier / e-mail / URL validation helpers.
pub mod validation;

pub mod profile;

pub(crate) mod aead;
pub(crate) mod length_prefix;

pub(crate) mod logged_route;

pub(crate) mod locked;

/// Endpoint and client policy shared by the credential-bearing outbound
/// HTTP clients.
#[cfg(any(
    feature = "delegated-exchange",
    feature = "delegated-stored",
    feature = "aws-sts",
    feature = "azure-fic",
    feature = "gcp-wif"
))]
pub(crate) mod outbound_http;
#[cfg(any(
    feature = "delegated-exchange",
    feature = "delegated-stored",
    feature = "aws-sts",
    feature = "azure-fic",
    feature = "gcp-wif"
))]
pub use outbound_http::ClientBuildError;

pub use axess_clock::{Clock, SignedDuration, SystemClock, TimeError, Timestamp, Until, UtcDate};
pub use axess_rng::{SecureRng, SystemRng};
pub use health::{CompositeHealthCheck, CompositeStatus, HealthCheck, HealthStatus};
pub use metrics::{
    AuditMetrics, AuthFlowMetrics, AuthzCacheMetrics, AxessMetrics, CsrfRefusal, DeviceKeyMetrics,
    FactorMetrics, MetricSinks, NoopMetrics, ProviderCategory, ProviderRegistryMetrics,
    RequestGuardMetrics, RotationMetrics, SessionMetrics,
};

#[cfg(any(test, feature = "testing"))]
pub use testing::{
    MemoryRefreshStoreError, MemoryRefreshTokenStore, MockClock, MockFactorStore,
    MockIdentityStore, MockResolver, MockRng,
};

#[cfg(all(feature = "authz", any(test, feature = "testing")))]
pub use testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator};

// ── Middleware ─────────────────────────────────────────────────────────────────

/// Optional axum/tower middleware: request ID, W3C trace context, rate
/// limiting, CSRF.
pub mod middleware;

#[cfg(feature = "request-id")]
#[cfg_attr(docsrs, doc(cfg(feature = "request-id")))]
pub use middleware::request_id::RequestIdLayer;

#[cfg(feature = "trace-context")]
#[cfg_attr(docsrs, doc(cfg(feature = "trace-context")))]
pub use middleware::trace_context::{TraceContext, TraceContextLayer};

pub use middleware::ratelimit::{
    KeyExtractor, RateLimitConfig, RateLimitConfigBuilder, RateLimitLayer,
    RateLimitLoginIdentifier, RateLimitService, RateLimitTenantId, RateLimitUserId,
};

// ── Re-export axum and tracing for macro hygiene ────────────────────────────────

#[doc(hidden)]
pub use axum;
#[doc(hidden)]
pub use tracing;
