//! Public-facing facade for `axess-core`. Prefer the subsystem namespaces
//! (`axess::session`, `axess::authn`, `axess::authz`, `axess::backends`,
//! `axess::workload`, `axess::delegated`, `axess::local_idp`) in new code;
//! root-level re-exports are kept for ergonomics on the most common entry
//! points (`SessionLayer`, `AuthnService`, `AuthzStore`, the route-guard
//! macros, and the DST primitives `Clock` / `SecureRng`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Identity test fixture builders (`tenant`, `user`, `device`, ...) plus
/// [`MockResolver`](crate::testing::MockResolver). Re-exported from `axess-identity` under the `testing`
/// feature.
#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing {
    pub use axess_core::{MockClock, MockFactorStore, MockIdentityStore, MockRng};
    pub use axess_identity::testing::*;

    #[cfg(feature = "ldap")]
    pub use axess_core::MockLdapProvider;
    #[cfg(feature = "oauth")]
    pub use axess_core::MockOAuthProvider;
    #[cfg(feature = "fido2")]
    pub use axess_factors::fido2::MockFido2Provider;
}

// Session layer. Kept at the root because `SessionLayer` and the core
// session types are common facade entry points.
pub use axess_core::{
    AuthSession, AuthState, SameSite, SessionBinding, SessionConfig, SessionConfigBuilder,
    SessionData, SessionId, SessionLayer, SessionRegistry, SessionRegistryAdapter,
    SessionRegistryHandle, SessionRevoker, SessionStore, UserAgentBinding,
};
#[cfg(any(test, feature = "memory"))]
pub use axess_core::{MemorySessionRegistry, MemorySessionStore};

/// Session sub-module re-exports (crypto, refresh tokens, etc.).
pub mod session {
    pub use axess_core::session::refresh::{RefreshTokenId, TokenFamilyId};
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "valkey"))]
    pub use axess_core::session::{CryptoError, SessionCrypto};
    pub use axess_core::session::{RefreshToken, RefreshTokenConfig, RefreshTokenStore};
}

/// Authentication namespace. Prefer `axess::authn::*` in new code.
pub mod authn {
    pub use axess_core::{
        AuditQuery, AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType, AuthMethod,
        AuthnBackend, AuthnError, AuthnScope, AuthnService, DeviceId, EmailOtpConfig, EntityState,
        EventQueryFilter, FactorConfig, FactorCredential, FactorKind, FactorOutcome, FactorStep,
        FactorStore, FactorTemplate, FederatedProvider, Fido2Config, HotpConfig, IdentityAdmin,
        IdentityAuthnLog, IdentityLookup, IdentityStore, IpPolicy, LdapBindFactorConfig,
        LockoutPolicy, LoginOutcome, NoSessionRegistryError, NoopAuthnLog, OtpAlgorithm,
        PasswordConfig, PasswordRules, PrepareOutcome, ProvisioningError, SessionValidator,
        SignupOutcome, StatusDetail, Tenant, TenantBootstrap, TenantId, TotpConfig, User, UserId,
        ZeroizedString, create_tenant, default_catalog, require_valid_session,
    };
    pub use axess_factors::{
        HOTP_LENGTH, HotpAlgorithm, TOTP_LENGTH, TOTP_PERIOD, TotpAlgorithm, TotpVerifyParams,
        build_totp_uri, generate_password_hash, generate_totp_secret, verify_hotp, verify_password,
        verify_totp,
    };
}

// Authorization re-exports from axess-core with module-level docs.
//
// `authz` is the canonical spelling used throughout the workspace (matches
// the `Authz*` type prefix convention). `authorization` is kept as a thin
// alias for prose-friendly imports and to match the OAuth/OIDC spec
// vocabulary; new code should prefer `axess::authz`.
#[cfg(feature = "authz")]
pub mod authz;

/// Long-form alias of [`crate::authz`]. Prefer `axess::authz` in new code.
#[cfg(feature = "authz")]
pub mod authorization {
    pub use crate::authz::*;
}

// Top-level authz re-exports for convenience. Prefer `axess::authz::*` in new code;
// keep these at the root for compatibility and low-friction migration.
#[cfg(feature = "authz")]
pub use authz::{
    AuthzDecision, AuthzDenied, AuthzEntityProvider, AuthzError, AuthzSession, AuthzStore,
    BuildRequestContext, NoContext, PolicyEvaluator, PolicyStore, StandardRequestContext,
    make_action_uid, make_entity_uid,
};

/// Request ID middleware. Re-exports [`axess_core::middleware::request_id`].
#[cfg(feature = "request-id")]
pub mod request_id {
    pub use axess_core::middleware::request_id::*;
}

/// W3C Trace Context middleware. Re-exports [`axess_core::middleware::trace_id`].
#[cfg(feature = "trace-id")]
pub mod trace_id {
    pub use axess_core::middleware::trace_id::*;
}

/// CSRF protection middleware. Re-exports [`axess_core::middleware::csrf`].
pub mod csrf {
    pub use axess_core::middleware::csrf::*;
}

// In-memory backend for prototyping. Wraps mock identity/factor stores;
// gated behind `testing` so production builds cannot ship it.
#[cfg(any(test, feature = "testing"))]
pub use axess_core::InMemoryBackend;

/// Storage backends grouped by data store. Each backend module exposes
/// the per-store types under their unprefixed names so adopters write
/// `use axess::backends::sqlite::{SessionStore, DeviceStore};` instead
/// of stitching together `SqliteSessionStore`, `SqliteDeviceStore`,
/// `SqlStoreError`, `SqlDeviceStoreError` from disjoint flat symbols.
pub mod backends {
    /// SQLite-backed stores. Requires the `sqlite` feature; device-store
    /// types additionally require the `device` feature. The
    /// `SessionStoreError` here is the codec-level error shared with
    /// PostgreSQL, gated on either feature.
    #[cfg(feature = "sqlite")]
    pub mod sqlite {
        pub use axess_core::SqliteSessionStore as SessionStore;
        #[cfg(any(feature = "sqlite", feature = "postgres"))]
        pub use axess_core::session::storage::session_codec::SqlStoreError as SessionStoreError;

        #[cfg(feature = "device")]
        pub use axess_core::SqlDeviceStoreError as DeviceStoreError;
        #[cfg(feature = "device")]
        pub use axess_core::SqliteDeviceStore as DeviceStore;
    }

    /// PostgreSQL-backed stores. Requires the `postgres` feature;
    /// device-store types additionally require the `device` feature.
    #[cfg(feature = "postgres")]
    pub mod postgres {
        pub use axess_core::PostgresSessionStore as SessionStore;
        pub use axess_core::PostgresStoreError as SessionStoreError;

        #[cfg(feature = "device")]
        pub use axess_core::PostgresDeviceStore as DeviceStore;
        #[cfg(feature = "device")]
        pub use axess_core::SqlDeviceStoreError as DeviceStoreError;
    }

    /// MySQL- and MariaDB-backed stores. Requires the `mysql` feature;
    /// device-store types additionally require the `device` feature.
    /// Tested against MySQL 8.x and MariaDB 10.5+; MySQL 5.7 works for
    /// sessions but is not validated for devices.
    #[cfg(feature = "mysql")]
    pub mod mysql {
        pub use axess_core::MysqlSessionStore as SessionStore;
        pub use axess_core::MysqlStoreError as SessionStoreError;

        #[cfg(feature = "device")]
        pub use axess_core::MysqlDeviceStore as DeviceStore;
        #[cfg(feature = "device")]
        pub use axess_core::SqlDeviceStoreError as DeviceStoreError;
    }

    /// Valkey/Redis-backed stores. Requires the `valkey` feature;
    /// device-store types additionally require the `device` feature.
    #[cfg(feature = "valkey")]
    pub mod valkey {
        pub use axess_core::ValkeySessionRegistry as SessionRegistry;
        pub use axess_core::ValkeySessionStore as SessionStore;
        pub use axess_core::ValkeyStoreError as SessionStoreError;

        #[cfg(feature = "device")]
        pub use axess_core::ValkeyDeviceStore as DeviceStore;
        #[cfg(feature = "device")]
        pub use axess_core::ValkeyDeviceStoreError as DeviceStoreError;
    }

    /// In-memory stores. Session-store + registry require `memory`;
    /// refresh-token store is a test double and requires `testing`;
    /// device-store types additionally require `device`. Recommended for
    /// prototypes, tests, and single-process deployments only, not for
    /// production.
    #[cfg(any(test, feature = "memory", feature = "testing"))]
    pub mod memory {
        #[cfg(any(test, feature = "testing"))]
        pub use axess_core::MemoryRefreshStoreError as RefreshStoreError;
        #[cfg(any(test, feature = "testing"))]
        pub use axess_core::MemoryRefreshTokenStore as RefreshTokenStore;
        #[cfg(any(test, feature = "memory"))]
        pub use axess_core::MemorySessionRegistry as SessionRegistry;
        #[cfg(any(test, feature = "memory"))]
        pub use axess_core::MemorySessionStore as SessionStore;

        #[cfg(feature = "device")]
        pub use axess_core::MemoryDevicePiiStore as DevicePiiStore;
        #[cfg(feature = "device")]
        pub use axess_core::MemoryDevicePiiStoreError as DevicePiiStoreError;
        #[cfg(feature = "device")]
        pub use axess_core::MemoryDeviceStore as DeviceStore;
        #[cfg(feature = "device")]
        pub use axess_core::MemoryDeviceStoreError as DeviceStoreError;
    }
}

/// Device identity, fingerprint extraction, lifecycle, and per-tenant PII
/// tokenisation. Re-exports [`axess_core::device`].
#[cfg(feature = "device")]
pub mod device {
    pub use axess_core::{
        AttestationClass, CachedDeviceStore, DefaultFingerprintExtractor, Device, DeviceBinding,
        DeviceEventSink, DeviceFingerprintExtractor, DeviceLifecycleService, DevicePiiCategory,
        DevicePiiMapping, DevicePiiResolver, DevicePiiStore, DeviceResolver, DeviceStore,
        DeviceTrustLevel, FingerprintHash, LifecycleDeviceResolver, MemoryDevicePiiStore,
        MemoryDevicePiiStoreError, MemoryDeviceStore, MemoryDeviceStoreError, NoopDeviceEventSink,
        NoopDeviceResolver, PiiToken, REDACTED_PLACEHOLDER, RedactedResolver, StepUpPolicy,
        StepUpPolicyBuilder, SweepConfig, SweepConfigBuilder, SweepCounts, TenantPepperResolver,
        cascade_revoke_by_refresh_family, cascade_revoke_devices, decide_step_up,
    };
}

// Device-store backends are now grouped under `backends::{sqlite,postgres,valkey,memory}::DeviceStore`
// (and `DeviceStoreError`); see the `backends` module above.

// DST utilities. Clock + RNG abstractions for deterministic-simulation
// testing. Production `Clock`/`SecureRng`/`SystemClock`/`SystemRng`
// are unconditional; the mock counterparts are gated behind `testing`.
pub use axess_core::{Clock, SecureRng, SystemClock, SystemRng};

/// In-process IdP. Re-exports the production [`LocalIdp`] and (under
/// `testing`) the [`LocalIdpFixture`] test double. See
/// [`axess_core::local_idp`] for the full surface.
///
/// [`LocalIdp`]: axess_core::local_idp::LocalIdp
/// [`LocalIdpFixture`]: axess_core::testing::local_idp::LocalIdpFixture
#[cfg(feature = "local-idp")]
pub mod local_idp {
    pub use axess_core::local_idp::{
        IssuanceError, LoadedKeys, LocalIdp, LocalIdpKeyStore, LocalIdpMetadata,
        MemoryLocalIdpKeyStore, MemoryLocalIdpKeyStoreError,
    };
    /// RFC 8414 discovery document + axum handler functions.
    pub mod discovery {
        pub use axess_core::local_idp::discovery::{LocalIdpMetadata, handlers};
    }
    // Primitives shared between the production `LocalIdp` and the test
    // `LocalIdpFixture`. Live outside `crate::testing` so production
    // builds with `local-idp` do not transitively pull mocks.
    pub use axess_core::local_idp::primitives::{
        IssuanceEvent, IssuanceListener, LocalIdpKeyError, LocalIdpSigningKey, MintClaims,
    };
    // Test fixture variants of LocalIdp (keypair-per-`new`, mock listeners,
    // recording helpers). Gated behind `testing`.
    #[cfg(any(test, feature = "testing"))]
    pub use axess_core::testing::local_idp::{
        LocalIdpFixture, MockIssuanceListener, RecordedIssuance,
    };
}

// Observability
pub use axess_core::{
    AuthnMetrics, CompositeHealthCheck, CompositeStatus, HealthCheck, HealthStatus, NoopMetrics,
};

// Rate limiting
pub use axess_core::{KeyExtractor, RateLimitConfig, RateLimitConfigBuilder, RateLimitLayer};

/// External identity providers and federation adapters. Mirrors
/// [`axess_core::federation`].
pub mod federation {
    /// FIDO2 / WebAuthn passkey provider.
    #[cfg(feature = "fido2")]
    pub mod fido2 {
        pub use axess_factors::fido2::{DefaultFido2Provider, Fido2Provider};
    }

    /// LDAP bind authentication.
    #[cfg(feature = "ldap")]
    pub mod ldap {
        pub use axess_core::{
            LdapBindResult, LdapError, LdapGroupSearch, LdapProvider, LdapProviderConfig,
        };
    }

    /// OAuth 2.0 / OIDC providers, including FAPI 2.0 types under the
    /// `fapi` feature.
    #[cfg(feature = "oauth")]
    pub mod oauth {
        pub use axess_core::{
            AuthUrlResult, OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProvider,
            OAuthProviderConfig, ResponseMode, UserInfoClaims, spawn_jwks_refresh,
        };

        #[cfg(feature = "fapi")]
        pub use axess_core::{DpopProof, FapiConfig, ParResponse, SenderConstraint};
    }

    /// JWT verification primitives and (under `jwt-svid`) SPIFFE JWT-SVID
    /// resolution.
    #[cfg(feature = "oauth")]
    pub mod jwt {
        #[cfg(feature = "jwt-svid")]
        pub use axess_factors::jwt::svid;
        pub use axess_factors::jwt::{claims, validation, verifier};
    }

    /// mTLS workload-identity resolution via SPIFFE X509-SVID.
    #[cfg(feature = "mtls")]
    pub mod mtls {
        pub use axess_factors::mtls::{
            MtlsError, MtlsResolver, PeerCertChain, SpiffeIdComponents, peek_spiffe,
        };
    }

    /// RFC 7636 PKCE `code_verifier` predicate for application-side
    /// validation.
    pub mod pkce {
        pub use axess_factors::pkce::*;
    }

    /// Generic workload-identity resolver. Adopters wire it against
    /// a custom claim parser + mapping closure for any JWT-bearer
    /// IdP (GitHub Actions, k8s SA, GitLab CI, Okta, Azure AD,
    /// Auth0, …); see the `axess-example-workload-identity` crate
    /// for ready-made recipes.
    #[cfg(feature = "jwt")]
    pub use axess_factors::federation::workload;
}

/// Plain-OAuth-2.0 user login ("social login"). **Weaker security
/// model** than the OIDC path under [`federation::oauth`]: claims
/// come from a TLS-trusted userinfo endpoint, not from a signed
/// assertion. Use only when the IdP does not support OIDC (GitHub
/// user login, Twitter/X, Discord, Reddit, Spotify, …). Off by
/// default; opt in via the `social` feature. See module docs for
/// the full security delta.
#[cfg(feature = "social")]
pub mod social {
    pub use axess_factors::social::{
        AuthUrl, SocialClaims, SocialError, SocialProvider, SocialProviderConfig,
    };
}

/// Workload identity. Re-exports [`axess_core::workload`]. The
/// `workload-id` umbrella feature enables the full bundle (SPIFFE
/// JWT-SVID + mTLS + generic JWT-bearer + outbound + cloud STS).
/// The generic `WorkloadResolver` for non-SPIFFE bearer flows is
/// gated on `jwt` (or pulled in transitively by any of the other
/// features below).
#[cfg(any(
    feature = "jwt",
    feature = "jwt-svid",
    feature = "mtls",
    feature = "outbound-oauth",
    feature = "outbound-mtls",
    feature = "aws-sts",
    feature = "gcp-wif",
    feature = "azure-fic",
))]
pub mod workload {
    pub use axess_core::workload::*;
}

/// On-behalf-of (OBO) access. Re-exports [`axess_core::delegated`].
/// Submodules: `stored` (persistent user-authorized delegation, gated on
/// `delegated-stored`) and `exchange` (RFC 8693 Token Exchange, gated on
/// `delegated-exchange`).
#[cfg(any(feature = "delegated-stored", feature = "delegated-exchange"))]
pub mod delegated {
    pub use axess_core::delegated::*;
}

// Factor verification functions from axess-factors
pub use axess_factors::{
    HOTP_LENGTH, HotpAlgorithm, TOTP_LENGTH, TOTP_PERIOD, TotpAlgorithm, TotpVerifyParams,
    build_totp_uri, generate_password_hash, generate_totp_secret, verify_hotp, verify_password,
    verify_totp,
};

// Macros re-exported from axess-macros where they live.
#[cfg(feature = "authz")]
pub use axess_macros::require_authz;
pub use axess_macros::{require_authn, require_partial_authn};

// WebSocket helpers (revocation-aware connection wrapper) re-exported
// from axess-core where the implementation lives.
#[cfg(feature = "ws")]
pub use axess_core::middleware::ws;
