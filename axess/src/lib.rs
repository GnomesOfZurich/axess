//! Public-facing facade for `axess-core`. Prefer the subsystem namespaces
//! (`axess::session`, `axess::authn`, `axess::authz`, `axess::backends`,
//! `axess::workload`, `axess::delegated`, `axess::local_idp`) in new code;
//! root-level re-exports are kept for ergonomics on the most common entry
//! points (`SessionLayer`, `AuthnService`, `AuthzStore`, the route-guard
//! macros, and the DST primitives `Clock` / `SecureRng`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// The `testing` feature compiles the test doubles of every crate beneath
// this facade. A release build that links it ships those in a production
// binary, and cargo feature unification lets any one dependent switch it on
// for the whole build, so the build refuses by name.
// `allow-testing-in-release` is the named opt-out for a build that means
// it. Every crate with a `testing` feature carries this gate
// (scripts/check-testing-gates.sh).
#[cfg(all(
    feature = "testing",
    not(debug_assertions),
    not(feature = "allow-testing-in-release")
))]
compile_error!(
    "the `testing` feature of axess is enabled in a release build; it ships test doubles in a \
     production binary. Remove the feature from the release build, or enable \
     `allow-testing-in-release` to keep it on purpose."
);

/// Identity test fixture builders (`tenant`, `user`, `device`, ...) plus
/// [`MockResolver`](crate::testing::MockResolver). Re-exported from `axess-identity` under the `testing`
/// feature.
#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing {
    /// Conformance checks for a session registry of your own: the one-step
    /// move of a session, the key a session is under now, an ending by a
    /// former key and the cut-off of a user's other sessions.
    pub use axess_core::testing::registry_contract;
    /// A session registry that records every call and takes a hook before
    /// and after each.
    pub use axess_core::testing::registry_double;
    /// Conformance checks for a store of your own: a session store's
    /// conditional write, a factor store's passkey credential-id claim.
    pub use axess_core::testing::store_contract;
    pub use axess_core::testing::{AuthSessionTestExt, Shift, test_key};
    pub use axess_core::{
        BreachCheckOutage, MockClock, MockFactorStore, MockIdentityStore, MockRng,
    };
    pub use axess_identity::testing::*;

    /// An in-process SPIRE agent for tests of the `spire` client.
    #[cfg(all(feature = "spire", unix))]
    pub use axess_core::testing::spire_agent;

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
    AuthFlow, AuthSession, AuthState, ConditionalUpdate, CutOff, Impersonation, MoveOutcome,
    RevocationError, SESSION_KEY_DOMAIN, SameSite, SessionBinding, SessionConfig,
    SessionConfigBuilder, SessionData, SessionId, SessionKey, SessionKeyError, SessionKeyPrefix,
    SessionLayer, SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle, SessionRevoker,
    SessionStore, UserAgentBinding,
};
#[cfg(feature = "memory")]
pub use axess_core::{MemorySessionRegistry, MemorySessionStore};

/// Session sub-module re-exports (crypto, refresh tokens, etc.).
pub mod session {
    pub use axess_core::session::LegacyBlobs;
    // The refresh-token entry points: `issue_refresh_token`, `Refresh` (the
    // one refresh, with its tenant, status, device and binding checks) and
    // `revoke_refresh_token`. Wrap the store in `device::CascadingRefreshStore`
    // so a reused rotated-out token revokes the family's devices as well. A
    // glob, so a new public item is exported without a second edit.
    pub use axess_core::session::refresh::*;
    #[cfg(any(
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql",
        feature = "valkey"
    ))]
    pub use axess_core::session::{CryptoError, SessionCrypto};
    pub use axess_core::session::{
        CycleOutcome, DeviceTokenRevocation, PreviousPepper, RefreshToken, RefreshTokenConfig,
        RefreshTokenStore, RotationOutcome, WeakKeyError,
    };
    // How many records of its sessions' moves a registry keeps for one user:
    // the bound a registry of your own keeps too.
    pub use axess_core::session::MAX_MOVE_RECORDS_PER_USER;
    // The session layer's audit sink: what every `SessionLayer` constructor
    // takes (`AuthnService::session_end_audit` is the stock implementation,
    // `UnrecordedSessionEnds` the named opt-out) and what a sink of your own
    // is told about each session the layer ends. `EndingClaim` is the mark
    // the layer leaves on a stored session while it ends it
    // (`SessionData::ending`).
    pub use axess_core::session::{
        EndingClaim, LayerSessionEnded, SessionEndAudit, SessionEndReason, UnrecordedSessionEnds,
    };
}

/// Where password hashing runs: [`KdfExecutor`](blocking::KdfExecutor) and its
/// error.
pub mod blocking {
    pub use axess_core::blocking::*;
}

/// Authentication namespace. Prefer `axess::authn::*` in new code.
///
/// The audit archive is here too: the [`AuditArchiver`](crate::authn::AuditArchiver)
/// trait, the [`AuditRetentionLoop`](crate::authn::AuditRetentionLoop) that moves
/// audit rows from the hot table to it, and, with `audit-archive-fs`, the
/// filesystem-backed reference archiver:
///
/// ```
/// # #[cfg(feature = "audit-archive-fs")]
/// # fn main() {
/// use axess::authn::{AuditArchiver, FilesystemArchiveError, FilesystemAuditArchiver};
///
/// fn archives<A: AuditArchiver<Error = FilesystemArchiveError>>(archiver: &A) -> &A {
///     archiver
/// }
///
/// let archiver = FilesystemAuditArchiver::new("/var/lib/axess/audit");
/// assert_eq!(archives(&archiver).root(), std::path::Path::new("/var/lib/axess/audit"));
/// # }
/// # #[cfg(not(feature = "audit-archive-fs"))]
/// # fn main() {}
/// ```
pub mod authn {
    // What each factor of a session proved, and the step-up a refusal
    // names: `StepUp` parses the `step_up` field of a `step_up_required`
    // answer for `RequestAuthnService::begin_step_up_for`.
    pub use axess_core::authn::assurance::{
        CredentialBinding, FactorAssurance, StepUp, StepUpParseError,
    };
    pub use axess_core::authn::factor_secret::{
        FactorSecretBinding, FactorSecretCipher, FactorSecretError, OpenedSecret,
    };
    /// The reason on the failed `SignupCompleted` audit row written when the
    /// session of a signup being completed could not be registered.
    pub use axess_core::authn::service::SIGNUP_SESSION_NOT_REGISTERED_REASON;
    /// What `RequestAuthnService::invalidate_other_sessions` reports when
    /// it did not leave the kept session as the user's only one, and the
    /// reasons on its failed audit rows.
    pub use axess_core::authn::service::{
        OTHER_SESSIONS_NOT_ENDED_REASON, OtherSessionsError, REFRESH_TOKENS_NOT_REVOKED_REASON,
    };
    pub use axess_core::authn::{
        ArchiveBatchId, AuditArchiver, AuditRetentionLoop, AuditRetentionPolicy,
        AuditRetentionSource, NoopAuditArchiver, RetentionError, RetentionTickReport,
    };
    /// The filesystem-backed reference [`AuditArchiver`] and its error.
    #[cfg(feature = "audit-archive-fs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "audit-archive-fs")))]
    pub use axess_core::authn::{FilesystemArchiveError, FilesystemAuditArchiver};
    pub use axess_core::{
        ActiveSessionsError, Actor, AuditContext, AuditOutcome, AuditQuery, AuditTrail, AuthEvent,
        AuthEventBuilder, AuthEventStatus, AuthEventType, AuthFailureReason, AuthMethod,
        AuthnBackend, AuthnError, AuthnScope, AuthnService, AuthnServiceBuilder, BreachCheckError,
        BreachCheckUnavailable, BreachedPasswordCheck, BreachedPasswordList, ChosenPasswordError,
        CounterUnavailable, DeviceId, EmailOtpConfig, EntityState, EventQueryFilter, FactorConfig,
        FactorCredential, FactorKind, FactorOutcome, FactorSecret, FactorStep, FactorStore,
        FactorTemplate, FederatedProvider, Fido2Config, Fido2CredentialClaim, HotpConfig,
        IdentityAdmin, IdentityAuthnLog, IdentityLookup, IdentityPasswordHistory,
        IdentityPasswordReset, IdentityStore, IpPolicy, LdapBindFactorConfig, LockoutPolicy,
        LockoutPolicyError, LoginOutcome, NoSessionRegistryError, NoopAuthnLog, OtpAlgorithm,
        PasswordConfig, PasswordRules, PrepareOutcome, ProvisioningError, RequestAuthnService,
        ResolvedFactor, SealedFactorSecret, SessionValidator, SignupOutcome, SignupVerification,
        StatusCause, StatusDetail, Tenant, TenantBootstrap, TenantId, Throttle, ThrottleKey,
        ThrottleState, ThrottleSubject, TotpConfig, UnreadableReason, UnreadableRows, User, UserId,
        ZeroizedString, create_tenant, default_catalog, require_valid_session,
    };
    pub use axess_factors::{
        GeneratedRecoveryCodes, HOTP_LENGTH, HotpAlgorithm, HotpThrottle, NewPasswordError,
        PepperTooShort, RECOVERY_CODE_COUNT, RecoveryCodePepper, RecoveryCodesConfig,
        StoredRecoveryCode, TOTP_LENGTH, TOTP_PERIOD, TotpAlgorithm, TotpVerifyParams,
        build_totp_uri, check_password_breached, count_in_range, generate_password_hash,
        generate_password_hash_with_rng, generate_recovery_codes, generate_recovery_codes_peppered,
        generate_totp_secret, hash_new_password, hash_new_password_checked,
        normalize_recovery_code, range_prefix, verify_hotp, verify_password, verify_recovery_code,
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

/// Shared-secret authentication for internal machine callers. Re-exports
/// [`axess_core::middleware::service_secret`].
#[cfg(feature = "service-secret")]
pub mod service_secret {
    pub use axess_core::middleware::service_secret::*;
}

/// W3C Trace Context middleware. Re-exports [`axess_core::middleware::trace_context`].
#[cfg(feature = "trace-context")]
pub mod trace_context {
    pub use axess_core::middleware::trace_context::*;
}

/// CSRF protection middleware. Re-exports [`axess_core::middleware::csrf`].
pub mod csrf {
    pub use axess_core::middleware::csrf::*;
}

// In-memory backend for prototyping. Wraps mock identity/factor stores;
// gated behind `testing` so production builds cannot ship it.
#[cfg(feature = "testing")]
pub use axess_core::InMemoryBackend;

/// Storage backends grouped by data store. Each backend module exposes
/// the per-store types under their unprefixed names so adopters write
/// `use axess::backends::sqlite::{SessionStore, DeviceStore};` instead
/// of stitching together `SqliteSessionStore`, `SqliteDeviceStore`,
/// `SqlStoreError`, `SqlDeviceStoreError` from disjoint flat symbols.
pub mod backends {
    /// SQLite-backed stores. Requires the `sqlite` feature, or
    /// `sqlite-unbundled` for the same stores linked to the system's SQLite
    /// library; device-store types additionally require the `device`
    /// feature. The
    /// `SessionStoreError` here is the codec-level error shared with
    /// PostgreSQL, gated on either feature.
    #[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
    pub mod sqlite {
        pub use axess_core::SqliteSessionStore as SessionStore;
        #[cfg(any(feature = "sqlite", feature = "sqlite-unbundled", feature = "postgres"))]
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

        /// Why a replay store's server is not known to keep its records
        /// (`JtiReplayStore::checked`).
        #[cfg(any(
            feature = "jwt",
            feature = "oauth",
            feature = "outbound-oauth",
            feature = "local-idp",
            feature = "device-keys"
        ))]
        pub use axess_core::replay::EvictionPolicyError as JtiReplayEvictionError;
        /// A `jti` replay store every node shares, for the JWT and DPoP
        /// verifiers.
        #[cfg(any(
            feature = "jwt",
            feature = "oauth",
            feature = "outbound-oauth",
            feature = "local-idp",
            feature = "device-keys"
        ))]
        pub use axess_core::replay::ValkeyJtiReplayStore as JtiReplayStore;
    }

    /// In-memory stores. Session-store + registry require `memory`;
    /// refresh-token store is a test double and requires `testing`;
    /// device-store types additionally require `device`. Recommended for
    /// prototypes, tests, and single-process deployments only, not for
    /// production.
    #[cfg(any(feature = "memory", feature = "testing"))]
    pub mod memory {
        #[cfg(feature = "testing")]
        pub use axess_core::MemoryRefreshStoreError as RefreshStoreError;
        #[cfg(feature = "testing")]
        pub use axess_core::MemoryRefreshTokenStore as RefreshTokenStore;
        #[cfg(feature = "memory")]
        pub use axess_core::MemorySessionRegistry as SessionRegistry;
        #[cfg(feature = "memory")]
        pub use axess_core::MemorySessionStore as SessionStore;
        /// A `jti` replay store in one process, for the JWT and DPoP
        /// verifiers and for device-key request proofs on a single node.
        #[cfg(all(
            feature = "memory",
            any(
                feature = "jwt",
                feature = "oauth",
                feature = "outbound-oauth",
                feature = "local-idp",
                feature = "device-keys"
            )
        ))]
        pub use axess_core::replay::MemoryJtiReplayStore as JtiReplayStore;

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
    /// Writes device and device-key audit rows through an identity store's
    /// `record_event`.
    pub use axess_core::device::events::IdentityStoreEventSink;
    pub use axess_core::{
        AttestationClass, BindingsUpdate, BoundDevice, CachedDeviceStore, CascadingRefreshStore,
        DefaultFingerprintExtractor, Device, DeviceBinding, DeviceCookieConfig, DeviceEventSink,
        DeviceFingerprintExtractor, DeviceLifecycleService, DevicePiiCategory, DevicePiiMapping,
        DevicePiiResolver, DevicePiiStore, DeviceResolver, DeviceStore, DeviceTrustLevel,
        FingerprintHash, LifecycleDeviceResolver, LifecycleResolveError, MemoryDevicePiiStore,
        MemoryDevicePiiStoreError, MemoryDeviceStore, MemoryDeviceStoreError, NoopDeviceEventSink,
        NoopDeviceResolver, OwnerClaim, PiiToken, ProvenDevice, REDACTED_PLACEHOLDER,
        RedactedResolver, RevokeDeviceError, SessionUser, StepUpPolicy, StepUpPolicyBuilder,
        SweepConfig, SweepConfigBuilder, SweepConfigError, SweepCounts, TenantPepperResolver,
        TrustTransition, UserDevice, cascade_revoke_by_refresh_family_and_tokens,
        cascade_revoke_devices, decide_step_up_for_optional, decide_step_up_for_user,
        revoke_device,
    };
}

/// Device keys: the values a device-bound session is made of and, with the
/// `device-keys` feature, the service that registers and proves them.
/// Re-exports [`axess_core::device_key`].
pub mod device_key {
    pub use axess_core::device_key::*;

    /// The proof verifier the key service is built on: `KeyProofError` (what
    /// `DeviceKeyError::Proof` carries), the proof shapes, the browser
    /// draft's wire names (`key_proof::browser_draft`) and, with `testing`,
    /// the software key a test registers and signs with
    /// (`key_proof::testing::SoftwareKey`).
    #[cfg(feature = "device-keys")]
    pub use axess_factors::key_proof;
}

// Device-store backends are now grouped under `backends::{sqlite,postgres,valkey,memory}::DeviceStore`
// (and `DeviceStoreError`); see the `backends` module above.

// DST utilities. Clock + RNG abstractions for deterministic-simulation
// testing. Production `Clock`/`SecureRng`/`SystemClock`/`SystemRng`
// are unconditional; the mock counterparts are gated behind `testing`.
pub use axess_core::{Clock, SecureRng, SystemClock, SystemRng};

// The time types every `now`, stamp and expiry of the API is written in, so
// an adopter names them through the facade.
pub use axess_core::{SignedDuration, TimeError, Timestamp, Until, UtcDate};

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
    #[cfg(feature = "testing")]
    pub use axess_core::testing::local_idp::{
        LocalIdpFixture, MockIssuanceListener, RecordedIssuance,
    };
}

// Observability
pub use axess_core::{
    AuditMetrics, AuthFlowMetrics, AuthzCacheMetrics, AxessMetrics, CompositeHealthCheck,
    CompositeStatus, CsrfRefusal, DeviceKeyMetrics, FactorMetrics, HealthCheck, HealthStatus,
    MetricSinks, NoopMetrics, ProviderCategory, ProviderRegistryMetrics, RequestGuardMetrics,
    RotationMetrics, SessionMetrics,
};

// Rate limiting
pub use axess_core::{KeyExtractor, RateLimitConfig, RateLimitConfigBuilder, RateLimitLayer};

/// The client's address, resolved once per request.
///
/// Ungated, and deliberately not under `authz`: the rate limiter, the audit
/// trail and the device gate all need an address, and none of them should
/// compile a policy engine to get one.
pub mod client_ip {
    pub use axess_core::client_ip::{CidrParseError, ClientIp, Source, TrustedProxies, layer};
}

/// Input validation helpers (`is_valid_password`, `meets_password_rules`,
/// `is_valid_email`, ...). Re-exports [`axess_core::validation`].
pub use axess_core::validation;

/// The security profile: `SecurityProfile::Standard` restates the library's
/// defaults as named values and `SecurityProfile::Strict` is the tightened
/// set for a deployment that holds money or regulated data; `ProfileValues`
/// is read, changed and applied to each configuration type, and a service
/// builder put under a profile is held to it when the service is built
/// (`ProfileSetting`, `AuthnBuildError`). Re-exports
/// [`axess_core::profile`]; the `sqlite` and `fapi` examples apply it.
pub mod profile {
    pub use axess_core::profile::{
        AuthnBuildError, ProfileError, ProfileSetting, ProfileValues, SecurityProfile,
    };
}

/// JWT verification primitives and, under `jwt-svid`, SPIFFE JWT-SVID
/// resolution.
///
/// At the root rather than under `federation`, and gated on `jwt` rather
/// than `oauth`, so `features = ["jwt-svid"]` reaches the resolver and a
/// workload deployment with no OAuth in sight does not enable OAuth.
///
/// [`encode`](crate::jwt::encode), [`decode`](crate::jwt::decode),
/// [`sign`](crate::jwt::sign) and [`verify`](crate::jwt::verify) are
/// `jsonwebtoken`'s operations after
/// [`ensure_crypto_provider`](crate::jwt::ensure_crypto_provider): an
/// application's own code that signs or verifies with `jsonwebtoken` goes
/// through them, so its first operation cannot fix the provider that panics.
#[cfg(feature = "jwt")]
pub mod jwt {
    #[cfg(feature = "jwt-svid")]
    pub use axess_factors::jwt::svid;
    pub use axess_factors::jwt::{
        claims, decode, encode, ensure_crypto_provider, sign, validation, verifier, verify,
    };
}

/// External identity providers and federation adapters. Mirrors
/// [`axess_core::federation`].
pub mod federation {
    /// FIDO2 / WebAuthn passkey provider.
    #[cfg(feature = "fido2")]
    pub mod fido2 {
        pub use axess_core::authn::service::DiscoverableLogin;
        pub use axess_factors::fido2::{
            AttestationCaList, AuthenticatorAttachment, CredentialID, DEFAULT_FIDO2_CEREMONY,
            DEFAULT_FIDO2_MAX_AUTHN_AGE, DefaultFido2Provider, DiscoverableCredential,
            DiscoverablePrompt, Fido2Authentication, Fido2Ceremony, Fido2Credential, Fido2Key,
            Fido2Options, Fido2Provider, Fido2Registration, SecurityKeyVerification,
        };
    }

    /// LDAP bind authentication.
    #[cfg(feature = "ldap")]
    pub mod ldap {
        pub use axess_core::{
            LdapBindResult, LdapError, LdapGroupSearch, LdapProvider, LdapProviderConfig,
        };
    }

    /// OAuth 2.0 / OIDC providers, including the FAPI 2.0 profile (`fapi`
    /// is an alias for `oauth`).
    #[cfg(feature = "oauth")]
    pub mod oauth {
        pub use axess_core::{
            AuthUrlResult, ClientAssertionError, ClientAssertionSigner, OAuthClaims, OAuthError,
            OAuthLoginOptions, OAuthProvider, OAuthProviderBuilder, OAuthProviderConfig,
            ResponseMode, SignerSpec, UserInfoClaims, spawn_jwks_refresh,
        };
        /// The key DPoP-bound tokens are tied to, what a request needs to
        /// sign a proof with it, and the proof. A provider binds its tokens
        /// to one by default when the IdP advertises DPoP; keep the key
        /// beside the refresh token (`DpopKey::to_seed_bytes`,
        /// `DpopKey::from_seed`).
        pub use axess_core::{DpopKey, DpopProof, DpopSigner};
        /// What the server may fetch for a URL a tenant supplied: the screen
        /// `StoredTenantOAuthProviders` applies, and its named opt-outs.
        pub use axess_factors::egress::{EgressPolicy, EgressRefusal, ReservedRange};

        /// The reason on the audit row of an operator's attestation that a
        /// tenant owns an OAuth client.
        pub use axess_core::authn::service::CLIENT_OWNERSHIP_ATTESTED_REASON;
        /// The reason on the row a scoped token revocation writes before
        /// the provider is asked.
        pub use axess_core::authn::service::OAUTH_REVOCATION_REQUESTED_REASON;
        /// The route a callback arrived on, which `finish_oauth_login`
        /// compares with the registration the login began with.
        pub use axess_core::authn::service::OAuthCallbackRoute;
        /// The by-name helpers (refresh, userinfo, revocation, logout URL)
        /// resolved by a session's or a tenant's provider.
        pub use axess_core::authn::service::ScopedOAuth;
        /// The reasons on the rows of an operator's hand-over of a client's
        /// issuer and client id: the request, and each record removed.
        pub use axess_core::authn::service::{
            CLIENT_PAIR_HAND_OVER_REQUESTED_REASON, CLIENT_PAIR_HANDED_OVER_REASON,
        };
        #[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
        pub use axess_core::federation::oauth_tenant::SqliteTenantOAuthProviderStore;
        /// Bring your own IdP: providers resolved by `(tenant, name)` from
        /// a store at request time.
        pub use axess_core::federation::oauth_tenant::{
            BrokenTenantProvider, IssuerProviders, MemoryTenantOAuthProviderStore, ReassignedPair,
            Reproved, StoredTenantOAuthProviders, TenantClientCredential, TenantDpop,
            TenantOAuthProviderRecord, TenantOAuthProviderStore, TenantOAuthProviderStoreError,
            TenantOAuthProviders, TenantOAuthRecords, TenantProvider,
        };
        /// Proof that a tenant owns the client it registers, which the
        /// directory asks before it stores a record.
        pub use axess_core::federation::oauth_tenant::{
            ClientOwnershipProof, DEFAULT_OWNERSHIP_PROBE_TIMEOUT, OperatorAttestation,
            OwnershipAttestation, OwnershipClaim, OwnershipFuture, OwnershipProofs,
            OwnershipProven, OwnershipPurpose, OwnershipRefused, TokenEndpointProbe,
        };
        // IdP-initiated logout: mount the back-channel handler as a route,
        // and pass `AuthnService::backchannel_logout_audit` to `with_audit`
        // so the sessions it ends are audited.
        pub use axess_core::federation::backchannel_logout::{
            BackChannelLogoutHandler, IdpSessionEnded, LogoutAudit, LogoutProviderError,
        };
        // The `sid` map and the replay log behind a trait, so instances can
        // share them (`ValkeySidStore` and `ValkeyReplayLog` with `valkey`).
        pub use axess_core::federation::replay_log::{
            LogoutReplayLog, Recorded, ReplayFuture, ReplayLogError,
        };
        pub use axess_core::federation::sid_map::SidMap;
        pub use axess_core::federation::sid_store::{SidFuture, SidStore, SidStoreError};
        #[cfg(feature = "valkey")]
        pub use axess_core::federation::valkey_logout::{ValkeyReplayLog, ValkeySidStore};
        // The front-channel handler, and the bound form `new` returns, which
        // ends a session only when it is the request's own and is mounted
        // behind the session layer (`new_unbound` makes the plain handler).
        pub use axess_core::federation::frontchannel_logout::{
            BoundFrontChannelLogoutHandler, FrontChannelLogoutHandler, FrontChannelLogoutParams,
        };

        pub use axess_core::{FapiConfig, ParResponse, SenderConstraint};
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
    feature = "spire",
))]
pub mod workload {
    /// The cause inside the STS errors' `ClientBuild` variant.
    #[cfg(any(feature = "aws-sts", feature = "azure-fic", feature = "gcp-wif"))]
    pub use axess_core::ClientBuildError;
    pub use axess_core::workload::*;
}

/// On-behalf-of (OBO) access. Re-exports [`axess_core::delegated`].
/// Submodules: `stored` (persistent user-authorized delegation, gated on
/// `delegated-stored`) and `exchange` (RFC 8693 Token Exchange, gated on
/// `delegated-exchange`).
#[cfg(any(feature = "delegated-stored", feature = "delegated-exchange"))]
pub mod delegated {
    /// The cause inside `DelegatedError::ClientBuild`.
    pub use axess_core::ClientBuildError;
    pub use axess_core::delegated::*;
}

// Factor verification functions from axess-factors
pub use axess_factors::{
    BreachCheckError, BreachCheckUnavailable, BreachedPasswordCheck, GeneratedRecoveryCodes,
    HOTP_LENGTH, HotpAlgorithm, NewPasswordError, PepperTooShort, RECOVERY_CODE_COUNT,
    RecoveryCodePepper, RecoveryCodesConfig, StoredRecoveryCode, TOTP_LENGTH, TOTP_PERIOD,
    TotpAlgorithm, TotpVerifyParams, build_totp_uri, check_password_breached, count_in_range,
    generate_password_hash, generate_password_hash_with_rng, generate_recovery_codes,
    generate_recovery_codes_peppered, generate_totp_secret, hash_new_password,
    hash_new_password_checked, normalize_recovery_code, range_prefix, verify_hotp, verify_password,
    verify_recovery_code, verify_totp,
};

// Macros re-exported from axess-macros where they live.
#[cfg(feature = "authz")]
pub use axess_macros::require_authz;
pub use axess_macros::{require_authn, require_partial_authn};

// WebSocket helpers (revocation-aware connection wrapper) re-exported
// from axess-core where the implementation lives.
#[cfg(feature = "ws")]
pub use axess_core::middleware::ws;
