//! Deterministic-simulation-testing (DST) fixtures: mocks, fakes, and
//! record builders that adopter test suites can use against `axess-core`'s
//! production traits.
//!
//! The whole module is gated behind `#[cfg(any(test, feature = "testing"))]`
//! so production builds cannot import test doubles. Adopters writing
//! integration tests against `AuthnService`, `AuthzStore`, `SessionLayer`
//! etc. need to enable the feature on their dev-dependency line:
//!
//! ```toml
//! [dev-dependencies]
//! axess = { version = "0.19.0", features = ["testing"] }
//! ```
//!
//! Individual mocks inside this module may carry *additional* gates tied
//! to the production feature they mock (`authz`, `local-idp`); those are
//! gated on the prod feature, not on a separate `testing` flag.
//!
//! ## What lives here
//!
//! Two categories of test double share this module. *Mocks* are
//! trait-shaped substitutes that simulate a single surface (a store, a
//! random source, a clock). *Fixtures* are working in-process
//! implementations that test code can drive directly without standing
//! up external infrastructure. The categories are listed separately
//! because they behave differently: a mock answers what the test tells
//! it to answer; a fixture runs the same code path the production
//! variant would, just against in-memory state.
//!
//! ### Mocks
//!
//! - `mock_authn`: `MockFactorStore` / `MockIdentityStore` / `MockStoreError`,
//!   and `CallLog` for asserting the order of store calls.
//! - `mock_clock`: re-export of [`axess_clock::testing::MockClock`].
//! - `mock_random`: re-export of [`axess_rng::testing::MockRng`].
//! - `mock_refresh_store`: `MemoryRefreshTokenStore` + error type.
//! - `valkey_fake` (tests of this crate only): an in-memory Valkey keyspace
//!   that logs each command and runs a hook between two of them, so a race
//!   between pods is a deterministic test.
//! - `mock_policy` (feature `authz`): Cedar policy fixtures.
//! - `MockResolver` (re-exported from [`axess_identity::testing`]): `PrincipalResolver` stub.
//!
//! ### Fixtures
//!
//! - `local_idp` (feature `local-idp`): in-process IdP fixture for
//!   workload-identity tests. Shares signing primitives with the
//!   production [`LocalIdp`](crate::local_idp::LocalIdp); the primitives
//!   live in [`crate::local_idp::primitives`] (out of this `testing`
//!   tree) so production code does not have to import from here.
//! - `oauth_provider` (features `testing` and `oauth`): an
//!   [`OAuthProviderConfig`](axess_factors::oauth::OAuthProviderConfig)
//!   discovered from an identity provider at a given address. Pair it with
//!   `axess_testing::oauth_wiremock`, which stands the provider up, to
//!   exercise the `begin_oauth_login` / `finish_oauth_login` /
//!   `complete_oauth_login` ceremony without provisioning a real IdP.
//!   The tracing capture and the wiremock fixture live in the
//!   `axess-testing` crate, a dev-dependency, so that no production
//!   dependency graph can reach `wiremock`. The edge-value tables
//!   (`durations`, `ipv6_forms`) and the cancellation helpers (`stall`) live
//!   there too.
//!
//! ### Other helpers
//!
//! - Record builders: `user_record`, `tenant_record`, `test_session`.
//! - `AuthSessionTestExt`: re-exposes `pub(crate)` state-mutation methods
//!   on [`AuthSession`](crate::session::extractor::AuthSession) for fixtures
//!   that need to plant a session in a known state.

pub mod mock_authn;
pub mod mock_clock;
pub mod mock_random;
pub mod mock_refresh_store;

pub mod recording_metrics;
pub mod store_contract;

#[cfg(all(test, any(feature = "postgres", feature = "mysql")))]
pub(crate) mod sql_live;

#[cfg(all(test, feature = "valkey-cache"))]
pub(crate) mod valkey_fake;

// Authz mocks are not restricted to #[cfg(test)] so that downstream crates
// can use them in their own test suites.
#[cfg(feature = "authz")]
pub mod mock_policy;

/// In-process IdP test fixture; see [`local_idp`] module docs.
/// Gated on the `local-idp` feature (pulls in `rsa`).
#[cfg(feature = "local-idp")]
pub mod local_idp;

/// A provider discovered from an identity provider at a given address, for
/// adopter test suites that drive the OAuth/OIDC ceremony end-to-end.
#[cfg(feature = "oauth")]
pub mod oauth_provider;

/// A 32-byte key for tests that is not a single repeated byte, so the
/// constructors that refuse a placeholder accept it. Distinct seeds give
/// distinct keys.
pub const fn test_key(seed: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        key[i] = seed.wrapping_add(i as u8);
        i += 1;
    }
    key
}

pub use mock_authn::{CallLog, MockFactorStore, MockIdentityStore, MockStoreError};
pub use mock_clock::MockClock;
pub use mock_random::MockRng;
pub use mock_refresh_store::{MemoryRefreshStoreError, MemoryRefreshTokenStore};
pub use recording_metrics::RecordingMetrics;

// `MockResolver` lives in the leaf `axess-identity` crate so
// adopters who depend on `axess-identity` directly (without all of
// axess-core) can still use it in their test suites. axess-core
// re-exports it here for callers that import everything from one
// place; matches the shape of the other DST mocks in this module.
pub use axess_identity::testing::MockResolver;

/// Build a ready-to-use [`User`](crate::authn::types::User) record from a
/// short label, matching the [`axess_identity::testing::user`] id helper.
///
/// `label` drives a stable UUID v5 for the user id; the same label always
/// produces the same id across the workspace, so test fixtures that
/// rebuild a user agree on its bytes. The tenant id is derived from
/// `tenant_label` via the same scheme. Other fields default to:
/// `identifier = display_name = label`,
/// `status = EntityState::Active`, `webauthn_id = None`,
/// `created_by = updated_by = UserId::system()`,
/// `created_at = updated_at = chrono::Utc::now()`.
///
/// For deterministic timestamps use [`user_record_at`].
pub fn user_record(label: &str, tenant_label: &str) -> crate::authn::types::User {
    user_record_at(label, tenant_label, chrono::Utc::now())
}

/// [`user_record`] with `created_at = updated_at = now`.
pub fn user_record_at(
    label: &str,
    tenant_label: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::authn::types::User {
    crate::authn::types::User {
        id: axess_identity::testing::user(label),
        tenant_id: axess_identity::testing::tenant(tenant_label),
        identifier: label.into(),
        display_name: label.into(),
        status: crate::authn::types::EntityState::Active,
        webauthn_id: None,
        created_by: crate::authn::ids::UserId::system(),
        created_at: now,
        updated_by: crate::authn::ids::UserId::system(),
        updated_at: now,
    }
}

/// Build a ready-to-use [`Tenant`](crate::authn::types::Tenant) record
/// from a short label, matching the [`axess_identity::testing::tenant`]
/// id helper. Mirror of [`user_record`].
pub fn tenant_record(label: &str) -> crate::authn::types::Tenant {
    tenant_record_at(label, chrono::Utc::now())
}

/// [`tenant_record`] with `created_at = updated_at = now`.
pub fn tenant_record_at(
    label: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::authn::types::Tenant {
    crate::authn::types::Tenant {
        id: axess_identity::testing::tenant(label),
        identifier: label.into(),
        display_name: label.into(),
        status: crate::authn::types::EntityState::Active,
        created_by: crate::authn::ids::UserId::system(),
        created_at: now,
        updated_by: crate::authn::ids::UserId::system(),
        updated_at: now,
    }
}

/// Create an `AuthSession` with a fresh session ID for use in tests.
///
/// This avoids needing access to `pub(crate)` constructors from integration tests.
/// The id, and every id the session rotates to, comes from the system RNG;
/// use [`test_session_with_rng`] for a reproducible sequence.
pub fn test_session() -> crate::session::extractor::AuthSession {
    test_session_with_rng(axess_rng::SystemRng)
}

/// [`test_session`] whose initial id and later rotations are drawn from `rng`.
pub fn test_session_with_rng(
    rng: impl axess_rng::SecureRng,
) -> crate::session::extractor::AuthSession {
    use crate::session::{
        data::SessionData,
        id::SessionId,
        layer::{SessionHandle, SessionInner},
    };
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let rng: Arc<dyn axess_rng::SecureRng> = Arc::new(rng);
    let inner = SessionInner {
        id: SessionId::new(&rng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng,
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
        consume: None,
    };
    crate::session::extractor::AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

/// [`test_session`] that the device subsystem has bound to `device_id`, as the
/// session layer's device resolver does for a request from that device.
#[cfg(feature = "device")]
pub fn test_session_on_device(
    device_id: crate::authn::ids::DeviceId,
) -> crate::session::extractor::AuthSession {
    let session = test_session();
    session
        .0
        .0
        .try_write()
        .expect("a fresh session is unshared")
        .data
        .device_id = Some(device_id);
    session
        .0
        .0
        .try_write()
        .expect("a fresh session is unshared")
        .data
        .device_proven = true;
    session
}

/// [`test_session_on_device`] for a device a resolver found by fingerprint
/// alone: the session carries the id and the lockout exemption ignores it.
#[cfg(feature = "device")]
pub fn test_session_on_unproven_device(
    device_id: crate::authn::ids::DeviceId,
) -> crate::session::extractor::AuthSession {
    let session = test_session();
    session
        .0
        .0
        .try_write()
        .expect("a fresh session is unshared")
        .data
        .device_id = Some(device_id);
    session
}

/// Test-fixture extension trait that re-exposes the
/// state-mutation methods on
/// [`AuthSession`](crate::session::extractor::AuthSession). The
/// inherent methods (`set_authenticated`, `begin_authenticating`,
/// `advance_factor`, `record_attempt_at`) are `pub(crate)` so handler
/// code can't corrupt the factor-pipeline state machine by calling
/// them directly; the service-side login flow drives them through
/// audited entry points. Integration tests legitimately need to plant
/// a session in a fixture state; importing this trait makes those
/// methods callable on `AuthSession` again. Method names match the
/// inherent surface so existing test code only needs the new `use`
/// line: no per-site rewrite.
///
/// Always-on (not behind `cfg(test)`) so adopter integration tests
/// pick up the trait via `axess-core` in `[dev-dependencies]`.
/// Importing `AuthSessionTestExt` in handler code is itself a strong
/// review signal that the handler is reaching past the audited entry
/// points; code reviewers should treat the `use` line as a red flag.
pub use session_ext::AuthSessionTestExt;

mod session_ext {
    use crate::authn::factor::FactorKind;
    use crate::authn::ids::{TenantId, UserId};
    use crate::session::extractor::AuthSession;
    use chrono::{DateTime, Utc};
    use std::sync::Arc;

    /// Extension trait; see module-level docs for the rationale.
    pub trait AuthSessionTestExt {
        /// Force the session into [`AuthState::Authenticated`](crate::session::data::AuthState::Authenticated).
        fn set_authenticated(
            &self,
            user_id: UserId,
            tenant_id: TenantId,
            authn_time: DateTime<Utc>,
        ) -> impl std::future::Future<Output = ()> + Send;

        /// Force the session into [`AuthState::Authenticating`](crate::session::data::AuthState::Authenticating)
        /// with the given factor sequence, each kind a required step.
        fn begin_authenticating(
            &self,
            user_id: UserId,
            tenant_id: TenantId,
            method_name: Arc<str>,
            factors: Vec<FactorKind>,
        ) -> impl std::future::Future<Output = ()> + Send;

        /// Drive one factor-pipeline step from the test side,
        /// advancing the in-session `remaining` queue and transitioning
        /// to [`AuthState::Authenticated`](crate::session::data::AuthState::Authenticated)
        /// when empty.
        fn advance_factor(
            &self,
            kind: &FactorKind,
            authn_time: DateTime<Utc>,
        ) -> impl std::future::Future<Output = ()> + Send;

        /// [`advance_factor`](Self::advance_factor) recording `proof`, what
        /// the factor proved, instead of what its kind alone proves
        /// ([`FactorAssurance::for_kind`](crate::authn::assurance::FactorAssurance::for_kind)):
        /// for a test that needs a user-verified or device-bound FIDO2 step.
        fn advance_factor_with(
            &self,
            proof: crate::authn::assurance::FactorAssurance,
        ) -> impl std::future::Future<Output = ()> + Send;

        /// Stamp a failed-attempt timestamp on the session without
        /// touching the persistent lockout counter; mirrors what the
        /// factor pipeline does on credential mismatch, but
        /// addressable from a unit test.
        fn record_attempt_at(
            &self,
            now: DateTime<Utc>,
        ) -> impl std::future::Future<Output = ()> + Send;

        /// Mark an authenticated session as `admin`'s impersonation begun
        /// at `since`, the marker `begin_impersonation` leaves; `false`,
        /// changing nothing, when the session is not authenticated.
        fn set_impersonator(
            &self,
            admin: UserId,
            since: DateTime<Utc>,
        ) -> impl std::future::Future<Output = bool> + Send;
    }

    impl AuthSessionTestExt for AuthSession {
        async fn set_authenticated(
            &self,
            user_id: UserId,
            tenant_id: TenantId,
            authn_time: DateTime<Utc>,
        ) {
            // Fully-qualified resolves to the pub(crate) inherent
            // method on AuthSession; the trait method body runs
            // inside axess-core where the inherent is visible.
            AuthSession::set_authenticated(self, user_id, tenant_id, authn_time).await;
        }

        async fn begin_authenticating(
            &self,
            user_id: UserId,
            tenant_id: TenantId,
            method_name: Arc<str>,
            factors: Vec<FactorKind>,
        ) {
            let steps = factors
                .into_iter()
                .map(crate::authn::factor::FactorStep::Required)
                .collect();
            AuthSession::begin_authenticating(self, user_id, tenant_id, method_name, steps).await;
        }

        async fn advance_factor(&self, kind: &FactorKind, authn_time: DateTime<Utc>) {
            let proof =
                crate::authn::assurance::FactorAssurance::for_kind(kind.clone(), authn_time);
            AuthSession::advance_factor(self, proof, &[]).await;
        }

        async fn advance_factor_with(&self, proof: crate::authn::assurance::FactorAssurance) {
            AuthSession::advance_factor(self, proof, &[]).await;
        }

        async fn record_attempt_at(&self, now: DateTime<Utc>) {
            AuthSession::record_attempt_at(self, now).await;
        }

        async fn set_impersonator(&self, admin: UserId, since: DateTime<Utc>) -> bool {
            AuthSession::set_impersonator(self, admin, since).await
        }
    }
}
