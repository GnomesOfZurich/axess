//! The world a test starts in: one clock, a tenant, its users, their factor
//! configurations and their sessions, all at one instant.
//!
//! A test's world runs on one clock: the [`test_clock`] it builds once, a
//! mock set to the reference instant [`start`]. Every service, store, cipher,
//! layer and provider the test drives is built on that clock through its
//! `with_clock` (a helper that builds part of the world takes it as a
//! parameter), the test reads the time from it, and time moves only when the
//! test advances it.
//!
//! The fixtures here are what exists when the world begins: they stamp their
//! records with [`start`], so a world built on [`test_clock`] finds them made
//! at its first instant, and a world set later finds them older. The record
//! builders beside this module ([`user_record`](super::user_record),
//! [`tenant_record_at`](super::tenant_record_at)) take a label and an instant
//! of the caller's choosing; these fix both, so that tests which share a
//! world need not agree on them again.
//!
//! The default world is tenant `"t1"` with user `"u1"`: [`test_tenant`],
//! [`test_user`], [`user_scope`] and the two methods all point at it.

use axess_clock::Timestamp;

use super::MockClock;
use crate::authn::{
    factor::{FactorConfig, FactorKind, PasswordConfig, PasswordRules, TotpConfig, ZeroizedString},
    ids::{TenantId, UserId},
    store::AuthMethod,
    types::{AuthnScope, EntityState, Tenant, User},
};
use crate::session::extractor::AuthSession;

// ── Clock ────────────────────────────────────────────────────────────────────

/// The clock a test world runs on: a [`MockClock`] set to [`start`]. Each
/// call returns a new clock, so tests never share one; a test builds it once
/// and hands clones of it to every part of its world.
pub fn test_clock() -> MockClock {
    MockClock::at_reference()
}

/// The instant every test world starts at, and the time the fixtures stamp
/// their records with: [`MockClock::reference_time`].
pub fn start() -> Timestamp {
    MockClock::reference_time()
}

// ── ID builders ──────────────────────────────────────────────────────────────

/// A [`UserId`] from a test label, through
/// [`axess_identity::testing::user`]: the same label always gives the same
/// id, across crates and runs.
pub fn uid(v: &str) -> UserId {
    crate::authn::ids::testing::user(v)
}

/// A [`TenantId`] from a test label; as stable as [`uid`].
pub fn tid(v: &str) -> TenantId {
    crate::authn::ids::testing::tenant(v)
}

// ── Provider changes ─────────────────────────────────────────────────────────

/// The administrator a test's provider changes are made as. The audited
/// `_as` methods name whoever is passed; they look nobody up.
pub fn provider_admin() -> UserId {
    uid("provider-admin")
}

/// The reload's own refusal out of an audited provider change that was
/// refused, for a test that asserts on why. An audit failure, which only a
/// test that breaks the audit store provokes, fails the test here.
///
/// The two error types exist only where a provider can be reloaded, so the
/// helper is compiled with one of the features that bring one.
#[cfg(any(feature = "oauth", feature = "fido2", feature = "ldap"))]
pub fn reload_refusal(
    error: crate::authn::service::ProviderChangeError,
) -> crate::authn::service::ProviderReloadError {
    match error {
        crate::authn::service::ProviderChangeError::Refused(refusal) => refusal,
        other => panic!("the change was refused, but not by the reload: {other}"),
    }
}

// ── Entity fixtures ──────────────────────────────────────────────────────────

/// A standard active tenant with id `"t1"`. Default choice for single-tenant
/// tests that don't need to exercise multi-tenant logic.
pub fn test_tenant() -> Tenant {
    let now = start();
    Tenant {
        id: tid("t1"),
        identifier: "default".into(),
        display_name: "Test Tenant".into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

/// A standard active user in tenant `"t1"`. Pass the `id` and `identifier`
/// separately so tests can assert on both.
pub fn test_user(id: &str, identifier: &str) -> User {
    test_user_in_tenant(id, identifier, "t1")
}

/// User fixture with explicit tenant; use when a test exercises
/// cross-tenant boundary behaviour.
pub fn test_user_in_tenant(id: &str, identifier: &str, tenant: &str) -> User {
    let now = start();
    User {
        id: uid(id),
        tenant_id: tid(tenant),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

// ── Factor + scope fixtures ──────────────────────────────────────────────────

/// Build a [`FactorConfig::Password`] that hashes the supplied plaintext.
pub fn password_config(password: &str) -> FactorConfig {
    let hash = axess_factors::generate_password_hash(password);
    FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(hash),
        rules: PasswordRules::default(),
        password_id: None,
    })
}

/// Build a [`FactorConfig::Totp`] backed by the supplied base32 secret.
pub fn totp_config(secret: &str) -> FactorConfig {
    FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(secret).into(),
        ..TotpConfig::default()
    })
}

/// The user-scope pointer for tenant `"t1"`, user `"u1"`; matches the
/// default fixtures [`test_tenant`] and [`test_user`].
pub fn user_scope() -> AuthnScope {
    AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u1"),
    }
}

/// Password-only sequential auth method against [`user_scope`].
pub fn password_method() -> AuthMethod {
    AuthMethod::sequential("password", vec![FactorKind::Password], user_scope())
}

/// Password-then-TOTP sequential auth method against [`user_scope`].
pub fn password_totp_method() -> AuthMethod {
    AuthMethod::sequential(
        "password+totp",
        vec![FactorKind::Password, FactorKind::Totp],
        user_scope(),
    )
}

// ── Session fixtures ─────────────────────────────────────────────────────────

/// A session authenticated as `user` at [`start`], for the calls that act
/// on the caller's own account (passkey enrolment and deletion).
pub async fn session_for(user: &User) -> AuthSession {
    let session = super::test_session();
    session
        .set_authenticated(user.id, user.tenant_id, start())
        .await;
    session
}

/// A session pending signup for `user` since [`start`], as `begin_signup`
/// leaves it.
pub async fn signup_session_for(user: &User) -> AuthSession {
    use crate::session::data::{WorkflowKind, WorkflowState};
    let session = super::test_session();
    session
        .set_pending_workflow(
            user.id,
            user.tenant_id,
            WorkflowState::new(WorkflowKind::Signup, 1, start()),
        )
        .await;
    session
}
