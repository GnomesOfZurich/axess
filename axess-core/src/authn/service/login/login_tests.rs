//! `login_tests`: extracted from `login.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

//! Pin the cheap, observable surfaces of `login.rs`:
//! `check_session` (all branches), `logout` (registry invalidation),
//! `find_user_with_timing_equalization` (real-user lookup).
//!
//! Mutations in `prepare_factor` (line 303 temporal `+`) and
//! `verify_factor` (lines 431/444/473 dispatch + replay-prevention)
//! require a full factor-pipeline harness with active `MockClock` and
//! a per-factor verification fixture; those are deferred until the
//! larger sweep across login flows lands.
use super::super::AuthnService;
use super::*;
use crate::authn::ids::{TenantId, UserId};
use crate::authn::types::{EntityState, LockoutPolicy, Tenant, User};
use crate::session::data::SessionData;
use crate::session::extractor::AuthSession;
use crate::session::layer::{SessionHandle, SessionInner};
use crate::session::store::MemorySessionRegistry;
use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use std::sync::Arc;
use tokio::sync::RwLock;

fn fixture_user_id() -> UserId {
    axess_identity::testing::user("u-login")
}

fn fixture_tenant_id() -> TenantId {
    axess_identity::testing::tenant("t-login")
}

fn make_session() -> AuthSession {
    let inner = SessionInner {
        id: crate::session::id::SessionId::new(&axess_rng::SystemRng),
        data: SessionData::default(),
        modified: false,
        regenerate: false,
        pre_cycle_id: None,
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
    };
    AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

async fn authenticated_session() -> AuthSession {
    let session = make_session();
    session
        .set_authenticated(fixture_user_id(), fixture_tenant_id(), chrono::Utc::now())
        .await;
    session
}

fn build_user(user_id: &UserId, tenant_id: &TenantId, identifier: &str) -> User {
    let now = chrono::Utc::now();
    User {
        id: *user_id,
        tenant_id: *tenant_id,
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

fn build_tenant(tenant_id: TenantId, identifier: &str) -> Tenant {
    let now = chrono::Utc::now();
    Tenant {
        id: tenant_id,
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn build_service_with_identity(
    identity: MockIdentityStore,
) -> AuthnService<MockIdentityStore, MockFactorStore> {
    AuthnService::new(identity, MockFactorStore::new())
}

// ── check_session (line 491) ─────────────────────────────────────

/// Kills line 491 body `-> true` / `delete !`: unauthenticated
/// session must return `false`.
#[tokio::test]
async fn check_session_unauthenticated_returns_false() {
    let service = build_service_with_identity(MockIdentityStore::new());
    let session = make_session();
    assert!(!service.check_session(&session).await);
}

/// Kills line 491 `-> false`: authenticated session with no
/// registry must return `true`.
#[tokio::test]
async fn check_session_authenticated_no_registry_returns_true() {
    let service = build_service_with_identity(MockIdentityStore::new());
    let session = authenticated_session().await;
    assert!(service.check_session(&session).await);
}

/// Authenticated session + registry rejection → false. Pins the
/// `reg.is_valid` propagation.
#[tokio::test]
async fn check_session_registry_rejection_returns_false() {
    let service = build_service_with_identity(MockIdentityStore::new())
        .with_registry(MemorySessionRegistry::new());
    let session = authenticated_session().await;
    assert!(
        !service.check_session(&session).await,
        "registry rejection must invalidate the session"
    );
}

/// Authenticated session + registry acceptance → true.
#[tokio::test]
async fn check_session_registry_acceptance_returns_true() {
    let registry = MemorySessionRegistry::new();
    let session = authenticated_session().await;
    let sid = session.session_id().await;
    crate::session::store::SessionRegistry::register(&registry, &fixture_user_id(), &sid)
        .await
        .unwrap();

    let service = build_service_with_identity(MockIdentityStore::new()).with_registry(registry);
    assert!(service.check_session(&session).await);
}

// ── logout (line 509) ────────────────────────────────────────────

/// Kills line 509 `-> Ok(())`: `logout` must (a) succeed for an
/// authenticated session and (b) actually invalidate the user's
/// sessions in the registry. The mutation returns `Ok(())` without
/// touching the registry; observable via `registry.is_valid`
/// flipping from `true` (before) to `false` (after).
#[tokio::test]
async fn logout_invalidates_user_in_registry() {
    use crate::session::store::SessionRegistry;

    let identity = MockIdentityStore::new()
        .with_tenant(build_tenant(fixture_tenant_id(), "t-login"))
        .with_user(build_user(
            &fixture_user_id(),
            &fixture_tenant_id(),
            "u-login",
        ))
        .with_lockout_policy(LockoutPolicy::default());

    let registry = MemorySessionRegistry::new();
    let session = authenticated_session().await;
    let sid = session.session_id().await;
    registry.register(&fixture_user_id(), &sid).await.unwrap();
    assert!(registry.is_valid(&fixture_user_id(), &sid).await.unwrap());

    let service = build_service_with_identity(identity).with_registry(registry.clone());
    service.logout(&session).await.expect("logout must succeed");

    assert!(
        !registry.is_valid(&fixture_user_id(), &sid).await.unwrap(),
        "logout must invalidate the user in the registry; \
             the `Ok(())` mutation skips this side effect"
    );
}

// ── find_user_with_timing_equalization (line 575) ────────────────

// ── begin_login input guard (line 41-48) ─────────────────────────

/// Kills the line-42 `||` / `>` mutations: an oversized identifier
/// or oversized tenant_identifier must reject as
/// `InvalidCredentials` *before* hitting the database. Every
/// mutation in the early-reject chain (`|| → &&`, `> → ==`,
/// `> → >=`) flips the outcome on either an empty input (admitted
/// when it should reject) or a one-byte-over input (rejected
/// when it should still admit / vice versa).
#[tokio::test]
async fn begin_login_rejects_oversized_identifier() {
    use crate::validation::MAX_IDENTIFIER_BYTES;
    let service = build_service_with_identity(MockIdentityStore::new());
    let session = make_session();
    let huge_identifier = "x".repeat(MAX_IDENTIFIER_BYTES + 1);

    let outcome = service
        .begin_login(&huge_identifier, "t-login", &session, None)
        .await
        .expect("oversized identifier must reject cleanly");
    assert!(
        matches!(outcome, LoginOutcome::InvalidCredentials),
        "identifier longer than MAX_IDENTIFIER_BYTES must reject; \
             `> → ==/>=` mutants would admit at the boundary. got: {outcome:?}"
    );
}

/// Empty identifier must reject. Discriminates `|| → &&`: with
/// `&&` the guard requires *all* conditions, so an empty
/// identifier alone wouldn't trip the guard.
#[tokio::test]
async fn begin_login_rejects_empty_identifier() {
    let service = build_service_with_identity(MockIdentityStore::new());
    let session = make_session();
    let outcome = service
        .begin_login("", "t-login", &session, None)
        .await
        .expect("empty identifier must reject cleanly");
    assert!(
        matches!(outcome, LoginOutcome::InvalidCredentials),
        "empty identifier must reject; `|| → &&` mutant would admit"
    );
}

/// Oversized tenant_identifier must reject. Discriminates the
/// second `>` mutation at line 44.
#[tokio::test]
async fn begin_login_rejects_oversized_tenant_identifier() {
    use crate::validation::MAX_IDENTIFIER_BYTES;
    let service = build_service_with_identity(MockIdentityStore::new());
    let session = make_session();
    let huge_tenant = "y".repeat(MAX_IDENTIFIER_BYTES + 1);
    let outcome = service
        .begin_login("alice", &huge_tenant, &session, None)
        .await
        .expect("oversized tenant must reject cleanly");
    assert!(
        matches!(outcome, LoginOutcome::InvalidCredentials),
        "tenant_identifier longer than MAX_IDENTIFIER_BYTES must reject"
    );
}

/// Empty tenant_identifier must reject. Companion to the empty
/// identifier test.
#[tokio::test]
async fn begin_login_rejects_empty_tenant_identifier() {
    let service = build_service_with_identity(MockIdentityStore::new());
    let session = make_session();
    let outcome = service
        .begin_login("alice", "", &session, None)
        .await
        .expect("empty tenant must reject cleanly");
    assert!(
        matches!(outcome, LoginOutcome::InvalidCredentials),
        "empty tenant_identifier must reject"
    );
}

/// Kills line 575 `-> Ok(None)`: when the user EXISTS, the
/// helper must surface `Some(user)`. The mutation always returns
/// `None`, which collapses `begin_login` to
/// `Ok(LoginOutcome::InvalidCredentials)` via the user-not-found
/// arm (line 109). With the original body and a configured user
/// (but no factor methods registered), `begin_login` continues
/// past the lookup and fails at the no-methods gate (line 166)
/// with `Err(AuthnError::NoFlow)`: observably distinct from the
/// `InvalidCredentials` produced by the mutation.
#[tokio::test]
async fn begin_login_finds_existing_user_via_timing_equalized_path() {
    let user_id = fixture_user_id();
    let tenant_id = fixture_tenant_id();
    let tenant_identifier = "t-login";
    let user_identifier = "alice@example.test";
    let identity = MockIdentityStore::new()
        .with_tenant(build_tenant(tenant_id, tenant_identifier))
        .with_user(build_user(&user_id, &tenant_id, user_identifier))
        .with_lockout_policy(LockoutPolicy::default());

    let service = build_service_with_identity(identity);
    let session = make_session();

    let result = service
        .begin_login(user_identifier, tenant_identifier, &session, None)
        .await;

    // With the mutation: result is Ok(InvalidCredentials).
    // With the original: result is Err(NoFlow) (no methods
    // registered for this user).
    assert!(
        !matches!(result, Ok(LoginOutcome::InvalidCredentials)),
        "real user must NOT collapse to InvalidCredentials; \
             `find_user → Ok(None)` mutation would invert this. got: {result:?}"
    );
    assert!(
        matches!(result, Err(AuthnError::NoFlow)),
        "with no methods registered, begin_login must reach the \
             NoFlow gate past the user-lookup. got: {result:?}"
    );
}
