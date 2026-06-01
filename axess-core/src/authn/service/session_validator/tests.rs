//! Branch-coverage tests for [`super::SessionValidator::is_valid`].
//!
//! Pulled sideways from `service.rs` so the production-vs-tests ratio
//! in the main service file becomes scannable. The tests pin every
//! branch against body-replacement, `!` deletion, and equality-flip
//! mutations.

#![cfg(test)]

use super::*;
use crate::authn::types::{EntityState, Tenant, User};
use crate::session::data::SessionData;
use crate::session::extractor::AuthSession;
use crate::session::layer::{SessionHandle, SessionInner};
use crate::session::store::{
    MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle,
};
use crate::testing::mock_authn::MockIdentityStore;
use tokio::sync::RwLock;

fn fixture_user_id() -> crate::authn::ids::UserId {
    axess_identity::testing::user("u-validator")
}

fn fixture_tenant_id() -> crate::authn::ids::TenantId {
    axess_identity::testing::tenant("t-validator")
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

fn registry_handle(registry: MemorySessionRegistry) -> Arc<dyn SessionRegistryHandle> {
    Arc::new(SessionRegistryAdapter(registry))
}

fn identity_handle(store: MockIdentityStore) -> Arc<dyn IdentityHandle> {
    Arc::new(IdentityWrapper(Arc::new(store)))
}

fn build_user(
    user_id: &crate::authn::ids::UserId,
    tenant_id: &crate::authn::ids::TenantId,
) -> User {
    let now = chrono::Utc::now();
    User {
        id: *user_id,
        tenant_id: *tenant_id,
        identifier: "validator-user".into(),
        display_name: "validator-user".into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: crate::authn::ids::UserId::system(),
        created_at: now,
        updated_by: crate::authn::ids::UserId::system(),
        updated_at: now,
    }
}

fn build_tenant(id: crate::authn::ids::TenantId, identifier: &str) -> Tenant {
    let now = chrono::Utc::now();
    Tenant {
        id,
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        created_by: crate::authn::ids::UserId::system(),
        created_at: now,
        updated_by: crate::authn::ids::UserId::system(),
        updated_at: now,
    }
}

/// Kills line 290 `replace -> true` / `-> false` / `delete !`:
/// non-authenticated → false.
#[tokio::test]
async fn unauthenticated_session_returns_false() {
    let validator = SessionValidator {
        registry: None,
        identity: None,
    };
    let session = make_session();
    assert!(
        !validator.is_valid(&session).await,
        "unauthenticated session must be invalid"
    );
}

/// Authenticated + no gates → true. Kills the `-> false` body
/// replacement and the `delete !` (which would early-return false).
#[tokio::test]
async fn authenticated_session_no_registry_no_identity_returns_true() {
    let validator = SessionValidator {
        registry: None,
        identity: None,
    };
    let session = authenticated_session().await;
    assert!(
        validator.is_valid(&session).await,
        "authenticated session with no extra gates must be valid"
    );
}

/// Kills line 299 `delete !`: registry rejection must invalidate.
#[tokio::test]
async fn registry_rejection_returns_false() {
    let registry = MemorySessionRegistry::new();
    let validator = SessionValidator {
        registry: Some(registry_handle(registry)),
        identity: None,
    };
    let session = authenticated_session().await;
    assert!(
        !validator.is_valid(&session).await,
        "registry rejection must invalidate the session"
    );
}

/// Companion to the rejection test: registry acceptance must
/// keep the session valid.
#[tokio::test]
async fn registry_acceptance_returns_true() {
    let registry = MemorySessionRegistry::new();
    let session = authenticated_session().await;
    let sid = session.session_id().await;
    registry.register(&fixture_user_id(), &sid).await.unwrap();

    let validator = SessionValidator {
        registry: Some(registry_handle(registry)),
        identity: None,
    };
    assert!(
        validator.is_valid(&session).await,
        "registered session must be valid"
    );
}

/// Kills line 312 match-guard `with true` / `with false` and
/// `== → !=`: tenant matches → valid.
#[tokio::test]
async fn identity_check_tenant_matches_returns_true() {
    let user_id = fixture_user_id();
    let tenant_id = fixture_tenant_id();
    let identity = MockIdentityStore::new()
        .with_tenant(build_tenant(tenant_id, "validator-tenant"))
        .with_user(build_user(&user_id, &tenant_id));

    let validator = SessionValidator {
        registry: None,
        identity: Some(identity_handle(identity)),
    };
    let session = authenticated_session().await;
    assert!(
        validator.is_valid(&session).await,
        "tenant cross-check must pass when user.tenant_id == session.tenant_id"
    );
}

/// Kills the same match-guard mutations from the other side:
/// tenant mismatches → invalid.
#[tokio::test]
async fn identity_check_tenant_mismatch_returns_false() {
    let user_id = fixture_user_id();
    let session_tenant = fixture_tenant_id();
    let other_tenant = axess_identity::testing::tenant("t-other");

    let identity = MockIdentityStore::new()
        .with_tenant(build_tenant(other_tenant, "other-tenant"))
        .with_user(build_user(&user_id, &other_tenant));

    let validator = SessionValidator {
        registry: None,
        identity: Some(identity_handle(identity)),
    };
    let session = make_session();
    session
        .set_authenticated(user_id, session_tenant, chrono::Utc::now())
        .await;
    assert!(
        !validator.is_valid(&session).await,
        "tenant-mismatch must invalidate the session"
    );
}

/// Defends the `None` arm at line 322: an authenticated session
/// whose `user_id` is unknown to the identity store must be
/// invalid.
#[tokio::test]
async fn identity_check_user_not_found_returns_false() {
    let identity = MockIdentityStore::new();
    let validator = SessionValidator {
        registry: None,
        identity: Some(identity_handle(identity)),
    };
    let session = authenticated_session().await;
    assert!(
        !validator.is_valid(&session).await,
        "unknown user must invalidate the session"
    );
}

/// `oauth_providers()` must surface the configured registry, not a
/// leaked default. The mutation replaces the body with
/// `Box::leak(Box::new(Default::default()))` which returns an empty
/// registry regardless of how many providers were registered via
/// `with_oauth_provider`. Build a service with one provider and
/// assert the accessor reports `provider_count() == 1`.
#[cfg(feature = "oauth")]
#[test]
fn oauth_providers_accessor_returns_configured_registry() {
    use crate::authn::service::AuthnService;
    use crate::testing::mock_authn::MockFactorStore;
    use axess_factors::oauth::MockOAuthProvider;

    let service = AuthnService::new(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(MockOAuthProvider::new("ax-028-idp"));

    let registry = service.oauth_providers();
    assert_eq!(
        registry.provider_count(),
        1,
        "oauth_providers() must return the live registry; \
         a leaked-default would report 0"
    );
    let names = registry.provider_names();
    assert!(
        names.iter().any(|n| n.as_ref() == "ax-028-idp"),
        "registry must contain the registered provider; names={:?}",
        names
    );
}
