#![cfg(all(feature = "testing", feature = "oauth"))]
//! OAuth completion is bound to the begin-side expected tenant, and the
//! identity-cross-checked `SessionValidator` catches mid-flight tenant
//! tampering.

mod common;

use axess_core::authn::{error::AuthnError, service::AuthnService};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::oauth::OAuthClaims;
use chrono::Utc;
use common::{test_tenant, test_user_in_tenant, tid};

// Mirror of the (pub-crate) `axess.oauth.expected_tenant` constant: pinned
// here so the test breaks loudly if the production constant is ever renamed
// without updating the EXPECTED_TENANT contract.
const EXPECTED_TENANT_KEY: &str = "axess.oauth.expected_tenant";
const CLAIM_LOCK_KEY: &str = "axess.oauth.claim_lock";

/// Claim-lock helper: mirror of `oauth_service::compute_claim_lock`. Tests
/// that bypass `finish_oauth_login` must pre-stash the same
/// SHA-256(provider || ":" || subject || ":" || session_id) value that
/// `complete_oauth_login` will recompute and compare against.
async fn stash_claim_lock(
    session: &axess_core::session::extractor::AuthSession,
    provider: &str,
    subject: &str,
) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    let sid = session.session_id().await;
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update(b":");
    hasher.update(subject.as_bytes());
    hasher.update(b":");
    hasher.update(sid.as_bytes());
    let lock = URL_SAFE_NO_PAD.encode(hasher.finalize());
    session
        .set_custom(CLAIM_LOCK_KEY, serde_json::Value::String(lock))
        .await;
}

fn fake_claims() -> OAuthClaims {
    OAuthClaims {
        provider: "test".into(),
        subject: "external-sub-123".into(),
        email: Some("alice@example.com".into()),
        email_verified: Some(true),
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: None,
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
    }
}

fn empty_claims(subject: &str) -> OAuthClaims {
    OAuthClaims {
        provider: "test".into(),
        subject: subject.into(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: None,
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
    }
}

// ── EXPECTED_TENANT enforcement ──────────────────────────────────────────────

#[tokio::test]
async fn complete_oauth_login_refuses_cross_tenant_when_expected_tenant_set() {
    // Begin-side declared tenant t1, but the resolver returned a user from t2.
    // Library MUST refuse.
    let user = test_user_in_tenant("u1", "alice", "t2");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let session = test_session();

    // Simulate begin_oauth_login_in_tenant having stashed the binding.
    session
        .set_custom(
            EXPECTED_TENANT_KEY,
            serde_json::Value::String(axess_core::authn::ids::testing::tenant("t1").to_string()),
        )
        .await;
    // Pre-stash the claim_lock that finish_oauth_login would have minted.
    // Without this, complete_oauth_login refuses with NoFlow before reaching
    // the cross-tenant check.
    stash_claim_lock(&session, "test", "external-sub-123").await;

    let res = svc
        .complete_oauth_login(&user, &fake_claims(), &session)
        .await;
    assert!(matches!(res, Err(AuthnError::CrossTenant)));
    assert!(
        !session.is_authenticated().await,
        "session must NOT have been authenticated on cross-tenant refusal"
    );
}

#[tokio::test]
async fn complete_oauth_login_accepts_when_tenant_matches() {
    let user = test_user_in_tenant("u1", "alice", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let session = test_session();

    session
        .set_custom(
            EXPECTED_TENANT_KEY,
            serde_json::Value::String(axess_core::authn::ids::testing::tenant("t1").to_string()),
        )
        .await;
    stash_claim_lock(&session, "test", "external-sub-123").await;

    svc.complete_oauth_login(&user, &fake_claims(), &session)
        .await
        .expect("matching tenant should authenticate");
    assert!(session.is_authenticated().await);
}

#[tokio::test]
async fn complete_oauth_login_unbound_session_unaffected() {
    // Backward compat: if EXPECTED_TENANT is not set (caller used the
    // unscoped begin_oauth_login), behaviour is unchanged.
    let user = test_user_in_tenant("u1", "alice", "t2");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let session = test_session();
    stash_claim_lock(&session, "test", "external-sub-123").await;
    svc.complete_oauth_login(&user, &fake_claims(), &session)
        .await
        .expect("unbound session should authenticate (backward compat)");
    assert!(session.is_authenticated().await);
}

// ── SessionValidator with identity cross-check ──────────────────────────────

#[tokio::test]
async fn validator_with_identity_check_invalidates_tenant_mismatch() {
    let user = test_user_in_tenant("u1", "alice", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());

    let session = test_session();
    stash_claim_lock(&session, "test", "external-sub").await;
    svc.complete_oauth_login(&user, &empty_claims("external-sub"), &session)
        .await
        .unwrap();

    // Plain validator: passes (registry not configured, no tenant rail).
    let plain = svc.session_validator();
    assert!(plain.is_valid(&session).await);

    // Tamper the session: rewrite tenant_id to t2 (simulating store tampering).
    tamper_session_tenant_to(&session, "t2").await;

    // Plain validator can't catch it.
    assert!(plain.is_valid(&session).await);

    // Validator with identity check catches the mismatch.
    let strict = svc.session_validator_with_identity_check();
    assert!(
        !strict.is_valid(&session).await,
        "tenant tampering must be caught by identity-cross-checked validator"
    );
}

#[tokio::test]
async fn validator_with_identity_check_passes_unmodified_session() {
    let user = test_user_in_tenant("u1", "alice", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let session = test_session();
    stash_claim_lock(&session, "test", "external-sub").await;
    svc.complete_oauth_login(&user, &empty_claims("external-sub"), &session)
        .await
        .unwrap();
    let strict = svc.session_validator_with_identity_check();
    assert!(strict.is_valid(&session).await);
}

/// Mutate the session's stated tenant_id directly. Simulates an attacker who
/// has rewritten the session-store row without going through the library's
/// state-transition methods. The simplest in-test approximation: re-issue
/// set_authenticated with the wrong tenant, which the library happily does
/// if the caller asks (no rail there).
async fn tamper_session_tenant_to(
    session: &axess_core::session::extractor::AuthSession,
    tenant: &str,
) {
    let user_id = session.user_id().await.unwrap();
    session
        .set_authenticated(user_id, tid(tenant), Utc::now())
        .await;
}
