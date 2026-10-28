//! A login whose `Authenticated` audit row cannot be written leaves nothing
//! reachable: no authenticated session, no registry entry, no `sid` mapping.

use super::super::helpers::compute_claim_lock;
use crate::authn::service::AuthnService;
use crate::session::{MemorySessionRegistry, store::SessionRegistry};
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    tenant_record, test_session, user_record,
};
use axess_factors::oauth::{OAuthClaims, types::keys as oauth_keys};

fn claims() -> OAuthClaims {
    OAuthClaims {
        provider: "test".into(),
        subject: "external-sub".into(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: Some("idp-sid-1".to_string()),
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
    }
}

async fn login(arm_failure: bool) -> (bool, usize, usize) {
    let user = user_record("u1", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record("t1"))
        .with_user(user.clone());
    if arm_failure {
        identity.arm_record_event_failure();
    }
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .build();
    let req = svc.with_audit_context(crate::authn::event::AuditContext::default());
    let session = test_session();
    let c = claims();
    let lock = compute_claim_lock("test", &c.subject, &session).await;
    session
        .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
        .await;

    let res = req.complete_oauth_login(&user, &c, &session).await;
    assert_eq!(res.is_err(), arm_failure, "{res:?}");
    let registered = registry.active_sessions(&user.id).await.unwrap().len();
    (
        session.is_authenticated().await,
        registered,
        svc.inner.sid_map.len(),
    )
}

#[tokio::test]
async fn audit_failure_leaves_no_session_registry_entry_or_sid_mapping() {
    let (authed, registered, mapped) = login(true).await;
    assert!(!authed, "session must not stay Authenticated");
    assert_eq!(registered, 0, "registry entry must be dropped");
    assert_eq!(mapped, 0, "sid mapping must be removed");
}

#[tokio::test]
async fn successful_login_keeps_session_registry_entry_and_sid_mapping() {
    let (authed, registered, mapped) = login(false).await;
    assert!(authed);
    assert_eq!(registered, 1);
    assert_eq!(mapped, 1);
}

/// A refused login ends nobody else's session. Logging in as another user
/// under the same `(issuer, sid)` displaces the first user's mapping, but when
/// the audit write then fails and the login is refused, the first user's
/// session stays live: it is ended only once the new login has succeeded.
#[tokio::test]
async fn a_refused_login_does_not_end_the_session_it_would_have_displaced() {
    let first = user_record("u1", "t1");
    let second = user_record("u2", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record("t1"))
        .with_user(first.clone())
        .with_user(second.clone());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry.clone())
        .build();
    let req = svc.with_audit_context(crate::authn::event::AuditContext::default());

    let c = claims();
    let first_session = test_session();
    let lock = compute_claim_lock("test", &c.subject, &first_session).await;
    first_session
        .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
        .await;
    req.complete_oauth_login(&first, &c, &first_session)
        .await
        .expect("first login");
    let first_id = first_session.session_id().await;
    assert!(registry.is_valid(&first.id, &first_id).await.unwrap());

    // The second login reuses the sid, and its audit write fails.
    identity.arm_record_event_failure();
    let second_session = test_session();
    let lock = compute_claim_lock("test", &c.subject, &second_session).await;
    second_session
        .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
        .await;
    let res = req.complete_oauth_login(&second, &c, &second_session).await;
    assert!(res.is_err(), "the second login is refused");

    assert!(
        registry.is_valid(&first.id, &first_id).await.unwrap(),
        "the refused login must not have ended the first user's session"
    );
    assert!(
        svc.inner.sid_map.subject_len() >= 1,
        "the first session stays reachable by sub"
    );
}

/// The displaced session is still ended once the displacing login succeeds.
#[tokio::test]
async fn a_successful_login_still_ends_the_session_it_displaces() {
    let first = user_record("u1", "t1");
    let second = user_record("u2", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record("t1"))
        .with_user(first.clone())
        .with_user(second.clone());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .build();
    let req = svc.with_audit_context(crate::authn::event::AuditContext::default());

    let c = claims();
    let mut ids = Vec::new();
    for user in [&first, &second] {
        let session = test_session();
        let lock = compute_claim_lock("test", &c.subject, &session).await;
        session
            .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
            .await;
        req.complete_oauth_login(user, &c, &session)
            .await
            .expect("login");
        ids.push(session.session_id().await);
    }

    assert!(!registry.is_valid(&first.id, &ids[0]).await.unwrap());
    assert!(registry.is_valid(&second.id, &ids[1]).await.unwrap());
}
