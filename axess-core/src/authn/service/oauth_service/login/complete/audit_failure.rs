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
