#![cfg(feature = "testing")]
//! Deleting a user through the service ends what the store alone cannot
//! reach: the registered sessions and the refresh tokens go first, then the
//! user, then an audit row names who did it.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{Actor, AuthnService};
use axess_core::authn::store::IdentityLookup;
use axess_core::session::data::SessionData;
use axess_core::session::refresh::{
    IssueRequest, Refresh, RefreshTokenConfig, issue_refresh_token,
};
use axess_core::session::store::{
    MemorySessionRegistry, MemorySessionStore, SessionRegistry, SessionStore,
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::{
    MemoryRefreshTokenStore, MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user, tid, uid};
use std::time::Duration;

#[tokio::test]
async fn deleting_a_user_ends_their_sessions_and_tokens_then_audits() {
    let clock = MockClock::now();
    let registry = MemorySessionRegistry::new();
    let rows = MemorySessionStore::new();
    let refresh = MemoryRefreshTokenStore::new();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .with_session_store(rows.clone())
        .with_refresh_store(refresh.clone())
        .build()
        .with_audit_context(AuditContext::default());

    // Signed in: a registered session with a stored row, and a refresh token.
    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("t1"), clock.now())
        .await;
    let sid = session.session_id().await;
    registry.register(&uid("u1"), &sid).await.unwrap();
    rows.save(&sid, &SessionData::default(), Duration::from_secs(600))
        .await
        .unwrap();
    let config = RefreshTokenConfig::default();
    let rng = MockRng::new(7);
    let (plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &uid("u1"),
            tenant_id: &tid("t1"),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &refresh,
        &rng,
        clock.now(),
    )
    .await
    .unwrap();
    assert!(registry.is_valid(&uid("u1"), &sid).await.unwrap());
    assert!(rows.load(&sid).await.unwrap().is_some());

    svc.delete_user(Actor::Admin(&uid("admin")), &uid("u1"), &tid("t1"))
        .await
        .unwrap();

    assert!(
        !registry.is_valid(&uid("u1"), &sid).await.unwrap(),
        "the registry no longer holds the session, so the old cookie is a guest"
    );
    assert!(
        rows.load(&sid).await.unwrap().is_none(),
        "the stored row is gone"
    );
    assert!(
        Refresh::any_tenant(&plaintext, |_| async { true })
            .run(&refresh, &config, &rng, clock.now())
            .await
            .is_err(),
        "the refresh token is revoked"
    );
    assert!(identity.get_user(&uid("u1")).await.unwrap().is_none());
    let deleted: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::AccountDeleted)
        .collect();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].event_status, AuthEventStatus::Success);
    assert_eq!(deleted[0].user_id, Some(uid("u1")));
    assert_eq!(deleted[0].tenant_id, Some(tid("t1")));
    assert_eq!(deleted[0].actor_id, Some(uid("admin")));
}

#[tokio::test]
async fn deleting_across_the_tenant_rail_is_refused_and_deletes_nothing() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(MemorySessionRegistry::new())
        .build()
        .with_audit_context(AuditContext::default());

    let res = svc
        .delete_user(Actor::Admin(&uid("admin")), &uid("u1"), &tid("other"))
        .await;

    assert!(matches!(res, Err(AuthnError::CrossTenant)), "{res:?}");
    assert!(identity.get_user(&uid("u1")).await.unwrap().is_some());
    assert!(
        !identity
            .events()
            .iter()
            .any(|e| e.event_type == AuthEventType::AccountDeleted
                && e.event_status == AuthEventStatus::Success)
    );
}
