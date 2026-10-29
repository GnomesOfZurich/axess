#![cfg(feature = "testing")]
//! An administrative session kick is audited: the sessions end first, then a
//! `SessionInvalidated` row records the user, the session if one was named and
//! the actor.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{Actor, AuthnService};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{test_tenant, test_user, tid, uid};

#[tokio::test]
async fn kicking_one_session_writes_one_row_naming_the_actor() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid = session.session_id().await;
    registry.register(&uid("u1"), &sid).await.unwrap();

    svc.invalidate_session(&uid("u1"), &sid, Actor::Admin(&uid("admin")))
        .await
        .unwrap();

    assert!(
        registry
            .active_sessions(&uid("u1"))
            .await
            .unwrap()
            .is_empty()
    );
    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::SessionInvalidated)
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_status, AuthEventStatus::Success);
    assert_eq!(rows[0].user_id, Some(uid("u1")));
    assert_eq!(rows[0].actor_id, Some(uid("admin")));
    assert_eq!(rows[0].session_id, Some(sid));
}

#[tokio::test]
async fn kicking_every_session_is_audited_without_a_session_id() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry)
        .build()
        .with_audit_context(AuditContext::default());
    svc.invalidate_user_sessions(&uid("u1"), Actor::System)
        .await
        .unwrap();
    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::SessionInvalidated)
        .collect();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].actor_id.is_none() && rows[0].session_id.is_none());
}

#[tokio::test]
async fn without_a_registry_nothing_is_audited() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let svc = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    assert!(
        svc.invalidate_user_sessions(&uid("u1"), Actor::System)
            .await
            .is_err()
    );
    assert!(identity.events().is_empty());
}
