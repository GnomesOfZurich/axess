#![cfg(feature = "testing")]
//! An administrative session kick is audited: the sessions end first, then a
//! `SessionInvalidated` row records the user, the session if one was named and
//! the actor.

use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{Actor, AuthnService};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user, tid, uid};

#[tokio::test]
async fn kicking_one_session_writes_one_row_naming_the_actor() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), common::start())
        .await;
    let sid = session.session_key().await;
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
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
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
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    assert!(
        svc.invalidate_user_sessions(&uid("u1"), Actor::System)
            .await
            .is_err()
    );
    assert!(identity.events().is_empty());
}

mod ownership {
    //! A kick names a user and a session; the session must be that user's.
    //! A pair that does not match deletes nothing, publishes nothing and
    //! writes no audit row, and a registry that cannot say whose the session
    //! is refuses rather than guessing.

    use super::*;
    use axess_core::authn::error::AuthnError;
    use axess_core::session::data::SessionData;
    use axess_core::session::store::{MemorySessionStore, SessionStore};
    use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct World {
        svc: axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
        identity: MockIdentityStore,
        registry: RegistryDouble,
        asking_down: Arc<AtomicBool>,
        store: MemorySessionStore,
        /// Alice's session.
        sa: SessionKey,
        /// Bob's session.
        sb: SessionKey,
    }

    /// A registry that cannot say which key a session is under while
    /// `asking_down` is set, every other call working.
    fn mapped(inner: MemorySessionRegistry, asking_down: Arc<AtomicBool>) -> RegistryDouble {
        RegistryDouble::over(inner).before(move |call, _| {
            let down = call.op() == RegistryOp::CurrentKey && asking_down.load(Ordering::SeqCst);
            async move {
                if down {
                    Step::Fail("registry down")
                } else {
                    Step::Forward
                }
            }
        })
    }

    async fn world() -> World {
        let clock = common::test_clock();
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant())
            .with_user(test_user("alice", "alice"))
            .with_user(test_user("bob", "bob"));
        let asking_down = Arc::new(AtomicBool::new(false));
        let registry = mapped(
            MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone())),
            asking_down.clone(),
        );
        let store = MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone()));
        let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_registry(registry.clone())
            .with_session_store(store.clone())
            .build()
            .with_audit_context(AuditContext::default());
        let mut ids = Vec::new();
        for who in ["alice", "bob"] {
            let session = test_session();
            session
                .set_authenticated(uid(who), tid("default"), common::start())
                .await;
            let sid = session.session_key().await;
            registry.register(&uid(who), &sid).await.unwrap();
            store
                .save(&sid, &SessionData::default(), Duration::from_secs(600))
                .await
                .unwrap();
            ids.push(sid);
        }
        World {
            svc,
            identity,
            registry,
            asking_down,
            store,
            sa: ids[0],
            sb: ids[1],
        }
    }

    async fn bob_still_has_his_session(w: &World) {
        assert_eq!(
            w.registry
                .inner()
                .active_sessions(&uid("bob"))
                .await
                .unwrap(),
            vec![w.sb],
            "bob's registry entry survives"
        );
        assert!(
            w.store.load(&w.sb).await.unwrap().is_some(),
            "bob's stored row survives"
        );
        assert!(
            !w.identity
                .events()
                .iter()
                .any(|e| e.event_type == AuthEventType::SessionInvalidated),
            "no audit row claims a session ended"
        );
    }

    #[tokio::test]
    async fn a_session_that_is_not_the_users_is_left_alone() {
        let w = world().await;
        assert_eq!(
            w.registry
                .inner()
                .active_sessions(&uid("bob"))
                .await
                .unwrap(),
            vec![w.sb]
        );
        assert!(w.store.load(&w.sb).await.unwrap().is_some());

        let res = w
            .svc
            .invalidate_session(&uid("alice"), &w.sb, Actor::Admin(&uid("admin")))
            .await;

        assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
        bob_still_has_his_session(&w).await;
        assert_eq!(
            w.registry
                .inner()
                .active_sessions(&uid("alice"))
                .await
                .unwrap(),
            vec![w.sa],
            "alice's own session is untouched too"
        );
    }

    #[tokio::test]
    async fn a_registry_that_cannot_say_whose_the_session_is_refuses() {
        let w = world().await;
        w.asking_down.store(true, Ordering::SeqCst);

        let res = w
            .svc
            .invalidate_session(&uid("bob"), &w.sb, Actor::Admin(&uid("admin")))
            .await;

        assert!(
            matches!(res, Err(AuthnError::ExternalService(_))),
            "{res:?}"
        );
        bob_still_has_his_session(&w).await;
    }

    #[tokio::test]
    async fn the_users_own_session_is_ended_and_audited() {
        let w = world().await;
        w.svc
            .invalidate_session(&uid("bob"), &w.sb, Actor::Admin(&uid("admin")))
            .await
            .unwrap();
        assert!(
            w.registry
                .inner()
                .active_sessions(&uid("bob"))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(w.store.load(&w.sb).await.unwrap().is_none());
        assert_eq!(
            w.identity
                .events()
                .iter()
                .filter(|e| e.event_type == AuthEventType::SessionInvalidated)
                .count(),
            1
        );
    }
}
