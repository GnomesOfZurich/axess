#![cfg(feature = "testing")]
//! An administrative session kick is audited: the sessions end first, then a
//! `SessionInvalidated` row records the user, the session if one was named and
//! the actor.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{Actor, AuthnService};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::AuthSessionTestExt;
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

mod ownership {
    //! A kick names a user and a session; the session must be that user's.
    //! A pair that does not match deletes nothing, publishes nothing and
    //! writes no audit row, and a registry that cannot say whose the session
    //! is refuses rather than guessing.

    use super::*;
    use axess_core::authn::error::AuthnError;
    use axess_core::session::data::SessionData;
    use axess_core::session::store::{MemorySessionStore, SessionStore};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct World {
        svc: axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
        identity: MockIdentityStore,
        registry: Mapped,
        store: MemorySessionStore,
        /// Alice's session.
        sa: axess_core::session::id::SessionId,
        /// Bob's session.
        sb: axess_core::session::id::SessionId,
    }

    /// A registry whose `active_sessions` fails while `listing_down` is set,
    /// every other call working.
    #[derive(Clone)]
    struct Mapped {
        inner: MemorySessionRegistry,
        listing_down: Arc<AtomicBool>,
    }

    impl SessionRegistry for Mapped {
        type Error = std::io::Error;
        async fn register(
            &self,
            u: &axess_core::authn::UserId,
            s: &axess_core::session::id::SessionId,
        ) -> Result<(), Self::Error> {
            self.inner
                .register(u, s)
                .await
                .map_err(std::io::Error::other)
        }
        async fn is_valid(
            &self,
            u: &axess_core::authn::UserId,
            s: &axess_core::session::id::SessionId,
        ) -> Result<bool, Self::Error> {
            self.inner
                .is_valid(u, s)
                .await
                .map_err(std::io::Error::other)
        }
        async fn invalidate_user(&self, u: &axess_core::authn::UserId) -> Result<(), Self::Error> {
            self.inner
                .invalidate_user(u)
                .await
                .map_err(std::io::Error::other)
        }
        async fn invalidate_session(
            &self,
            u: &axess_core::authn::UserId,
            s: &axess_core::session::id::SessionId,
        ) -> Result<(), Self::Error> {
            self.inner
                .invalidate_session(u, s)
                .await
                .map_err(std::io::Error::other)
        }
        async fn active_sessions(
            &self,
            u: &axess_core::authn::UserId,
        ) -> Result<Vec<axess_core::session::id::SessionId>, Self::Error> {
            if self.listing_down.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("registry down"));
            }
            self.inner
                .active_sessions(u)
                .await
                .map_err(std::io::Error::other)
        }
    }

    async fn world() -> World {
        let identity = MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("alice", "alice"))
            .with_user(test_user("bob", "bob"));
        let registry = Mapped {
            inner: MemorySessionRegistry::new(),
            listing_down: Arc::new(AtomicBool::new(false)),
        };
        let store = MemorySessionStore::new();
        let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_registry(registry.clone())
            .with_session_store(store.clone())
            .build()
            .with_audit_context(AuditContext::default());
        let mut ids = Vec::new();
        for who in ["alice", "bob"] {
            let session = test_session();
            session
                .set_authenticated(uid(who), tid("default"), Utc::now())
                .await;
            let sid = session.session_id().await;
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
            store,
            sa: ids[0],
            sb: ids[1],
        }
    }

    async fn bob_still_has_his_session(w: &World) {
        assert_eq!(
            w.registry.inner.active_sessions(&uid("bob")).await.unwrap(),
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
            w.registry.inner.active_sessions(&uid("bob")).await.unwrap(),
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
                .inner
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
        w.registry.listing_down.store(true, Ordering::SeqCst);

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
                .inner
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
