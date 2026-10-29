#![cfg(all(feature = "testing", feature = "memory"))]
//! Revocation that cannot be carried out is reported, the stored rows go with
//! the registry entries when the store is wired, and a login does not carry
//! pre-login session data into the authenticated session.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::StatusDetail;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::AuthEventType;
use axess_core::authn::{
    Actor,
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, FactorOutcome},
};
use axess_core::session::data::SessionData;
use axess_core::session::store::{
    MemorySessionRegistry, MemorySessionStore, SessionRegistry, SessionRegistryAdapter,
    SessionRevoker, SessionStore,
};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A registry whose revocations fail while `failing` is set.
#[derive(Clone)]
struct FlakyRegistry {
    inner: MemorySessionRegistry,
    failing: Arc<AtomicBool>,
}

impl FlakyRegistry {
    fn new() -> Self {
        Self {
            inner: MemorySessionRegistry::new(),
            failing: Arc::new(AtomicBool::new(false)),
        }
    }
    fn outage(&self) -> Result<(), std::io::Error> {
        if self.failing.load(Ordering::SeqCst) {
            Err(std::io::Error::other("registry down"))
        } else {
            Ok(())
        }
    }
}

impl SessionRegistry for FlakyRegistry {
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
        self.outage()?;
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
        self.outage()?;
        self.inner
            .invalidate_session(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn active_sessions(
        &self,
        u: &axess_core::authn::UserId,
    ) -> Result<Vec<axess_core::session::id::SessionId>, Self::Error> {
        self.inner
            .active_sessions(u)
            .await
            .map_err(std::io::Error::other)
    }
}

fn identity_and_factors() -> (MockIdentityStore, MockFactorStore) {
    (
        MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice")),
        MockFactorStore::new()
            .with_factor(user_scope(), password_config("Gnomes2+"))
            .with_method(&uid("u1"), password_method()),
    )
}

#[tokio::test]
async fn the_registry_adapter_reports_a_failed_revocation() {
    let flaky = FlakyRegistry::new();
    flaky.failing.store(true, Ordering::SeqCst);
    let handle = SessionRegistryAdapter(flaky);
    let sid = axess_core::session::id::SessionId::new(&axess_rng::SystemRng);
    assert!(
        handle.invalidate_user(&uid("u1")).await.is_err(),
        "a down registry must not report a user's sessions as revoked"
    );
    assert!(handle.invalidate_session(&uid("u1"), &sid).await.is_err());
}

#[tokio::test]
async fn an_admin_kick_the_registry_could_not_carry_out_is_an_error_and_not_audited() {
    let (identity, factors) = identity_and_factors();
    let flaky = FlakyRegistry::new();
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_registry(flaky.clone())
        .build()
        .with_audit_context(AuditContext::default());
    flaky.failing.store(true, Ordering::SeqCst);

    let err = svc
        .invalidate_user_sessions(&uid("u1"), Actor::Admin(&uid("admin")))
        .await
        .expect_err("the kick did not happen");
    assert!(matches!(err, AuthnError::ExternalService(_)), "{err:?}");
    assert!(
        identity
            .events()
            .iter()
            .all(|e| e.event_type != AuthEventType::SessionInvalidated),
        "no row may claim sessions were ended when the registry refused"
    );

    flaky.failing.store(false, Ordering::SeqCst);
    svc.invalidate_user_sessions(&uid("u1"), Actor::Admin(&uid("admin")))
        .await
        .expect("the registry is back");
}

#[tokio::test]
async fn a_suspension_reports_a_registry_that_could_not_end_the_sessions() {
    let (identity, factors) = identity_and_factors();
    let flaky = FlakyRegistry::new();
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_registry(flaky.clone())
        .build()
        .with_audit_context(AuditContext::default());
    flaky.failing.store(true, Ordering::SeqCst);

    let result = svc
        .suspend_user_across_tenants(
            Actor::System,
            &uid("u1"),
            StatusDetail {
                reason: "hold".into(),
                since: Utc::now(),
                until: None,
            },
        )
        .await;
    assert!(
        result.is_err(),
        "the caller must learn the sessions may live"
    );
    assert!(
        identity
            .events()
            .iter()
            .any(|e| e.event_type == AuthEventType::AccountSuspended),
        "the suspension itself stands and is audited"
    );
}

#[tokio::test]
async fn kicking_a_user_deletes_the_stored_rows_when_the_store_is_wired() {
    for wired in [true, false] {
        let (identity, factors) = identity_and_factors();
        let registry = MemorySessionRegistry::new();
        let store = MemorySessionStore::new();
        let mut builder = AuthnService::builder(identity, factors).with_registry(registry.clone());
        if wired {
            builder = builder.with_session_store(store.clone());
        }
        let svc = builder.build().with_audit_context(AuditContext::default());

        let sid = axess_core::session::id::SessionId::new(&axess_rng::SystemRng);
        store
            .save(&sid, &SessionData::default(), Duration::from_secs(60))
            .await
            .unwrap();
        registry.register(&uid("u1"), &sid).await.unwrap();

        svc.invalidate_user_sessions(&uid("u1"), Actor::System)
            .await
            .unwrap();

        assert_eq!(
            store.load(&sid).await.unwrap().is_none(),
            wired,
            "the row goes with the registry entry only when the store was handed over"
        );
    }
}

#[tokio::test]
async fn a_login_clears_what_the_visitor_planted_and_keeps_registered_keys() {
    let (identity, factors) = identity_and_factors();
    let svc = AuthnService::builder(identity, factors)
        .with_preserved_custom_keys(["locale"])
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session.set_custom("cart", serde_json::json!([1, 2])).await;
    session.set_custom("locale", serde_json::json!("sv")).await;

    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );

    assert!(
        session.get_custom("cart").await.is_none(),
        "pre-login state must not ride into the authenticated session"
    );
    assert_eq!(
        session.get_custom("locale").await,
        Some(serde_json::json!("sv"))
    );
}
