#![cfg(all(feature = "testing", feature = "memory"))]
//! Revocation that cannot be carried out is reported, the stored rows go with
//! the registry entries when the store is wired, and a login does not carry
//! pre-login session data into the authenticated session.

use axess_core::session::{SessionId, SessionKey};
use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
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
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A registry whose revocations fail while `failing` is set.
struct FlakyRegistry {
    registry: RegistryDouble,
    failing: Arc<AtomicBool>,
}

impl FlakyRegistry {
    fn new(clock: &MockClock) -> Self {
        let failing = Arc::new(AtomicBool::new(false));
        let down = failing.clone();
        let inner = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
        let registry = RegistryDouble::over(inner).before(move |call, _| {
            let revocation = matches!(
                call.op(),
                RegistryOp::InvalidateUser | RegistryOp::InvalidateSession
            );
            let refused = revocation && down.load(Ordering::SeqCst);
            async move {
                if refused {
                    Step::Fail("registry down")
                } else {
                    Step::Forward
                }
            }
        });
        Self { registry, failing }
    }
}

fn identity_and_factors(clock: &MockClock) -> (MockIdentityStore, MockFactorStore) {
    (
        MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice")),
        MockFactorStore::new()
            .with_factor(user_scope(), password_config("Sample2+"))
            .with_method(&uid("u1"), password_method()),
    )
}

#[tokio::test]
async fn the_registry_adapter_reports_a_failed_revocation() {
    let clock = common::test_clock();
    let flaky = FlakyRegistry::new(&clock);
    flaky.failing.store(true, Ordering::SeqCst);
    let handle = SessionRegistryAdapter(flaky.registry);
    let sid = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    assert!(
        handle.invalidate_user(&uid("u1")).await.is_err(),
        "a down registry must not report a user's sessions as revoked"
    );
    assert!(handle.invalidate_session(&uid("u1"), &sid).await.is_err());
}

#[tokio::test]
async fn an_admin_kick_the_registry_could_not_carry_out_is_an_error_and_not_audited() {
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let flaky = FlakyRegistry::new(&clock);
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_registry(flaky.registry.clone())
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
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let flaky = FlakyRegistry::new(&clock);
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_registry(flaky.registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    flaky.failing.store(true, Ordering::SeqCst);

    let result = svc
        .suspend_user_across_tenants(
            Actor::System,
            &uid("u1"),
            StatusDetail::administrative("hold", common::start()),
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
    let clock = common::test_clock();
    for wired in [true, false] {
        let (identity, factors) = identity_and_factors(&clock);
        let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
        let store = MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone()));
        let mut builder = AuthnService::builder(identity, factors)
            .with_clock(clock.clone())
            .with_registry(registry.clone());
        if wired {
            builder = builder.with_session_store(store.clone());
        }
        let svc = builder.build().with_audit_context(AuditContext::default());

        let sid = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
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
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_preserved_custom_keys(["locale"])
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session.set_custom("cart", serde_json::json!([1, 2])).await;
    session.set_custom("locale", serde_json::json!("sv")).await;

    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Sample2+"));
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
