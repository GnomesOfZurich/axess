#![cfg(feature = "testing")]
//! The concurrent-session cap: a cap of one keeps exactly the new session,
//! and parallel logins that each saw room still end at the cap.

use axess_core::session::{SessionId, SessionKey};
use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, FactorOutcome, RequestAuthnService},
};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

async fn login<I, F>(svc: &RequestAuthnService<I, F>) -> SessionKey
where
    I: axess_core::authn::store::IdentityStore,
    F: axess_core::authn::store::FactorStore<Error = I::Error>,
{
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Sample2+"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    session.session_key().await
}

/// With a cap of one, a second login evicts the first: exactly the new
/// session remains.
#[tokio::test]
async fn a_cap_of_one_keeps_only_the_newest_session() {
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .with_max_sessions_per_user(NonZeroUsize::MIN)
        .build()
        .with_audit_context(AuditContext::default());

    let first = login(&svc).await;
    let second = login(&svc).await;

    let active = registry.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(active, vec![second]);
    assert!(!active.contains(&first));
}

/// A registry that, on its first listing, lets another login register
/// between this login's count and its register: the interleaving of two
/// parallel logins.
fn interleaving_registry(inner: MemorySessionRegistry, intruder: SessionKey) -> RegistryDouble {
    let fired = Arc::new(AtomicBool::new(false));
    RegistryDouble::over(inner).after(move |call, inner| {
        let first = call.op() == RegistryOp::ActiveSessions && !fired.swap(true, Ordering::SeqCst);
        async move {
            if first {
                inner.register(call.user(), &intruder).await.unwrap();
            }
        }
    })
}

/// Two parallel logins that each saw room both register: the user would end
/// above the cap. The login trims after it registers, so the set converges.
#[tokio::test]
async fn parallel_logins_that_each_saw_room_still_end_at_the_cap() {
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let inner = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let rng = MockRng::new(7);
    let (old1, old2) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    inner.register(&uid("u1"), &old1).await.unwrap();
    inner.register(&uid("u1"), &old2).await.unwrap();
    let registry = interleaving_registry(inner.clone(), SessionKey::of(&SessionId::new(&rng)));
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(registry)
        .with_max_sessions_per_user(NonZeroUsize::new(2).unwrap())
        .build()
        .with_audit_context(AuditContext::default());

    let mine = login(&svc).await;

    let active = inner.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(
        active.len(),
        2,
        "the cap holds after the interleaving: {active:?}"
    );
    assert!(active.contains(&mine), "a login never evicts itself");
}

/// A registry on which a rival login lands right after this one registers
/// (so both are in the list when each trims): the late half of the race.
fn late_rival_registry(inner: MemorySessionRegistry, rival: SessionKey) -> RegistryDouble {
    RegistryDouble::over(inner).after(move |call, inner| async move {
        if call.op() == RegistryOp::Register {
            // The rival registers after the login under test.
            inner.register(call.user(), &rival).await.unwrap();
        }
    })
}

/// At a cap of one, two logins that interleave must leave exactly one live
/// session, and only that login may report success. The login that finds a
/// newer registration behind it loses: it fails and the rival stays valid,
/// where evicting "everyone but me" revoked the rival and left both
/// reporting a session.
#[tokio::test]
async fn at_a_cap_of_one_the_login_that_loses_the_race_fails_and_the_rival_survives() {
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let inner = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let rival = SessionKey::of(&SessionId::new(&MockRng::new(11)));
    let registry = late_rival_registry(inner.clone(), rival);
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(registry)
        .with_max_sessions_per_user(NonZeroUsize::MIN)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Sample2+"));
    let outcome = svc.verify_factor(&cred, &session).await;
    assert!(outcome.is_err(), "the losing login must fail: {outcome:?}");
    assert!(!session.is_authenticated().await);

    let active = inner.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(active, vec![rival], "exactly the rival is live");
}

/// A registry whose listing fails while `down` is set.
fn listing_down_registry(inner: MemorySessionRegistry, down: Arc<AtomicBool>) -> RegistryDouble {
    RegistryDouble::over(inner).before(move |call, _| {
        let refused = call.op() == RegistryOp::ActiveSessions && down.load(Ordering::SeqCst);
        async move {
            if refused {
                Step::Fail("listing is down")
            } else {
                Step::Forward
            }
        }
    })
}

async fn login_attempt<I, F>(
    svc: &RequestAuthnService<I, F>,
) -> (
    Result<FactorOutcome, axess_core::authn::AuthnError<I::Error>>,
    bool,
)
where
    I: axess_core::authn::store::IdentityStore,
    F: axess_core::authn::store::FactorStore<Error = I::Error>,
{
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Sample2+"));
    let outcome = svc.verify_factor(&cred, &session).await;
    (outcome, session.is_authenticated().await)
}

/// With a cap set, a registry that cannot list the user's sessions refuses
/// the login: counting nothing would let every login in over the cap while
/// the registry is down.
#[tokio::test]
async fn with_a_cap_a_login_is_refused_when_the_registry_cannot_list_sessions() {
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let down = Arc::new(AtomicBool::new(true));
    let inner = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(listing_down_registry(inner.clone(), down.clone()))
        .with_max_sessions_per_user(NonZeroUsize::MIN)
        .build()
        .with_audit_context(AuditContext::default());

    let (outcome, authenticated) = login_attempt(&svc).await;
    assert!(outcome.is_err(), "the login must be refused: {outcome:?}");
    assert!(!authenticated);
    assert!(inner.active_sessions(&uid("u1")).await.unwrap().is_empty());
}

/// The service's listing reports a registry that cannot answer instead of
/// returning no sessions.
#[tokio::test]
async fn active_sessions_reports_a_registry_that_cannot_list_sessions() {
    use axess_core::authn::service::ActiveSessionsError;
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(listing_down_registry(
            MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone())),
            Arc::new(AtomicBool::new(true)),
        ))
        .build()
        .with_audit_context(AuditContext::default());
    let listed = svc.active_sessions(&uid("u1")).await;
    assert!(
        matches!(listed, Err(ActiveSessionsError::Registry(_))),
        "{listed:?}"
    );
}

/// Without a cap nothing needs the listing, so an outage does not lock users
/// out.
#[tokio::test]
async fn without_a_cap_a_login_goes_through_when_the_registry_cannot_list_sessions() {
    let clock = common::test_clock();
    let (identity, factors) = identity_and_factors(&clock);
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(listing_down_registry(
            MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone())),
            Arc::new(AtomicBool::new(true)),
        ))
        .build()
        .with_audit_context(AuditContext::default());

    let (outcome, authenticated) = login_attempt(&svc).await;
    assert!(
        matches!(outcome, Ok(FactorOutcome::Authenticated)),
        "{outcome:?}"
    );
    assert!(authenticated);
}
