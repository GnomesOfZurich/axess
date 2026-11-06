#![cfg(feature = "testing")]
//! The concurrent-session cap: a cap of one keeps exactly the new session,
//! and parallel logins that each saw room still end at the cap.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, FactorOutcome, RequestAuthnService},
};
use axess_core::session::id::SessionId;
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

async fn login<I, F>(svc: &RequestAuthnService<I, F>) -> SessionId
where
    I: axess_core::authn::store::IdentityStore,
    F: axess_core::authn::store::FactorStore<Error = I::Error>,
{
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    session.session_id().await
}

/// With a cap of one, a second login evicts the first: exactly the new
/// session remains.
#[tokio::test]
async fn a_cap_of_one_keeps_only_the_newest_session() {
    let (identity, factors) = identity_and_factors();
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, factors)
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
#[derive(Clone)]
struct InterleavingRegistry {
    inner: MemorySessionRegistry,
    intruder: SessionId,
    fired: Arc<AtomicBool>,
}

impl SessionRegistry for InterleavingRegistry {
    type Error = <MemorySessionRegistry as SessionRegistry>::Error;

    async fn register(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        self.inner.register(user_id, session_id).await
    }

    async fn is_valid(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        self.inner.is_valid(user_id, session_id).await
    }

    async fn invalidate_user(
        &self,
        user_id: &axess_core::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        self.inner.invalidate_user(user_id).await
    }

    async fn invalidate_session(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        self.inner.invalidate_session(user_id, session_id).await
    }

    async fn active_sessions(
        &self,
        user_id: &axess_core::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        let seen = self.inner.active_sessions(user_id).await?;
        if !self.fired.swap(true, Ordering::SeqCst) {
            self.inner.register(user_id, &self.intruder).await?;
        }
        Ok(seen)
    }
}

/// Two parallel logins that each saw room both register: the user would end
/// above the cap. The login trims after it registers, so the set converges.
#[tokio::test]
async fn parallel_logins_that_each_saw_room_still_end_at_the_cap() {
    let (identity, factors) = identity_and_factors();
    let inner = MemorySessionRegistry::new();
    let rng = MockRng::new(7);
    let (old1, old2) = (SessionId::new(&rng), SessionId::new(&rng));
    inner.register(&uid("u1"), &old1).await.unwrap();
    inner.register(&uid("u1"), &old2).await.unwrap();
    let registry = InterleavingRegistry {
        inner: inner.clone(),
        intruder: SessionId::new(&rng),
        fired: Arc::new(AtomicBool::new(false)),
    };
    let svc = AuthnService::builder(identity, factors)
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
#[derive(Clone)]
struct LateRivalRegistry {
    inner: MemorySessionRegistry,
    rival: SessionId,
}

impl SessionRegistry for LateRivalRegistry {
    type Error = <MemorySessionRegistry as SessionRegistry>::Error;

    async fn register(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        self.inner.register(user_id, session_id).await?;
        // The rival registers once, after the login under test.
        self.inner.register(user_id, &self.rival).await
    }

    async fn is_valid(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        self.inner.is_valid(user_id, session_id).await
    }

    async fn invalidate_user(
        &self,
        user_id: &axess_core::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        self.inner.invalidate_user(user_id).await
    }

    async fn invalidate_session(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        self.inner.invalidate_session(user_id, session_id).await
    }

    async fn active_sessions(
        &self,
        user_id: &axess_core::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        self.inner.active_sessions(user_id).await
    }
}

/// At a cap of one, two logins that interleave must leave exactly one live
/// session, and only that login may report success. The login that finds a
/// newer registration behind it loses: it fails and the rival stays valid,
/// where evicting "everyone but me" revoked the rival and left both
/// reporting a session.
#[tokio::test]
async fn at_a_cap_of_one_the_login_that_loses_the_race_fails_and_the_rival_survives() {
    let (identity, factors) = identity_and_factors();
    let inner = MemorySessionRegistry::new();
    let rival = SessionId::new(&MockRng::new(11));
    let registry = LateRivalRegistry {
        inner: inner.clone(),
        rival,
    };
    let svc = AuthnService::builder(identity, factors)
        .with_registry(registry)
        .with_max_sessions_per_user(NonZeroUsize::MIN)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let outcome = svc.verify_factor(&cred, &session).await;
    assert!(outcome.is_err(), "the losing login must fail: {outcome:?}");
    assert!(!session.is_authenticated().await);

    let active = inner.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(active, vec![rival], "exactly the rival is live");
}

/// A registry whose listing fails while `down` is set.
#[derive(Clone)]
struct ListingDownRegistry {
    inner: MemorySessionRegistry,
    down: Arc<AtomicBool>,
}

#[derive(Debug, thiserror::Error)]
#[error("listing is down")]
struct ListingDown;

impl SessionRegistry for ListingDownRegistry {
    type Error = ListingDown;

    async fn register(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        self.inner
            .register(user_id, session_id)
            .await
            .map_err(|e| match e {})
    }

    async fn is_valid(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        self.inner
            .is_valid(user_id, session_id)
            .await
            .map_err(|e| match e {})
    }

    async fn invalidate_user(
        &self,
        user_id: &axess_core::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        self.inner
            .invalidate_user(user_id)
            .await
            .map_err(|e| match e {})
    }

    async fn invalidate_session(
        &self,
        user_id: &axess_core::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        self.inner
            .invalidate_session(user_id, session_id)
            .await
            .map_err(|e| match e {})
    }

    async fn active_sessions(
        &self,
        user_id: &axess_core::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        if self.down.load(Ordering::SeqCst) {
            return Err(ListingDown);
        }
        self.inner
            .active_sessions(user_id)
            .await
            .map_err(|e| match e {})
    }
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
    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let outcome = svc.verify_factor(&cred, &session).await;
    (outcome, session.is_authenticated().await)
}

/// With a cap set, a registry that cannot list the user's sessions refuses
/// the login: counting nothing would let every login in over the cap while
/// the registry is down.
#[tokio::test]
async fn with_a_cap_a_login_is_refused_when_the_registry_cannot_list_sessions() {
    let (identity, factors) = identity_and_factors();
    let down = Arc::new(AtomicBool::new(true));
    let inner = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, factors)
        .with_registry(ListingDownRegistry {
            inner: inner.clone(),
            down: down.clone(),
        })
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
    let (identity, factors) = identity_and_factors();
    let svc = AuthnService::builder(identity, factors)
        .with_registry(ListingDownRegistry {
            inner: MemorySessionRegistry::new(),
            down: Arc::new(AtomicBool::new(true)),
        })
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
    let (identity, factors) = identity_and_factors();
    let svc = AuthnService::builder(identity, factors)
        .with_registry(ListingDownRegistry {
            inner: MemorySessionRegistry::new(),
            down: Arc::new(AtomicBool::new(true)),
        })
        .build()
        .with_audit_context(AuditContext::default());

    let (outcome, authenticated) = login_attempt(&svc).await;
    assert!(
        matches!(outcome, Ok(FactorOutcome::Authenticated)),
        "{outcome:?}"
    );
    assert!(authenticated);
}
