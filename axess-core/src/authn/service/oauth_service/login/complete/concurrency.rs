//! The registry calls one OAuth login makes run concurrently, within a bound,
//! instead of one round trip after another.

use super::super::helpers::compute_claim_lock;
use super::concurrent::REGISTRY_CONCURRENCY;
use crate::authn::ids::UserId;
use crate::authn::service::AuthnService;
use crate::session::id::SessionId;
use crate::session::{MemorySessionRegistry, store::SessionRegistry};
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    tenant_record, test_session, user_record,
};
use axess_factors::oauth::{OAuthClaims, types::keys as oauth_keys};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A registry whose `is_valid` and `invalidate_session` take a few
/// milliseconds and record the most calls ever in flight at once.
#[derive(Clone)]
struct SlowRegistry {
    inner: MemorySessionRegistry,
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl SlowRegistry {
    async fn slow(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(5)).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl SessionRegistry for SlowRegistry {
    type Error = std::io::Error;

    async fn register(&self, u: &UserId, s: &SessionId) -> Result<(), Self::Error> {
        self.inner
            .register(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn is_valid(&self, u: &UserId, s: &SessionId) -> Result<bool, Self::Error> {
        self.slow().await;
        self.inner
            .is_valid(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn invalidate_user(&self, u: &UserId) -> Result<(), Self::Error> {
        self.inner
            .invalidate_user(u)
            .await
            .map_err(std::io::Error::other)
    }
    async fn invalidate_session(&self, u: &UserId, s: &SessionId) -> Result<(), Self::Error> {
        self.slow().await;
        self.inner
            .invalidate_session(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn active_sessions(&self, u: &UserId) -> Result<Vec<SessionId>, Self::Error> {
        self.inner
            .active_sessions(u)
            .await
            .map_err(std::io::Error::other)
    }
}

fn claims(subject: &str, sid: Option<&str>) -> OAuthClaims {
    OAuthClaims {
        provider: "test".into(),
        subject: subject.into(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: sid.map(str::to_string),
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
        dpop_key: None,
    }
}

struct Harness {
    svc: AuthnService<MockIdentityStore, MockFactorStore>,
    registry: SlowRegistry,
    clock: axess_clock::testing::MockClock,
    user: crate::authn::types::User,
}

fn harness(capacity: usize) -> Harness {
    let user = user_record("u1", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record("t1"))
        .with_user(user.clone());
    let registry = SlowRegistry {
        inner: MemorySessionRegistry::new(),
        in_flight: Arc::default(),
        peak: Arc::default(),
    };
    let clock = axess_clock::testing::MockClock::now();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .with_clock(clock.clone())
        .with_sid_map_capacity(capacity)
        .build();
    Harness {
        svc,
        registry,
        clock,
        user,
    }
}

impl Harness {
    async fn login(&self, sid: Option<&str>) -> SessionId {
        let req = self
            .svc
            .with_audit_context(crate::authn::event::AuditContext::default());
        let session = test_session();
        let c = claims("external-sub", sid);
        let lock = compute_claim_lock("test", &c.subject, &session).await;
        session
            .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
            .await;
        req.complete_oauth_login(&self.user, &c, &session)
            .await
            .expect("login");
        session.session_id().await
    }

    fn peak(&self) -> usize {
        self.registry.peak.swap(0, Ordering::SeqCst)
    }
}

/// The sweep's liveness checks for a full batch of candidates overlap, and
/// never exceed the bound.
#[tokio::test]
async fn the_subject_sweep_checks_liveness_concurrently_within_the_bound() {
    let h = harness(10_000);
    // 64 sessions the registry never heard of: each reads as gone.
    for _ in 0..64 {
        let session = SessionId::new(&axess_rng::testing::MockRng::new(rand_seed()));
        h.svc
            .sid_map()
            .register_subject_session("test", "stale-sub", h.user.id, session);
    }
    h.peak();

    h.login(None).await;

    let peak = h.peak();
    assert!(peak > 1, "liveness checks ran one at a time (peak {peak})");
    assert!(peak <= REGISTRY_CONCURRENCY, "peak {peak} passed the bound");
    assert_eq!(
        h.svc.sid_map().subject_len(),
        1,
        "the gone sessions were forgotten; only the new login remains"
    );
}

/// A login that displaces many sessions ends them concurrently, and every
/// one of them ends.
#[tokio::test]
async fn displaced_sessions_are_ended_concurrently_and_all_of_them() {
    let h = harness(10_000);
    let mut sessions = Vec::new();
    for n in 0..40 {
        sessions.push(h.login(Some(&format!("sid-{n}"))).await);
    }
    h.peak();
    // Move past the 24 h TTL, so the next login's prune ends all 40 in one
    // call.
    h.clock.advance_secs(25 * 3600);

    h.login(Some("fresh")).await;

    let peak = h.peak();
    assert!(peak > 1, "invalidations ran one at a time (peak {peak})");
    assert!(peak <= REGISTRY_CONCURRENCY, "peak {peak} passed the bound");
    for session in &sessions {
        assert!(
            !h.registry
                .inner
                .is_valid(&h.user.id, session)
                .await
                .unwrap(),
            "a pruned session must end"
        );
    }
}

fn rand_seed() -> u64 {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst) as u64
}
