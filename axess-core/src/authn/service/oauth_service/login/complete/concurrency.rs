//! The registry calls one OAuth login makes run concurrently, within a bound,
//! instead of one round trip after another.

use super::super::helpers::compute_claim_lock;
use super::concurrent::REGISTRY_CONCURRENCY;
use crate::authn::service::AuthnService;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::SessionRegistry;
use crate::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    tenant_record_at, test_session, user_record_at,
};
use axess_factors::oauth::{OAuthClaims, types::keys as oauth_keys};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A registry whose `is_valid`, `current_key` and `invalidate_session` take
/// a few milliseconds and record in `peak` the most calls ever in flight at
/// once.
fn slow_registry(peak: Arc<AtomicUsize>) -> RegistryDouble {
    let in_flight = Arc::new(AtomicUsize::new(0));
    RegistryDouble::new().before(move |call, _| {
        let (in_flight, peak) = (in_flight.clone(), peak.clone());
        async move {
            if matches!(
                call.op(),
                RegistryOp::IsValid | RegistryOp::CurrentKey | RegistryOp::InvalidateSession
            ) {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            Step::Forward
        }
    })
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
        nonce: None,
        dpop_key: None,
    }
}

struct Harness {
    svc: AuthnService<MockIdentityStore, MockFactorStore>,
    registry: RegistryDouble,
    peak: Arc<AtomicUsize>,
    clock: axess_clock::testing::MockClock,
    user: crate::authn::types::User,
}

fn harness(capacity: usize) -> Harness {
    let user = user_record_at(
        "u1",
        "t1",
        axess_clock::testing::MockClock::reference_time(),
    );
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record_at(
            "t1",
            axess_clock::testing::MockClock::reference_time(),
        ))
        .with_user(user.clone());
    let peak = Arc::new(AtomicUsize::new(0));
    let registry = slow_registry(peak.clone());
    let clock = axess_clock::testing::MockClock::at_reference();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .with_clock(clock.clone())
        .with_sid_map_capacity(capacity)
        .build();
    Harness {
        svc,
        registry,
        peak,
        clock,
        user,
    }
}

impl Harness {
    async fn login(&self, sid: Option<&str>) -> SessionKey {
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
        session.session_key().await
    }

    fn peak(&self) -> usize {
        self.peak.swap(0, Ordering::SeqCst)
    }
}

/// The sweep's questions to the registry for a full batch of candidates
/// overlap, and never exceed the bound.
#[tokio::test]
async fn the_subject_sweep_asks_the_registry_concurrently_within_the_bound() {
    let h = harness(10_000);
    // 64 sessions the registry never heard of: each reads as gone.
    for _ in 0..64 {
        let session = SessionKey::of(&SessionId::new(&axess_rng::testing::MockRng::new(
            rand_seed(),
        )));
        h.svc
            .sid_map()
            .register_subject_session("test", "stale-sub", None, h.user.id, session);
    }
    h.peak();

    h.login(None).await;

    let peak = h.peak();
    assert!(
        peak > 1,
        "the sweep's questions ran one at a time (peak {peak})"
    );
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
                .inner()
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
