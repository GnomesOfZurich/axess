//! What `complete_oauth_login` does to the `sid` map and to the sessions
//! behind it when the map ages out or fills.

use super::super::helpers::compute_claim_lock;
use crate::authn::service::AuthnService;
use crate::session::{MemorySessionRegistry, store::SessionRegistry};
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    tenant_record, test_session, user_record,
};
use axess_clock::testing::MockClock;
use axess_factors::oauth::{OAuthClaims, types::keys as oauth_keys};

fn claims(sid: &str) -> OAuthClaims {
    OAuthClaims {
        provider: "test".into(),
        subject: "external-sub".into(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: Some(sid.to_string()),
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
    }
}

struct Harness {
    svc: AuthnService<MockIdentityStore, MockFactorStore>,
    registry: MemorySessionRegistry,
    clock: MockClock,
    user: crate::authn::types::User,
}

fn harness(capacity: usize) -> Harness {
    let user = user_record("u1", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record("t1"))
        .with_user(user.clone());
    let registry = MemorySessionRegistry::new();
    let clock = MockClock::now();
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
    async fn login(&self, sid: &str) {
        let req = self
            .svc
            .with_audit_context(crate::authn::event::AuditContext::default());
        let session = test_session();
        let c = claims(sid);
        let lock = compute_claim_lock("test", &c.subject, &session).await;
        session
            .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
            .await;
        req.complete_oauth_login(&self.user, &c, &session)
            .await
            .expect("login");
    }

    async fn live_sessions(&self) -> usize {
        self.registry
            .active_sessions(&self.user.id)
            .await
            .unwrap()
            .len()
    }
}

/// Filling the map drops the oldest mappings and nothing else: every
/// session stays valid, so a full map never logs a user out.
#[tokio::test]
async fn capacity_eviction_drops_the_mapping_and_keeps_the_session() {
    let h = harness(3);
    for n in 0..3 {
        h.login(&format!("sid-{n}")).await;
        h.clock.advance_secs(1);
    }
    assert_eq!(h.svc.sid_map().len(), 3);

    h.login("sid-3").await;

    // Eviction takes a batch (up to 128) of the oldest mappings, which here
    // is all three, so only the new login's mapping remains.
    let map = h.svc.sid_map();
    // No provider is registered, so the issuer in the key is the provider name.
    let key = |sid: &str| ("test".to_string(), sid.to_string());
    assert_eq!(map.len(), 1);
    assert!(map.contains_key(&key("sid-3")));
    assert!(!map.contains_key(&key("sid-0")));
    assert_eq!(
        h.live_sessions().await,
        4,
        "no session was ended to make room in the map"
    );
}

/// Ageing out past the TTL ends the sessions of the entries it drops, at
/// most one batch per login; the rest wait for the next login.
#[tokio::test]
async fn ttl_prune_is_bounded_per_login() {
    let h = harness(10_000);
    for n in 0..130 {
        h.login(&format!("old-{n}")).await;
    }
    assert_eq!(h.live_sessions().await, 130);
    h.clock.advance_secs(25 * 3600);

    h.login("fresh").await;

    assert_eq!(
        h.svc.sid_map().len(),
        130 - 128 + 1,
        "128 aged out, 2 old ones and the new login remain"
    );
    assert_eq!(
        h.live_sessions().await,
        130 - 128 + 1,
        "the pruned entries' sessions were ended"
    );

    h.login("fresh-2").await;
    assert_eq!(
        h.svc.sid_map().len(),
        2,
        "the backlog drained on the next login"
    );
}

#[tokio::test]
async fn the_service_hands_out_the_map_it_fills() {
    let h = harness(10);
    let handle = h.svc.sid_map();
    assert!(handle.is_empty());
    h.login("sid-a").await;
    assert_eq!(handle.len(), 1, "a handle taken earlier sees the login");
}
