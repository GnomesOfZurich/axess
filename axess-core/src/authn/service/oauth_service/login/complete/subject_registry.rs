//! A logout by `sub` alone reaches every session an OAuth login of that user
//! established, with or without an ID-token `sid`, and capacity eviction of
//! the `sid` map never hides a live session from it.

use super::super::helpers::compute_claim_lock;
use crate::authn::ids::UserId;
use crate::authn::service::AuthnService;
use crate::federation::backchannel_logout::{BackChannelLogoutHandler, LogoutParams};
use crate::session::id::SessionId;
use crate::session::{MemorySessionRegistry, SessionRegistryAdapter, store::SessionRegistry};
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    tenant_record, test_session, user_record,
};
use axess_clock::testing::MockClock;
use axess_factors::oauth::{MockOAuthProvider, OAuthClaims, OAuthProvider, types::keys};
use axum::{extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Arc;

/// The mock provider's name; its issuer is `https://test-idp.example.com`.
const PROVIDER: &str = "test-idp";
const ISSUER: &str = "https://test-idp.example.com";

/// A registry that answers `is_valid` with an error while `failing` is set.
#[derive(Clone)]
struct FlakyRegistry {
    inner: MemorySessionRegistry,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

impl SessionRegistry for FlakyRegistry {
    type Error = std::io::Error;

    async fn register(&self, u: &UserId, s: &SessionId) -> Result<(), Self::Error> {
        self.inner
            .register(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn is_valid(&self, u: &UserId, s: &SessionId) -> Result<bool, Self::Error> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("registry unreachable"));
        }
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

struct Harness {
    failing: Arc<std::sync::atomic::AtomicBool>,
    svc: AuthnService<MockIdentityStore, MockFactorStore>,
    registry: MemorySessionRegistry,
    clock: MockClock,
    user: crate::authn::types::User,
    jti: std::cell::Cell<u32>,
}

fn harness(capacity: usize) -> Harness {
    let user = user_record("u1", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record("t1"))
        .with_user(user.clone());
    let registry = MemorySessionRegistry::new();
    let clock = MockClock::now();
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flaky = FlakyRegistry {
        inner: registry.clone(),
        failing: failing.clone(),
    };
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(flaky)
        .with_clock(clock.clone())
        .with_sid_map_capacity(capacity)
        .with_oauth_provider(MockOAuthProvider::new(PROVIDER))
        .build();
    Harness {
        failing,
        svc,
        registry,
        clock,
        user,
        jti: std::cell::Cell::new(0),
    }
}

impl Harness {
    /// Log in once; returns the new session's id.
    async fn login(&self, sid: Option<&str>) -> crate::session::id::SessionId {
        let claims = OAuthClaims {
            provider: PROVIDER.into(),
            subject: "external-sub".into(),
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
        };
        let session = test_session();
        let lock = compute_claim_lock(PROVIDER, &claims.subject, &session).await;
        session
            .set_custom(keys::CLAIM_LOCK, serde_json::Value::String(lock))
            .await;
        let req = self
            .svc
            .with_audit_context(crate::authn::event::AuditContext::default());
        req.complete_oauth_login(&self.user, &claims, &session)
            .await
            .expect("login");
        self.clock.advance_secs(1);
        session.session_id().await
    }

    async fn live(&self, id: &crate::session::id::SessionId) -> bool {
        self.registry.is_valid(&self.user.id, id).await.unwrap()
    }

    /// POST an unsigned logout token (the mock provider skips signature
    /// verification) carrying `sub` and/or `sid`.
    async fn logout(&self, sub: bool, sid: Option<&str>) {
        let providers: Vec<Arc<dyn OAuthProvider>> =
            vec![Arc::new(MockOAuthProvider::new(PROVIDER))];
        let handler = BackChannelLogoutHandler::new(
            &providers,
            Arc::new(SessionRegistryAdapter(self.registry.clone())),
            self.svc.sid_map(),
            Arc::new(axess_clock::SystemClock),
        )
        .expect("handler");
        self.jti.set(self.jti.get() + 1);
        let mut payload = serde_json::json!({
            "iss": ISSUER,
            "aud": "mock-client-id",
            "iat": chrono::Utc::now().timestamp(),
            "jti": format!("jti-{}", self.jti.get()),
            "events": { axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT: {} },
        });
        if sub {
            // The IdP's own subject, which is not the local user id.
            payload["sub"] = "external-sub".into();
        }
        if let Some(sid) = sid {
            payload["sid"] = sid.into();
        }
        let token = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
        );
        let status = BackChannelLogoutHandler::handle_backchannel_logout(
            State(handler),
            axum::extract::Form(LogoutParams {
                logout_token: token,
            }),
        )
        .await;
        assert_eq!(status, Ok(StatusCode::OK));
    }
}

/// A login whose ID token carried no `sid` has no `sid` mapping, and a
/// `sub`-only logout token still ends it. The token names the IdP's subject
/// (`external-sub`), not the local user id the session is registered under.
#[tokio::test]
async fn sid_less_login_is_ended_by_a_sub_only_logout() {
    let h = harness(100);
    let session = h.login(None).await;
    assert!(h.svc.sid_map().is_empty(), "no sid, so no sid mapping");
    assert_eq!(h.svc.sid_map().subject_len(), 1);
    assert!(h.live(&session).await);

    h.logout(true, None).await;

    assert!(!h.live(&session).await);
    assert_eq!(h.svc.sid_map().subject_len(), 0);
}

/// A mapping dropped at capacity leaves the live session reachable: a token
/// carrying the evicted `sid` and a `sub` ends it through the `sub` path,
/// while a `sid`-only token for the evicted mapping finds nothing.
#[tokio::test]
async fn evicted_sid_mapping_is_still_ended_through_sub() {
    let h = harness(2);
    let first = h.login(Some("sid-0")).await;
    let second = h.login(Some("sid-1")).await;
    let third = h.login(Some("sid-2")).await;
    let map = h.svc.sid_map();
    let key = |sid: &str| (ISSUER.to_string(), sid.to_string());
    assert!(!map.contains_key(&key("sid-0")), "sid-0 was evicted");
    assert_eq!(map.subject_len(), 3, "live sessions stay in the registry");

    h.logout(false, Some("sid-0")).await;
    assert!(h.live(&first).await, "a sid-only token has nothing to find");

    h.logout(true, Some("sid-0")).await;
    for session in [&first, &second, &third] {
        assert!(!h.live(session).await, "the sub path ends it");
    }
}

/// Eviction forgets a subject entry only when its session is already gone.
#[tokio::test]
async fn capacity_eviction_forgets_only_sessions_that_are_gone() {
    let h = harness(2);
    let gone = h.login(Some("sid-0")).await;
    let live = h.login(Some("sid-1")).await;
    h.registry
        .invalidate_session(&h.user.id, &gone)
        .await
        .unwrap();

    h.login(Some("sid-2")).await;

    let map = h.svc.sid_map();
    assert_eq!(map.subject_len(), 2, "the dead session left, two live stay");
    assert!(
        !map.forget_subject_session(ISSUER, &h.user.id, &gone),
        "the gone session was already forgotten"
    );
    assert!(map.forget_subject_session(ISSUER, &h.user.id, &live));
}

/// Sessions that ended on their own are swept out of the registry by later
/// logins, so sid-less logins do not accumulate.
#[tokio::test]
async fn sessions_that_ended_are_swept_from_the_registry() {
    let h = harness(100);
    let old = h.login(None).await;
    h.registry
        .invalidate_session(&h.user.id, &old)
        .await
        .unwrap();
    assert_eq!(h.svc.sid_map().subject_len(), 1);

    let fresh = h.login(None).await;

    assert_eq!(h.svc.sid_map().subject_len(), 1, "only the fresh login");
    assert!(h.live(&fresh).await);
}

/// A `sid` logout removes the subject entry with the session it ends.
#[tokio::test]
async fn sid_logout_drops_the_subject_entry() {
    let h = harness(100);
    let session = h.login(Some("sid-0")).await;

    h.logout(false, Some("sid-0")).await;

    assert!(!h.live(&session).await);
    assert_eq!(h.svc.sid_map().subject_len(), 0);
}

/// While the registry cannot answer, neither capacity eviction nor the
/// per-login sweep forgets a live session; once it recovers, a `sub`-only
/// logout still ends every one of them.
#[tokio::test]
async fn registry_outage_does_not_drop_live_subject_entries() {
    let h = harness(2);
    let first = h.login(Some("sid-0")).await;
    let second = h.login(None).await;
    h.failing.store(true, std::sync::atomic::Ordering::SeqCst);

    // Capacity eviction and the sweep both run during these logins, and the
    // registry errors on every liveness question.
    let mut sessions = vec![first, second];
    for n in 1..4 {
        sessions.push(h.login(Some(&format!("sid-{n}"))).await);
    }
    assert_eq!(
        h.svc.sid_map().subject_len(),
        sessions.len(),
        "nothing was forgotten on an unknown answer"
    );

    h.failing.store(false, std::sync::atomic::Ordering::SeqCst);
    h.logout(true, None).await;
    for session in &sessions {
        assert!(!h.live(session).await, "the sub logout still reaches it");
    }
}
