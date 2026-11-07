//! A registry that cannot carry out the revocation: the handler answers a
//! retryable status, keeps the token unspent and the mappings in place, and
//! the IdP's resend ends the session once the registry is back.

use super::*;
use crate::session::id::SessionId;
use crate::session::store::{
    MemorySessionRegistry, RevocationError, SessionRegistry, SessionRegistryAdapter,
};
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const ISS: &str = "https://outage.example.com";
const CLIENT: &str = "client-outage";

/// Which revocations the registry refuses.
#[derive(Clone, Copy)]
enum Refuse {
    None,
    Every,
    Only(SessionId),
}

/// A registry whose `invalidate_session` fails on demand without touching
/// the sessions it holds, as a lost connection would.
struct Flaky {
    inner: SessionRegistryAdapter<MemorySessionRegistry>,
    refuse: Mutex<Refuse>,
}

impl Flaky {
    fn set(&self, refuse: Refuse) {
        *self.refuse.lock().unwrap() = refuse;
    }

    fn refuses(&self, session: &SessionId) -> bool {
        match *self.refuse.lock().unwrap() {
            Refuse::None => false,
            Refuse::Every => true,
            Refuse::Only(s) => s == *session,
        }
    }
}

impl SessionRevoker for Flaky {
    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        self.inner.invalidate_user(user_id)
    }

    fn invalidate_session<'a>(
        &'a self,
        user_id: &'a UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        if self.refuses(session_id) {
            return Box::pin(async { Err(RevocationError("connection lost".into())) });
        }
        self.inner.invalidate_session(user_id, session_id)
    }
}

/// Counts the sessions reported as ended.
#[derive(Default)]
struct CountingAudit(AtomicUsize);

impl LogoutAudit for CountingAudit {
    fn session_ended<'a>(
        &'a self,
        _ended: &'a IdpSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

fn token(extra: serde_json::Value) -> String {
    let mut payload = serde_json::json!({
        "iss": ISS,
        "aud": CLIENT,
        "iat": chrono::Utc::now().timestamp(),
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
    });
    payload
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let header = serde_json::json!({"alg": "none", "typ": "logout+jwt"});
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    )
}

struct Rig {
    handler: BackChannelLogoutHandler,
    registry: MemorySessionRegistry,
    flaky: Arc<Flaky>,
    sid_map: SidMap,
    audit: Arc<CountingAudit>,
}

fn rig() -> Rig {
    let registry = MemorySessionRegistry::new();
    let flaky = Arc::new(Flaky {
        inner: SessionRegistryAdapter(registry.clone()),
        refuse: Mutex::new(Refuse::None),
    });
    let sid_map = SidMap::new();
    let audit = Arc::new(CountingAudit::default());
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("outage")
            .with_issuer(ISS)
            .with_client_id(CLIENT),
    )];
    let handler = BackChannelLogoutHandler::new(
        &providers,
        flaky.clone(),
        sid_map.clone(),
        Arc::new(SystemClock),
    )
    .expect("handler")
    .with_audit(audit.clone());
    Rig {
        handler,
        registry,
        flaky,
        sid_map,
        audit,
    }
}

async fn post(h: &BackChannelLogoutHandler, t: &str) -> Result<StatusCode, StatusCode> {
    BackChannelLogoutHandler::handle_outcome(
        State(h.clone()),
        Form(LogoutParams {
            logout_token: t.to_string(),
        }),
    )
    .await
}

/// A `sid` token meets a registry outage: the answer is retryable, the
/// session stays live and mapped, no "ended" row is written, and the same
/// token (same `jti`) is accepted and acted on once the registry is back.
#[tokio::test]
async fn a_failed_sid_invalidation_is_retryable_and_the_resend_ends_the_session() {
    let r = rig();
    let rng = MockRng::new(11);
    let session = SessionId::new(&rng);
    let user = axess_identity::testing::user("user-outage");
    r.registry.register(&user, &session).await.unwrap();
    let key: SidKey = (ISS.to_string(), "sid-1".to_string());
    r.sid_map
        .register_subject_session(ISS, "subject-1", None, user, session);
    r.sid_map.insert(
        key.clone(),
        "subject-1",
        None,
        user,
        session,
        chrono::Utc::now(),
    );
    assert!(r.sid_map.contains_key(&key), "the case to refuse exists");

    let t = token(serde_json::json!({ "sub": "subject-1", "sid": "sid-1", "jti": "j-outage" }));

    r.flaky.set(Refuse::Every);
    assert_eq!(
        post(&r.handler, &t).await,
        Err(StatusCode::SERVICE_UNAVAILABLE),
        "a failed invalidation is not a success"
    );
    assert!(
        r.registry.is_valid(&user, &session).await.unwrap(),
        "the session is still live"
    );
    assert!(
        r.sid_map.contains_key(&key),
        "the sid mapping survives the failed attempt"
    );
    assert_eq!(
        r.sid_map.subject_len(),
        1,
        "the subject registration survives"
    );
    assert_eq!(
        r.audit.0.load(Ordering::SeqCst),
        0,
        "nothing ended, nothing reported"
    );

    r.flaky.set(Refuse::None);
    assert_eq!(
        post(&r.handler, &t).await,
        Ok(StatusCode::OK),
        "the resend is not a replay"
    );
    assert!(!r.registry.is_valid(&user, &session).await.unwrap());
    assert!(!r.sid_map.contains_key(&key));
    assert_eq!(r.sid_map.subject_len(), 0);
    assert_eq!(r.audit.0.load(Ordering::SeqCst), 1);

    assert_eq!(
        post(&r.handler, &t).await,
        Err(StatusCode::BAD_REQUEST),
        "a third delivery of a spent token is a replay"
    );
}

/// A `sub` token ends two sessions and the registry fails on the second: the
/// first is ended, cleaned up and reported; the second stays live and
/// registered; the answer is retryable; the resend ends only the second.
#[tokio::test]
async fn a_partly_failed_sub_logout_keeps_the_failed_session_for_the_retry() {
    let r = rig();
    let rng = MockRng::new(12);
    let (x, y) = (SessionId::new(&rng), SessionId::new(&rng));
    let user = axess_identity::testing::user("user-two");
    for s in [&x, &y] {
        r.registry.register(&user, s).await.unwrap();
        r.sid_map
            .register_subject_session(ISS, "subject-2", None, user, *s);
    }
    let key_y: SidKey = (ISS.to_string(), "sid-y".to_string());
    r.sid_map.insert(
        key_y.clone(),
        "subject-2",
        None,
        user,
        y,
        chrono::Utc::now(),
    );
    assert_eq!(r.sid_map.subject_len(), 2);

    let t = token(serde_json::json!({ "sub": "subject-2", "jti": "j-partial" }));
    r.flaky.set(Refuse::Only(y));
    assert_eq!(
        post(&r.handler, &t).await,
        Err(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert!(!r.registry.is_valid(&user, &x).await.unwrap(), "x ended");
    assert!(
        r.registry.is_valid(&user, &y).await.unwrap(),
        "y still live"
    );
    assert!(r.sid_map.contains_key(&key_y), "y stays mapped by sid");
    assert_eq!(r.sid_map.subject_len(), 1, "only y stays registered");
    assert_eq!(r.audit.0.load(Ordering::SeqCst), 1, "only x is reported");

    r.flaky.set(Refuse::None);
    assert_eq!(post(&r.handler, &t).await, Ok(StatusCode::OK));
    assert!(!r.registry.is_valid(&user, &y).await.unwrap());
    assert!(!r.sid_map.contains_key(&key_y));
    assert_eq!(r.sid_map.subject_len(), 0);
    assert_eq!(r.audit.0.load(Ordering::SeqCst), 2);
}
