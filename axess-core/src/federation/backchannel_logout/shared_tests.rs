//! Handlers that share a `sid` store and a replay log, and handlers whose
//! store or log fails. The in-process implementations stand in for the
//! shared ones here; the Valkey implementations have live tests of their own.

use super::*;
use crate::federation::replay_log::{ReplayFuture, ReplayLogError};
use crate::federation::sid_store::{SidFuture, SidStoreError};
use crate::session::id::SessionId;
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use crate::testing::RecordingMetrics;
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const ISS: &str = "https://shared.example.com";
const CLIENT: &str = "client-shared";

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

fn handler(registry: &MemorySessionRegistry, store: Arc<dyn SidStore>) -> BackChannelLogoutHandler {
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("shared")
            .with_issuer(ISS)
            .with_client_id(CLIENT),
    )];
    BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        SidMap::new(),
        Arc::new(SystemClock),
    )
    .expect("handler")
    .with_sid_store(store)
}

async fn post(h: &BackChannelLogoutHandler, t: String) -> Result<StatusCode, StatusCode> {
    BackChannelLogoutHandler::handle_outcome(
        State(h.clone()),
        Form(LogoutParams { logout_token: t }),
    )
    .await
}

/// A login of `user` with `sid`, recorded in `store` as the login path does.
async fn login(
    registry: &MemorySessionRegistry,
    store: &Arc<dyn SidStore>,
    sid: &str,
) -> (UserId, SessionId) {
    let user = axess_identity::testing::user("alice");
    let session = SessionId::new(&MockRng::new(31));
    registry.register(&user, &session).await.unwrap();
    store
        .register_subject_session(ISS, "idp-sub", None, user, session)
        .await
        .unwrap();
    store
        .insert_displacing(
            (ISS.to_string(), sid.to_string()),
            "idp-sub",
            None,
            user,
            session,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    (user, session)
}

/// Two instances with separate in-process maps: the token reaches the one that
/// did not handle the login. It is answered `200`, as the specification has
/// it, the session stays, and the miss is counted so an operator sees it.
#[tokio::test]
async fn a_token_that_finds_no_session_is_answered_200_and_counted() {
    let registry = MemorySessionRegistry::new();
    let login_side: Arc<dyn SidStore> = Arc::new(SidMap::new());
    let (user, session) = login(&registry, &login_side, "sid-1").await;

    let metrics = Arc::new(RecordingMetrics::default());
    let other = handler(&registry, Arc::new(SidMap::new())).with_metrics(metrics.clone());
    let t = token(serde_json::json!({ "sid": "sid-1", "jti": "j1" }));

    assert_eq!(post(&other, t).await, Ok(StatusCode::OK));
    assert!(
        registry.is_valid(&user, &session).await.unwrap(),
        "the instance without the mapping could not end it"
    );
    assert_eq!(metrics.count("back_channel_logout_unmatched"), 1);
}

/// Two handlers on one store: the token posted to the second ends the session
/// logged in through the first, and nothing is counted as unmatched.
#[tokio::test]
async fn a_token_posted_to_the_second_handler_ends_the_session_of_the_first_login() {
    let registry = MemorySessionRegistry::new();
    let shared: Arc<dyn SidStore> = Arc::new(SidMap::new());
    let (user, session) = login(&registry, &shared, "sid-1").await;

    let metrics = Arc::new(RecordingMetrics::default());
    let _first = handler(&registry, Arc::clone(&shared));
    let second = handler(&registry, Arc::clone(&shared)).with_metrics(metrics.clone());
    let t = token(serde_json::json!({ "sid": "sid-1", "jti": "j1" }));

    assert_eq!(post(&second, t).await, Ok(StatusCode::OK));
    assert!(!registry.is_valid(&user, &session).await.unwrap());
    assert_eq!(metrics.count("back_channel_logout_unmatched"), 0);
}

/// A replay log the handlers share catches a token replayed to the other one.
#[tokio::test]
async fn a_shared_replay_log_refuses_a_token_replayed_to_another_handler() {
    let registry = MemorySessionRegistry::new();
    let store: Arc<dyn SidStore> = Arc::new(SidMap::new());
    let log: Arc<dyn LogoutReplayLog> = Arc::new(jti_log::JtiLog::new(JTI_CACHE_MAX));
    let a = handler(&registry, Arc::clone(&store)).with_replay_log(Arc::clone(&log));
    let b = handler(&registry, Arc::clone(&store)).with_replay_log(Arc::clone(&log));

    let t = token(serde_json::json!({ "sid": "none", "jti": "j1" }));
    assert_eq!(post(&a, t.clone()).await, Ok(StatusCode::OK));
    assert_eq!(post(&b, t).await, Err(StatusCode::BAD_REQUEST));
}

/// A store that fails every read.
struct DownStore;

impl SidStore for DownStore {
    fn insert_displacing<'a>(
        &'a self,
        _: SidKey,
        _: &'a str,
        _: Option<TenantId>,
        _: UserId,
        _: SessionId,
        _: chrono::DateTime<chrono::Utc>,
    ) -> SidFuture<'a, Option<crate::federation::sid_map::DisplacedSid>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn restore_if_vacant(
        &self,
        _: SidKey,
        _: crate::federation::sid_map::DisplacedSid,
    ) -> SidFuture<'_, bool> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn get<'a>(
        &'a self,
        _: &'a SidKey,
        _: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn remove_if_session<'a>(
        &'a self,
        _: &'a SidKey,
        _: &'a SessionId,
    ) -> SidFuture<'a, Option<SidEntry>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn register_subject_session<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Option<TenantId>,
        _: UserId,
        _: SessionId,
    ) -> SidFuture<'a, ()> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn forget_subject_session<'a>(
        &'a self,
        _: &'a str,
        _: &'a UserId,
        _: &'a SessionId,
    ) -> SidFuture<'a, bool> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn subject_sessions<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionId)>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn sweep_subject_candidates(
        &self,
        _: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionId)>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn remove_session<'a>(&'a self, _: &'a SessionId) -> SidFuture<'a, usize> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn evict_inserted_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn evict_oldest(&self, _: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
    fn mapping_count(&self) -> SidFuture<'_, usize> {
        Box::pin(async { Err(SidStoreError("down".into())) })
    }
}

/// A store that cannot be read answers a retryable 503 (the IdP resends),
/// and the token is not spent.
#[tokio::test]
async fn a_store_that_cannot_be_read_is_a_retryable_503_and_the_token_is_not_spent() {
    let registry = MemorySessionRegistry::new();
    let down = handler(&registry, Arc::new(DownStore) as Arc<dyn SidStore>);
    let t = token(serde_json::json!({ "sid": "s", "jti": "j1" }));
    assert_eq!(
        post(&down, t.clone()).await,
        Err(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(
        post(&down, t).await,
        Err(StatusCode::SERVICE_UNAVAILABLE),
        "forgotten after the failure, so the resend is not a replay"
    );
}

/// A replay log that fails every call.
struct DownLog;

impl LogoutReplayLog for DownLog {
    fn record<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> ReplayFuture<'a, Recorded> {
        Box::pin(async { Err(ReplayLogError("down".into())) })
    }
    fn settle<'a>(&'a self, _: &'a str, _: &'a str) -> ReplayFuture<'a, ()> {
        Box::pin(async { Err(ReplayLogError("down".into())) })
    }
    fn forget<'a>(&'a self, _: &'a str, _: &'a str) -> ReplayFuture<'a, ()> {
        Box::pin(async { Err(ReplayLogError("down".into())) })
    }
}

#[tokio::test]
async fn a_replay_log_that_cannot_be_asked_is_a_retryable_503() {
    let registry = MemorySessionRegistry::new();
    let h = handler(&registry, Arc::new(SidMap::new())).with_replay_log(Arc::new(DownLog));
    let t = token(serde_json::json!({ "sid": "s", "jti": "j1" }));
    assert_eq!(post(&h, t).await, Err(StatusCode::SERVICE_UNAVAILABLE));
}
