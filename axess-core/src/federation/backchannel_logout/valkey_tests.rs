//! Two handlers on one Valkey `sid` store and replay log, against a live
//! server, ignored by default: `VALKEY_URL=redis://127.0.0.1:6390 cargo test
//! -p axess-core --features testing,oauth,jwt-aws-lc,valkey -- --ignored
//! valkey_handlers`.

use super::*;
use crate::federation::valkey_logout::{ValkeyReplayLog, ValkeySidStore};
use crate::session::id::SessionId;
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use crate::testing::RecordingMetrics;
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fred::prelude::{ClientLike, Config};

const ISS: &str = "https://valkey.example.com";
const CLIENT: &str = "client-valkey";

fn token(sid: &str, jti: &str) -> String {
    let payload = serde_json::json!({
        "iss": ISS,
        "aud": CLIENT,
        "iat": chrono::Utc::now().timestamp(),
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        "sid": sid,
        "jti": jti,
    });
    let header = serde_json::json!({"alg": "none", "typ": "logout+jwt"});
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    )
}

async fn valkey() -> fred::prelude::Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = fred::prelude::Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    client
}

/// An instance: its own handler, on the shared store and replay log.
fn instance(
    registry: &MemorySessionRegistry,
    store: &ValkeySidStore,
    log: &ValkeyReplayLog,
    metrics: Arc<RecordingMetrics>,
) -> BackChannelLogoutHandler {
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("valkey")
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
    .with_sid_store(Arc::new(store.clone()))
    .with_replay_log(Arc::new(log.clone()))
    .with_metrics(metrics)
}

async fn post(h: &BackChannelLogoutHandler, t: String) -> Result<StatusCode, StatusCode> {
    BackChannelLogoutHandler::handle_outcome(
        State(h.clone()),
        Form(LogoutParams { logout_token: t }),
    )
    .await
}

/// The session is logged in through the first instance; the IdP's token
/// reaches the second, which ends it, and a replay of the token to the first
/// is refused.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_handlers_end_the_session_another_instance_logged_in() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let prefix = format!("axo_handlers_{nanos}");
    let client = valkey().await;
    let store = ValkeySidStore::new(client.clone()).with_prefix(prefix.clone());
    let log = ValkeyReplayLog::new(client).with_prefix(prefix);
    let registry = MemorySessionRegistry::new();
    let (m1, m2) = (
        Arc::new(RecordingMetrics::default()),
        Arc::new(RecordingMetrics::default()),
    );
    let first = instance(&registry, &store, &log, m1);
    let second = instance(&registry, &store, &log, m2.clone());

    // The login, as the login path records it on the first instance.
    let user = axess_identity::testing::user("alice");
    let session = SessionId::new(&MockRng::new(51));
    registry.register(&user, &session).await.unwrap();
    store
        .register_subject_session(ISS, "idp-sub", None, user, session)
        .await
        .unwrap();
    store
        .insert_displacing(
            (ISS.to_string(), "sid-1".to_string()),
            "idp-sub",
            None,
            user,
            session,
            chrono::Utc::now(),
        )
        .await
        .unwrap();

    let t = token("sid-1", "j1");
    assert_eq!(post(&second, t.clone()).await, Ok(StatusCode::OK));
    assert!(
        !registry.is_valid(&user, &session).await.unwrap(),
        "the second instance ended the first one's session"
    );
    assert_eq!(m2.count("back_channel_logout_unmatched"), 0);

    assert_eq!(
        post(&first, t).await,
        Err(StatusCode::BAD_REQUEST),
        "the replay log is shared too"
    );
}
