//! A `sid` ends one session, providers sharing an issuer, and a full replay
//! log. Unsigned tokens are used throughout: the mock provider skips
//! signature verification.

use super::*;
use crate::session::id::SessionId;
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const ISS: &str = "https://shared.example.com";

fn token(client_id: &str, extra: serde_json::Value) -> String {
    let mut payload = serde_json::json!({
        "iss": ISS,
        "aud": client_id,
        "iat": chrono::Utc::now().timestamp(),
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
    });
    payload
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    )
}

fn handler(registry: &MemorySessionRegistry, sid_map: SidMap) -> BackChannelLogoutHandler {
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![
        Arc::new(
            MockOAuthProvider::new("app-a")
                .with_issuer(ISS)
                .with_client_id("client-a"),
        ),
        Arc::new(
            MockOAuthProvider::new("app-b")
                .with_issuer(ISS)
                .with_client_id("client-b"),
        ),
    ];
    BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map,
        Arc::new(SystemClock),
    )
    .expect("handler")
}

async fn post(h: &BackChannelLogoutHandler, t: String) -> Result<StatusCode, StatusCode> {
    BackChannelLogoutHandler::handle_backchannel_logout(
        State(h.clone()),
        Form(LogoutParams { logout_token: t }),
    )
    .await
}

/// A token with both `sub` and `sid` ends the session the `sid` maps to and
/// leaves the subject\'s other session alone.
#[tokio::test]
async fn a_token_with_sub_and_sid_ends_only_the_sid_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = handler(&registry, sid_map.clone());
    let rng = MockRng::new(3);
    let (x, y) = (SessionId::new(&rng), SessionId::new(&rng));
    let user = axess_identity::testing::user("user-1");
    let sub = "idp-subject-s";
    for s in [&x, &y] {
        registry.register(&user, s).await.unwrap();
        sid_map.register_subject_session(ISS, sub, user, *s);
    }
    sid_map.insert(
        (ISS.to_string(), "sid-x".to_string()),
        sub,
        user,
        x,
        chrono::Utc::now(),
    );

    let t = token(
        "client-a",
        serde_json::json!({ "sub": sub, "sid": "sid-x", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Ok(StatusCode::OK));

    assert!(!registry.is_valid(&user, &x).await.unwrap(), "X ended");
    assert!(registry.is_valid(&user, &y).await.unwrap(), "Y survives");

    // With no `sid` the whole subject goes.
    let t = token("client-a", serde_json::json!({ "sub": sub, "jti": "j2" }));
    assert_eq!(post(&h, t).await, Ok(StatusCode::OK));
    assert!(!registry.is_valid(&user, &y).await.unwrap());
}

/// Two providers of one issuer both verify tokens addressed to their own
/// client id; neither replaces the other, and an unknown client id is refused.
#[tokio::test]
async fn providers_sharing_an_issuer_each_verify_their_own_tokens() {
    let registry = MemorySessionRegistry::new();
    let h = handler(&registry, SidMap::new());
    assert_eq!(
        post(
            &h,
            token("client-a", serde_json::json!({"sid": "s", "jti": "a1"}))
        )
        .await,
        Ok(StatusCode::OK),
        "the first provider\'s client id"
    );
    assert_eq!(
        post(
            &h,
            token("client-b", serde_json::json!({"sid": "s", "jti": "b1"}))
        )
        .await,
        Ok(StatusCode::OK)
    );
    assert_eq!(
        post(
            &h,
            token("client-c", serde_json::json!({"sid": "s", "jti": "c1"}))
        )
        .await,
        Err(StatusCode::BAD_REQUEST)
    );
}

/// A replay log full of live entries answers a new token with a retryable 503
/// and forgets none: the oldest token is still a replay.
#[tokio::test]
async fn a_full_replay_log_answers_503_and_still_catches_the_oldest_replay() {
    let registry = MemorySessionRegistry::new();
    let h = handler(&registry, SidMap::new());
    let now = h.clock.now();
    let cutoff = now - chrono::Duration::seconds(JTI_RETENTION_SECS);
    for n in 0..JTI_CACHE_MAX {
        assert_eq!(
            h.seen_jtis.record(ISS, &format!("fill-{n}"), now, cutoff),
            Recorded::New
        );
    }

    let fresh = token("client-a", serde_json::json!({"sid": "s", "jti": "new"}));
    assert_eq!(post(&h, fresh).await, Err(StatusCode::SERVICE_UNAVAILABLE));

    let replay = token("client-a", serde_json::json!({"sid": "s", "jti": "fill-0"}));
    assert_eq!(
        post(&h, replay).await,
        Err(StatusCode::BAD_REQUEST),
        "the oldest live entry is still a replay"
    );
}
