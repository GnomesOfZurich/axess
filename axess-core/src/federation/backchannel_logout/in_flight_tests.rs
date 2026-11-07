//! A resend of a token whose first delivery is still being acted on: it is
//! retryable, not a replay, since the first delivery may yet fail.

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
use tokio::sync::Notify;

const ISS: &str = "https://slow.example.com";
const CLIENT: &str = "client-slow";

/// A registry that holds a revocation until released, then carries it out.
struct Held {
    inner: SessionRegistryAdapter<MemorySessionRegistry>,
    entered: Notify,
    release: Notify,
}

impl SessionRevoker for Held {
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
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            self.inner.invalidate_session(user_id, session_id).await
        })
    }
}

fn token() -> String {
    let payload = serde_json::json!({
        "iss": ISS,
        "aud": CLIENT,
        "iat": chrono::Utc::now().timestamp(),
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        "sid": "sid-slow",
        "jti": "slow-1",
    });
    let header = serde_json::json!({"alg": "none", "typ": "logout+jwt"});
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    )
}

async fn post(h: &BackChannelLogoutHandler, t: String) -> Result<StatusCode, StatusCode> {
    BackChannelLogoutHandler::handle_outcome(
        State(h.clone()),
        Form(LogoutParams { logout_token: t }),
    )
    .await
}

#[tokio::test]
async fn a_resend_while_the_first_delivery_runs_is_retryable_and_a_later_one_is_a_replay() {
    let registry = MemorySessionRegistry::new();
    let held = Arc::new(Held {
        inner: SessionRegistryAdapter(registry.clone()),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let sid_map = SidMap::new();
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("slow")
            .with_issuer(ISS)
            .with_client_id(CLIENT),
    )];
    let handler = BackChannelLogoutHandler::new(
        &providers,
        held.clone(),
        sid_map.clone(),
        Arc::new(SystemClock),
    )
    .expect("handler");
    let rng = MockRng::new(9);
    let session = SessionId::new(&rng);
    let user = axess_identity::testing::user("user-slow");
    registry.register(&user, &session).await.unwrap();
    sid_map.insert(
        (ISS.to_string(), "sid-slow".to_string()),
        "idp-subject-slow",
        None,
        user,
        session,
        chrono::Utc::now(),
    );

    let first = {
        let handler = handler.clone();
        tokio::spawn(async move { post(&handler, token()).await })
    };
    held.entered.notified().await;

    assert_eq!(
        post(&handler, token()).await,
        Err(StatusCode::SERVICE_UNAVAILABLE),
        "the IdP is told to send it again"
    );

    held.release.notify_one();
    assert_eq!(first.await.unwrap(), Ok(StatusCode::OK));
    assert_eq!(
        post(&handler, token()).await,
        Err(StatusCode::BAD_REQUEST),
        "once acted on, the same token is a replay"
    );
}
