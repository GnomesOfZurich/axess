//! The audit hook: one report per session a logout token ends, none for a
//! token that ends nothing, and a failing sink does not undo the logout.

use super::*;
use crate::session::id::SessionId;
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Mutex;

const ISS: &str = "https://audit.example.com";

/// Collects what it is told; answers `Err` when `fail` is set.
struct Collect {
    ended: Mutex<Vec<IdpSessionEnded>>,
    fail: bool,
}

impl LogoutAudit for Collect {
    fn session_ended<'a>(
        &'a self,
        ended: &'a IdpSessionEnded,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.ended.lock().unwrap().push(ended.clone());
            if self.fail {
                Err("sink down".to_string())
            } else {
                Ok(())
            }
        })
    }
}

fn token(extra: serde_json::Value) -> String {
    let mut payload = serde_json::json!({
        "iss": ISS,
        "aud": "client-a",
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

async fn run(fail: bool) -> (Vec<IdpSessionEnded>, bool, StatusCode) {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("app-a")
            .with_issuer(ISS)
            .with_client_id("client-a"),
    )];
    let sink = Arc::new(Collect {
        ended: Mutex::new(Vec::new()),
        fail,
    });
    let handler = BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map.clone(),
        Arc::new(SystemClock),
    )
    .expect("handler")
    .with_audit(sink.clone());

    let rng = MockRng::new(5);
    let (x, y) = (SessionId::new(&rng), SessionId::new(&rng));
    let user = axess_identity::testing::user("user-1");
    for s in [&x, &y] {
        registry.register(&user, s).await.unwrap();
        sid_map.register_subject_session(ISS, "idp-sub", user, *s);
    }

    // No `sid`: both sessions of the subject end, and both are reported.
    let status = BackChannelLogoutHandler::handle_backchannel_logout(
        State(handler),
        Form(LogoutParams {
            logout_token: token(serde_json::json!({ "sub": "idp-sub", "jti": "j1" })),
        }),
    )
    .await
    .unwrap_or_else(|s| s);
    let both_ended = !registry.is_valid(&user, &x).await.unwrap()
        && !registry.is_valid(&user, &y).await.unwrap();
    let reported = sink.ended.lock().unwrap().clone();
    (reported, both_ended, status)
}

#[tokio::test]
async fn every_session_a_logout_ends_is_reported_once() {
    let (reported, both_ended, status) = run(false).await;
    assert_eq!(status, StatusCode::OK);
    assert!(both_ended);
    assert_eq!(reported.len(), 2, "one report per session");
    assert!(reported.iter().all(|e| e.iss == ISS));
    assert_ne!(reported[0].session_id, reported[1].session_id);
}

#[tokio::test]
async fn a_failing_sink_does_not_undo_the_logout() {
    let (reported, both_ended, status) = run(true).await;
    assert_eq!(status, StatusCode::OK, "the IdP is not told to retry");
    assert!(
        both_ended,
        "the sessions are ended before the sink is asked"
    );
    assert_eq!(reported.len(), 2, "each report is still attempted");
}

/// The service's hook writes a `SessionInvalidated` row for the user and the
/// session, with no acting administrator.
#[tokio::test]
async fn the_service_hook_writes_a_session_invalidated_row() {
    use crate::authn::event::AuthEventType;
    use crate::authn::service::AuthnService;
    use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore};

    let record = crate::testing::user_record("u1", "t1");
    let user = record.id;
    let identity = MockIdentityStore::new().with_user(record);
    let authn = AuthnService::new(identity.clone(), MockFactorStore::new());
    let rng = MockRng::new(9);
    let session_id = SessionId::new(&rng);

    authn
        .backchannel_logout_audit()
        .session_ended(&IdpSessionEnded {
            iss: ISS.to_string(),
            user_id: user,
            session_id,
        })
        .await
        .expect("audit");

    let rows = identity.events();
    let row = rows
        .iter()
        .find(|e| e.event_type == AuthEventType::SessionInvalidated)
        .expect("a SessionInvalidated row");
    assert_eq!(row.user_id, Some(user));
    assert_eq!(row.session_id, Some(session_id));
    assert!(row.actor_id.is_none());
}
