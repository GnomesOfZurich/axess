//! A resend of a token whose first delivery is still being acted on: it is
//! retryable, not a replay, since the first delivery may yet fail.

use super::*;
use crate::federation::replay_log::ReplayFuture;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{
    MemorySessionRegistry, RevocationError, SessionRegistry, SessionRegistryAdapter,
};
use crate::testing::mock_random::MockRng;
use axess_clock::testing::MockClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axess_testing::stall::{Gate, abort_inside};
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::future::Future;
use std::pin::Pin;
use tokio::sync::Notify;

const ISS: &str = "https://slow.example.com";
const CLIENT: &str = "client-slow";

/// How long a test waits for a delivery to reach the registry it holds: far
/// beyond the milliseconds it takes, so a delivery that never gets there
/// fails the test instead of hanging it.
const REACH_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// The instant every clock of these tests stands at. Nothing here waits on
/// time, so the clocks never move.
fn start() -> axess_clock::Timestamp {
    axess_clock::Timestamp::from_utc(2026, 1, 1, 0, 0, 0).expect("a valid instant")
}

fn clock() -> Arc<MockClock> {
    Arc::new(MockClock::at(start()))
}

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
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            self.inner.invalidate_session(user_id, session).await
        })
    }

    fn current_key<'a>(
        &'a self,
        user_id: &'a UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SessionKey>, RevocationError>> + Send + 'a>>
    {
        self.inner.current_key(user_id, session)
    }
}

fn token() -> String {
    let payload = serde_json::json!({
        "iss": ISS,
        "aud": CLIENT,
        "iat": start().unix_seconds(),
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
            .with_client_id(CLIENT)
            .with_clock(clock()),
    )];
    let handler = BackChannelLogoutHandler::new(&providers, held.clone(), sid_map.clone(), clock())
        .expect("handler");
    let rng = MockRng::new(9);
    let session = SessionKey::of(&SessionId::new(&rng));
    let user = axess_identity::testing::user("user-slow");
    registry.register(&user, &session).await.unwrap();
    sid_map.insert(
        (ISS.to_string(), "sid-slow".to_string()),
        "idp-subject-slow",
        None,
        user,
        session,
        start(),
    );

    let first = {
        let handler = handler.clone();
        tokio::spawn(async move { post(&handler, token()).await })
    };
    tokio::time::timeout(REACH_BOUND, held.entered.notified())
        .await
        .expect("the first delivery reaches the session registry");

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

/// The real in-process log, except that the first `settle` parks on a gate:
/// where a shared log does network I/O and the request is cancelled in the
/// middle of it. With `committed_first`, the log takes that settle before
/// parking: the write reached the store and the request is cancelled while
/// the acknowledgement is on its way back. A later `settle` (the repeat a
/// cancelled request leaves behind) goes through.
struct GatedSettle {
    inner: Arc<jti_log::JtiLog>,
    gate: Gate,
    committed_first: bool,
    parked: std::sync::atomic::AtomicBool,
}

impl LogoutReplayLog for GatedSettle {
    fn record<'a>(
        &'a self,
        issuer: &'a str,
        jti: &'a str,
        now: axess_clock::Timestamp,
    ) -> ReplayFuture<'a, Recorded> {
        LogoutReplayLog::record(&*self.inner, issuer, jti, now)
    }

    fn settle<'a>(&'a self, issuer: &'a str, jti: &'a str) -> ReplayFuture<'a, ()> {
        Box::pin(async move {
            let first = !self.parked.swap(true, std::sync::atomic::Ordering::SeqCst);
            if first {
                if self.committed_first {
                    LogoutReplayLog::settle(&*self.inner, issuer, jti).await?;
                }
                self.gate.wait().await;
            }
            LogoutReplayLog::settle(&*self.inner, issuer, jti).await
        })
    }

    fn forget<'a>(&'a self, issuer: &'a str, jti: &'a str) -> ReplayFuture<'a, ()> {
        LogoutReplayLog::forget(&*self.inner, issuer, jti)
    }
}

/// A delivery cancelled while its outcome is being written to a shared log
/// does not leave the pair in flight: the IdP's resend is acted on or refused
/// as a replay, never answered "come again" until retention ends.
#[tokio::test]
async fn a_cancelled_finish_does_not_leave_the_pair_in_flight() {
    let (log, resend) = cancelled_while_settling(false).await;
    drop(log);
    assert_ne!(
        resend,
        Recorded::InFlight,
        "the pair is stuck in flight after a cancelled delivery"
    );
}

/// A delivery cancelled after the shared log committed the settle, while the
/// acknowledgement was on its way back, stays settled: the cancellation does
/// not forget the pair, so the same token presented again is a replay, not a
/// fresh token to act on.
#[tokio::test]
async fn a_cancellation_after_the_settle_committed_does_not_reopen_the_token() {
    let (log, resend) = cancelled_while_settling(true).await;
    drop(log);
    assert_eq!(
        resend,
        Recorded::Replay,
        "the settle the log committed was undone by the cancelled request"
    );
}

/// Deliver a token whose settle parks (after committing when
/// `committed_first`), cancel the delivery there, and present the token's
/// pair to the log again.
async fn cancelled_while_settling(committed_first: bool) -> (Arc<jti_log::JtiLog>, Recorded) {
    let registry = MemorySessionRegistry::new();
    let log = Arc::new(jti_log::JtiLog::new(16));
    let gate = Gate::new();
    let sid_map = SidMap::new();
    let session = SessionKey::of(&SessionId::new(&MockRng::new(11)));
    let user = axess_identity::testing::user("user-cancel");
    registry.register(&user, &session).await.unwrap();
    sid_map.insert(
        (ISS.to_string(), "sid-slow".to_string()),
        "idp-subject-cancel",
        None,
        user,
        session,
        start(),
    );
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("slow")
            .with_issuer(ISS)
            .with_client_id(CLIENT)
            .with_clock(clock()),
    )];
    let handler = BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map,
        clock(),
    )
    .expect("handler")
    .with_replay_log(Arc::new(GatedSettle {
        inner: log.clone(),
        gate: gate.clone(),
        committed_first,
        parked: std::sync::atomic::AtomicBool::new(false),
    }));

    let delivery = {
        let handler = handler.clone();
        tokio::spawn(async move {
            let _ = post(&handler, token()).await;
        })
    };
    abort_inside(&gate, delivery).await;

    let resend = LogoutReplayLog::record(&*log, ISS, "slow-1", start())
        .await
        .expect("the log answers");
    (log, resend)
}
