//! A session in the middle of a step-up is the signed-in session it began
//! from, so the load checks it as that session: against the registry, the
//! absolute age cap from its login's time, and the impersonation
//! cap. A login in progress is not registered, and is not checked.

use super::*;
use crate::authn::factor::{FactorKind, FactorStep};
use crate::authn::ids::testing as ids;
use crate::session::data::{AuthFlow, AuthState, SessionData};
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::UnknownLiveness;
use crate::session::store::{MemorySessionRegistry, MemorySessionStore, SessionRegistryHandle};
use crate::testing::mock_random::MockRng;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::sync::Arc;
use std::time::Duration;

const HOUR: Duration = Duration::from_secs(3600);

/// A session signed in `ago` before the reference time, now in a step-up
/// that asks for a TOTP code.
fn step_up_signed_in(ago: axess_clock::SignedDuration) -> SessionData {
    let mut data = SessionData::default();
    data.auth_state.set_authenticated(
        ids::user("u"),
        ids::tenant("t"),
        MockClock::reference_time().minus(ago),
    );
    assert!(
        data.auth_state
            .begin_step_up(vec![FactorStep::Required(FactorKind::Totp)])
    );
    data
}

/// A login in progress for the same user.
fn login_in_progress() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state.begin_authenticating(
        ids::user("u"),
        ids::tenant("t"),
        "password".into(),
        vec![FactorStep::Required(FactorKind::Password)],
    );
    data
}

fn is_step_up(state: &AuthState) -> bool {
    matches!(
        state,
        AuthState::Authenticating {
            flow: AuthFlow::StepUp { .. },
            ..
        }
    )
}

/// What the load made of `data`, stored under an id the registry was given
/// and, when `revoked`, then had taken away: the outcome and whether the row
/// is still in the store.
async fn load_with_registry(
    cfg: &SessionConfig,
    data: &SessionData,
    revoked: bool,
) -> (LoadOutcome, bool) {
    let clock = MockClock::at_reference();
    let registry: Arc<dyn SessionRegistryHandle> = MemorySessionRegistry::new()
        .with_clock(Arc::new(clock.clone()))
        .handle();
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let id = SessionId::new(&MockRng::new(9));
    assert!(
        registry
            .register(&ids::user("u"), &SessionKey::of(&id))
            .await
    );
    if revoked {
        registry.invalidate_user(&ids::user("u")).await.unwrap();
    }
    store
        .save(&SessionKey::of(&id), data, cfg.ttl)
        .await
        .unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            cfg.cookie_name.as_ref(),
            keys.sign_cookie(&CookieSession::of_id(id))
        ))
        .unwrap(),
    );
    let audit: Arc<dyn SessionEndAudit> = Arc::new(crate::session::UnrecordedSessionEnds);
    let outcome = load_session(
        &store,
        &keys,
        cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy {
            registry: Some(registry.as_ref()),
            unknown: UnknownLiveness::Reject,
            clock: &clock,
            metrics: None,
            audit: &audit,
        },
    )
    .await;
    let row_kept = store.load(&SessionKey::of(&id)).await.unwrap().is_some();
    (outcome, row_kept)
}

/// A step-up of a session the registry no longer holds is ended on load, as
/// the signed-in session would be: the request runs as a guest and the row
/// is deleted.
#[tokio::test]
async fn a_step_up_of_a_revoked_session_is_ended_on_load() {
    let cfg = SessionConfig::default();
    let (outcome, row_kept) = load_with_registry(
        &cfg,
        &step_up_signed_in(axess_clock::SignedDuration::ZERO),
        true,
    )
    .await;
    assert!(outcome.session_ended, "the revoked step-up is ended");
    assert!(!outcome.stored);
    assert!(outcome.data.auth_state.is_guest());
    assert!(!row_kept, "the row is deleted");
}

/// A step-up of a session the registry holds goes on: the step-up keeps the
/// id it was registered under.
#[tokio::test]
async fn a_step_up_of_a_held_session_is_kept_on_load() {
    let cfg = SessionConfig::default();
    let (outcome, row_kept) = load_with_registry(
        &cfg,
        &step_up_signed_in(axess_clock::SignedDuration::ZERO),
        false,
    )
    .await;
    assert!(!outcome.session_ended);
    assert!(outcome.stored);
    assert!(
        is_step_up(&outcome.data.auth_state),
        "{:?}",
        outcome.data.auth_state
    );
    assert!(row_kept);
}

/// A step-up past the absolute age cap of the login it began from is ended
/// on load; the cap is not reset by asking for a step-up.
#[tokio::test]
async fn a_step_up_past_the_absolute_age_cap_is_ended_on_load() {
    let cfg = SessionConfig::builder()
        .max_authenticated_age(Some(HOUR))
        .build();
    let (outcome, row_kept) = load_with_registry(
        &cfg,
        &step_up_signed_in(axess_clock::SignedDuration::minutes(61)),
        false,
    )
    .await;
    assert!(outcome.session_ended, "the step-up outlived the cap");
    assert!(outcome.data.auth_state.is_guest());
    assert!(!row_kept);

    let (young, _) = load_with_registry(
        &cfg,
        &step_up_signed_in(axess_clock::SignedDuration::minutes(59)),
        false,
    )
    .await;
    assert!(
        is_step_up(&young.data.auth_state),
        "one within the cap stands"
    );
}

/// A step-up of an impersonation past the impersonation age cap is ended on
/// load, as the impersonation would be.
#[tokio::test]
async fn a_step_up_of_an_impersonation_past_its_cap_is_ended_on_load() {
    let cfg = SessionConfig::builder()
        .max_impersonation_age(Some(HOUR))
        .build();
    let impersonation = |since: axess_clock::SignedDuration| {
        let mut data = SessionData::default();
        data.auth_state.set_authenticated(
            ids::user("u"),
            ids::tenant("t"),
            MockClock::reference_time(),
        );
        assert!(
            data.auth_state
                .set_impersonator(ids::user("admin"), MockClock::reference_time().minus(since))
        );
        assert!(
            data.auth_state
                .begin_step_up(vec![FactorStep::Required(FactorKind::Totp)])
        );
        data
    };
    let (old, _) = load_with_registry(
        &cfg,
        &impersonation(axess_clock::SignedDuration::hours(2)),
        false,
    )
    .await;
    assert!(old.session_ended, "the impersonation outlived its cap");
    assert!(old.data.auth_state.is_guest());
}

/// A login in progress is in no registry yet, and is not checked against
/// one: a registry that holds nothing for the user leaves it as it is.
#[tokio::test]
async fn a_login_in_progress_is_not_checked_against_the_registry() {
    let cfg = SessionConfig::default();
    let (outcome, row_kept) = load_with_registry(&cfg, &login_in_progress(), true).await;
    assert!(!outcome.session_ended);
    assert!(
        matches!(
            outcome.data.auth_state,
            AuthState::Authenticating {
                flow: AuthFlow::Login,
                ..
            }
        ),
        "{:?}",
        outcome.data.auth_state
    );
    assert!(row_kept);
}
