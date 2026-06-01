#![cfg(feature = "testing")]
//! Session state transitions: `AuthState`, `WorkflowState`, eager session-id
//! rotation on auth-state changes, atomic `take_custom`, and `AuthSession`
//! extractor surface.

mod common;

use axess_core::authn::factor::FactorKind;
use axess_core::session::data::{AuthState, SessionData, WorkflowKind, WorkflowState};
use axess_core::testing::{AuthSessionTestExt, test_session};
use chrono::Utc;
use common::{tid, uid};

// ── SessionData / AuthState shape ────────────────────────────────────────────

#[test]
fn session_data_default_is_guest() {
    let data = SessionData::default();
    assert!(data.auth_state.is_guest());
    assert!(!data.auth_state.is_authenticated());
}

#[test]
fn auth_state_user_id_returns_none_for_guest() {
    let state = AuthState::Guest;
    assert!(state.user_id().is_none());
    assert!(state.tenant_id().is_none());
}

#[test]
fn auth_state_authenticated_has_user_and_tenant() {
    let state = AuthState::Authenticated {
        user_id: uid("u1"),
        tenant_id: tid("t1"),
        authn_time: Utc::now(),
        factors_completed: vec![],
    };
    assert!(state.is_authenticated());
    assert_eq!(state.user_id(), Some(&uid("u1")));
    assert_eq!(state.tenant_id(), Some(&tid("t1")));
}

#[test]
fn auth_state_authenticating_is_not_authenticated() {
    let state = AuthState::Authenticating {
        user_id: uid("u1"),
        tenant_id: tid("t1"),
        method_name: "password".into(),
        remaining: vec![],
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
    };
    assert!(state.is_authenticating());
    assert!(!state.is_authenticated());
    assert!(!state.is_guest());
}

// ── Eager session-id rotation ────────────────────────────────────────────────

/// Regression: handler-side `session.session_id().await` after
/// `set_authenticated` must return the **post-rotation** id so callers
/// that register the session against `SessionRegistry` key against the
/// id the cookie will actually carry on the next request.
#[tokio::test]
async fn set_authenticated_rotates_session_id_eagerly() {
    let session = test_session();
    let pre = session.session_id().await;
    session
        .set_authenticated(uid("u1"), tid("t1"), Utc::now())
        .await;
    let post = session.session_id().await;
    assert_ne!(
        pre, post,
        "set_authenticated must rotate session id eagerly"
    );
}

/// Regression: `advance_factor` to the final factor must rotate the id
/// (the transition that flips state to Authenticated).
#[tokio::test]
async fn advance_factor_to_authenticated_rotates_session_id() {
    let session = test_session();
    session
        .begin_authenticating(
            uid("u1"),
            tid("t1"),
            "password".into(),
            vec![FactorKind::Password],
        )
        .await;
    let pre = session.session_id().await;
    session
        .advance_factor(&FactorKind::Password, Utc::now())
        .await;
    let post = session.session_id().await;
    assert!(session.is_authenticated().await);
    assert_ne!(
        pre, post,
        "advance_factor that completes auth must rotate session id"
    );
}

/// Regression: explicit `regenerate()` rotates immediately.
#[tokio::test]
async fn regenerate_rotates_session_id_eagerly() {
    let session = test_session();
    let pre = session.session_id().await;
    session.regenerate().await;
    let post = session.session_id().await;
    assert_ne!(pre, post, "regenerate() must rotate session id");
}

// ── take_custom atomicity ────────────────────────────────────────────────────

/// Regression: `take_custom` reads and removes atomically. A second take
/// must return None even if interleaved with a slow caller.
#[tokio::test]
async fn take_custom_consumes_value_atomically() {
    let session = test_session();
    session
        .set_custom("ceremony", serde_json::json!({"state": "abc"}))
        .await;

    let first = session.take_custom("ceremony").await;
    assert_eq!(first, Some(serde_json::json!({"state": "abc"})));

    // Second take must return None: the value was consumed.
    let second = session.take_custom("ceremony").await;
    assert_eq!(
        second, None,
        "take_custom must remove the value, not just read it"
    );

    // get_custom after take must also see nothing.
    assert_eq!(session.get_custom("ceremony").await, None);
}

/// Regression: parallel `take_custom` racers: only one observes the
/// value. This is the actual replay-protection contract.
#[tokio::test]
async fn take_custom_only_one_racer_wins() {
    let session = test_session();
    session
        .set_custom("ceremony", serde_json::json!("only-once"))
        .await;

    let s1 = session.clone();
    let s2 = session.clone();
    let (a, b) = tokio::join!(
        tokio::spawn(async move { s1.take_custom("ceremony").await }),
        tokio::spawn(async move { s2.take_custom("ceremony").await }),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    // Exactly one must have received the value.
    assert_eq!(
        (a.is_some() as u8) + (b.is_some() as u8),
        1,
        "exactly one racer must observe the ceremony state"
    );
}

// ── SessionData JSON round-trip / WorkflowState ──────────────────────────────

#[test]
fn session_data_json_roundtrip() {
    let data = SessionData {
        version: axess_core::session::data::SESSION_DATA_VERSION,
        auth_state: AuthState::Authenticated {
            user_id: uid("u1"),
            tenant_id: tid("t1"),
            authn_time: Utc::now(),
            factors_completed: vec![],
        },
        fingerprint: Some("abc123".to_string()),
        device_id: None,
        custom: serde_json::json!({"key": "value"}),
    };
    let json = serde_json::to_string(&data).unwrap();
    let restored: SessionData = serde_json::from_str(&json).unwrap();
    assert!(restored.auth_state.is_authenticated());
    assert_eq!(restored.fingerprint.as_deref(), Some("abc123"));
    assert_eq!(restored.custom["key"], "value");
}

#[test]
fn workflow_state_new_sets_step_zero() {
    let ws = WorkflowState::new(WorkflowKind::Signup, 3, Utc::now());
    assert_eq!(ws.current_step, 0);
    assert_eq!(ws.total_steps, 3);
}

// ── Extractor surface ────────────────────────────────────────────────────────

#[tokio::test]
async fn set_authenticated_marks_regenerate() {
    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("t1"), Utc::now())
        .await;
    assert!(session.is_authenticated().await);
    assert_eq!(session.user_id().await, Some(uid("u1")));
}

#[tokio::test]
async fn authenticated_ids_returns_both() {
    let session = test_session();
    assert!(session.authenticated_ids().await.is_none());

    session
        .set_authenticated(uid("u1"), tid("t1"), Utc::now())
        .await;
    let (uid_got, tid_got) = session.authenticated_ids().await.unwrap();
    assert_eq!(uid_got, uid("u1"));
    assert_eq!(tid_got, tid("t1"));
}

#[tokio::test]
async fn advance_factor_removes_first_match_only() {
    let session = test_session();
    session
        .begin_authenticating(
            uid("u1"),
            tid("t1"),
            "test".into(),
            vec![FactorKind::Password, FactorKind::Totp, FactorKind::Password],
        )
        .await;

    session
        .advance_factor(&FactorKind::Password, Utc::now())
        .await;

    // Should have removed only the FIRST Password, leaving [Totp, Password].
    let state = session.auth_state().await;
    if let AuthState::Authenticating { remaining, .. } = state {
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0], FactorKind::Totp);
        assert_eq!(remaining[1], FactorKind::Password);
    } else {
        panic!("expected Authenticating state");
    }
}

#[tokio::test]
async fn advance_factor_transitions_to_authenticated_when_empty() {
    let session = test_session();
    session
        .begin_authenticating(
            uid("u1"),
            tid("t1"),
            "test".into(),
            vec![FactorKind::Password],
        )
        .await;

    session
        .advance_factor(&FactorKind::Password, Utc::now())
        .await;
    assert!(session.is_authenticated().await);
}

#[tokio::test]
async fn clear_resets_to_guest() {
    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("t1"), Utc::now())
        .await;
    assert!(session.is_authenticated().await);

    session.clear().await;
    assert!(session.auth_state().await.is_guest());
}

#[tokio::test]
async fn custom_data_round_trip() {
    let session = test_session();
    session.set_custom("foo", serde_json::json!(42)).await;
    let v = session.get_custom("foo").await;
    assert_eq!(v.unwrap(), serde_json::json!(42));
}

#[tokio::test]
async fn set_pending_workflow() {
    let session = test_session();
    let ws = WorkflowState::new(WorkflowKind::Signup, 3, Utc::now());
    session.set_pending_workflow(uid("u1"), tid("t1"), ws).await;

    let state = session.auth_state().await;
    assert!(matches!(state, AuthState::PendingWorkflow { .. }));
}
