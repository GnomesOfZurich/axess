//! The two times of a signed-in state: `signed_in_at`, when the login that
//! created the session completed, and `authn_time`, when the person last
//! proved presence. A step-up moves the second and keeps the first, a stored
//! row keeps both, and a row stored before the first existed reads it from
//! what the row records.

#![cfg(test)]

use super::*;
use axess_clock::testing::Shift;

fn at(minutes: i64) -> Timestamp {
    axess_clock::testing::MockClock::reference_time().plus(axess_clock::SignedDuration::minutes(
        i32::try_from(minutes).unwrap(),
    ))
}

fn times(state: &AuthState) -> (Timestamp, Timestamp) {
    match state {
        AuthState::Authenticated {
            signed_in_at,
            authn_time,
            ..
        } => (*signed_in_at, *authn_time),
        other => panic!("expected a signed-in state, got {other:?}"),
    }
}

/// Signed in at minute 0 and stepped up with a TOTP code at minute 50.
fn stepped_up() -> AuthState {
    let mut state = AuthState::Guest;
    state.set_authenticated(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        at(0),
    );
    assert!(state.begin_step_up(vec![FactorStep::Required(FactorKind::Totp)]));
    let outcome = state.advance_factor(FactorAssurance::for_kind(FactorKind::Totp, at(50)));
    assert_eq!(outcome, AdvanceOutcome::Completed);
    state
}

#[test]
fn a_step_up_keeps_the_login_and_moves_the_authentication_time() {
    assert_eq!(times(&stepped_up()), (at(0), at(50)));
}

/// The stored login time is read back as stored, in JSON and in the
/// MessagePack the stores write, also when the row's factors would say
/// otherwise.
#[test]
fn a_signed_in_row_round_trips_its_login_time() {
    let state = stepped_up();
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["signed_in_at"], serde_json::json!(at(0)));
    let mut row = json.clone();
    row["factors_completed"] = serde_json::json!([]);
    let read: AuthState = serde_json::from_value(row).unwrap();
    assert_eq!(
        times(&read),
        (at(0), at(50)),
        "the stored login, not a guess"
    );

    let packed = rmp_serde::to_vec_named(&state).unwrap();
    let read: AuthState = rmp_serde::from_slice(&packed).unwrap();
    assert_eq!(read, state);
}

/// A login time handed over from another state (an impersonation keeps the
/// administrator's) never lands after the state's own `authn_time`.
#[test]
fn a_kept_login_time_is_never_after_the_authentication_time() {
    let mut state = AuthState::Guest;
    state.set_authenticated(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        at(10),
    );
    assert!(state.keep_signed_in_at(at(0)));
    assert_eq!(times(&state), (at(0), at(10)));
    assert!(state.keep_signed_in_at(at(30)));
    assert_eq!(times(&state), (at(10), at(10)));
    assert!(!AuthState::Guest.keep_signed_in_at(at(0)));
}
