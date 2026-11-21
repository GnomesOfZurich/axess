//! [`AuthFlow`]: what opens a login and what opens a step-up, and how each
//! is stored.

#![cfg(test)]

use super::*;

fn user_and_tenant() -> (UserId, TenantId) {
    (
        axess_identity::testing::user("u1"),
        axess_identity::testing::tenant("t1"),
    )
}

fn at_reference() -> Timestamp {
    axess_clock::testing::MockClock::reference_time()
}

/// A login in progress under the method `method`.
fn login_under(method: &str) -> AuthState {
    let (user, tenant) = user_and_tenant();
    let mut state = AuthState::Guest;
    state.begin_authenticating(
        user,
        tenant,
        method.into(),
        vec![FactorStep::Required(FactorKind::Password)],
    );
    state
}

/// A step-up in progress: a signed-in session asked for a TOTP code.
fn step_up() -> AuthState {
    let (user, tenant) = user_and_tenant();
    let mut state = AuthState::Guest;
    state.set_authenticated(user, tenant, at_reference());
    assert!(state.begin_step_up(vec![FactorStep::Required(FactorKind::Totp)]));
    state
}

fn flow_of(state: &AuthState) -> Option<AuthFlow> {
    match state {
        AuthState::Authenticating { flow, .. } => Some(*flow),
        _ => None,
    }
}

#[test]
fn a_login_is_opened_as_a_login_and_a_step_up_as_a_step_up() {
    assert_eq!(flow_of(&login_under("password")), Some(AuthFlow::Login));
    assert_eq!(
        flow_of(&step_up()),
        Some(AuthFlow::StepUp {
            signed_in_at: at_reference()
        }),
        "a step-up carries the login time of the session it began from"
    );
}

/// The name a method carries decides nothing: a login under a method named
/// as a step-up is labelled is a login.
#[test]
fn a_login_under_a_method_named_as_the_step_up_label_is_a_login() {
    assert_eq!(flow_of(&login_under(STEP_UP_LABEL)), Some(AuthFlow::Login));
}

/// A login and a step-up are each stored with their flow, and read back as
/// what they are; a pending state without it is not read.
#[test]
fn each_is_stored_with_its_flow() {
    let login = serde_json::to_value(login_under("password")).unwrap();
    assert_eq!(login["flow"], serde_json::json!("login"), "{login}");
    assert_eq!(
        serde_json::from_value::<AuthState>(login).unwrap(),
        login_under("password")
    );

    let stored = serde_json::to_value(step_up()).unwrap();
    assert_eq!(
        stored["flow"],
        serde_json::json!({ "step_up": { "signed_in_at": at_reference() } })
    );
    assert_eq!(
        serde_json::from_value::<AuthState>(stored.clone()).unwrap(),
        step_up()
    );

    let mut unmarked = stored;
    unmarked.as_object_mut().unwrap().remove("flow");
    assert!(serde_json::from_value::<AuthState>(unmarked).is_err());
}

/// The stores write MessagePack: a step-up stored in it reads back as one,
/// with its flow.
#[test]
fn a_step_up_round_trips_through_message_pack() {
    let current = SessionData {
        auth_state: step_up(),
        ..SessionData::default()
    };
    let bytes = rmp_serde::to_vec_named(&current).expect("encode");
    let read: SessionData = rmp_serde::from_slice(&bytes).expect("decode");
    assert_eq!(read.auth_state, step_up());
    assert_eq!(
        flow_of(&read.auth_state),
        Some(AuthFlow::StepUp {
            signed_in_at: at_reference()
        })
    );
}

/// The label is an ordinary method name: a login and a step-up stored at
/// the current version both read back, each as what it is.
#[test]
fn a_current_row_is_kept_whatever_its_method_is_called() {
    for state in [login_under(STEP_UP_LABEL), step_up()] {
        let data = SessionData {
            auth_state: state.clone(),
            ..SessionData::default()
        };
        assert_eq!(data.version, SESSION_DATA_VERSION);
        let row = serde_json::to_value(&data).unwrap();
        let read: SessionData = serde_json::from_value(row).unwrap();
        assert_eq!(read.auth_state, state);
    }
}
