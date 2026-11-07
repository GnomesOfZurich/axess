//! The assurance record rides the authenticated state: carried through a
//! step-up, replaced per kind, dropped by a new login, absent from a session
//! written before it existed, and not written when empty.

use super::assured_fixture::assured_session;
use super::*;
use crate::authn::assurance::{CredentialBinding, FactorAssurance};

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000 + seconds, 0).expect("valid time")
}

fn login(kinds: Vec<FactorKind>) -> AuthState {
    let mut state = AuthState::Guest;
    state.begin_authenticating(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        Arc::from("method"),
        kinds.into_iter().map(FactorStep::Required).collect(),
    );
    state
}

#[test]
fn a_step_up_keeps_the_logins_proofs_and_replaces_the_kind_it_verifies_again() {
    let mut state = login(vec![FactorKind::Password, FactorKind::Fido2]);
    state.advance_factor(FactorAssurance::for_kind(FactorKind::Password, at(0)));
    state.advance_factor(FactorAssurance::fido2(true, true, true, None, at(1)));
    assert!(state.is_authenticated());

    assert!(state.begin_step_up(vec![FactorStep::Required(FactorKind::Fido2)]));
    assert!(
        state.assurance().is_empty(),
        "mid step-up the session is not authenticated and asserts nothing"
    );
    state.advance_factor(FactorAssurance::fido2(true, false, false, None, at(60)));

    let record = state.assurance();
    assert_eq!(record.len(), 2);
    assert_eq!(record[0].kind, FactorKind::Password);
    assert_eq!(record[0].at, at(0), "the login's password proof is kept");
    assert_eq!(record[1].kind, FactorKind::Fido2);
    assert_eq!(record[1].at, at(60));
    assert_eq!(
        record[1].credential,
        CredentialBinding::DeviceBound,
        "the step-up's passkey replaced the synced one"
    );
}

#[test]
fn a_factor_the_step_does_not_accept_records_nothing() {
    let mut state = login(vec![FactorKind::Password, FactorKind::Totp]);
    state.advance_factor(FactorAssurance::fido2(true, false, false, None, at(0)));
    state.advance_factor(FactorAssurance::for_kind(FactorKind::Password, at(1)));
    state.advance_factor(FactorAssurance::for_kind(FactorKind::Totp, at(2)));
    let kinds: Vec<_> = state.assurance().iter().map(|p| p.kind.clone()).collect();
    assert_eq!(kinds, vec![FactorKind::Password, FactorKind::Totp]);
}

#[test]
fn a_new_login_drops_the_record() {
    let mut state = assured_session().auth_state;
    assert!(!state.assurance().is_empty());
    state.begin_authenticating(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        Arc::from("password"),
        vec![FactorStep::Required(FactorKind::Password)],
    );
    state.advance_factor(FactorAssurance::for_kind(FactorKind::Password, at(5)));
    assert_eq!(state.assurance().len(), 1, "only the new login's proof");
}

#[test]
fn a_session_written_before_the_record_existed_reads_with_none() {
    let stored = serde_json::json!({
        "kind": "Authenticated",
        "user_id": axess_identity::testing::user("old"),
        "tenant_id": axess_identity::testing::tenant("old"),
        "authn_time": at(0),
        "factors_completed": [["Fido2", at(0)]],
    });
    let state: AuthState = serde_json::from_value(stored).expect("a 0.17 session reads");
    assert!(state.is_authenticated());
    assert_eq!(
        state.factor_completed_at(&FactorKind::Fido2),
        Some(at(0)),
        "its factors are kept"
    );
    assert!(
        state.assurance().is_empty(),
        "but nothing it proved is invented"
    );
}

#[test]
fn an_empty_record_is_not_written_and_a_full_one_round_trips() {
    let mut empty = AuthState::Guest;
    empty.set_authenticated(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        at(0),
    );
    let json = serde_json::to_value(&empty).unwrap();
    assert!(json.get("assurance").is_none(), "no bytes for no proof");

    let data = assured_session();
    let packed = rmp_serde::to_vec_named(&data).expect("encode");
    let back: SessionData = rmp_serde::from_slice(&packed).expect("decode");
    assert_eq!(back.auth_state, data.auth_state);
    assert_eq!(
        back.auth_state.assurance()[1].trust_anchor.as_deref(),
        Some("vendor-roots")
    );
}

#[test]
fn a_federated_login_records_its_provider_without_user_verification() {
    let mut state = AuthState::Guest;
    let proof = FactorAssurance::for_kind(
        FactorKind::Federated(crate::authn::factor::FederatedProvider::Custom(
            "idp".into(),
        )),
        at(0),
    );
    state.set_authenticated_with(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        at(0),
        Some(proof.clone()),
    );
    assert_eq!(state.assurance(), &[proof]);
    assert!(!state.assurance()[0].user_verified);
}
