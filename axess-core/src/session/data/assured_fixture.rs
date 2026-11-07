//! A session carrying assurance, for the backends' round-trip tests.

use super::*;
use crate::authn::assurance::FactorAssurance;

/// An authenticated session whose record holds a password and an attested,
/// user-verified, device-bound passkey, at fixed whole-second times so every
/// backend's encoding round-trips it exactly.
pub(crate) fn assured_session() -> SessionData {
    let login = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid time");
    let step_up = DateTime::<Utc>::from_timestamp(1_700_000_060, 0).expect("valid time");
    let mut data = SessionData::default();
    data.auth_state.begin_authenticating(
        axess_identity::testing::user("assured"),
        axess_identity::testing::tenant("assured"),
        Arc::from("password+fido2"),
        vec![
            FactorStep::Required(FactorKind::Password),
            FactorStep::Required(FactorKind::Fido2),
        ],
    );
    data.auth_state
        .advance_factor(FactorAssurance::for_kind(FactorKind::Password, login));
    data.auth_state.advance_factor(FactorAssurance::fido2(
        true,
        false,
        false,
        Some(Arc::from("vendor-roots")),
        step_up,
    ));
    assert_eq!(
        data.auth_state.assurance().len(),
        2,
        "fixture holds two proofs"
    );
    data
}
