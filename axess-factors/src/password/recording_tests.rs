//! The record of the Argon2 parameters each password operation ran under:
//! a hash notes the cost it ran, a verification the cost its stored hash
//! carries, and taking the record empties it.

use super::*;

const SALT: [u8; PASSWORD_SALT_LEN] = [7; PASSWORD_SALT_LEN];

/// The pinned parameters as the record writes them.
const PINNED: recording::Parameters = (ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST);

#[test]
fn a_hash_is_recorded_under_the_cost_it_ran_and_taking_empties_the_record() {
    let _ = recording::take_runs();

    let _ = hash_password_with_salt("correct horse", &SALT);

    assert_eq!(recording::take_runs(), vec![PINNED]);
    assert!(recording::take_runs().is_empty());
}

#[test]
fn a_verification_is_recorded_under_the_cost_its_hash_carries() {
    let hash = hash_password_with_salt("correct horse", &SALT);
    let _ = recording::take_runs();

    verify_password("correct horse", &hash).expect("the password matches");

    assert_eq!(recording::take_runs(), vec![PINNED]);
}

#[test]
fn a_verification_against_a_hash_that_does_not_parse_is_recorded_as_zeroes() {
    let _ = recording::take_runs();

    assert_eq!(
        verify_password("correct horse", "not a hash"),
        Err(PasswordVerifyError::Malformed)
    );

    assert_eq!(recording::take_runs(), vec![(0, 0, 0)]);
}
