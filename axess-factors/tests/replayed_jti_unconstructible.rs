//! `JtiReplayError::AlreadyUsed` carries a key only as
//! `JtiReplayError::already_used` escaped and cut it.
//!
//! The variant holds a `ReplayedJti` whose field is private, so a key as the
//! token wrote it cannot be put into the error by hand. A `compile_fail`
//! doctest passes on any compile error, and on this toolchain does not check
//! the error code it names; these cases hold the compiler to the two errors
//! that are the guarantee, one for a string where the key type is expected
//! and one for the private field, by their recorded text
//! (`tests/ui/*.stderr`).

#![cfg(feature = "jwt")]

#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_replayed_key_is_built_only_through_already_used() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/replayed_jti_from_string.rs");
    cases.compile_fail("tests/ui/replayed_jti_private_field.rs");
}
