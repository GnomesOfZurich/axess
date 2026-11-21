//! `EventSubject::Session` holds a `RecordedSessionId`, which only the reader
//! of a stored event produces.
//!
//! A new event names a session by its key. These cases hold the compiler to
//! the three errors that are the guarantee, by their recorded text
//! (`tests/ui/*.stderr`): the private field, a session id where the recorded
//! id is expected, and a conversion that does not exist.
//!
//! No recorded error points into the standard library. rustc prints the
//! source excerpt of such a location only where the `rust-src` component is
//! installed, so the expected text would differ between machines. The
//! conversion case asks for `From<SessionId>` through a bound of its own,
//! and the error points at that bound.

#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_recorded_session_id_is_not_built_from_a_session_id() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/recorded_session_id_private_field.rs");
    cases.compile_fail("tests/ui/recorded_session_id_from_session_id.rs");
    cases.compile_fail("tests/ui/recorded_session_id_conversion.rs");
}
