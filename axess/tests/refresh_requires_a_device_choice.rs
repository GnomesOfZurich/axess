//! A `Refresh` cannot run until it has said what it does about the device a
//! token names.
//!
//! A token may name a device, and a refresh that never looks at it refreshes
//! a revoked device's token and builds an unbound session for a device that
//! holds a key. So the choice has no default: the refresh is given the
//! device store (`Refresh::device_store`), or the caller writes the opt-out
//! by name (`Refresh::without_device_check`). This holds the compiler to
//! refusing a refresh that says neither, by its recorded text
//! (`tests/ui/*.stderr`).

#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_refresh_that_says_nothing_about_devices_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/refresh_without_device_choice.rs");
}
