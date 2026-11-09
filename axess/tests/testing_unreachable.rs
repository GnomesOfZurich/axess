//! A build without the `testing` feature has no `axess::testing`.
//!
//! The test doubles (deterministic clocks and random sources, mock stores,
//! constructors that skip key checks) live behind the feature so a release
//! build does not link them. This compiles a small program that names the
//! module and expects the compiler to refuse it. It is compiled only when the
//! feature is off, because with it on the module exists and the program
//! compiles; run it without `--all-features`.

#[cfg(not(feature = "testing"))]
#[test]
fn the_testing_module_is_unreachable_without_the_feature() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/testing_unreachable.rs");
}
