//! `Issuer::Custom` is built only through `Issuer::custom`.
//!
//! The variant holds a `CustomLabel` whose field is private, so a label the
//! constructor would refuse (a built-in issuer's wire string, a bad format)
//! cannot be written out by hand. A `compile_fail` doctest passes on any
//! compile error; these cases hold the compiler to the two errors that are
//! the guarantee, one for a string where the label type is expected and one
//! for the private field, by their recorded text (`tests/ui/*.stderr`).

#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn the_custom_variant_is_built_only_through_the_constructor() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/issuer_custom_string.rs");
    cases.compile_fail("tests/ui/issuer_custom_label.rs");
}
