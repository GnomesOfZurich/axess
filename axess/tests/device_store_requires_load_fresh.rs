//! A `DeviceStore` cannot leave `load_fresh` or one of its three conditional
//! writes out.
//!
//! `load_fresh` reads past any cache, and the revocation checks rest on it.
//! Were it a provided method that fell back to `load`, a store wrapped
//! around a cache would answer those checks from the cached row and
//! compile all the same.
//!
//! `replace_bindings`, `set_trust_level_if` and `claim_owner` are
//! compare-and-set operations. Were they provided methods, their bodies
//! could only be a load followed by a write, and a store that left one out
//! would compile into one where two concurrent callers both succeed: a lost
//! binding, a promotion written over a revocation, a device with two users
//! told they own it. Device keys rest on `replace_bindings` being one
//! compare-and-swap: a load-and-save body would let two refreshes with one
//! proof both win.
//!
//! Each case holds the compiler to the one error that is the guarantee: a
//! store that implements every other required method and is refused for
//! the missing one, by its recorded text (`tests/ui/*.stderr`).

#[cfg(feature = "device")]
#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_store_that_leaves_load_fresh_out_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/device_store_without_load_fresh.rs");
}

#[cfg(feature = "device")]
#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_store_that_leaves_replace_bindings_out_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/device_store_without_replace_bindings.rs");
}

#[cfg(feature = "device")]
#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_store_that_leaves_set_trust_level_if_out_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/device_store_without_set_trust_level_if.rs");
}

#[cfg(feature = "device")]
#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn a_store_that_leaves_claim_owner_out_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/device_store_without_claim_owner.rs");
}
