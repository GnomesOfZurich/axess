//! An `AuthzInstallation` has one way in: `AuthzInstallation::new`.
//!
//! `new` is where a policy store that reads `context` is refused without a
//! context provider. That refusal is worth what the constructor is: were the
//! installation's parts public, an application could write the value out by
//! hand, leave the provider off, and be back at a gate that finds out at the
//! first request. This holds the compiler to refusing that, by its recorded
//! text (`tests/ui/*.stderr`).
//!
//! The gate's side of the same rule (it reads the installation and no
//! separately installed store or provider) is tested where the gate is:
//! `macro_tests.rs` at run time, and the macro crate's own test of what the
//! expansion reads.

#[cfg(feature = "authz")]
#[test]
#[cfg_attr(
    miri,
    ignore = "trybuild runs cargo and the compiler as child processes, which Miri's isolation refuses"
)]
fn an_installation_written_out_by_its_parts_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/authz_installation_without_new.rs");
}
