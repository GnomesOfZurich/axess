//! What a secret read from the environment means: unset leaves the route
//! unconfigured, set but not UTF-8 is refused by name.

use super::*;
use std::env::VarError;

const LONG_ENOUGH: &str = "env-secret-0123456789abcdef0123456789";

#[test]
fn an_unset_variable_leaves_the_route_unconfigured() {
    let loaded =
        ServiceSecret::from_env_value("intake".into(), "INTAKE_SECRET", Err(VarError::NotPresent))
            .expect("unset is not an error");

    assert!(loaded.is_none());
}

#[test]
fn a_set_variable_is_the_secret() {
    let loaded =
        ServiceSecret::from_env_value("intake".into(), "INTAKE_SECRET", Ok(LONG_ENOUGH.to_owned()))
            .expect("a long enough secret")
            .expect("set");

    assert_eq!(loaded.name(), "intake");
}

/// A value that is not UTF-8 cannot be the secret it was meant to be; it is
/// refused by name, not read as an absent variable that leaves the route
/// answering `404` in silence.
#[cfg(unix)]
#[test]
fn a_set_but_non_utf8_variable_is_refused_by_name() {
    use std::os::unix::ffi::OsStringExt;
    let garbage = std::ffi::OsString::from_vec(vec![0xff, 0xfe, b'x']);

    let err = ServiceSecret::from_env_value(
        "intake".into(),
        "INTAKE_SECRET",
        Err(VarError::NotUnicode(garbage)),
    )
    .expect_err("a variable that is set but not UTF-8 is refused");

    assert!(
        matches!(&err, ServiceSecretError::NotUnicode { name, var } if name == "intake" && var == "INTAKE_SECRET"),
        "{err:?}"
    );
    assert!(err.to_string().contains("not valid UTF-8"), "{err}");
}

/// `from_env` reads the process environment itself, so it is exercised on a
/// variable every `cargo test` process is given: `CARGO_PKG_DESCRIPTION`,
/// whose value the test also knows at compile time through `env!`. The
/// `_FILE` form of that name is asserted unset first, so a shell that sets
/// it is named as the cause rather than read as a broken loader.
#[test]
fn a_variable_of_the_process_is_read_as_the_secret() {
    assert!(
        std::env::var_os("CARGO_PKG_DESCRIPTION_FILE").is_none(),
        "CARGO_PKG_DESCRIPTION_FILE is set in this shell; unset it to run this test"
    );
    let expected = env!("CARGO_PKG_DESCRIPTION").trim();
    assert!(
        expected.len() >= MIN_SECRET_LEN,
        "the crate description is the fixture and must be long enough"
    );

    let loaded = ServiceSecret::from_env("relay", "CARGO_PKG_DESCRIPTION")
        .expect("the description is long enough to be a secret")
        .expect("cargo sets the variable for every test process");

    assert_eq!(loaded.name(), "relay");
    let caller = ServiceSecrets::new()
        .with(loaded)
        .identify(expected.as_bytes())
        .expect("the loaded secret is the variable's value");
    assert_eq!(caller.name(), "relay");
}
