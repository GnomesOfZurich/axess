//! `OAUTH_PROVISIONING` accepts the two policies and nothing else: a typo
//! must not silently turn on creating users.

use axess_example_oauth::provisioning::Provisioning;

#[test]
fn the_two_policies_parse_and_unset_is_linked_only() {
    assert_eq!(
        Provisioning::from_setting(None),
        Ok(Provisioning::LinkedOnly)
    );
    assert_eq!(
        Provisioning::from_setting(Some("just-in-time")),
        Ok(Provisioning::JustInTime)
    );
    assert_eq!(
        Provisioning::from_setting(Some("linked-only")),
        Ok(Provisioning::LinkedOnly)
    );
}

#[test]
fn an_unknown_value_is_refused() {
    for typo in ["linked_only", "Linked-Only", "linkedonly", "", "off"] {
        assert!(
            Provisioning::from_setting(Some(typo)).is_err(),
            "{typo:?} was accepted"
        );
    }
}

/// A value the environment holds but cannot read as text is a setting that
/// was given and is wrong, not one that was never given: it must not fall
/// back to creating users.
#[test]
fn an_unreadable_value_is_refused_and_an_unset_one_is_not() {
    use std::env::VarError;
    assert_eq!(
        Provisioning::from_env(Err(VarError::NotPresent)),
        Ok(Provisioning::LinkedOnly)
    );
    assert_eq!(
        Provisioning::from_env(Ok("linked-only".to_string())),
        Ok(Provisioning::LinkedOnly)
    );
    assert!(
        Provisioning::from_env(Err(VarError::NotUnicode(std::ffi::OsString::from("x")))).is_err()
    );
}

/// An unset `OAUTH_ID_TOKEN_ALGS` pins the registered default instead of
/// accepting every algorithm the provider advertises.
#[test]
fn id_token_algorithms_default_to_rs256() {
    use axess_example_oauth::app::id_token_algs_from_setting as algs;
    assert_eq!(algs(None), ["RS256"]);
    assert_eq!(algs(Some("")), ["RS256"]);
    assert_eq!(algs(Some(" , ")), ["RS256"]);
    assert_eq!(algs(Some("ES256, PS256")), ["ES256", "PS256"]);
}
