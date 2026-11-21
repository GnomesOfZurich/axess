//! The FIDO2 option defaults: a credential change needs an authentication
//! from the last five minutes unless the adopter names the opt-out.

use super::*;

#[test]
fn a_credential_change_needs_a_recent_authentication_by_default() {
    assert_eq!(
        Fido2Options::default().max_authn_age,
        Some(std::time::Duration::from_secs(5 * 60)),
        "the default passkey-change recency is five minutes"
    );
    assert_eq!(
        Fido2Options::default().max_authn_age,
        Some(DEFAULT_FIDO2_MAX_AUTHN_AGE)
    );
}

#[test]
fn the_opt_out_is_named() {
    let options = Fido2Options {
        max_authn_age: None,
        ..Fido2Options::default()
    };
    assert_eq!(options.max_authn_age, None);
    assert_eq!(
        options.ceremony_timeout,
        std::time::Duration::from_secs(300)
    );
}
