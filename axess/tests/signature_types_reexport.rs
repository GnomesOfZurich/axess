//! The facade names the types that its own items carry in their public
//! signatures, so an adopter can write them down (a field, a helper's
//! parameter, a match arm's binding) without a direct dependency on the
//! crates beneath.

#[test]
fn the_hotp_lock_state_is_reachable_from_the_facade() {
    // The type of `HotpConfig::throttle`, which a literal fills with
    // `Default::default()`: unlocked, with no locks counted.
    let throttle = axess::authn::HotpThrottle::default();
    assert_eq!(
        format!("{throttle:?}"),
        "HotpThrottle { locked_until: None, lockouts: 0 }"
    );
}

#[test]
fn the_weak_key_refusal_is_reachable_from_the_facade() {
    let refused: Option<axess::session::WeakKeyError> = None;
    assert!(refused.is_none());
}

// The umbrella `delegated` turns on the facade's own `delegated` module.
#[cfg(any(
    feature = "delegated",
    feature = "delegated-stored",
    feature = "delegated-exchange"
))]
#[test]
fn the_client_build_cause_is_reachable_from_the_facade() {
    fn cause(
        error: &axess::delegated::error::DelegatedError,
    ) -> Option<&axess::delegated::ClientBuildError> {
        match error {
            axess::delegated::error::DelegatedError::ClientBuild(cause) => Some(cause),
            _ => None,
        }
    }
    assert!(cause(&axess::delegated::error::DelegatedError::NotConnected).is_none());
}

// The umbrella `cloud-sts` turns on the facade's own STS features.
#[cfg(any(
    feature = "cloud-sts",
    feature = "aws-sts",
    feature = "azure-fic",
    feature = "gcp-wif"
))]
#[test]
fn the_sts_client_build_cause_is_reachable_from_the_facade() {
    let cause: Option<&axess::workload::ClientBuildError> = None;
    assert!(cause.is_none());
}

// `fapi` is an alias for `oauth`: the profile's types come with `oauth`.
#[cfg(feature = "oauth")]
#[test]
fn the_fapi_profile_types_come_with_oauth() {
    let config = axess::federation::oauth::FapiConfig::default();
    assert!(matches!(
        config.sender_constraint,
        axess::federation::oauth::SenderConstraint::DPoP
    ));
}
