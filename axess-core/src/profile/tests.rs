//! The device-key lifetimes a profile applies: the shorter of the
//! configuration's own and the profile's, never the policy.

use super::*;
use crate::device_key::{DeviceKeyConfig, KeyBindingPolicy};

/// `Standard` restates the defaults and changes nothing; `Strict` halves
/// both lifetimes; neither touches the policy, and both produce a
/// configuration the service accepts.
#[test]
fn the_profiles_set_the_device_key_lifetimes_and_never_the_policy() {
    let base = DeviceKeyConfig::new("https://app.example");
    let standard = SecurityProfile::Standard
        .values()
        .device_key_config(base.clone());
    assert_eq!(standard.proof_ttl(), base.proof_ttl());
    assert_eq!(standard.challenge_ttl(), base.challenge_ttl());

    let strict = SecurityProfile::Strict
        .values()
        .device_key_config(base.clone());
    assert_eq!(strict.proof_ttl(), Duration::from_secs(5 * MINUTE));
    assert_eq!(strict.challenge_ttl(), Duration::from_secs(10 * MINUTE));
    assert_eq!(strict.validate(), Ok(()));

    let preferred = base.with_policy(KeyBindingPolicy::Off);
    let kept = SecurityProfile::Strict
        .values()
        .device_key_config(preferred);
    assert_eq!(kept.policy(), KeyBindingPolicy::Off);
}

/// Lifetimes the adopter shortened below both profiles' survive either
/// profile: the proof cookie is not made to live longer than the adopter
/// set it, and the result is still a configuration the service accepts.
#[test]
fn shorter_device_key_lifetimes_survive_either_profile() {
    let tight = DeviceKeyConfig::new("https://app.example")
        .with_proof_ttl(Duration::from_secs(2 * MINUTE))
        .with_challenge_ttl(Duration::from_secs(4 * MINUTE));
    assert_eq!(tight.validate(), Ok(()));
    for profile in [SecurityProfile::Standard, SecurityProfile::Strict] {
        let applied = profile.values().device_key_config(tight.clone());
        assert_eq!(
            applied.proof_ttl(),
            Duration::from_secs(2 * MINUTE),
            "{profile:?} lengthened the proof lifetime"
        );
        assert_eq!(
            applied.challenge_ttl(),
            Duration::from_secs(4 * MINUTE),
            "{profile:?} lengthened the challenge lifetime"
        );
        assert_eq!(applied.validate(), Ok(()));
    }
}

/// Each lifetime is taken on its own: a shorter proof lifetime on the
/// configuration and a shorter challenge lifetime in the profile give the
/// configuration's proof and the profile's challenge.
#[test]
fn each_device_key_lifetime_is_the_shorter_on_its_own() {
    let base = DeviceKeyConfig::new("https://app.example")
        .with_proof_ttl(Duration::from_secs(2 * MINUTE))
        .with_challenge_ttl(Duration::from_secs(HOUR));
    let applied = SecurityProfile::Strict.values().device_key_config(base);
    assert_eq!(applied.proof_ttl(), Duration::from_secs(2 * MINUTE));
    assert_eq!(applied.challenge_ttl(), Duration::from_secs(10 * MINUTE));
    assert_eq!(applied.validate(), Ok(()));
}

/// A profile pair that leaves no room for the configuration's acceptance
/// grace is not stretched to fit: the result is refused by the check the
/// service runs, on the challenge lifetime, and the grace is kept.
#[test]
fn a_profile_pair_without_room_for_the_grace_is_refused_not_stretched() {
    let grace = DeviceKeyConfig::MAX_ACCEPTANCE_GRACE;
    let base = DeviceKeyConfig::new("https://app.example").with_acceptance_grace(grace);
    assert_eq!(base.validate(), Ok(()));
    let applied = SecurityProfile::Strict.values().device_key_config(base);
    assert_eq!(applied.proof_ttl(), Duration::from_secs(5 * MINUTE));
    assert_eq!(applied.challenge_ttl(), Duration::from_secs(10 * MINUTE));
    assert_eq!(applied.acceptance_grace(), grace);
    assert_eq!(
        applied.validate().err().map(|refused| refused.setting),
        Some("challenge_ttl")
    );
}
