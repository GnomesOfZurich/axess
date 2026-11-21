//! [`DiscoverableCredential`]: whether a registration asks the
//! authenticator to store the credential it creates.

use super::Fido2Ceremony;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::CreationChallengeResponse;

/// Whether a passkey registration asks the authenticator to store the
/// credential it creates: a discoverable credential, which names its user
/// and so can sign in with no username (the passwordless login,
/// `begin_discoverable_login`).
///
/// It is [`Fido2Options::discoverable_credential`](super::Fido2Options::discoverable_credential)
/// and applies to the passkey and attested-passkey ceremonies. A security
/// key is a non-discoverable credential by definition, so the security-key
/// ceremony's challenge is left as `webauthn-rs` issues it.
///
/// The choice reaches the authenticator as the challenge's
/// `authenticatorSelection.residentKey` (and `requireResidentKey`). Nothing
/// the finish verifies changes: the browser enforces `required`, and the
/// stored credential is the passkey the ceremony registers whatever the
/// choice.
///
/// Written and parsed as `discouraged`, `preferred` and `required`, the
/// WebAuthn names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverableCredential {
    /// Leave it to the authenticator, as `webauthn-rs` asks: a passkey it
    /// does not store signs in only after a username. The default, which
    /// spares the few slots a hardware key has for stored credentials.
    #[default]
    Discouraged,
    /// Ask the authenticator to store the credential when it can; one that
    /// cannot still registers a credential that needs a username.
    Preferred,
    /// Require a stored credential: an authenticator that cannot store one
    /// fails the registration in the browser, so every passkey registered
    /// can sign in with no username. What a passkey meant for the
    /// passwordless login needs, whatever the authenticator.
    Required,
}

impl DiscoverableCredential {
    /// Write this choice into the registration `challenge` that `ceremony`
    /// began. [`Discouraged`](Self::Discouraged), and any security-key
    /// ceremony, leave the challenge as the provider issued it.
    pub fn apply(self, ceremony: &Fido2Ceremony, challenge: &mut CreationChallengeResponse) {
        let (wire, required) = match self {
            Self::Discouraged => return,
            Self::Preferred => ("preferred", false),
            Self::Required => ("required", true),
        };
        if matches!(ceremony, Fido2Ceremony::SecurityKey(_)) {
            return;
        }
        let selection = challenge
            .public_key
            .authenticator_selection
            .get_or_insert_with(Default::default);
        // `webauthn-rs` does not export the requirement type; it is read
        // from its wire name, the one the browser reads.
        selection.resident_key = serde_json::from_value(serde_json::json!(wire)).ok();
        selection.require_resident_key = required;
    }
}

#[cfg(test)]
mod tests {
    use super::DiscoverableCredential;
    use crate::fido2::{
        DefaultFido2Provider, Fido2Ceremony, Fido2Provider, SecurityKeyVerification,
    };
    use url::Url;
    use webauthn_rs::prelude::{Uuid, WebauthnBuilder};

    fn provider() -> DefaultFido2Provider {
        let origin = Url::parse("https://example.com").unwrap();
        DefaultFido2Provider::new(
            WebauthnBuilder::new("example.com", &origin)
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    /// The `authenticatorSelection` of `ceremony`'s registration challenge
    /// once `choice` is applied, which leaves the challenge bytes alone.
    fn selection(choice: DiscoverableCredential, ceremony: &Fido2Ceremony) -> serde_json::Value {
        let (mut challenge, _) = provider()
            .start_registration(ceremony, Uuid::nil(), "alice", "Alice", None)
            .expect("registration starts");
        let issued = challenge.public_key.challenge.clone();
        choice.apply(ceremony, &mut challenge);
        assert_eq!(
            challenge.public_key.challenge, issued,
            "the challenge is the one issued"
        );
        serde_json::to_value(&challenge).unwrap()["publicKey"]["authenticatorSelection"].clone()
    }

    #[test]
    fn the_default_leaves_the_passkey_challenge_as_webauthn_rs_issues_it() {
        assert_eq!(
            DiscoverableCredential::default(),
            DiscoverableCredential::Discouraged
        );
        let selection = selection(DiscoverableCredential::Discouraged, &Fido2Ceremony::Passkey);
        assert_eq!(selection["residentKey"], "discouraged");
        assert_eq!(selection["requireResidentKey"], false);
        assert_eq!(selection["userVerification"], "required");
    }

    #[test]
    fn required_asks_the_authenticator_to_store_the_passkey() {
        let selection = selection(DiscoverableCredential::Required, &Fido2Ceremony::Passkey);
        assert_eq!(selection["residentKey"], "required");
        assert_eq!(selection["requireResidentKey"], true);
        assert_eq!(
            selection["userVerification"], "required",
            "user verification is the ceremony's, unchanged"
        );
    }

    #[test]
    fn preferred_asks_without_requiring() {
        let selection = selection(DiscoverableCredential::Preferred, &Fido2Ceremony::Passkey);
        assert_eq!(selection["residentKey"], "preferred");
        assert_eq!(selection["requireResidentKey"], false);
    }

    #[test]
    fn a_security_key_stays_a_non_discoverable_credential() {
        let ceremony = Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred);
        let selection = selection(DiscoverableCredential::Required, &ceremony);
        assert_eq!(selection["residentKey"], "discouraged");
        assert_eq!(selection["requireResidentKey"], false);
    }

    #[test]
    fn a_choice_is_written_and_parsed_by_its_webauthn_name() {
        for (choice, name) in [
            (DiscoverableCredential::Discouraged, "discouraged"),
            (DiscoverableCredential::Preferred, "preferred"),
            (DiscoverableCredential::Required, "required"),
        ] {
            assert_eq!(serde_json::to_value(choice).unwrap(), name);
            let parsed: DiscoverableCredential = serde_json::from_value(name.into()).unwrap();
            assert_eq!(parsed, choice);
        }
    }
}
