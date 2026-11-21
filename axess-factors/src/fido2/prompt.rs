//! [`DiscoverablePrompt`]: how the browser is asked to present a
//! discoverable login, cross-device authentication included.

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::RequestChallengeResponse;

/// How the browser presents a discoverable (passwordless) login.
///
/// The relying party verifies the same assertion whichever is chosen. The
/// prompt changes only the request options the browser reads (`mediation`,
/// and the WebAuthn Level 3 `hints`), never the ceremony's state or what
/// its finish accepts, so a prompt is a choice of user interface and not of
/// security.
///
/// # Cross-device authentication
///
/// [`CrossDevice`](Self::CrossDevice) is the relying party's whole part in
/// cross-device authentication (the FIDO hybrid transport): the browser
/// shows a QR code, the phone that scans it proves it is nearby over
/// Bluetooth, and the passkey on the phone signs the challenge. The QR code
/// and the Bluetooth link run between the browser and the phone; the
/// relying party sees an ordinary assertion and finishes it as it finishes
/// any discoverable login. Nothing in the assertion that is signed says
/// which transport carried it.
///
/// A hint orders the browser's choices and removes none: a browser that
/// does not read hints shows its usual dialog, where another device is one
/// of the options.
///
/// Written and parsed as `autofill`, `modal` and `cross_device`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverablePrompt {
    /// Conditional mediation: the browser offers the passkeys it knows in
    /// the autofill of a field marked `autocomplete="username webauthn"`
    /// and opens no dialog. What `webauthn-rs` issues, and the default.
    #[default]
    Autofill,
    /// The browser's own dialog, opened at once, for a "sign in with a
    /// passkey" button: it offers every authenticator it can reach.
    Modal,
    /// The dialog, led by another device: the request carries the `hybrid`
    /// hint, so a browser that reads hints opens on the QR code.
    CrossDevice,
}

impl DiscoverablePrompt {
    /// Write this prompt into `challenge`, whatever the provider that began
    /// the ceremony put there: conditional mediation for
    /// [`Autofill`](Self::Autofill) and none for the two dialogs, and the
    /// `hybrid` hint for [`CrossDevice`](Self::CrossDevice). Hints the
    /// provider set are otherwise left as they are.
    pub fn apply(self, challenge: &mut RequestChallengeResponse) {
        // `webauthn-rs` exports neither the mediation nor the hint type;
        // each is read from its wire name, the one the browser reads.
        challenge.mediation = match self {
            Self::Autofill => serde_json::from_value(serde_json::json!("conditional")).ok(),
            Self::Modal | Self::CrossDevice => None,
        };
        if self == Self::CrossDevice {
            challenge.public_key.hints = serde_json::from_value(serde_json::json!(["hybrid"])).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DiscoverablePrompt;
    use url::Url;
    use webauthn_rs::prelude::{RequestChallengeResponse, WebauthnBuilder};

    fn challenge() -> RequestChallengeResponse {
        let origin = Url::parse("https://example.com").unwrap();
        WebauthnBuilder::new("example.com", &origin)
            .unwrap()
            .build()
            .unwrap()
            .start_discoverable_authentication()
            .unwrap()
            .0
    }

    /// The challenge as the browser reads it, once `prompt` is applied.
    fn render(
        prompt: DiscoverablePrompt,
        mut challenge: RequestChallengeResponse,
    ) -> serde_json::Value {
        prompt.apply(&mut challenge);
        serde_json::to_value(challenge).unwrap()
    }

    #[test]
    fn the_default_is_the_autofill_prompt_webauthn_rs_issues() {
        assert_eq!(DiscoverablePrompt::default(), DiscoverablePrompt::Autofill);
        let issued = serde_json::to_value(challenge()).unwrap();
        let prompted = render(DiscoverablePrompt::Autofill, challenge());
        assert_eq!(prompted["mediation"], "conditional");
        assert_eq!(prompted["mediation"], issued["mediation"]);
        assert!(prompted["publicKey"].get("hints").is_none());
    }

    #[test]
    fn autofill_asks_for_conditional_mediation_of_a_provider_that_set_none() {
        let mut bare = challenge();
        bare.mediation = None;
        let prompted = render(DiscoverablePrompt::Autofill, bare);
        assert_eq!(prompted["mediation"], "conditional");
    }

    #[test]
    fn a_modal_prompt_asks_for_no_mediation_and_gives_no_hint() {
        let prompted = render(DiscoverablePrompt::Modal, challenge());
        assert!(prompted.get("mediation").is_none(), "{prompted}");
        assert!(prompted["publicKey"].get("hints").is_none(), "{prompted}");
    }

    #[test]
    fn a_cross_device_prompt_is_a_dialog_hinted_at_the_hybrid_transport() {
        let prompted = render(DiscoverablePrompt::CrossDevice, challenge());
        assert!(prompted.get("mediation").is_none(), "{prompted}");
        assert_eq!(
            prompted["publicKey"]["hints"],
            serde_json::json!(["hybrid"])
        );
    }

    #[test]
    fn a_prompt_changes_nothing_the_assertion_is_verified_against() {
        let issued = challenge();
        let mut changed = issued.clone();
        DiscoverablePrompt::CrossDevice.apply(&mut changed);
        assert_eq!(changed.public_key.challenge, issued.public_key.challenge);
        assert_eq!(changed.public_key.rp_id, issued.public_key.rp_id);
        assert_eq!(
            serde_json::to_value(changed.public_key.user_verification).unwrap(),
            "required"
        );
        assert!(changed.public_key.allow_credentials.is_empty());
    }

    #[test]
    fn a_prompt_is_written_and_parsed_by_its_snake_case_name() {
        for (prompt, name) in [
            (DiscoverablePrompt::Autofill, "autofill"),
            (DiscoverablePrompt::Modal, "modal"),
            (DiscoverablePrompt::CrossDevice, "cross_device"),
        ] {
            assert_eq!(serde_json::to_value(prompt).unwrap(), name);
            let parsed: DiscoverablePrompt = serde_json::from_value(name.into()).unwrap();
            assert_eq!(parsed, prompt);
        }
        assert!(serde_json::from_value::<DiscoverablePrompt>("hybrid".into()).is_err());
    }
}
