//! The two forms a one-time-password secret takes at rest.
//!
//! A [`FactorSecret`] is either the plain base32 text an enrolment produced
//! or a [`SealedFactorSecret`], the same text encrypted with AES-256-GCM and
//! bound to the row it belongs to. This crate only defines the shapes; the
//! cipher that produces and opens them lives in `axess-core`
//! (`FactorSecretCipher`), because only the service knows the tenant, user
//! and factor a secret is bound to.
//!
//! The plain form serialises as the bare string, exactly as before, so a row
//! written by an earlier release still loads. A sealed secret serialises as an
//! object, which is how the two are told apart on the way back in.

use crate::secret::ZeroizedString;
use serde::{Deserialize, Serialize};

/// An encrypted OTP secret: the output of a factor-secret cipher.
///
/// `nonce` and `ciphertext` are base64url without padding. `key_id` names the
/// key that sealed it, so a rotation can tell the current key from the
/// previous one without trying both. None of the three is secret on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedFactorSecret {
    /// Fingerprint of the key that sealed this secret.
    pub key_id: String,
    /// The 96-bit AES-GCM nonce, base64url without padding.
    pub nonce: String,
    /// The ciphertext with its authentication tag, base64url without padding.
    pub ciphertext: String,
}

/// An OTP shared secret, plain or sealed.
///
/// Zeroized in memory when plain and redacted in `Debug`. Serialises as the
/// bare string when plain and as an object when sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FactorSecret {
    /// The secret as text. It is written to the store as it stands.
    Plain(ZeroizedString),
    /// The secret encrypted and bound to its row.
    Sealed(SealedFactorSecret),
}

impl FactorSecret {
    /// The secret text, or `None` while it is still sealed.
    pub fn plain(&self) -> Option<&str> {
        match self {
            FactorSecret::Plain(secret) => Some(secret),
            FactorSecret::Sealed(_) => None,
        }
    }

    /// Whether this secret is held in its sealed form.
    pub fn is_sealed(&self) -> bool {
        matches!(self, FactorSecret::Sealed(_))
    }
}

impl From<ZeroizedString> for FactorSecret {
    fn from(secret: ZeroizedString) -> Self {
        FactorSecret::Plain(secret)
    }
}

impl From<String> for FactorSecret {
    fn from(secret: String) -> Self {
        FactorSecret::Plain(ZeroizedString::new(secret))
    }
}

impl From<&str> for FactorSecret {
    fn from(secret: &str) -> Self {
        FactorSecret::Plain(ZeroizedString::new(secret))
    }
}

impl From<SealedFactorSecret> for FactorSecret {
    fn from(sealed: SealedFactorSecret) -> Self {
        FactorSecret::Sealed(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_serialises_as_the_bare_string_and_loads_from_it() {
        let secret = FactorSecret::from("JBSWY3DPEHPK3PXP");
        assert_eq!(
            serde_json::to_string(&secret).unwrap(),
            "\"JBSWY3DPEHPK3PXP\""
        );
        let back: FactorSecret = serde_json::from_str("\"JBSWY3DPEHPK3PXP\"").unwrap();
        assert_eq!(back.plain(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn sealed_round_trips_as_an_object() {
        let sealed = SealedFactorSecret {
            key_id: "k".into(),
            nonce: "n".into(),
            ciphertext: "c".into(),
        };
        let json = serde_json::to_string(&FactorSecret::Sealed(sealed.clone())).unwrap();
        assert!(json.starts_with('{'), "{json}");
        let back: FactorSecret = serde_json::from_str(&json).unwrap();
        assert!(back.is_sealed());
        assert_eq!(back.plain(), None);
        assert!(matches!(back, FactorSecret::Sealed(ref s) if *s == sealed));
    }

    #[test]
    fn debug_does_not_print_a_plain_secret() {
        let rendered = format!("{:?}", FactorSecret::from("JBSWY3DPEHPK3PXP"));
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"), "{rendered}");
    }
}
