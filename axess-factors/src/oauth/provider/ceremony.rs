//! Per-login secrets of the authorization-code ceremony: PKCE verifier,
//! CSRF `state` and OIDC `nonce`.
//!
//! All three come from the caller's [`SecureRng`] rather than from
//! `openidconnect`'s internal OS generator, so a seeded RNG reproduces the
//! authorization URL byte for byte. Each secret is its own 32-byte draw,
//! base64url-encoded without padding (43 characters, inside RFC 7636's
//! 43 to 128 verifier grammar). The raw draws are wiped once encoded.

use axess_rng::SecureRng;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier};
use zeroize::Zeroizing;

/// Bytes drawn for each of the verifier, the state and the nonce.
const SECRET_BYTES: usize = 32;

/// The three secrets of one authorization request.
pub(super) struct CeremonySecrets {
    pub(super) pkce_challenge: PkceCodeChallenge,
    pub(super) pkce_verifier: PkceCodeVerifier,
    pub(super) csrf_state: CsrfToken,
    pub(super) nonce: Nonce,
}

fn draw(rng: &dyn SecureRng) -> String {
    let mut raw = Zeroizing::new([0u8; SECRET_BYTES]);
    rng.fill_bytes(&mut *raw);
    URL_SAFE_NO_PAD.encode(*raw)
}

/// Mint the verifier, then the state, then the nonce, in that draw order.
pub(super) fn mint(rng: &dyn SecureRng) -> CeremonySecrets {
    let pkce_verifier = PkceCodeVerifier::new(draw(rng));
    let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
    CeremonySecrets {
        pkce_challenge,
        pkce_verifier,
        csrf_state: CsrfToken::new(draw(rng)),
        nonce: Nonce::new(draw(rng)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_rng::testing::MockRng;

    fn expected(rng: &MockRng) -> String {
        let mut raw = [0u8; SECRET_BYTES];
        rng.fill_bytes(&mut raw);
        URL_SAFE_NO_PAD.encode(raw)
    }

    #[test]
    fn secrets_are_three_consecutive_draws_in_a_fixed_order() {
        let secrets = mint(&MockRng::new(7));
        let reference = MockRng::new(7);
        let verifier = expected(&reference);
        let state = expected(&reference);
        let nonce = expected(&reference);

        assert_eq!(secrets.pkce_verifier.secret(), &verifier);
        assert_eq!(secrets.csrf_state.secret(), &state);
        assert_eq!(secrets.nonce.secret(), &nonce);
        assert_eq!(verifier.len(), 43);
        assert!(crate::pkce::is_valid_verifier(&verifier));
        assert_ne!(verifier, state);
        assert_ne!(state, nonce);
    }

    #[test]
    fn challenge_derives_from_the_minted_verifier() {
        let secrets = mint(&MockRng::new(99));
        let again = PkceCodeVerifier::new(secrets.pkce_verifier.secret().clone());
        assert_eq!(
            secrets.pkce_challenge.as_str(),
            PkceCodeChallenge::from_code_verifier_sha256(&again).as_str()
        );
    }

    #[test]
    fn same_seed_same_secrets_different_seed_different() {
        let a = mint(&MockRng::new(1));
        let b = mint(&MockRng::new(1));
        let c = mint(&MockRng::new(2));
        assert_eq!(a.csrf_state.secret(), b.csrf_state.secret());
        assert_ne!(a.csrf_state.secret(), c.csrf_state.secret());
    }
}
