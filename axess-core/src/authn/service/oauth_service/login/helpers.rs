//! Free helpers shared across the OAuth/OIDC login ceremony submodules.
//!
//! Used only by the login module:
//!
//! - [`normalize_issuer`]: canonicalises an OIDC issuer URL.
//! - [`is_valid_pkce_verifier`]: validates a PKCE `code_verifier` per RFC 7636.
//! - [`compute_claim_lock`]: SHA-256 binding of (provider, subject, session_id).
//! - [`encode_dpop_key`], [`decode_dpop_key`]: the spelling in the ceremony
//!   state of the DPoP key a login makes at begin and presents at finish.

use crate::session::extractor::AuthSession;

/// Normalize an OIDC issuer URL for safe comparison.
///
/// Strips trailing slashes and lowercases the scheme+host portion.
/// This prevents mismatches from trivial URL differences (e.g.
/// `"https://accounts.google.com/"` vs `"https://accounts.google.com"`).
pub(super) fn normalize_issuer(issuer: &str) -> String {
    let trimmed = issuer.trim_end_matches('/');
    match url::Url::parse(trimmed) {
        Ok(parsed) => {
            // Reconstruct with normalized host (lowercased by url::Url) and path.
            let mut normalized =
                format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            if let Some(port) = parsed.port() {
                normalized.push_str(&format!(":{port}"));
            }
            let path = parsed.path().trim_end_matches('/');
            if !path.is_empty() {
                normalized.push_str(path);
            }
            normalized
        }
        Err(_) => trimmed.to_string(),
    }
}

/// Validate a PKCE `code_verifier` against RFC 7636 §4.1.
///
/// > code-verifier = 43*128unreserved
/// > unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
///
/// Rejects any verifier outside the length window or containing a byte
/// not in the allowed alphabet. Called by `finish_oauth_login` against
/// the value stashed by `begin_oauth_login` before sending it to the AS.
pub(super) fn is_valid_pkce_verifier(verifier: &str) -> bool {
    axess_factors::pkce::is_valid_verifier(verifier)
}

/// Compute the claim-binding lock for an OAuth ceremony. The lock
/// is `SHA-256` over `provider`, `subject` and `session_id`, each behind its
/// length as eight big-endian bytes, encoded
/// as URL-safe base64. It binds the IdP-attested identity to the session,
/// so a caller that bypasses `finish_oauth_login` and invokes
/// `complete_oauth_login` directly cannot satisfy the verification: the
/// session won't carry a matching lock, and the lock's input is the
/// session id which the caller cannot forge.
pub(super) async fn compute_claim_lock(
    provider: &str,
    subject: &str,
    session: &AuthSession,
) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    let sid = session.session_id().await;
    let mut hasher = Sha256::new();
    // Each field behind its length, so where one ends and the next begins
    // is part of what is hashed.
    for field in [provider.as_bytes(), subject.as_bytes(), sid.as_bytes()] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

// ── Module-level tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod pkce_verifier_tests {
    use super::is_valid_pkce_verifier;

    /// 43-char min, RFC 7636 §4.1 unreserved characters.
    #[test]
    fn accepts_43_char_unreserved() {
        let v = "a".repeat(43);
        assert!(is_valid_pkce_verifier(&v));
    }

    /// 128-char max.
    #[test]
    fn accepts_128_char_unreserved() {
        let v = "Z".repeat(128);
        assert!(is_valid_pkce_verifier(&v));
    }

    /// 42-char rejected.
    #[test]
    fn rejects_42_char() {
        let v = "a".repeat(42);
        assert!(!is_valid_pkce_verifier(&v));
    }

    /// 129-char rejected.
    #[test]
    fn rejects_129_char() {
        let v = "a".repeat(129);
        assert!(!is_valid_pkce_verifier(&v));
    }

    /// All four punctuation members of `unreserved` accepted.
    #[test]
    fn accepts_all_unreserved_punctuation() {
        let body = "abcdefghij0123456789-._~ABCDEFGHIJKLMNOPQR";
        // 42 chars + one more to reach 43.
        let v = format!("{body}x");
        assert_eq!(v.len(), 43);
        assert!(is_valid_pkce_verifier(&v));
    }

    /// Reject `+` (which IS a base64 character but NOT in the
    /// PKCE `unreserved` set; common bug from copy-pasting a
    /// base64 verifier from an unrelated implementation).
    #[test]
    fn rejects_plus_character() {
        let mut v = "a".repeat(42);
        v.push('+');
        assert_eq!(v.len(), 43);
        assert!(!is_valid_pkce_verifier(&v));
    }

    /// Reject space (separator-style typo).
    #[test]
    fn rejects_space() {
        let mut v = "a".repeat(42);
        v.push(' ');
        assert!(!is_valid_pkce_verifier(&v));
    }

    /// Reject a multi-byte UTF-8 character (length-in-bytes vs
    /// length-in-chars confusion).
    #[test]
    fn rejects_non_ascii() {
        let mut v = "a".repeat(40);
        v.push('é');
        v.push_str("xx");
        assert!(!is_valid_pkce_verifier(&v));
    }
}

#[cfg(test)]
mod normalize_issuer_tests {
    use super::normalize_issuer;

    /// The trailing `/` on an issuer URL is meaningless to OIDC
    /// but breaks naive string compare. `normalize_issuer` strips it
    /// before the equality check that gates the cross-provider replay
    /// guard. A mutation to `String::new()` or `"xyzzy".into()` would
    /// neuter that gate; this test pins the canonical output.
    #[test]
    fn strips_single_trailing_slash() {
        assert_eq!(
            normalize_issuer("https://accounts.google.com/"),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn passes_through_already_normalised_issuer() {
        assert_eq!(
            normalize_issuer("https://accounts.google.com"),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn preserves_path_component() {
        assert_eq!(
            normalize_issuer("https://idp.example.com/realms/main"),
            "https://idp.example.com/realms/main"
        );
    }

    #[test]
    fn preserves_explicit_port() {
        assert_eq!(
            normalize_issuer("https://idp.example.com:8443/"),
            "https://idp.example.com:8443"
        );
    }

    /// Two textually-different but semantically-equivalent issuer URLs
    /// must normalise to the same canonical form so the equality check
    /// gating cross-provider replay actually succeeds.
    #[test]
    fn trailing_slash_variants_are_equal() {
        let a = normalize_issuer("https://accounts.google.com/");
        let b = normalize_issuer("https://accounts.google.com");
        assert_eq!(a, b);
    }

    #[test]
    fn strips_trailing_slash_on_path() {
        assert_eq!(
            normalize_issuer("https://idp.example.com/realms/main/"),
            "https://idp.example.com/realms/main"
        );
    }

    /// `https://host/` and `https://host` must both normalise to
    /// `https://host` (no trailing slash, no empty path component).
    #[test]
    fn root_path_normalises_to_host_only() {
        assert_eq!(normalize_issuer("https://host/"), "https://host");
        assert_eq!(normalize_issuer("https://host"), "https://host");
    }
}

/// The ceremony-state spelling of a DPoP key: the URL-safe base64 of its
/// seed, from which [`decode_dpop_key`] restores the same key.
pub(super) fn encode_dpop_key(key: &axess_factors::oauth::DpopKey) -> String {
    use base64::Engine as _;
    let seed = key.to_seed_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed.as_slice())
}

/// The key [`encode_dpop_key`] spelled, or `None` for anything else.
///
/// The seed is decoded into a zeroizing stack buffer and handed on by value
/// to [`DpopKey::from_seed`](axess_factors::oauth::DpopKey::from_seed), which
/// wipes its own copy, so no unwiped copy of it is left behind here.
pub(super) fn decode_dpop_key(encoded: &str) -> Option<axess_factors::oauth::DpopKey> {
    use base64::Engine as _;
    // Room for the longest input that can decode to 32 bytes (43 characters
    // decode to 33 bytes of buffer estimate); anything longer fails to
    // decode and is refused.
    let mut buf = zeroize::Zeroizing::new([0u8; 36]);
    let len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut *buf)
        .ok()?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(buf.get(..len).filter(|b| b.len() == 32)?);
    Some(axess_factors::oauth::DpopKey::from_seed(*seed))
}

#[cfg(test)]
mod dpop_key_tests {
    use super::{decode_dpop_key, encode_dpop_key};

    #[test]
    fn a_key_round_trips_through_its_spelling() {
        let key = axess_factors::oauth::DpopKey::from_seed([7u8; 32]);
        let back = decode_dpop_key(&encode_dpop_key(&key)).expect("decodes");
        assert_eq!(*back.to_seed_bytes(), *key.to_seed_bytes());
    }

    #[test]
    fn anything_but_a_32_byte_seed_is_refused() {
        use base64::Engine as _;
        let enc = |n: usize| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![7u8; n]);
        for n in [0, 31, 33, 64, 200] {
            assert!(decode_dpop_key(&enc(n)).is_none(), "{n} bytes");
        }
        assert!(decode_dpop_key("not base64!").is_none());
    }
}

#[cfg(test)]
mod claim_lock_tests {
    use super::compute_claim_lock;
    use crate::testing::test_session;

    /// The lock binds a provider, a subject and a session. Fields that
    /// differ only in where the boundary between them falls are different
    /// bindings: `("a:b", "c")` is not `("a", "b:c")`.
    #[tokio::test]
    async fn fields_that_differ_only_in_their_boundary_give_different_locks() {
        let session = test_session();
        let split_early = compute_claim_lock("a", "b:c", &session).await;
        let split_late = compute_claim_lock("a:b", "c", &session).await;
        assert_ne!(split_early, split_late);
    }

    #[tokio::test]
    async fn one_binding_gives_one_lock_and_a_session_changes_it() {
        let (one, other) = (test_session(), test_session());
        let first = compute_claim_lock("idp", "sub", &one).await;
        assert_eq!(first, compute_claim_lock("idp", "sub", &one).await);
        assert_ne!(first, compute_claim_lock("idp", "sub", &other).await);
    }
}
