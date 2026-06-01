//! Free helpers shared across the OAuth/OIDC login ceremony submodules.
//!
//! Three free functions used only by the login module:
//!
//! - [`normalize_issuer`]: canonicalises an OIDC issuer URL.
//! - [`is_valid_pkce_verifier`]: validates a PKCE `code_verifier` per RFC 7636.
//! - [`compute_claim_lock`]: SHA-256 binding of (provider, subject, session_id).

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
/// is `SHA-256(provider || ":" || subject || ":" || session_id)` encoded
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
    hasher.update(provider.as_bytes());
    hasher.update(b":");
    hasher.update(subject.as_bytes());
    hasher.update(b":");
    hasher.update(sid.as_bytes());
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
