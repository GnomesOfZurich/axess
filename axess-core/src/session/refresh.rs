//! Refresh token support for mobile/SPA clients.
//!
//! Provides long-lived refresh tokens that can be exchanged for new sessions.
//! Designed for clients that cannot use HTTP-only cookies (mobile apps, SPAs).
//!
//! # Security model
//!
//! - **Hash-only storage:** Only a hash of the token is persisted (SHA-256, or
//!   HMAC-SHA256 keyed by `RefreshTokenConfig::hash_pepper` when one is set);
//!   the plaintext is returned exactly once at issuance.
//! - **Token rotation:** Each use of a refresh token invalidates the old one
//!   and issues a new one, making stolen tokens single-use.
//! - **Device binding:** Optional device fingerprint is stored with the token
//!   and checked on refresh to detect cross-device replay.
//! - **Per-user cap:** A configurable maximum number of active tokens per user
//!   prevents unbounded accumulation; the oldest tokens are auto-revoked.

mod rotation;
mod store;
mod types;

#[cfg(test)]
use crate::authn::ids::{TenantId, UserId};
#[cfg(test)]
use crate::session::data::{AuthState, SessionData};
#[cfg(test)]
use chrono::{DateTime, Duration, Utc};
#[cfg(test)]
use rotation::{collect_family_device_targets, generate_token_value, hash_token};
#[cfg(test)]
use zeroize::Zeroizing;

pub use rotation::{
    IssueRequest, issue_refresh_token, refresh_session, refresh_session_with_status_check,
    revoke_refresh_token,
};
pub use store::{RefreshTokenStore, RotationOutcome};
pub use types::{RefreshError, RefreshToken, RefreshTokenConfig, RefreshTokenId, TokenFamilyId};

#[cfg(test)]
mod atomic_rotation;
#[cfg(test)]
mod authn_time;
#[cfg(test)]
mod basics;
#[cfg(all(test, feature = "device"))]
mod device_cascade;
#[cfg(test)]
mod status_check;
#[cfg(test)]
mod test_support;

#[cfg(test)]
mod refresh_unit_tests {
    use super::*;
    use crate::testing::mock_random::MockRng;

    // ── hash_token ──────────────────────────────────────────────────────

    /// Pin: hash_token without pepper produces a SHA-256 hash.
    #[test]
    fn hash_token_no_pepper_is_sha256() {
        let h1 = hash_token("test-token-value", None);
        let h2 = hash_token("test-token-value", None);
        assert_eq!(h1, h2, "hash must be deterministic");
        assert!(!h1.is_empty());
    }

    /// Pin: hash_token with pepper produces a different hash than without.
    #[test]
    fn hash_token_with_pepper_differs_from_without() {
        let without = hash_token("test-token", None);
        let with = hash_token("test-token", Some(b"my-secret-pepper"));
        assert_ne!(without, with, "peppered hash must differ from unpeppered");
    }

    /// Pin: hash_token with empty pepper falls back to SHA-256 (same as None).
    #[test]
    fn hash_token_empty_pepper_falls_back_to_sha256() {
        let none_pepper = hash_token("token", None);
        let empty_pepper = hash_token("token", Some(b""));
        assert_eq!(
            none_pepper, empty_pepper,
            "empty pepper must fall back to SHA-256 path"
        );
    }

    /// Pin: different inputs produce different hashes (collision resistance).
    #[test]
    fn hash_token_different_inputs_different_hashes() {
        let h1 = hash_token("token-a", None);
        let h2 = hash_token("token-b", None);
        assert_ne!(h1, h2);
    }

    /// Pin: different peppers produce different hashes.
    #[test]
    fn hash_token_different_peppers_different_hashes() {
        let h1 = hash_token("same-token", Some(b"pepper-1"));
        let h2 = hash_token("same-token", Some(b"pepper-2"));
        assert_ne!(h1, h2);
    }

    // ── generate_token_value ─────────────────────────────────────────────

    /// Pin: generate_token_value produces a non-empty base64 string.
    #[test]
    fn generate_token_value_produces_nonempty_base64() {
        let rng = MockRng::new(42);
        let token = generate_token_value(&rng);
        assert!(!token.is_empty());
        // Should be URL-safe base64 of 32 bytes = 43 chars.
        assert_eq!(token.len(), 43, "32 bytes → 43 base64url chars");
    }

    /// Pin: generate_token_value is deterministic with MockRng.
    #[test]
    fn generate_token_value_is_deterministic() {
        let t1 = generate_token_value(&MockRng::new(99));
        let t2 = generate_token_value(&MockRng::new(99));
        assert_eq!(t1, t2);
    }

    /// Pin: different seeds produce different tokens.
    #[test]
    fn generate_token_value_different_seeds_differ() {
        let t1 = generate_token_value(&MockRng::new(1));
        let t2 = generate_token_value(&MockRng::new(2));
        assert_ne!(t1, t2);
    }

    // ── RefreshTokenConfig::default ──────────────────────────────────────

    /// Pin: default config has production-safe values.
    #[test]
    fn default_config_has_safe_defaults() {
        let cfg = RefreshTokenConfig::default();
        assert_eq!(cfg.ttl, Duration::days(30));
        assert_eq!(cfg.max_per_user, 10);
        assert!(cfg.rotation, "rotation must be on by default");
        assert!(cfg.hash_pepper.is_none(), "no pepper by default");
    }

    // ── RefreshError Display ─────────────────────────────────────────────

    /// Pin: each RefreshError variant produces a distinct non-empty message.
    #[test]
    fn refresh_error_display_per_variant() {
        use std::io;
        let variants: Vec<(RefreshError<io::Error>, &str)> = vec![
            (RefreshError::NotFound, "not found"),
            (RefreshError::Expired, "expired"),
            (RefreshError::Revoked, "revoked"),
            (RefreshError::DeviceMismatch, "device mismatch"),
            (RefreshError::AccountInactive, "not active"),
            (RefreshError::Store(io::Error::other("boom")), "store error"),
        ];
        for (err, expected_substr) in variants {
            let msg = err.to_string();
            assert!(
                msg.contains(expected_substr),
                "RefreshError display for {:?} must contain {expected_substr:?}, got {msg:?}",
                std::mem::discriminant(&err)
            );
        }
    }

    /// The pepper lives in a wiping wrapper and `pepper()` reads through it:
    /// the field type is what makes every clone of the config wipe on drop.
    #[test]
    fn hash_pepper_is_held_in_a_wiping_wrapper() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let config = RefreshTokenConfig {
            hash_pepper: Some(Zeroizing::new(b"p".to_vec())),
            ..RefreshTokenConfig::default()
        };
        wipes_on_drop(config.hash_pepper.as_ref().expect("set"));
        assert_eq!(config.pepper(), Some(b"p".as_slice()));
        assert_eq!(RefreshTokenConfig::default().pepper(), None);
    }

    /// `Debug` on `RefreshTokenConfig` MUST NOT print the raw pepper
    /// bytes: the pepper is a per-deployment secret whose leak enables
    /// offline pre-image scans of the stored refresh-token-hash table.
    /// Pins the manual Debug impl against a future accidental
    /// `#[derive(Debug)]` reintroduction.
    #[test]
    fn refresh_token_config_debug_redacts_hash_pepper() {
        let pepper = b"super-secret-pepper-bytes".to_vec();
        let config = RefreshTokenConfig {
            hash_pepper: Some(Zeroizing::new(pepper.clone())),
            ..RefreshTokenConfig::default()
        };
        let dbg = format!("{:?}", config);
        assert!(
            dbg.contains("<redacted 25 bytes>"),
            "Debug must redact the pepper via the manual impl; got {dbg}"
        );
        assert!(
            !dbg.contains("super-secret") && !dbg.contains("pepper-bytes"),
            "raw pepper bytes must not appear in Debug output; got {dbg}"
        );
        // The `None` case still round-trips cleanly.
        let empty = RefreshTokenConfig::default();
        let dbg_empty = format!("{:?}", empty);
        assert!(dbg_empty.contains("hash_pepper: None"), "got {dbg_empty}");
    }
}
