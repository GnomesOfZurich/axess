//! Session identifier and session key: re-exports from `axess-identity`.
//!
//! A [`SessionId`] is the value a session cookie carries. A [`SessionKey`]
//! is the SHA-256 of a fixed tag and that id, and it is the name the session
//! is stored under: the session layer computes it once from the verified
//! cookie, every [`SessionStore`](crate::session::store::SessionStore)
//! method takes it, and no store ever sees the id. `SessionKey::of` is the
//! one way from an id to its key.
//!
//! The id is read in one place, the cookie codec of the session layer,
//! which signs it into the cookie and verifies it out of one; everything
//! else names the session by its key. The workload-identity
//! `HumanPrincipal { session_id }` carries the session's key
//! (`axess_identity::SessionKey`, which `pub use` makes the same type as
//! [`SessionKey`] here), read from the session's
//! [`AuthSnapshot`](crate::session::extractor::AuthSnapshot).
//!
//! Constructors: `SessionId::new(&rng)` requires `rng:
//! axess_rng::SecureRng`. Depend on `axess-rng` directly (and use its
//! `SystemRng` / `MockRng` / `SecureRng`); the bound is satisfied by
//! identity.

pub use axess_identity::{
    SESSION_KEY_DOMAIN, SessionId, SessionKey, SessionKeyError, SessionKeyPrefix,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::mock_random::MockRng;

    /// Pin that the re-exported type still mints deterministically
    /// from a `MockRng`; guards against an accidental switch of the
    /// `axess-identity` `new()` to a non-DST RNG (e.g. `Uuid::new_v4`).
    #[test]
    fn deterministic_with_mock_rng() {
        let r1 = MockRng::new(42);
        let r2 = MockRng::new(42);
        assert_eq!(SessionId::new(&r1), SessionId::new(&r2));
    }

    #[test]
    fn roundtrip_display_fromstr() {
        let rng = MockRng::new(7);
        let id = SessionId::new(&rng);
        let s = id.to_string();
        let id2: SessionId = s.parse().expect("parse");
        assert_eq!(id, id2);
    }

    /// Pin `as_uuid` against a `Default::default()` body mutation:
    /// would always return the nil UUID.
    #[test]
    fn as_uuid_returns_underlying_uuid() {
        let rng = MockRng::new(11);
        let id = SessionId::new(&rng);
        let uuid = id.as_uuid();
        assert_eq!(uuid.as_bytes(), id.as_bytes());
        assert_ne!(uuid, uuid::Uuid::nil(), "session id must not be nil");
    }
}
