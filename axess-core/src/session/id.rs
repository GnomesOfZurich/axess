//! Session identifier: re-export from `axess-identity`.
//!
//! Internal callers use `axess_core::session::id::SessionId`; the
//! workload-identity `HumanPrincipal { session_id }` carries
//! `axess_identity::SessionId`. Both names resolve to the same nominal
//! type, and `pub use` preserves type identity, so the resolver boundary
//! is a direct assignment, not a `from_bytes` round-trip.
//!
//! Constructors: `SessionId::new(&mut rng)` requires `rng:
//! axess_rng::SecureRng`. Depend on `axess-rng` directly (and use its
//! `SystemRng` / `MockRng` / `SecureRng`); the bound is satisfied by
//! identity.

pub use axess_identity::SessionId;

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
