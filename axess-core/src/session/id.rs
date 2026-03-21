//! Session identifier — 16 bytes, stack-only, cryptographically random.

use crate::utils::random::SecureRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// A cryptographically random session identifier.
///
/// 16 bytes (UUID v4), stack-allocated. Generated via [`SecureRng`] for DST compatibility.
/// The underlying UUID is version-4 shaped but filled with bytes from the injected RNG,
/// not from `uuid::Uuid::new_v4()`, so tests can use a deterministic [`MockRng`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Construct a `SessionId` directly from raw bytes (used in cookie decoding).
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(bytes))
    }

    /// Generate a new random session ID using the provided [`SecureRng`].
    pub fn new<R: SecureRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        // Stamp version 4 and variant bits so the UUID is well-formed.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(Uuid::from_bytes(bytes))
    }

    /// Return the underlying UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Return the raw 16-byte representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_hyphenated())
    }
}

impl FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::mock_random::MockRng;

    #[test]
    fn deterministic_with_mock_rng() {
        let mut r1 = MockRng::new(42);
        let mut r2 = MockRng::new(42);
        assert_eq!(SessionId::new(&mut r1), SessionId::new(&mut r2));
    }

    #[test]
    fn roundtrip_display_fromstr() {
        let mut rng = MockRng::new(7);
        let id = SessionId::new(&mut rng);
        let s = id.to_string();
        let id2: SessionId = s.parse().expect("parse");
        assert_eq!(id, id2);
    }
}
