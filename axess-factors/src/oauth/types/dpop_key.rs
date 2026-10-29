//! The key a DPoP-bound token is tied to (RFC 9449).
//!
//! A sender-constrained access token carries the thumbprint of one key
//! (`cnf.jkt`), and every proof presented with that token must be signed by
//! the same key. [`DpopKey`] is that key: generated once per session, kept for
//! the life of the token, and handed to the proof functions by reference.

use zeroize::Zeroizing;

/// A DPoP signing key: a P-256 private scalar.
///
/// Generate one with [`DpopKey::generate`] when a session starts, keep it
/// next to the token it binds (the scalar is exportable through
/// [`to_seed_bytes`](Self::to_seed_bytes) for that), and pass it to every
/// proof made for that token. Two proofs from one key for different URLs
/// report the same [`thumbprint`](Self::thumbprint), which is the value the
/// authorization server echoes as `cnf.jkt`.
///
/// `Debug` shows the thumbprint only, never the scalar, and the scalar is
/// zeroed on drop. There is deliberately no `Serialize` impl: a key reaches a
/// log or a response only through an explicit export.
pub struct DpopKey {
    scalar: Zeroizing<[u8; 32]>,
}

impl DpopKey {
    /// A fresh key from `rng`.
    ///
    /// The 32 bytes are read as a big-endian P-256 scalar; on the
    /// cosmically unlikely chance that they fall outside the curve order,
    /// the bytes are hashed once and retried, so the result is a pure
    /// function of what the rng returned and a seeded rng reproduces the key.
    pub fn generate(rng: &dyn axess_rng::SecureRng) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        Self::from_seed(*seed)
    }

    /// The key whose scalar is `seed` (or, when `seed` is not a valid
    /// scalar, the hash of it, repeated until one is). A scalar returned by
    /// [`to_seed_bytes`](Self::to_seed_bytes) is valid and round-trips
    /// unchanged.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        use sha2::Digest;
        loop {
            if p256::SecretKey::from_slice(&seed).is_ok() {
                let key = Self {
                    scalar: Zeroizing::new(seed),
                };
                zeroize::Zeroize::zeroize(&mut seed);
                return key;
            }
            seed = sha2::Sha256::digest(seed).into();
        }
    }

    /// The scalar, for a caller that stores the key beside the token it
    /// binds. Zeroed on drop; treat it like the token's refresh secret.
    pub fn to_seed_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.scalar)
    }

    /// The key as the `p256` type. A stored scalar was validated when the
    /// key was built, so this fails only for a `DpopKey` that could not have
    /// been constructed; the error is returned rather than assumed away.
    pub(crate) fn secret_key(&self) -> Result<p256::SecretKey, super::error::OAuthError> {
        p256::SecretKey::from_slice(&*self.scalar)
            .map_err(|e| super::error::OAuthError::Config(format!("DPoP key invalid: {e}")))
    }

    /// The public key as the `x` and `y` coordinates, base64url without
    /// padding.
    pub(crate) fn public_coordinates(&self) -> Result<(String, String), super::error::OAuthError> {
        use base64::Engine as _;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let secret = self.secret_key()?;
        let point = secret.public_key().to_encoded_point(false);
        let x = point.x().ok_or_else(|| {
            super::error::OAuthError::Config("DPoP: failed to extract EC x coordinate".to_string())
        })?;
        let y = point.y().ok_or_else(|| {
            super::error::OAuthError::Config("DPoP: failed to extract EC y coordinate".to_string())
        })?;
        Ok((b64.encode(x.as_slice()), b64.encode(y.as_slice())))
    }

    /// The RFC 7638 JWK thumbprint of the public key: base64url (no
    /// padding) of the SHA-256 of the canonical `{"crv","kty","x","y"}`
    /// JSON. This is the value an authorization server binds a token to as
    /// `cnf.jkt`.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`](super::error::OAuthError::Config) when the
    /// public key cannot be derived, which a validly constructed key never
    /// hits.
    pub fn thumbprint(&self) -> Result<String, super::error::OAuthError> {
        use base64::Engine as _;
        use sha2::Digest;
        let (x, y) = self.public_coordinates()?;
        // `BTreeMap` iterates in key order, which is the lexicographic order
        // RFC 7638 §3.2 requires, so a member added later cannot be
        // mis-ordered by hand.
        let mut members: std::collections::BTreeMap<&'static str, &str> =
            std::collections::BTreeMap::new();
        members.insert("crv", "P-256");
        members.insert("kty", "EC");
        members.insert("x", &x);
        members.insert("y", &y);
        let canonical = serde_json::to_string(&members).map_err(|e| {
            super::error::OAuthError::Config(format!("DPoP JWK canonical form: {e}"))
        })?;
        let digest = sha2::Sha256::digest(canonical.as_bytes());
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
    }
}

impl std::fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("DpopKey");
        if let Ok(jkt) = self.thumbprint() {
            s.field("thumbprint", &jkt);
        }
        s.field("scalar", &"<redacted>").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_scalar() {
        let key = DpopKey::from_seed([0x42; 32]);
        let shown = format!("{key:?}");
        assert!(shown.contains("redacted"), "{shown}");
        assert!(shown.contains(&key.thumbprint().unwrap()), "{shown}");
        // 0x42 is 66; a derived Debug would print the array.
        assert!(!shown.contains("66, 66"), "{shown}");
    }

    #[test]
    fn exported_scalar_round_trips_to_the_same_thumbprint() {
        let key = DpopKey::from_seed([0x07; 32]);
        let again = DpopKey::from_seed(*key.to_seed_bytes());
        assert_eq!(key.thumbprint().unwrap(), again.thumbprint().unwrap());
    }

    #[test]
    fn an_out_of_range_seed_is_rehashed_not_rejected() {
        // The all-ones scalar is above the P-256 group order.
        let key = DpopKey::from_seed([0xff; 32]);
        assert_ne!(*key.to_seed_bytes(), [0xff; 32]);
        assert_eq!(key.thumbprint().unwrap().len(), 43);
    }
}
