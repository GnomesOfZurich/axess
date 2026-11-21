//! A software device key for tests: a P-256 key that signs both proof shapes.
//!
//! A real device key lives in a TPM or a platform key store and cannot be
//! read. This one is derived from a seed, so a test under a seeded
//! [`SecureRng`] is reproducible, and it signs whatever it is handed, so a
//! test can build each proof a verifier must refuse.

use axess_rng::SecureRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};

use super::{APP_PROOF_TYP, KEY_PROOF_ALG, KeyProofShape, P256Key, ProofTarget, browser_draft};

/// A P-256 key pair held in memory, for tests.
#[derive(Clone)]
pub struct SoftwareKey {
    secret: p256::SecretKey,
}

impl std::fmt::Debug for SoftwareKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SoftwareKey(***)")
    }
}

impl SoftwareKey {
    /// Draw a key from `rng`.
    pub fn generate(rng: &dyn SecureRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// The key a seed stands for. A seed that is not a valid scalar (zero,
    /// or at least the group order) is hashed until it is one.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        loop {
            if let Ok(secret) = p256::SecretKey::from_slice(&seed) {
                return Self { secret };
            }
            seed = Sha256::digest(seed).into();
        }
    }

    /// The public half.
    pub fn public(&self) -> P256Key {
        let point = self.secret.public_key().to_sec1_point(false);
        let coordinate = |bytes: Option<&p256::FieldBytes>| -> [u8; 32] {
            let mut out = [0u8; 32];
            if let Some(bytes) = bytes {
                out.copy_from_slice(bytes);
            }
            out
        };
        P256Key {
            x: coordinate(point.x()),
            y: coordinate(point.y()),
        }
    }

    /// The header and claims of a well-formed proof in `shape` for `target`
    /// over `challenge`, carrying the public key when `with_key` is set (a
    /// registration) and not otherwise.
    pub fn proof_parts(
        &self,
        shape: KeyProofShape,
        target: ProofTarget<'_>,
        challenge: &str,
        with_key: bool,
    ) -> (serde_json::Value, serde_json::Value) {
        let jwk = self.public().to_jwk();
        match shape {
            KeyProofShape::App => {
                let mut header = serde_json::json!({ "alg": KEY_PROOF_ALG, "typ": APP_PROOF_TYP });
                if with_key {
                    header["jwk"] = jwk;
                }
                let claims = serde_json::json!({
                    "htm": target.method,
                    "htu": target.url,
                    "nonce": challenge,
                });
                (header, claims)
            }
            KeyProofShape::Browser => {
                let mut header =
                    serde_json::json!({ "alg": KEY_PROOF_ALG, "typ": browser_draft::PROOF_TYP });
                let mut claims =
                    serde_json::json!({ (browser_draft::PROOF_CHALLENGE_CLAIM): challenge });
                if let Some(audience) = browser_draft::PROOF_AUDIENCE_CLAIM {
                    claims[audience] = target.url.into();
                }
                if with_key {
                    match browser_draft::PROOF_KEY_PLACE {
                        browser_draft::KeyPlace::Header => {
                            header[browser_draft::PROOF_KEY_MEMBER] = jwk;
                        }
                        browser_draft::KeyPlace::Claims => {
                            claims[browser_draft::PROOF_KEY_MEMBER] = jwk;
                        }
                    }
                }
                (header, claims)
            }
        }
    }

    /// A proof in the app shape that rides on an ordinary request, as RFC
    /// 9449 lays it out: the public key in the `jwk` header, and `htm`,
    /// `htu`, `iat` and `jti`, with no challenge.
    pub fn sign_request(&self, target: ProofTarget<'_>, iat: i64, jti: &str) -> String {
        let header = serde_json::json!({
            "alg": KEY_PROOF_ALG,
            "typ": APP_PROOF_TYP,
            "jwk": self.public().to_jwk(),
        });
        let claims = serde_json::json!({
            "htm": target.method,
            "htu": target.url,
            "iat": iat,
            "jti": jti,
        });
        self.sign_parts(&header, &claims)
    }

    /// A well-formed proof: [`proof_parts`](Self::proof_parts), signed.
    pub fn sign(
        &self,
        shape: KeyProofShape,
        target: ProofTarget<'_>,
        challenge: &str,
        with_key: bool,
    ) -> String {
        let (header, claims) = self.proof_parts(shape, target, challenge, with_key);
        self.sign_parts(&header, &claims)
    }

    /// Sign any header and claims as a compact JWS with `ES256`, whatever
    /// the header says: how a test builds the proofs a verifier must refuse.
    pub fn sign_parts(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self.sign_bytes(signing_input.as_bytes());
        format!("{signing_input}.{signature}")
    }

    /// The base64url `ES256` signature of `message`.
    pub fn sign_bytes(&self, message: &[u8]) -> String {
        let pkcs8 = self
            .secret
            .to_pkcs8_der()
            .expect("a P-256 secret key always encodes as PKCS#8");
        let key = EncodingKey::from_ec_der(pkcs8.as_bytes());
        crate::jwt::sign(message, &key, Algorithm::ES256).expect("an EC key signs with ES256")
    }
}
