//! Primitives shared between the production [`LocalIdp`](crate::local_idp::LocalIdp)
//! and the test [`LocalIdpFixture`](crate::testing::local_idp::LocalIdpFixture).
//! Token-bearing types (signing key, claim builder), the issuance-listener
//! trait, and small helpers live here so production code does not have to
//! import from `crate::testing`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::Jwk;
#[cfg(any(test, feature = "testing"))]
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::SecretKey as EcSecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey as EcDecodePrivateKey, EncodePrivateKey as EcEncodePrivateKey};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::traits::PublicKeyParts;

pub(crate) const RSA_KEY_BITS: usize = 2048;
/// Smallest RSA modulus accepted from imported key material.
pub(crate) const RSA_MIN_BITS: usize = 2048;

/// RFC 7638 thumbprint of a canonical public-key JWK member string, used as
/// the `kid` of a generated key so two generated keys never share one.
fn thumbprint_kid(canonical_jwk: &str) -> String {
    use sha2::Digest as _;
    URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(canonical_jwk.as_bytes()))
}

// ── LocalIdpSigningKey ───────────────────────────────────────────────────────

/// A keypair + JWK + kid + algorithm bundle that drives the signing
/// side of a [`LocalIdpFixture`](crate::testing::local_idp::LocalIdpFixture).
/// Extracted as its own type so adopters can:
///
/// - Provide a **stable** keypair across test runs (load from a
///   checked-in PEM, environment variable, or HSM-issued file) instead
///   of regenerating on every fixture construction.
/// - Build a fixture exposing a JWKS with multiple active keys
///   (current + historical), exercising key-rotation scenarios.
/// - Prototype production wiring where keys come from a `KeyProvider`
///   layer rather than in-memory generation.
///
/// The keypair is held as DER bytes internally (PKCS#1 for RSA matching
/// [`EncodingKey::from_rsa_der`], PKCS#8 for EC matching
/// [`EncodingKey::from_ec_der`]), plus the precomputed public [`Jwk`]
/// used to populate the fixture's JWKS. Drop zeroizes the DER bytes held
/// here via [`zeroize`], and only those: the [`EncodingKey`] built from them
/// once at construction (one copy of the key, shared by every mint and every
/// clone of the same value), the parsed `RsaPrivateKey` / `SecretKey` the
/// constructors started from, and any copy `jsonwebtoken` makes while signing
/// are not zeroized. This is a test and development IdP, not a place for a
/// production key.
pub struct LocalIdpSigningKey {
    material: LocalIdpKeyMaterial,
    /// Built from `material` once, so signing does not copy the private key
    /// into a new unzeroized `EncodingKey` on every mint.
    encoding: EncodingKey,
    jwk: Jwk,
    key_id: String,
    algorithm: Algorithm,
}

/// Internal storage for a [`LocalIdpSigningKey`]'s private key bytes.
/// Each variant holds the DER format that [`EncodingKey`]'s
/// per-algorithm constructor expects.
enum LocalIdpKeyMaterial {
    /// PKCS#1 DER (`-----BEGIN RSA PRIVATE KEY-----` body): what
    /// [`EncodingKey::from_rsa_der`] consumes.
    Rsa { pkcs1_der: Vec<u8> },
    /// PKCS#8 DER (`-----BEGIN PRIVATE KEY-----` body): what
    /// [`EncodingKey::from_ec_der`] consumes. NOT raw SEC1
    /// `ECPrivateKey`; `jsonwebtoken` rejects the SEC1 wrapping
    /// silently with an "invalid key" surface that is easy to
    /// misdiagnose as a DPoP signing failure.
    Ec { pkcs8_der: Vec<u8> },
}

impl Drop for LocalIdpSigningKey {
    fn drop(&mut self) {
        match &mut self.material {
            LocalIdpKeyMaterial::Rsa { pkcs1_der } => zeroize::Zeroize::zeroize(pkcs1_der),
            LocalIdpKeyMaterial::Ec { pkcs8_der } => zeroize::Zeroize::zeroize(pkcs8_der),
        }
    }
}

impl Clone for LocalIdpSigningKey {
    fn clone(&self) -> Self {
        let material = match &self.material {
            LocalIdpKeyMaterial::Rsa { pkcs1_der } => LocalIdpKeyMaterial::Rsa {
                pkcs1_der: pkcs1_der.clone(),
            },
            LocalIdpKeyMaterial::Ec { pkcs8_der } => LocalIdpKeyMaterial::Ec {
                pkcs8_der: pkcs8_der.clone(),
            },
        };
        Self {
            material,
            encoding: self.encoding.clone(),
            jwk: self.jwk.clone(),
            key_id: self.key_id.clone(),
            algorithm: self.algorithm,
        }
    }
}

impl std::fmt::Debug for LocalIdpSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdpSigningKey")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl LocalIdpSigningKey {
    /// Generate a fresh RSA-2048 keypair under `RS256` with the
    /// default key id. Key generation takes ~50-200 ms; expensive to
    /// run per-test, so reuse via `Clone` across cases.
    ///
    /// Prefer [`Self::generate_es256`]: it is faster, its tokens are smaller,
    /// and it avoids the `rsa` crate's private-key operations, which carry a
    /// timing side channel (the Marvin advisory, not fixed upstream). Use RSA
    /// only when a verifier cannot take ES256, and keep signing off shared
    /// hosts.
    pub fn generate_rsa() -> Self {
        Self::generate_rsa_with_algorithm(Algorithm::RS256)
    }

    /// Generate a fresh RSA-2048 keypair under the given algorithm
    /// (`RS256` / `RS384` / `RS512`).
    ///
    /// # Panics
    ///
    /// On another algorithm, or if key generation fails; see
    /// [`Self::try_generate_rsa_with_algorithm`] for the fallible form.
    pub fn generate_rsa_with_algorithm(algorithm: Algorithm) -> Self {
        Self::generate_rsa_with_algorithm_and_rng(algorithm, &axess_rng::SystemRng)
    }

    /// Like [`Self::generate_rsa_with_algorithm`] but drives keygen with
    /// the supplied [`SecureRng`](axess_rng::SecureRng), enabling
    /// deterministic-simulation tests to reproduce key material.
    ///
    /// # Panics
    ///
    /// As [`Self::generate_rsa_with_algorithm`]; see
    /// [`Self::try_generate_rsa_with_algorithm_and_rng`] for the fallible form.
    pub fn generate_rsa_with_algorithm_and_rng(
        algorithm: Algorithm,
        rng: &dyn axess_rng::SecureRng,
    ) -> Self {
        Self::try_generate_rsa_with_algorithm_and_rng(algorithm, rng)
            .unwrap_or_else(|e| panic!("LocalIdpSigningKey RSA key generation: {e}"))
    }

    /// Like [`Self::generate_rsa_with_algorithm`] but returns
    /// [`LocalIdpKeyError::UnsupportedAlgorithm`] for an algorithm that is
    /// not `RS256`, `RS384` or `RS512` instead of panicking.
    pub fn try_generate_rsa_with_algorithm(algorithm: Algorithm) -> Result<Self, LocalIdpKeyError> {
        Self::try_generate_rsa_with_algorithm_and_rng(algorithm, &axess_rng::SystemRng)
    }

    /// Like [`Self::generate_rsa_with_algorithm_and_rng`] but returns an
    /// error instead of panicking.
    ///
    /// # Errors
    ///
    /// [`LocalIdpKeyError::UnsupportedAlgorithm`] for an algorithm that is
    /// not `RS256`, `RS384` or `RS512`; [`LocalIdpKeyError::KeyGeneration`]
    /// if the RSA keypair could not be generated.
    pub fn try_generate_rsa_with_algorithm_and_rng(
        algorithm: Algorithm,
        rng: &dyn axess_rng::SecureRng,
    ) -> Result<Self, LocalIdpKeyError> {
        check_rsa_alg(algorithm)?;
        let mut adapter = SecureRngAdapter(rng);
        let private_key = RsaPrivateKey::new(&mut adapter, RSA_KEY_BITS)
            .map_err(|e| LocalIdpKeyError::KeyGeneration(e.to_string()))?;
        let kid = thumbprint_kid(&format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be()),
        ));
        Ok(Self::from_rsa_private_key(&private_key, kid, algorithm))
    }

    /// Load from a PEM-encoded RSA private key. Accepts both
    /// PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8
    /// (`-----BEGIN PRIVATE KEY-----`) wrappings; the choice is
    /// auto-detected from the PEM header.
    ///
    /// Use this when the test fixture should reuse a key across
    /// runs (faster startup, stable signatures for cached
    /// expectations); check the key into the test tree or load
    /// from an environment variable.
    pub fn from_rsa_pem(
        pem: &str,
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        check_rsa_alg(algorithm)?;
        let pem_trimmed = pem.trim_start();
        let private_key = if pem_trimmed.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
            RsaPrivateKey::from_pkcs1_pem(pem)
                .map_err(|e| LocalIdpKeyError::PemParse(e.to_string()))?
        } else {
            RsaPrivateKey::from_pkcs8_pem(pem)
                .map_err(|e| LocalIdpKeyError::PemParse(e.to_string()))?
        };
        Self::from_imported_rsa_key(&private_key, key_id.into(), algorithm)
    }

    /// Load from a PKCS#1 DER-encoded RSA private key.
    pub fn from_rsa_pkcs1_der(
        der: &[u8],
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        check_rsa_alg(algorithm)?;
        let private_key = RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|e| LocalIdpKeyError::DerParse(e.to_string()))?;
        Self::from_imported_rsa_key(&private_key, key_id.into(), algorithm)
    }

    /// Load from a PKCS#8 DER-encoded RSA private key.
    pub fn from_rsa_pkcs8_der(
        der: &[u8],
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        check_rsa_alg(algorithm)?;
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| LocalIdpKeyError::DerParse(e.to_string()))?;
        Self::from_imported_rsa_key(&private_key, key_id.into(), algorithm)
    }

    /// Wrap imported RSA key material, refusing a modulus under
    /// [`RSA_MIN_BITS`]: an imported key is whatever the file held.
    fn from_imported_rsa_key(
        private_key: &RsaPrivateKey,
        key_id: String,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        let bits = private_key.n().bits();
        if bits < RSA_MIN_BITS {
            return Err(LocalIdpKeyError::WeakKey {
                bits,
                min: RSA_MIN_BITS,
            });
        }
        Ok(Self::from_rsa_private_key(private_key, key_id, algorithm))
    }

    fn from_rsa_private_key(
        private_key: &RsaPrivateKey,
        key_id: String,
        algorithm: Algorithm,
    ) -> Self {
        let public_key = private_key.to_public_key();
        let pkcs1_der = private_key
            .to_pkcs1_der()
            .expect("PKCS#1 DER encode never fails on valid RSA key")
            .as_bytes()
            .to_vec();
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let jwk = build_rsa_jwk(&key_id, algorithm, &n, &e);
        Self {
            encoding: EncodingKey::from_rsa_der(&pkcs1_der),
            material: LocalIdpKeyMaterial::Rsa { pkcs1_der },
            jwk,
            key_id,
            algorithm,
        }
    }

    /// Generate a fresh P-256 keypair under `ES256` with the default
    /// key id. EC key generation is much faster than RSA (~1 ms vs
    /// ~50-200 ms), and the resulting tokens are smaller; adopters
    /// targeting cloud-STS endpoints (which expect ES256-shaped
    /// tokens) or FAPI 2.0 (which mandates ES256/PS256) reach for
    /// this in preference to [`Self::generate_rsa`].
    pub fn generate_es256() -> Self {
        Self::generate_es256_with_rng(&axess_rng::SystemRng)
    }

    /// Like [`Self::generate_es256`] but drives keygen with the supplied
    /// [`SecureRng`](axess_rng::SecureRng), enabling
    /// deterministic-simulation tests to reproduce key material.
    pub fn generate_es256_with_rng(rng: &dyn axess_rng::SecureRng) -> Self {
        let mut adapter = SecureRngAdapter(rng);
        let secret = EcSecretKey::random(&mut adapter);
        let point = secret.public_key().to_encoded_point(false);
        let (x, y) = (
            point.x().expect("uncompressed P-256 point has x"),
            point.y().expect("uncompressed P-256 point has y"),
        );
        let kid = thumbprint_kid(&format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x.as_slice()),
            URL_SAFE_NO_PAD.encode(y.as_slice()),
        ));
        Self::from_ec_secret_key(&secret, kid, Algorithm::ES256)
    }

    /// Load an EC private key from PEM. Accepts PKCS#8
    /// (`-----BEGIN PRIVATE KEY-----`) or SEC1
    /// (`-----BEGIN EC PRIVATE KEY-----`); the choice is auto-detected
    /// from the PEM header.
    ///
    /// Currently only `ES256` (P-256) is supported.
    pub fn from_ec_pem(
        pem: &str,
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        check_ec_alg(algorithm)?;
        let pem_trimmed = pem.trim_start();
        let secret = if pem_trimmed.starts_with("-----BEGIN EC PRIVATE KEY-----") {
            // SEC1; `p256::SecretKey` reads it via `from_sec1_pem`.
            use p256::elliptic_curve::pkcs8::DecodePrivateKey as _;
            EcSecretKey::from_sec1_pem(pem)
                .or_else(|_| EcSecretKey::from_pkcs8_pem(pem))
                .map_err(|e| LocalIdpKeyError::PemParse(e.to_string()))?
        } else {
            EcSecretKey::from_pkcs8_pem(pem)
                .map_err(|e| LocalIdpKeyError::PemParse(e.to_string()))?
        };
        Ok(Self::from_ec_secret_key(&secret, key_id.into(), algorithm))
    }

    /// Load an EC private key from PKCS#8 DER bytes.
    pub fn from_ec_pkcs8_der(
        der: &[u8],
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        check_ec_alg(algorithm)?;
        let secret = EcSecretKey::from_pkcs8_der(der)
            .map_err(|e| LocalIdpKeyError::DerParse(e.to_string()))?;
        Ok(Self::from_ec_secret_key(&secret, key_id.into(), algorithm))
    }

    /// Load an EC private key from SEC1 DER bytes.
    pub fn from_ec_sec1_der(
        der: &[u8],
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        check_ec_alg(algorithm)?;
        let secret = EcSecretKey::from_sec1_der(der)
            .map_err(|e| LocalIdpKeyError::DerParse(e.to_string()))?;
        Ok(Self::from_ec_secret_key(&secret, key_id.into(), algorithm))
    }

    fn from_ec_secret_key(secret: &EcSecretKey, key_id: String, algorithm: Algorithm) -> Self {
        let pkcs8_der = secret
            .to_pkcs8_der()
            .expect("PKCS#8 DER encode never fails on valid P-256 key")
            .as_bytes()
            .to_vec();
        let public = secret.public_key();
        let point = public.to_encoded_point(false);
        let x = point.x().expect("uncompressed P-256 point has x");
        let y = point.y().expect("uncompressed P-256 point has y");
        let x_b64 = URL_SAFE_NO_PAD.encode(x.as_slice());
        let y_b64 = URL_SAFE_NO_PAD.encode(y.as_slice());
        let jwk = build_ec_jwk(&key_id, algorithm, &x_b64, &y_b64);
        Self {
            encoding: EncodingKey::from_ec_der(&pkcs8_der),
            material: LocalIdpKeyMaterial::Ec { pkcs8_der },
            jwk,
            key_id,
            algorithm,
        }
    }

    /// Borrow the key id (`kid`); appears in both the JWK and the
    /// header of every JWT this key signs.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Borrow the JWS algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Borrow the public JWK. Use this to feed a multi-key JWKS
    /// when (in the future) a fixture carries multiple signing
    /// keys for rotation scenarios.
    pub fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Return a copy of this key with the key id replaced.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        let key_id = key_id.into();
        if let Some(jwk_common) = self.jwk.common.key_id.as_mut() {
            *jwk_common = key_id.clone();
        } else {
            self.jwk.common.key_id = Some(key_id.clone());
        }
        self.key_id = key_id;
        self
    }

    /// The signing key, built once when this value was constructed.
    pub(crate) fn encoding_key(&self) -> &EncodingKey {
        &self.encoding
    }
}

fn check_rsa_alg(algorithm: Algorithm) -> Result<(), LocalIdpKeyError> {
    if matches!(
        algorithm,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
    ) {
        Ok(())
    } else {
        Err(LocalIdpKeyError::UnsupportedAlgorithm(format!(
            "{algorithm:?} (RSA constructors support RS256, RS384, RS512)"
        )))
    }
}

fn check_ec_alg(algorithm: Algorithm) -> Result<(), LocalIdpKeyError> {
    if matches!(algorithm, Algorithm::ES256) {
        Ok(())
    } else {
        Err(LocalIdpKeyError::UnsupportedAlgorithm(format!(
            "{algorithm:?} (EC constructors support ES256)"
        )))
    }
}

pub(crate) fn build_rsa_jwk(key_id: &str, algorithm: Algorithm, n: &str, e: &str) -> Jwk {
    let alg_name = alg_jwk_name(algorithm).unwrap_or_else(|| {
        panic!(
            "build_rsa_jwk called with unsupported algorithm {algorithm:?}; \
             only RS256/RS384/RS512 are supported (check_rsa_alg upstream)"
        )
    });
    let jwk_json = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": alg_name,
        "kid": key_id,
        "n": n,
        "e": e,
    });
    serde_json::from_value(jwk_json).expect("hand-constructed JWK JSON parses")
}

pub(crate) fn build_ec_jwk(key_id: &str, algorithm: Algorithm, x: &str, y: &str) -> Jwk {
    let alg_name = alg_jwk_name(algorithm).unwrap_or_else(|| {
        panic!(
            "build_ec_jwk called with unsupported algorithm {algorithm:?}; \
             only ES256 is supported (check_ec_alg upstream)"
        )
    });
    let crv = ec_curve_name(algorithm).unwrap_or_else(|| {
        panic!(
            "build_ec_jwk called with non-EC algorithm {algorithm:?}; \
             only ES256 (P-256) is supported (check_ec_alg upstream)"
        )
    });
    let jwk_json = serde_json::json!({
        "kty": "EC",
        "use": "sig",
        "alg": alg_name,
        "kid": key_id,
        "crv": crv,
        "x": x,
        "y": y,
    });
    serde_json::from_value(jwk_json).expect("hand-constructed JWK JSON parses")
}

/// Returns the JWK `alg` field name for supported JWS algorithms, or
/// `None` for algorithms outside the RSA/EC subset axess accepts. Total
/// function; callers handle `None` with a clear panic or error.
fn alg_jwk_name(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::RS256 => Some("RS256"),
        Algorithm::RS384 => Some("RS384"),
        Algorithm::RS512 => Some("RS512"),
        Algorithm::ES256 => Some("ES256"),
        _ => None,
    }
}

/// Returns the JWK `crv` field for EC algorithms, or `None` for any
/// non-EC algorithm.
fn ec_curve_name(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::ES256 => Some("P-256"),
        _ => None,
    }
}

/// Map a JWK-declared algorithm (RFC 7517 `alg` field, surfaced by
/// `jsonwebtoken` as [`jsonwebtoken::jwk::KeyAlgorithm`]) into the
/// [`Algorithm`] used by [`jsonwebtoken::Validation`]. Returns `None`
/// for non-JWS algorithms (e.g. `RSA-OAEP*` encryption variants) so
/// they're silently skipped by
/// [`LocalIdpFixture::verifier_algorithms`](crate::testing::local_idp::LocalIdpFixture::verifier_algorithms).
pub(crate) fn key_algorithm_to_algorithm(ka: jsonwebtoken::jwk::KeyAlgorithm) -> Option<Algorithm> {
    match format!("{ka}").as_str() {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EdDSA" => Some(Algorithm::EdDSA),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "HS256" => Some(Algorithm::HS256),
        "HS384" => Some(Algorithm::HS384),
        "HS512" => Some(Algorithm::HS512),
        _ => None,
    }
}

/// Error from constructing a [`LocalIdpSigningKey`] from
/// adopter-supplied key material.
#[derive(Debug, thiserror::Error)]
pub enum LocalIdpKeyError {
    /// PEM decode / parse failed.
    #[error("PEM parse failed: {0}")]
    PemParse(String),
    /// DER decode / parse failed.
    #[error("DER parse failed: {0}")]
    DerParse(String),
    /// The algorithm is not one this key type can sign with.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The RSA modulus is shorter than the minimum accepted.
    #[error("RSA key is {bits} bits; at least {min} are required")]
    WeakKey {
        /// Modulus length of the rejected key.
        bits: usize,
        /// Minimum accepted modulus length.
        min: usize,
    },
    /// The keypair could not be generated (the RNG or the RSA library
    /// refused).
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
}

#[cfg(any(test, feature = "testing"))]
pub(crate) fn rebuild_jwks(
    current: &LocalIdpSigningKey,
    historical: &[LocalIdpSigningKey],
    extra: &[Jwk],
) -> JwkSet {
    let mut keys = Vec::with_capacity(1 + historical.len() + extra.len());
    keys.push(current.jwk.clone());
    keys.extend(historical.iter().map(|k| k.jwk.clone()));
    keys.extend(extra.iter().cloned());
    JwkSet { keys }
}

mod claims;
mod issuance;

pub use claims::MintClaims;
pub(crate) use claims::build_claims_json;
#[cfg(any(test, feature = "testing"))]
pub(crate) use issuance::enforce_max_ttl;
pub use issuance::{IssuanceEvent, IssuanceListener};
pub(crate) use issuance::{TtlRefusal, enforce_max_ttl_fallible};

mod rng_adapter;
use rng_adapter::SecureRngAdapter;

#[cfg(test)]
mod primitives_tests;
