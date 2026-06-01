//! Primitives shared between the production [`LocalIdp`](crate::local_idp::LocalIdp)
//! and the test [`LocalIdpFixture`](crate::testing::local_idp::LocalIdpFixture).
//! Token-bearing types (signing key, claim builder), the issuance-listener
//! trait, and small helpers live here so production code does not have to
//! import from `crate::testing`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
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
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_KEY_ID: &str = "local-idp-fixture-key";
pub(crate) const RSA_KEY_BITS: usize = 2048;

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
/// used to populate the fixture's JWKS. Drop redacts the private DER via
/// [`zeroize`].
pub struct LocalIdpSigningKey {
    material: LocalIdpKeyMaterial,
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
    pub fn generate_rsa() -> Self {
        Self::generate_rsa_with_algorithm(Algorithm::RS256)
    }

    /// Generate a fresh RSA-2048 keypair under the given algorithm
    /// (`RS256` / `RS384` / `RS512`). Panics on other algorithms.
    pub fn generate_rsa_with_algorithm(algorithm: Algorithm) -> Self {
        Self::generate_rsa_with_algorithm_and_rng(algorithm, &axess_rng::SystemRng)
    }

    /// Like [`Self::generate_rsa_with_algorithm`] but drives keygen with
    /// the supplied [`SecureRng`](axess_rng::SecureRng), enabling
    /// deterministic-simulation tests to reproduce key material.
    pub fn generate_rsa_with_algorithm_and_rng(
        algorithm: Algorithm,
        rng: &dyn axess_rng::SecureRng,
    ) -> Self {
        assert_rsa_alg(algorithm);
        let mut adapter = SecureRngAdapter(rng);
        let private_key =
            RsaPrivateKey::new(&mut adapter, RSA_KEY_BITS).expect("RSA-2048 key generation");
        Self::from_rsa_private_key(&private_key, DEFAULT_KEY_ID.to_string(), algorithm)
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
        assert_rsa_alg(algorithm);
        let pem_trimmed = pem.trim_start();
        let private_key = if pem_trimmed.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
            RsaPrivateKey::from_pkcs1_pem(pem)
                .map_err(|e| LocalIdpKeyError::PemParse(e.to_string()))?
        } else {
            RsaPrivateKey::from_pkcs8_pem(pem)
                .map_err(|e| LocalIdpKeyError::PemParse(e.to_string()))?
        };
        Ok(Self::from_rsa_private_key(
            &private_key,
            key_id.into(),
            algorithm,
        ))
    }

    /// Load from a PKCS#1 DER-encoded RSA private key.
    pub fn from_rsa_pkcs1_der(
        der: &[u8],
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        assert_rsa_alg(algorithm);
        let private_key = RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|e| LocalIdpKeyError::DerParse(e.to_string()))?;
        Ok(Self::from_rsa_private_key(
            &private_key,
            key_id.into(),
            algorithm,
        ))
    }

    /// Load from a PKCS#8 DER-encoded RSA private key.
    pub fn from_rsa_pkcs8_der(
        der: &[u8],
        key_id: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        assert_rsa_alg(algorithm);
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| LocalIdpKeyError::DerParse(e.to_string()))?;
        Ok(Self::from_rsa_private_key(
            &private_key,
            key_id.into(),
            algorithm,
        ))
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
        Self::from_ec_secret_key(&secret, DEFAULT_KEY_ID.to_string(), Algorithm::ES256)
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
        assert_ec_alg(algorithm);
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
        assert_ec_alg(algorithm);
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
        assert_ec_alg(algorithm);
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

    pub(crate) fn encoding_key(&self) -> EncodingKey {
        match &self.material {
            LocalIdpKeyMaterial::Rsa { pkcs1_der } => EncodingKey::from_rsa_der(pkcs1_der),
            LocalIdpKeyMaterial::Ec { pkcs8_der } => EncodingKey::from_ec_der(pkcs8_der),
        }
    }
}

fn assert_rsa_alg(algorithm: Algorithm) {
    assert!(
        matches!(
            algorithm,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
        ),
        "LocalIdpSigningKey RSA constructors only support RS256/RS384/RS512; got {algorithm:?}"
    );
}

fn assert_ec_alg(algorithm: Algorithm) {
    assert!(
        matches!(algorithm, Algorithm::ES256),
        "LocalIdpSigningKey EC constructors only support ES256 (P-256); got {algorithm:?}"
    );
}

pub(crate) fn build_rsa_jwk(key_id: &str, algorithm: Algorithm, n: &str, e: &str) -> Jwk {
    let alg_name = alg_jwk_name(algorithm).unwrap_or_else(|| {
        panic!(
            "build_rsa_jwk called with unsupported algorithm {algorithm:?}; \
             only RS256/RS384/RS512 are supported (assert_rsa_alg upstream)"
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
             only ES256 is supported (assert_ec_alg upstream)"
        )
    });
    let crv = ec_curve_name(algorithm).unwrap_or_else(|| {
        panic!(
            "build_ec_jwk called with non-EC algorithm {algorithm:?}; \
             only ES256 (P-256) is supported (assert_ec_alg upstream)"
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
}

// ── Issuance audit hook ──────────────────────────────────────────────────────

/// A single mint event observed by an [`IssuanceListener`]. Borrowed
/// fields mirror what the fixture knew at signing time; the listener
/// can copy whichever pieces it needs into its own log type. The
/// signed JWT is **not** included: listeners that need to record
/// per-token state should use [`MintClaims::with_jwt_id`] and key off
/// `claims.jwt_id`.
///
/// `IssuanceEvent` is non-`Clone` and borrows from the fixture's
/// internal state, so listeners must extract owned data inside
/// [`IssuanceListener::on_mint`] rather than retaining the event
/// itself.
#[derive(Debug)]
pub struct IssuanceEvent<'a> {
    /// `iss` claim: the fixture's configured issuer.
    pub issuer: &'a str,
    /// JWT header `kid`: the signing key's id.
    pub key_id: &'a str,
    /// JWT header `alg`: the signing algorithm in effect.
    pub algorithm: Algorithm,
    /// Caller-supplied claim set (sub, aud, exp, nbf, iat, jti, custom).
    pub claims: &'a MintClaims,
}

/// Adopter-supplied callback fired after every successful mint.
/// Models the production-side audit log boundary: adopters writing
/// integration tests against axess can assert on issuance behaviour
/// (count, subject, audience, lifetime) without parsing the resulting
/// JWT.
///
/// The listener fires **after** the token is signed but **before**
/// [`LocalIdpFixture::mint`](crate::testing::local_idp::LocalIdpFixture::mint)
/// returns. Mints that violate the fixture's
/// [`with_max_ttl`](crate::testing::local_idp::LocalIdpFixture::with_max_ttl)
/// cap panic before reaching the listener, so the listener only sees mints
/// the fixture actually issued.
///
/// Implement this trait directly for custom recording shapes, or use
/// the included [`MockIssuanceListener`](crate::testing::local_idp::MockIssuanceListener)
/// for the common "capture everything, assert later" pattern.
pub trait IssuanceListener: Send + Sync {
    /// Invoked once per successful mint. Implementations should be
    /// fast and panic-free; the fixture is on the caller's hot path.
    fn on_mint(&self, event: &IssuanceEvent<'_>);
}

/// Panics if the claim set's `exp - iat` (or `exp - now` if `iat` is
/// unset) exceeds `max_ttl`. Called from
/// [`LocalIdpFixture::mint_with_header`](crate::testing::local_idp::LocalIdpFixture::mint_with_header)
/// when the fixture has a TTL policy configured. Reference time picks
/// `iat` when present so adopters with stable test clocks see
/// deterministic behaviour; when `iat` is absent we fall back to
/// `Utc::now()`.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn enforce_max_ttl(claims: &MintClaims, max_ttl: Duration) {
    let reference = claims.issued_at.unwrap_or_else(Utc::now);
    let lifetime = claims.expires_at - reference;
    assert!(
        lifetime <= max_ttl,
        "LocalIdpFixture::mint refusing token with lifetime {lifetime} \
         exceeding the fixture's max_ttl of {max_ttl}. \
         Set MintClaims.expires_at within the cap or relax the policy \
         via `with_max_ttl`.",
    );
}

/// Returns `Err((observed, max))` if the claim set's lifetime exceeds
/// `max_ttl`. Production-side counterpart to [`enforce_max_ttl`];
/// `LocalIdp::mint` surfaces this as `IssuanceError::LifetimeExceedsCap`
/// rather than panicking. Reference time is the supplied `now`
/// (typically `Clock::now()`); the fixture's variant inlines
/// `Utc::now()` for tests that don't inject a clock, while
/// production always has one.
pub(crate) fn enforce_max_ttl_fallible(
    claims: &MintClaims,
    max_ttl: Duration,
    now: DateTime<Utc>,
) -> Result<(), (Duration, Duration)> {
    let reference = claims.issued_at.unwrap_or(now);
    let lifetime = claims.expires_at - reference;
    if lifetime <= max_ttl {
        Ok(())
    } else {
        Err((lifetime, max_ttl))
    }
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

// ── MintClaims ───────────────────────────────────────────────────────────────

/// Builder for the claim set passed to
/// [`LocalIdpFixture::mint`](crate::testing::local_idp::LocalIdpFixture::mint).
///
/// The fixture sets `iss` automatically from its configured issuer.
/// All other claims (sub, aud, exp, nbf, iat, jti, custom) are
/// supplied by the caller via this builder.
#[derive(Debug, Clone)]
pub struct MintClaims {
    /// `sub`: required.
    pub subject: String,
    /// `aud`: empty `Vec` skips the claim; single-element renders
    /// as a string, multi-element as an array (per RFC 7519 §4.1.3).
    pub audience: Vec<String>,
    /// `exp`: required to keep tokens auto-expiring in test runs.
    pub expires_at: DateTime<Utc>,
    /// `nbf`: optional.
    pub not_before: Option<DateTime<Utc>>,
    /// `iat`: optional. Recommended; some verifiers reject tokens
    /// without `iat`.
    pub issued_at: Option<DateTime<Utc>>,
    /// `jti`: optional. Required when feeding a
    /// [`axess_factors::jwt::verifier::JwtVerifier`] configured with a
    /// `JtiReplayStore` (replay protection).
    pub jwt_id: Option<String>,
    /// Extra claims merged into the JSON object alongside the
    /// standard fields. Must be a JSON object; caller-supplied
    /// keys overwrite the standard claims if they collide (`iss`
    /// being the exception: the fixture wins).
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl MintClaims {
    /// Build with the two required claims.
    pub fn new(subject: impl Into<String>, expires_at: DateTime<Utc>) -> Self {
        Self {
            subject: subject.into(),
            audience: Vec::new(),
            expires_at,
            not_before: None,
            issued_at: None,
            jwt_id: None,
            custom: serde_json::Map::new(),
        }
    }

    /// Set a single `aud` value.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = vec![audience.into()];
        self
    }

    /// Set multiple `aud` values (renders as a JSON array).
    pub fn with_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audience = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Set `nbf`.
    pub fn with_not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.not_before = Some(nbf);
        self
    }

    /// Set `iat`.
    pub fn with_issued_at(mut self, iat: DateTime<Utc>) -> Self {
        self.issued_at = Some(iat);
        self
    }

    /// Set `jti`.
    pub fn with_jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jwt_id = Some(jti.into());
        self
    }

    /// Add a single custom claim. Replaces any existing value for
    /// the same key.
    pub fn with_custom_claim(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StandardClaimsView {
    iss: String,
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

pub(crate) fn build_claims_json(issuer: &str, claims: &MintClaims) -> serde_json::Value {
    let aud_value = match claims.audience.as_slice() {
        [] => None,
        [single] => Some(serde_json::Value::String(single.clone())),
        many => Some(serde_json::Value::Array(
            many.iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        )),
    };

    let view = StandardClaimsView {
        iss: issuer.to_string(),
        sub: claims.subject.clone(),
        exp: claims.expires_at.timestamp(),
        aud: aud_value,
        nbf: claims.not_before.map(|t| t.timestamp()),
        iat: claims.issued_at.map(|t| t.timestamp()),
        jti: claims.jwt_id.clone(),
    };

    let mut value = serde_json::to_value(view).expect("StandardClaimsView serialises");
    if let serde_json::Value::Object(ref mut map) = value {
        for (k, v) in &claims.custom {
            // `iss` is fixture-controlled; refuse to let custom
            // claims override it (would make the JWKS-routing
            // semantics break).
            if k == "iss" {
                continue;
            }
            map.insert(k.clone(), v.clone());
        }
    }
    value
}

/// Bridges [`axess_rng::SecureRng`] to the `rand_core::RngCore +
/// CryptoRng` trait pair used by `rsa` and `p256`. Lets keygen run
/// against any DST-injected RNG without depending on `OsRng` directly.
struct SecureRngAdapter<'a>(&'a dyn axess_rng::SecureRng);

impl rsa::rand_core::RngCore for SecureRngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for SecureRngAdapter<'_> {}

#[cfg(test)]
mod primitives_tests {
    use super::*;
    use jsonwebtoken::jwk::KeyAlgorithm;
    use rsa::rand_core::RngCore;

    /// Every JWS algorithm `LocalIdpFixture::verifier_algorithms` is
    /// allowed to surface must round-trip through this mapper. Kills
    /// `delete match arm "<ALG>"` for each algorithm: with the arm gone,
    /// `key_algorithm_to_algorithm` falls through to `_ => None`.
    #[test]
    fn key_algorithm_to_algorithm_covers_every_jws_alg() {
        let cases: &[(KeyAlgorithm, Algorithm)] = &[
            (KeyAlgorithm::RS256, Algorithm::RS256),
            (KeyAlgorithm::RS384, Algorithm::RS384),
            (KeyAlgorithm::RS512, Algorithm::RS512),
            (KeyAlgorithm::ES256, Algorithm::ES256),
            (KeyAlgorithm::ES384, Algorithm::ES384),
            (KeyAlgorithm::EdDSA, Algorithm::EdDSA),
            (KeyAlgorithm::PS256, Algorithm::PS256),
            (KeyAlgorithm::PS384, Algorithm::PS384),
            (KeyAlgorithm::PS512, Algorithm::PS512),
            (KeyAlgorithm::HS256, Algorithm::HS256),
            (KeyAlgorithm::HS384, Algorithm::HS384),
            (KeyAlgorithm::HS512, Algorithm::HS512),
        ];
        for (ka, expected) in cases {
            let got = key_algorithm_to_algorithm(*ka);
            assert_eq!(
                got,
                Some(*expected),
                "key_algorithm_to_algorithm({ka:?}) must yield Some({expected:?})",
            );
        }
    }

    /// `SecureRngAdapter` must forward every RngCore call to its
    /// underlying [`axess_rng::SecureRng`]. Kills `next_u32 -> 0/1`,
    /// `next_u64 -> 0/1`, `try_fill_bytes -> Ok(())` body replacements
    /// by comparing the adapter's output against a separately-seeded
    /// reference `MockRng` driven through the same byte counts.
    #[test]
    fn secure_rng_adapter_forwards_to_inner_rng() {
        use axess_rng::SecureRng;
        use axess_rng::testing::MockRng;

        const SEED: u64 = 0xA110_CA7E_5EED_F00Du64;

        // Reference: feed bytes through MockRng the same way the adapter
        // does and compute expected outputs.
        let reference = MockRng::new(SEED);
        let mut buf = [0u8; 4];
        reference.fill_bytes(&mut buf);
        let expected_u32 = u32::from_le_bytes(buf);
        let mut buf = [0u8; 8];
        reference.fill_bytes(&mut buf);
        let expected_u64 = u64::from_le_bytes(buf);
        let mut expected_fill = [0u8; 32];
        reference.fill_bytes(&mut expected_fill);
        let mut expected_try = [0u8; 32];
        reference.fill_bytes(&mut expected_try);

        // Adapter under test: driven in the same byte order against an
        // identically-seeded MockRng.
        let inner = MockRng::new(SEED);
        let mut adapter = SecureRngAdapter(&inner as &dyn SecureRng);

        let got_u32 = adapter.next_u32();
        assert_eq!(
            got_u32, expected_u32,
            "next_u32 must forward to inner SecureRng (kills `-> 0` and `-> 1`)",
        );

        let got_u64 = adapter.next_u64();
        assert_eq!(
            got_u64, expected_u64,
            "next_u64 must forward to inner SecureRng (kills `-> 0` and `-> 1`)",
        );

        let mut fill = [0u8; 32];
        adapter.fill_bytes(&mut fill);
        assert_eq!(
            fill, expected_fill,
            "fill_bytes must forward to inner SecureRng",
        );

        let mut tried = [0u8; 32];
        adapter
            .try_fill_bytes(&mut tried)
            .expect("try_fill_bytes is infallible against MockRng");
        assert_eq!(
            tried, expected_try,
            "try_fill_bytes must forward to inner SecureRng (kills `-> Ok(())`)",
        );
    }
}
