//! RSA keys for the local IdP (feature `local-idp-rsa`): key generation
//! and PKCS#1 / PKCS#8 parsing for `RS256`, `RS384` and `RS512`.
//!
//! This is the one module of the crate that names the `rsa` crate. It uses
//! it to generate a key, to parse one and to read the public parts for the
//! JWK; none of these is a private-key operation. A signature is made by
//! `jsonwebtoken` from the DER bytes kept here: in `rsa` 0.9 under
//! `jwt-rust-crypto` alone, which is the code RUSTSEC-2023-0071 describes,
//! and in aws-lc-rs under `jwt-aws-lc` (`deny.toml` has the whole account).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use zeroize::Zeroizing;

use super::{LocalIdpKeyError, LocalIdpSigningKey, SecureRngAdapter, alg_jwk_name, thumbprint_kid};

const RSA_KEY_BITS: usize = 2048;
/// Smallest RSA modulus accepted from imported key material.
const RSA_MIN_BITS: usize = 2048;

impl LocalIdpSigningKey {
    /// Generate a fresh RSA-2048 keypair under `RS256` with the
    /// default key id. Key generation takes ~50-200 ms; expensive to
    /// run per-test, so reuse via `Clone` across cases.
    ///
    /// Prefer [`Self::generate_es256`]: it is faster and its tokens are
    /// smaller. Where an RSA signature is computed depends on the JWT
    /// backend. Under `jwt-rust-crypto` alone it runs in `rsa` 0.9, whose
    /// private-key operations leak timing (RUSTSEC-2023-0071, the Marvin
    /// attack; fixed in `rsa` 0.10.0, which `jsonwebtoken` does not accept
    /// yet). Under `jwt-aws-lc` it runs in aws-lc-rs. Use RSA only when a
    /// verifier cannot take ES256, and then on `jwt-aws-lc` wherever
    /// someone else can time the signing.
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
        let pkcs1_der = Zeroizing::new(
            private_key
                .to_pkcs1_der()
                .expect("PKCS#1 DER encode never fails on valid RSA key")
                .as_bytes()
                .to_vec(),
        );
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let jwk = build_rsa_jwk(&key_id, algorithm, &n, &e);
        Self {
            encoding: EncodingKey::from_rsa_der(&pkcs1_der),
            private_der: pkcs1_der,
            jwk,
            key_id,
            algorithm,
        }
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

fn build_rsa_jwk(key_id: &str, algorithm: Algorithm, n: &str, e: &str) -> Jwk {
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

// `rsa` 0.9 draws from `rand_core` 0.6; `p256` draws from 0.10, and that half
// of the bridge is beside the adapter.
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
mod tests;
