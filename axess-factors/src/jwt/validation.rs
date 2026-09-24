//! JWT signature verification against a JWKS key set.
//!
//! Public surface for adopters that need to verify a JWT against an
//! externally supplied JWKS (workload identity, federated OIDC, custom
//! logout flows). Algorithm allowlist excludes symmetric (`HS*`) and
//! `none` by design.
//!
//! # DST
//!
//! [`verify_jwt`] accepts a [`axess_clock::Clock`] and
//! validates `exp` / `nbf` manually against it, with
//! `jsonwebtoken`'s internal `SystemTime::now()`-based exp/nbf checks
//! disabled. This lets a `MockClock` drive the time path under
//! deterministic-simulation tests: advance the clock past `exp` and
//! verify rejection without relying on real wall-clock latency.
//!
//! The simpler [`verify_jwt_signature`] wrapper defaults to
//! [`axess_clock::SystemClock`] so existing
//! callers that don't need DST keep their signature unchanged.

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use axess_clock::{Clock, SystemClock};

/// Default allowed asymmetric algorithms for JWT verification.
///
/// Covers the two most common asymmetric families issued by mainstream
/// IdPs: RSA-PKCS#1-v1.5 (`RS*`) and ECDSA over the NIST curves (`ES256`,
/// `ES384`). Symmetric (`HS*`) and `none` are excluded by design: the
/// former requires shared-secret distribution that defeats the JWKS
/// model, and the latter has been a recurring source of CVEs.
///
/// **RSA-PSS (`PS256` / `PS384` / `PS512`) and Ed25519 (`EdDSA`) are
/// also asymmetric and well-supported by `jsonwebtoken`, but are
/// excluded from the default to keep the parsed-token attack surface
/// small.** Adopters that need them (notably FAPI 2.0 deployments,
/// which prefer PSS, and Microsoft Entra in some configurations) can
/// opt in per verifier via
/// [`JwtVerifier::with_algorithms`](crate::jwt::verifier::JwtVerifier::with_algorithms),
/// e.g. `JwtVerifier::new().with_algorithms([Algorithm::PS256, Algorithm::ES256])`.
pub const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Errors from JWT signature verification.
///
/// Deliberately free of any OAuth types so this module stays reusable
/// outside the OAuth feature path.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// The JWT header could not be decoded.
    #[error("invalid JWT header: {0}")]
    InvalidHeader(String),

    /// The JWT's algorithm is not in the caller's allowlist.
    #[error("disallowed JWT algorithm: {0:?}")]
    DisallowedAlgorithm(Algorithm),

    /// The JWT has no `kid` header field.
    #[error("JWT has no `kid` header")]
    MissingKid,

    /// No key in the JWKS matches the JWT's `kid`.
    #[error("no key in JWKS matching kid `{0}`")]
    UnknownKid(String),

    /// The JWK's declared algorithm does not match the JWT header's algorithm.
    #[error("JWT header alg {header_alg:?} does not match JWK alg {jwk_alg}")]
    AlgorithmMismatch {
        /// Algorithm declared in the JWT header.
        header_alg: Algorithm,
        /// Algorithm declared on the matched JWK (RFC 7517 `alg` member).
        jwk_alg: String,
    },

    /// Failed to construct a decoding key from the JWK.
    #[error("failed to build key from JWK: {0}")]
    KeyConstruction(String),

    /// The JWT signature or claim validation failed.
    #[error("JWT verification failed: {0}")]
    VerificationFailed(String),
}

/// Caller-tunable claim validation knobs consumed by [`verify_jwt`].
///
/// Constructed via [`ValidationConfig::new`] (sensible defaults) or by
/// the [`crate::jwt::verifier::JwtVerifier`] builder for richer
/// fluent configuration.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Expected `iss` claim. When `Some`, mismatch is rejected.
    pub issuer: Option<String>,
    /// Expected `aud` claim. When `Some`, jsonwebtoken validates the
    /// audience against this value.
    pub audience: Option<String>,
    /// Clock-skew tolerance for `exp` and `nbf` (jsonwebtoken's `leeway`).
    /// Default: 60 seconds.
    pub leeway_secs: u64,
    /// When `true`, a token missing `nbf` is rejected. (jsonwebtoken
    /// validates `nbf` when present but does not require it.)
    pub require_nbf: bool,
}

impl ValidationConfig {
    /// Default-tuned config: 60 s leeway, no iss/aud pinning, nbf optional.
    pub fn new() -> Self {
        Self {
            issuer: None,
            audience: None,
            leeway_secs: 60,
            require_nbf: false,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a JWT signature against a JWKS key set.
///
/// Returns the decoded claims on success. Reusable across OAuth logout,
/// backchannel logout, and future bearer token middleware.
///
/// When `expected_audience` is `Some`, the `aud` claim is validated against
/// it by `jsonwebtoken`. When `None`, audience validation is disabled.
///
/// **Clock**: defaults to [`SystemClock`] for the wall-clock-driven
/// callers (today's bearer / OAuth back-channel logout). DST-driven
/// callers should use [`verify_jwt`] with an injected [`Clock`]
/// or the [`crate::jwt::verifier::JwtVerifier`] builder
/// with `with_clock`.
///
/// For richer claim validation (issuer pinning, configurable clock skew,
/// `nbf` requirement), use [`verify_jwt`] directly with a
/// [`ValidationConfig`] or the [`crate::jwt::verifier::JwtVerifier`]
/// builder.
pub fn verify_jwt_signature(
    token: &str,
    jwks: &JwkSet,
    expected_audience: Option<&str>,
    allowed_algorithms: &[Algorithm],
) -> Result<serde_json::Value, JwtError> {
    let mut config = ValidationConfig::new();
    config.audience = expected_audience.map(String::from);
    verify_jwt(token, jwks, &config, allowed_algorithms, &SystemClock)
}

/// Verify a JWT signature and validate registered claims per the
/// supplied [`ValidationConfig`] against an injected [`Clock`].
///
/// Adds four knobs over [`verify_jwt_signature`]:
/// 1. **Issuer pinning**: when `config.issuer` is `Some`, `iss` mismatch is rejected.
/// 2. **Clock skew**: `config.leeway_secs` is applied to `exp` and `nbf`.
/// 3. **`nbf` requirement**: when `config.require_nbf` is `true`, a token without
///    `nbf` is rejected.
/// 4. **Injected clock**: `exp` / `nbf` are validated against
///    `clock.now()`, *not* `SystemTime::now()`. Pass a
///    `MockClock` (via the local
///    [`axess_clock::Clock`] re-export) to drive the time
///    path deterministically under DST tests. `jsonwebtoken`'s own
///    internal `exp`/`nbf` checks are disabled when this function calls
///    `decode`, so the only time signal is the injected `Clock`.
pub fn verify_jwt(
    token: &str,
    jwks: &JwkSet,
    config: &ValidationConfig,
    allowed_algorithms: &[Algorithm],
    clock: &dyn Clock,
) -> Result<serde_json::Value, JwtError> {
    // 0. A provider, before anything asks jsonwebtoken to verify: with both
    // backends compiled in it has no default and panics. See
    // `crate::jwt::ensure_crypto_provider`.
    crate::jwt::ensure_crypto_provider();

    // 1. Decode header (no signature check).
    let header = decode_header(token).map_err(|e| JwtError::InvalidHeader(format!("{e}")))?;

    // 2. Check algorithm against allowlist.
    if !allowed_algorithms.contains(&header.alg) {
        return Err(JwtError::DisallowedAlgorithm(header.alg));
    }

    // 3. Look up kid in JWKS.
    let kid = header.kid.as_deref().ok_or(JwtError::MissingKid)?;

    let jwk = jwks
        .find(kid)
        .ok_or_else(|| JwtError::UnknownKid(kid.to_string()))?;

    // Defense in depth: if the JWK itself declares an algorithm (RFC 7517
    // `alg` member), require the header's alg to match it. Prevents key
    // confusion attacks across a rotating JWKS that mixes RSA and EC keys.
    if let Some(jwk_alg) = jwk.common.key_algorithm
        && format!("{jwk_alg}") != format!("{:?}", header.alg)
    {
        return Err(JwtError::AlgorithmMismatch {
            header_alg: header.alg,
            jwk_alg: format!("{jwk_alg}"),
        });
    }

    // 4. Build DecodingKey + Validation.
    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|e| JwtError::KeyConstruction(format!("{e}")))?;

    let mut validation = Validation::new(header.alg);
    // jsonwebtoken 10.x requires all algorithms in the Validation list to share
    // the same family as the verifying key. Filter the caller's allowlist to the
    // header algorithm's family so mixed RSA+EC allowlists don't trip the check.
    let family = header.alg.family();
    validation.algorithms = allowed_algorithms
        .iter()
        .copied()
        .filter(|a| a.family() == family)
        .collect();

    if let Some(aud) = config.audience.as_deref() {
        validation.set_audience(&[aud]);
        validation.validate_aud = true;
    } else {
        validation.validate_aud = false;
    }

    if let Some(iss) = config.issuer.as_deref() {
        validation.set_issuer(&[iss]);
    }

    // Disable jsonwebtoken's internal `exp` / `nbf` checks. They run
    // against `SystemTime::now()` which is not DST-injectable; we
    // re-implement those checks against the caller-supplied `clock`
    // below so MockClock-driven tests can exercise the time path.
    // `leeway` is still set so callers reading the `Validation` struct
    // see the intended clock-skew value, but it does nothing while
    // validate_exp / validate_nbf are false.
    validation.leeway = config.leeway_secs;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims.clear();

    // 5. decode() with signature verification (exp/nbf checks disabled
    //    per above; we do them manually below against the injected clock).
    let token_data = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| JwtError::VerificationFailed(format!("{e}")))?;

    // 6. manual exp/nbf validation against the injected clock.
    //    `leeway_secs` is `u64` and `exp` / `nbf` are `i64` Unix seconds.
    //    Cast saturating to avoid the pathological-large-leeway overflow
    //    where `u64::MAX as i64` would be negative.
    let now = clock.now().timestamp();
    let leeway: i64 = i64::try_from(config.leeway_secs).unwrap_or(i64::MAX);

    if let Some(exp) = token_data.claims.get("exp").and_then(|v| v.as_i64()) {
        // Expired iff now is strictly past (exp + leeway). Equality is
        // allowed for tokens issued at the boundary.
        if now > exp.saturating_add(leeway) {
            return Err(JwtError::VerificationFailed("token expired".to_string()));
        }
    }

    match token_data.claims.get("nbf").and_then(|v| v.as_i64()) {
        Some(nbf) if now < nbf.saturating_sub(leeway) => {
            return Err(JwtError::VerificationFailed(
                "token not yet valid".to_string(),
            ));
        }
        Some(_) => {}
        None if config.require_nbf => {
            return Err(JwtError::VerificationFailed(
                "missing required nbf claim".to_string(),
            ));
        }
        None => {}
    }

    Ok(token_data.claims)
}

#[cfg(test)]
mod jwt_validation_tests;
