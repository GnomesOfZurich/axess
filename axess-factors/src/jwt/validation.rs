//! JWT signature verification against a JWKS key set.
//!
//! Public surface for adopters that need to verify a JWT against an
//! externally supplied JWKS (workload identity, federated OIDC, custom
//! logout flows). Algorithm allowlist excludes symmetric (`HS*`) and
//! `none` by design, and [`verify_jwt`] refuses `HS*` even when a caller
//! puts one in the allowlist. A JWK marked `use: enc` is not a signature key
//! and is refused.
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
//! Every production caller passes its own clock to [`verify_jwt`]; the
//! wall-clock convenience wrapper exists only for this crate's tests.

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use axess_clock::Clock;

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

/// Whether `alg` is an HMAC algorithm (`HS256`, `HS384`, `HS512`).
fn is_symmetric(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

/// Most bytes of a `kid` that [`JwtError::UnknownKid`] carries.
pub const MAX_KID_ECHO_BYTES: usize = 128;

/// `kid` cut to [`MAX_KID_ECHO_BYTES`] bytes at a character boundary, with an
/// ellipsis when anything was dropped.
fn truncate_kid(kid: &str) -> String {
    if kid.len() <= MAX_KID_ECHO_BYTES {
        return kid.to_string();
    }
    let mut end = MAX_KID_ECHO_BYTES;
    while !kid.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &kid[..end])
}

/// Errors from JWT signature verification.
///
/// Deliberately free of any OAuth types so this module stays reusable
/// outside the OAuth feature path.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// The token is longer than [`MAX_JWT_BYTES`](super::claims::MAX_JWT_BYTES).
    /// Refused before any decoding, so a crafted multi-megabyte token costs
    /// nothing but its length check.
    #[error("JWT too large ({len} bytes, max {max})")]
    TooLarge {
        /// Length of the token in bytes.
        len: usize,
        /// The limit it exceeded.
        max: usize,
    },

    /// The JWT header could not be decoded.
    #[error("invalid JWT header: {0}")]
    InvalidHeader(String),

    /// The JWT's algorithm is not in the caller's allowlist.
    #[error("disallowed JWT algorithm: {0:?}")]
    DisallowedAlgorithm(Algorithm),

    /// The JWT has no `kid` header field.
    #[error("JWT has no `kid` header")]
    MissingKid,

    /// No key in the JWKS matches the JWT's `kid`. The `kid` is cut to
    /// [`MAX_KID_ECHO_BYTES`] bytes: it is attacker-supplied and ends up in
    /// logs and error responses.
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
    /// When `true` (the default), a token without an `exp` claim is
    /// rejected. A token that never expires is a credential with no end,
    /// and a replay store cannot bound it; only a caller that has another
    /// bound on the token's life turns this off.
    pub require_exp: bool,
}

impl ValidationConfig {
    /// Default-tuned config: 60 s leeway, no iss/aud pinning, nbf optional,
    /// exp required.
    pub fn new() -> Self {
        Self {
            issuer: None,
            audience: None,
            leeway_secs: 60,
            require_nbf: false,
            require_exp: true,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a JWT signature against a JWKS key set on the wall clock.
///
/// Test-only convenience over [`verify_jwt`] with a default
/// [`ValidationConfig`] and [`axess_clock::SystemClock`]. Production code
/// calls [`verify_jwt`] with the clock it was configured with, so a
/// `MockClock` governs `exp` and `nbf` on every path.
#[cfg(test)]
pub(crate) fn verify_jwt_signature(
    token: &str,
    jwks: &JwkSet,
    expected_audience: Option<&str>,
    allowed_algorithms: &[Algorithm],
) -> Result<serde_json::Value, JwtError> {
    let mut config = ValidationConfig::new();
    config.audience = expected_audience.map(String::from);
    verify_jwt(
        token,
        jwks,
        &config,
        allowed_algorithms,
        &axess_clock::SystemClock,
    )
}

/// Verify a JWT signature and validate registered claims per the
/// supplied [`ValidationConfig`] against an injected [`Clock`].
///
/// Beyond signature verification it adds four knobs:
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

    // The size bound comes first: every later step allocates in proportion
    // to the token.
    if token.len() > super::claims::MAX_JWT_BYTES {
        return Err(JwtError::TooLarge {
            len: token.len(),
            max: super::claims::MAX_JWT_BYTES,
        });
    }

    // 1. Decode header (no signature check).
    let header = decode_header(token).map_err(|e| JwtError::InvalidHeader(format!("{e}")))?;

    // 2. Check algorithm against allowlist. A symmetric algorithm is refused
    // whatever the allowlist says: a JWKS is public, so an HMAC key in it
    // verifies for anyone who can read the set and forge for anyone who can
    // write it, and the key-confusion attacks all start from an HS* token
    // verified with a key meant for RS*/ES*.
    if !allowed_algorithms.contains(&header.alg) || is_symmetric(header.alg) {
        return Err(JwtError::DisallowedAlgorithm(header.alg));
    }

    // 3. Look up kid in JWKS.
    let kid = header.kid.as_deref().ok_or(JwtError::MissingKid)?;

    let jwk = jwks
        .find(kid)
        .ok_or_else(|| JwtError::UnknownKid(truncate_kid(kid)))?;

    // A key published for another use (`enc`) is not a signature key
    // (RFC 7517 §4.2). An absent `use` is unrestricted and passes.
    if let Some(key_use) = &jwk.common.public_key_use
        && !matches!(key_use, jsonwebtoken::jwk::PublicKeyUse::Signature)
    {
        return Err(JwtError::KeyConstruction(
            "the JWK is not marked for signature use (`use` is not `sig`)".to_string(),
        ));
    }

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
    // jsonwebtoken checks a pinned `iss` or `aud` only when the claim is
    // PRESENT; a token signed by the trusted key with the claim stripped
    // would pass the pin. A pinned claim is therefore a required one.
    if config.issuer.is_some() {
        validation.required_spec_claims.insert("iss".to_string());
    }
    if config.audience.is_some() {
        validation.required_spec_claims.insert("aud".to_string());
    }

    // 5. decode() with signature verification (exp/nbf checks disabled
    //    per above; we do them manually below against the injected clock).
    let token_data = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| JwtError::VerificationFailed(format!("{e}")))?;

    check_time_claims(&token_data.claims, config, clock)?;

    Ok(token_data.claims)
}

/// Manual `exp` / `nbf` validation against the injected clock.
///
/// `leeway_secs` is `u64` and `exp` / `nbf` are `i64` Unix seconds. The cast
/// saturates to avoid the pathological-large-leeway overflow where
/// `u64::MAX as i64` would be negative.
fn check_time_claims(
    claims: &serde_json::Value,
    config: &ValidationConfig,
    clock: &dyn Clock,
) -> Result<(), JwtError> {
    let now = clock.now().timestamp();
    let leeway: i64 = i64::try_from(config.leeway_secs).unwrap_or(i64::MAX);

    // An `exp` that is present but not an integer (a float, a string) is
    // not "no exp": it is a claim this verifier cannot read, and a token it
    // cannot bound is refused. A missing `exp` is refused unless the caller
    // turned `require_exp` off.
    match claims.get("exp") {
        Some(v) => {
            let exp = v.as_i64().ok_or_else(|| {
                JwtError::VerificationFailed("exp claim is not an integer".to_string())
            })?;
            // Expired iff now is strictly past (exp + leeway). Equality is
            // allowed for tokens issued at the boundary.
            if now > exp.saturating_add(leeway) {
                return Err(JwtError::VerificationFailed("token expired".to_string()));
            }
        }
        None if config.require_exp => {
            return Err(JwtError::VerificationFailed(
                "missing required exp claim".to_string(),
            ));
        }
        None => {}
    }

    match claims.get("nbf") {
        Some(v) => {
            let nbf = v.as_i64().ok_or_else(|| {
                JwtError::VerificationFailed("nbf claim is not an integer".to_string())
            })?;
            if now < nbf.saturating_sub(leeway) {
                return Err(JwtError::VerificationFailed(
                    "token not yet valid".to_string(),
                ));
            }
        }
        None if config.require_nbf => {
            return Err(JwtError::VerificationFailed(
                "missing required nbf claim".to_string(),
            ));
        }
        None => {}
    }
    Ok(())
}

#[cfg(test)]
mod jwt_validation_tests;
