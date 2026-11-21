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

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode_header};

use super::decode;

use axess_clock::Clock;
use std::time::Duration;

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

/// An unverified `kid` as an error may carry it: every character
/// [`escapes`](crate::log_text::escapes) names (control characters, the line
/// and paragraph separators, bidirectional controls, zero-width characters,
/// the byte order mark, the Hangul fillers) escaped, and the whole cut to
/// [`MAX_KID_ECHO_BYTES`] bytes at a character boundary, the mark of the cut
/// included.
fn echo_kid(kid: &str) -> String {
    crate::log_text::log_safe(kid, MAX_KID_ECHO_BYTES)
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

    /// The JWT has no `kid` header field. Every path refuses such a token
    /// but the JWT-SVID resolver, which tries each key of its trust domain.
    #[error("JWT has no `kid` header")]
    MissingKid,

    /// No key in the JWKS matches the JWT's `kid`. The `kid` is cut to
    /// [`MAX_KID_ECHO_BYTES`] bytes and every character
    /// [`escapes`](crate::log_text::escapes) names (control characters, the
    /// line and paragraph separators, bidirectional controls, zero-width
    /// characters, the byte order mark, the Hangul fillers) is escaped: it is
    /// attacker-supplied and ends up in logs and error responses.
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

/// The widest clock-skew tolerance [`verify_jwt`] accepts for `exp` and
/// `nbf`: five minutes. A larger leeway keeps an expired token valid for as
/// long as the leeway says, so a configuration above it is refused before
/// any token is read. Two clocks more than five minutes apart are fixed
/// where they run, not in the verifier.
pub const MAX_LEEWAY: Duration = Duration::from_secs(300);

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
    /// Default: 60 seconds. A whole number of seconds, as `exp` and `nbf`
    /// are (RFC 7519 NumericDate), and at most [`MAX_LEEWAY`]: [`verify_jwt`]
    /// refuses any other configuration by name.
    pub leeway: Duration,
    /// When `true`, a token missing `nbf` is rejected. (jsonwebtoken
    /// validates `nbf` when present but does not require it.)
    pub require_nbf: bool,
    /// When `true` (the default), a token without an `exp` claim is
    /// rejected. A token that never expires is a credential with no end,
    /// and a replay store cannot bound it; only a caller that has another
    /// bound on the token's life turns this off.
    pub require_exp: bool,
    /// Accept a token for any audience when `audience` is `None`. Off by
    /// default: [`verify_jwt`] refuses a config that pins no audience, since
    /// a token minted for another service of the same issuer would verify.
    /// Set it only for an issuer that mints tokens for this application
    /// alone.
    pub allow_any_audience: bool,
    /// Accept a token from any issuer when `issuer` is `None`. Off by
    /// default: [`verify_jwt`] refuses a config that pins no issuer, since
    /// a token signed by any key in the set would verify whatever it names
    /// as its issuer.
    pub allow_any_issuer: bool,
}

impl ValidationConfig {
    /// Default-tuned config: 60 s leeway, nbf optional, exp required, and
    /// neither `iss` nor `aud` pinned. [`verify_jwt`] refuses that until
    /// both are pinned or [`allow_any_audience`](Self::allow_any_audience)
    /// and [`allow_any_issuer`](Self::allow_any_issuer) say otherwise.
    pub fn new() -> Self {
        Self {
            issuer: None,
            audience: None,
            leeway: Duration::from_secs(60),
            require_nbf: false,
            require_exp: true,
            allow_any_audience: false,
            allow_any_issuer: false,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a JWT signature against a JWKS key set at the reference instant.
///
/// Test-only convenience over [`verify_jwt`] with a default
/// [`ValidationConfig`] and a clock at
/// [`MockClock::reference_time`](axess_clock::testing::MockClock::reference_time). Production code
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
    config.allow_any_audience = true;
    config.allow_any_issuer = true;
    verify_jwt(
        token,
        jwks,
        &config,
        allowed_algorithms,
        &axess_clock::testing::MockClock::at_reference(),
    )
}

/// Verify a JWT signature and validate registered claims per the
/// supplied [`ValidationConfig`] against an injected [`Clock`].
///
/// Refuses a config that pins no audience or no issuer unless its
/// `allow_any_audience` or `allow_any_issuer` is set.
///
/// Beyond signature verification it adds four knobs:
/// 1. **Issuer pinning**: when `config.issuer` is `Some`, `iss` mismatch is rejected.
/// 2. **Clock skew**: `config.leeway` is applied to `exp` and `nbf`.
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
    verify_jwt_with_typ(token, jwks, config, allowed_algorithms, clock, None)
}

/// As [`verify_jwt`], and when `expected_typ` is `Some`, the token's JOSE
/// `typ` header must be that media type.
///
/// The comparison ignores case and a leading `application/` on both sides
/// (RFC 7515 section 4.1.9), so `at+jwt`, `AT+JWT` and `application/at+jwt`
/// are one type. A token with no `typ`, or with another one, is refused with
/// [`JwtError::VerificationFailed`] before its signature is looked at. With
/// `None` the header type is not read, which is what [`verify_jwt`] does.
///
/// A key that signs more than one kind of token (ID tokens, access tokens,
/// logout tokens, DPoP proofs) makes the type the only thing that tells one
/// kind from another (RFC 8725 section 3.11). The values a deployment
/// requires: `at+jwt` for an access token (RFC 9068), `logout+jwt` for a
/// logout token, `dpop+jwt` for a DPoP proof (RFC 9449),
/// `oauth-authz-req+jwt` for a signed authorization request (RFC 9101, which
/// FAPI 2.0 message signing requires) and `token-introspection+jwt` for a
/// signed introspection response (RFC 9701).
pub fn verify_jwt_with_typ(
    token: &str,
    jwks: &JwkSet,
    config: &ValidationConfig,
    allowed_algorithms: &[Algorithm],
    clock: &dyn Clock,
    expected_typ: Option<&str>,
) -> Result<serde_json::Value, JwtError> {
    verify_jwt_choosing(
        token,
        jwks,
        config,
        allowed_algorithms,
        clock,
        expected_typ,
        KeyChoice::ByKid,
    )
}

/// How the key that verifies a token is picked from the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyChoice {
    /// By the token's `kid`, which must be present: every path but the
    /// JWT-SVID resolver's.
    ByKid,
    /// By the token's `kid` when it has one, and the same refusals as
    /// [`ByKid`](Self::ByKid) then. Without one, each key of the set that
    /// could have made the signature is tried in turn: the JWT-SVID standard
    /// (section 2.2) makes `kid` optional, so a validator holding a trust
    /// domain's bundle verifies a token that names none against the bundle.
    #[cfg(feature = "jwt-svid")]
    EachKey,
}

/// The most keys a token without a `kid` is tried against. A key set past
/// it is refused before any signature is checked, so one token costs at
/// most this many verifications. A SPIRE bundle holds one or two keys, a
/// few more while keys rotate.
#[cfg(feature = "jwt-svid")]
pub(crate) const MAX_KEYLESS_KEYS: usize = 32;

/// [`verify_jwt_with_typ`] with the key picked as `choice` says.
pub(crate) fn verify_jwt_choosing(
    token: &str,
    jwks: &JwkSet,
    config: &ValidationConfig,
    allowed_algorithms: &[Algorithm],
    clock: &dyn Clock,
    expected_typ: Option<&str>,
    choice: KeyChoice,
) -> Result<serde_json::Value, JwtError> {
    // The configuration is judged before any token is read.
    refuse_unbounded_config(config)?;

    // The size bound comes first: every later step allocates in proportion
    // to the token.
    if token.len() > super::claims::MAX_JWT_BYTES {
        return Err(JwtError::TooLarge {
            len: token.len(),
            max: super::claims::MAX_JWT_BYTES,
        });
    }

    // 1. Decode header (no signature check).
    let header = decode_header(token)
        .map_err(|e| JwtError::InvalidHeader(crate::remote_text::error_text(&e)))?;

    if let Some(expected) = expected_typ
        && !typ_matches(header.typ.as_deref(), expected)
    {
        return Err(JwtError::VerificationFailed(format!(
            "the JOSE `typ` header is not `{expected}`"
        )));
    }

    // 2. Check algorithm against allowlist. A symmetric algorithm is refused
    // whatever the allowlist says: a JWKS is public, so an HMAC key in it
    // verifies for anyone who can read the set and forge for anyone who can
    // write it, and the key-confusion attacks all start from an HS* token
    // verified with a key meant for RS*/ES*.
    if !allowed_algorithms.contains(&header.alg) || is_symmetric(header.alg) {
        return Err(JwtError::DisallowedAlgorithm(header.alg));
    }

    // 3. The rules every key must meet, whichever picks it.
    let validation = validation_for(header.alg, allowed_algorithms, config);

    // 4. The key, and the signature under it. A token with a `kid` takes
    // the key of that `kid` or none: it never falls through to the others.
    let token_data = match (header.kid.as_deref(), choice) {
        (Some(kid), _) => {
            let jwk = jwks
                .find(kid)
                .ok_or_else(|| JwtError::UnknownKid(echo_kid(kid)))?;
            check_key_for(jwk, header.alg)?;
            let decoding_key = DecodingKey::from_jwk(jwk)
                .map_err(|e| JwtError::KeyConstruction(crate::remote_text::error_text(&e)))?;
            decode::<serde_json::Value>(token, &decoding_key, &validation)
                .map_err(|e| JwtError::VerificationFailed(crate::remote_text::error_text(&e)))?
        }
        (None, KeyChoice::ByKid) => return Err(JwtError::MissingKid),
        #[cfg(feature = "jwt-svid")]
        (None, KeyChoice::EachKey) => decode_with_each_key(token, jwks, header.alg, &validation)?,
    };

    check_time_claims(&token_data.claims, config, clock)?;

    Ok(token_data.claims)
}

/// The key `jwk`, picked by `kid`, may verify a token under `alg`: it is
/// published for signatures, and the algorithm it names, if any, is `alg`.
fn check_key_for(jwk: &Jwk, alg: Algorithm) -> Result<(), JwtError> {
    // A key published for another use (`enc`) is not a signature key
    // (RFC 7517 §4.2). An absent `use` is unrestricted and passes.
    if !published_for_signatures(jwk) {
        return Err(JwtError::KeyConstruction(
            "the JWK is not marked for signature use (`use` is not `sig`)".to_string(),
        ));
    }

    // Defense in depth: if the JWK itself declares an algorithm (RFC 7517
    // `alg` member), require the header's alg to match it. Prevents key
    // confusion attacks across a rotating JWKS that mixes RSA and EC keys.
    if let Some(jwk_alg) = jwk.common.key_algorithm
        && format!("{jwk_alg}") != format!("{alg:?}")
    {
        return Err(JwtError::AlgorithmMismatch {
            header_alg: alg,
            jwk_alg: format!("{jwk_alg}"),
        });
    }
    Ok(())
}

/// Whether `jwk` is published for signatures: its `use` is `sig`, or it has
/// none, which is unrestricted (RFC 7517 section 4.2).
fn published_for_signatures(jwk: &Jwk) -> bool {
    jwk.common
        .public_key_use
        .as_ref()
        .is_none_or(|key_use| matches!(key_use, jsonwebtoken::jwk::PublicKeyUse::Signature))
}

/// A token without a `kid`, verified against each key of `jwks` that could
/// have signed it under `alg`; the first under which it verifies wins.
///
/// The work is bounded before any is done: a set of more than
/// [`MAX_KEYLESS_KEYS`] keys is refused whole. A key is skipped, not
/// refused, when it cannot have made the signature, since the token names
/// none: one published for another use, one whose `alg` member names
/// another algorithm, one whose type or curve does not sign under `alg`,
/// and one `jsonwebtoken` cannot build. When no key verifies, the answer is
/// one refusal that names no key, so the set's contents are not read back
/// one key at a time.
#[cfg(feature = "jwt-svid")]
fn decode_with_each_key(
    token: &str,
    jwks: &JwkSet,
    alg: Algorithm,
    validation: &Validation,
) -> Result<jsonwebtoken::TokenData<serde_json::Value>, JwtError> {
    if jwks.keys.len() > MAX_KEYLESS_KEYS {
        return Err(JwtError::VerificationFailed(format!(
            "the token names no `kid`, and the key set holds more than the \
             {MAX_KEYLESS_KEYS} keys such a token is tried against"
        )));
    }
    let candidates = jwks.keys.iter().filter(|jwk| {
        published_for_signatures(jwk)
            && jwk
                .common
                .key_algorithm
                .is_none_or(|jwk_alg| format!("{jwk_alg}") == format!("{alg:?}"))
            && key_type_signs(jwk, alg)
    });
    for jwk in candidates {
        let Ok(key) = DecodingKey::from_jwk(jwk) else {
            continue;
        };
        if let Ok(data) = decode::<serde_json::Value>(token, &key, validation) {
            return Ok(data);
        }
    }
    Err(JwtError::VerificationFailed(
        "the token names no `kid`, and no key of the set verifies it".to_string(),
    ))
}

/// Whether a key of `jwk`'s type and curve signs under `alg`: RSA for the
/// `RS*` and `PS*` algorithms, P-256 for `ES256`, P-384 for `ES384`, Ed25519
/// for `EdDSA`. Any other pairing cannot have made the signature.
#[cfg(feature = "jwt-svid")]
fn key_type_signs(jwk: &Jwk, alg: Algorithm) -> bool {
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
    match (&jwk.algorithm, alg) {
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
        ) => true,
        (AlgorithmParameters::EllipticCurve(ec), Algorithm::ES256) => {
            ec.curve == EllipticCurve::P256
        }
        (AlgorithmParameters::EllipticCurve(ec), Algorithm::ES384) => {
            ec.curve == EllipticCurve::P384
        }
        (AlgorithmParameters::OctetKeyPair(okp), Algorithm::EdDSA) => {
            okp.curve == EllipticCurve::Ed25519
        }
        _ => false,
    }
}

/// The checks `jsonwebtoken` makes beside the signature for a token under
/// `alg`: the caller's algorithms of that family, the pinned audience and
/// issuer, and no time checks of its own (the injected clock makes them).
fn validation_for(
    alg: Algorithm,
    allowed_algorithms: &[Algorithm],
    config: &ValidationConfig,
) -> Validation {
    let mut validation = Validation::new(alg);
    // jsonwebtoken 10.x requires all algorithms in the Validation list to share
    // the same family as the verifying key. Filter the caller's allowlist to the
    // header algorithm's family so mixed RSA+EC allowlists don't trip the check.
    let family = alg.family();
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
    // against `SystemTime::now()` which is not DST-injectable;
    // `check_time_claims` makes them against the caller-supplied `clock`
    // once a signature verifies, so MockClock-driven tests can exercise
    // the time path.
    // `leeway` is still set so callers reading the `Validation` struct
    // see the intended clock-skew value, but it does nothing while
    // validate_exp / validate_nbf are false.
    validation.leeway = config.leeway.as_secs();
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
    validation
}

/// A media type as RFC 7515 section 4.1.9 compares it: without case, and
/// without a leading `application/`.
fn normalized_typ(typ: &str) -> String {
    let lower = typ.to_ascii_lowercase();
    lower
        .strip_prefix("application/")
        .map(str::to_owned)
        .unwrap_or(lower)
}

/// Whether a header's `typ` (absent: `None`) is the type required, compared
/// as RFC 7515 section 4.1.9 says: without case, and without a leading
/// `application/` on either side. The one comparison of `typ` values in the
/// crate.
pub(crate) fn typ_matches(presented: Option<&str>, expected: &str) -> bool {
    presented.is_some_and(|typ| normalized_typ(typ) == normalized_typ(expected))
}

/// Refuse a configuration that would check nothing, or too little, or that
/// the claims cannot be compared with: a leeway past [`MAX_LEEWAY`] or with
/// a fraction of a second, or no pinned audience or issuer without the
/// config saying so. Judged before any token is read, as the verifier does.
fn refuse_unbounded_config(config: &ValidationConfig) -> Result<(), JwtError> {
    // `exp` and `nbf` are whole seconds, and jsonwebtoken takes the leeway
    // as whole seconds: a fraction would be dropped, not applied.
    if config.leeway.subsec_nanos() != 0 {
        return Err(JwtError::VerificationFailed(format!(
            "leeway of {:?} is not a whole number of seconds: `exp` and `nbf` are whole \
             seconds (RFC 7519 NumericDate), so a fraction would be dropped. Set `leeway` (or \
             the verifier's clock skew) to whole seconds",
            config.leeway
        )));
    }
    // A leeway past the bound keeps an expired token valid for as long as
    // it says.
    if config.leeway > MAX_LEEWAY {
        return Err(JwtError::VerificationFailed(format!(
            "leeway of {} s is above the bound of {} s: a leeway that large keeps an \
             expired token valid for as long as it says. Set `leeway` (or the verifier's \
             clock skew) to at most {} s",
            config.leeway.as_secs(),
            MAX_LEEWAY.as_secs(),
            MAX_LEEWAY.as_secs()
        )));
    }
    // A claim nobody pinned is a claim nobody checks.
    if config.audience.is_none() && !config.allow_any_audience {
        return Err(JwtError::VerificationFailed(
            "no audience is pinned: a token minted for any other service of the same \
             issuer would verify. Set `audience`, or `allow_any_audience` to state that \
             accepting any audience is intended"
                .to_string(),
        ));
    }
    if config.issuer.is_none() && !config.allow_any_issuer {
        return Err(JwtError::VerificationFailed(
            "no issuer is pinned: a token signed by any key in the set would verify. \
             Set `issuer`, or `allow_any_issuer` to state that accepting any issuer is \
             intended"
                .to_string(),
        ));
    }
    Ok(())
}

/// Manual `exp` / `nbf` validation against the injected clock.
///
/// The leeway's whole seconds are a `u64` and `exp` / `nbf` are `i64` Unix
/// seconds. The conversion saturates to avoid the pathological-large-leeway
/// overflow where `u64::MAX as i64` would be negative.
fn check_time_claims(
    claims: &serde_json::Value,
    config: &ValidationConfig,
    clock: &dyn Clock,
) -> Result<(), JwtError> {
    let now = clock.now().unix_seconds();
    let leeway: i64 = i64::try_from(config.leeway.as_secs()).unwrap_or(i64::MAX);

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
