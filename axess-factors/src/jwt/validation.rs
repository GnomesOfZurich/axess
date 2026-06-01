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

/// Algorithm family discriminant. `jsonwebtoken` 10.x requires all algorithms in
/// a `Validation` to share the same family as the verifying key, but
/// `Algorithm::family()` is `pub(crate)`. This mirrors the classification so
/// callers can pass a mixed RSA+EC allowlist without tripping the family check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlgFamily {
    Rsa,
    Ec,
    Hmac,
    Ed,
}

fn alg_family(alg: Algorithm) -> AlgFamily {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgFamily::Hmac,
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => AlgFamily::Rsa,
        Algorithm::ES256 | Algorithm::ES384 => AlgFamily::Ec,
        Algorithm::EdDSA => AlgFamily::Ed,
    }
}

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
///    [`MockClock`](axess_clock::testing::MockClock) (via the local
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
    let family = alg_family(header.alg);
    validation.algorithms = allowed_algorithms
        .iter()
        .copied()
        .filter(|a| alg_family(*a) == family)
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
mod jwt_validation_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    /// Generate an RSA-2048 key pair and return (private DER, JwkSet with one key, kid).
    fn rsa_keypair() -> (Vec<u8>, JwkSet, String) {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
        let public_key = private_key.to_public_key();
        let kid = "test-key-1".to_string();

        let private_der = private_key
            .to_pkcs1_der()
            .expect("PKCS1 DER encode")
            .as_bytes()
            .to_vec();

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwk_json = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e,
            }]
        });
        let jwks: JwkSet = serde_json::from_value(jwk_json).expect("JwkSet parse");

        (private_der, jwks, kid)
    }

    /// Sign a JWT with the given claims, kid, and algorithm.
    fn sign_jwt(claims: &serde_json::Value, kid: &str, private_der: &[u8]) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_der(private_der);
        encode(&header, claims, &key).expect("JWT encode")
    }

    fn sample_claims() -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-42",
            "aud": "my-client",
            "exp": now + 3600,
            "iat": now,
        })
    }

    // ── Happy path ─────────────────────────────────────────────────────

    /// Valid RS256 JWT against its own JWKS verifies successfully.
    #[test]
    fn valid_rs256_jwt_verifies() {
        let (der, jwks, kid) = rsa_keypair();
        let token = sign_jwt(&sample_claims(), &kid, &der);

        let result = verify_jwt_signature(&token, &jwks, Some("my-client"), ALLOWED_ALGORITHMS);
        assert!(result.is_ok(), "valid JWT must verify: {result:?}");

        let claims = result.unwrap();
        assert_eq!(claims["sub"], "user-42");
    }

    /// Pin the strict-greater boundary `now > exp + leeway` on line
    /// 285. At `now == exp + leeway` (the inclusive expiry boundary)
    /// the token must STILL be accepted. Kills `> → >=` which would
    /// reject tokens at the boundary and cut every token's usable
    /// lifetime short by `1` second.
    #[test]
    fn verify_jwt_accepts_at_exact_exp_plus_leeway_boundary() {
        use axess_clock::testing::MockClock;
        use chrono::{TimeZone, Utc};
        let (der, jwks, kid) = rsa_keypair();
        // Token expires at t=1_000_000_100; leeway = 60; clock at
        // exp + leeway = 1_000_000_160.
        let exp = 1_000_000_100i64;
        let leeway: u64 = 60;
        let now = exp + leeway as i64;
        let claims = serde_json::json!({ "iss": "x", "sub": "u", "exp": exp });
        let token = sign_jwt(&claims, &kid, &der);
        let clock = MockClock::at(Utc.timestamp_opt(now, 0).single().unwrap());
        let cfg = ValidationConfig {
            audience: None,
            leeway_secs: leeway,
            ..ValidationConfig::default()
        };
        let result = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock);
        assert!(
            result.is_ok(),
            "token at exact exp+leeway boundary must verify (kills `> → >=` on line 285): {result:?}"
        );

        // And one second past must reject; confirms the boundary is at
        // the right value, not shifted.
        let clock_after = MockClock::at(Utc.timestamp_opt(now + 1, 0).single().unwrap());
        let result_after = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock_after);
        assert!(
            matches!(result_after, Err(JwtError::VerificationFailed(_))),
            "token one second past exp+leeway must reject: {result_after:?}"
        );
    }

    /// Pin the strict-less boundary `now < nbf - leeway` on line 291
    /// at `now == nbf - leeway` the token must STILL be accepted
    /// (it just became valid). Kills `< → <=` which would reject
    /// tokens at the boundary, opening a 1-second blackout right at
    /// validity start.
    #[test]
    fn verify_jwt_accepts_at_exact_nbf_minus_leeway_boundary() {
        use axess_clock::testing::MockClock;
        use chrono::{TimeZone, Utc};
        let (der, jwks, kid) = rsa_keypair();
        // Token nbf = 1_000_000_500; leeway = 60; clock at
        // nbf - leeway = 1_000_000_440 (exactly the boundary).
        let nbf = 1_000_000_500i64;
        let leeway: u64 = 60;
        let now = nbf - leeway as i64;
        // Add a far-future exp so the exp check passes unconditionally.
        let claims = serde_json::json!({
            "iss": "x",
            "sub": "u",
            "nbf": nbf,
            "exp": nbf + 3600,
        });
        let token = sign_jwt(&claims, &kid, &der);
        let clock = MockClock::at(Utc.timestamp_opt(now, 0).single().unwrap());
        let cfg = ValidationConfig {
            audience: None,
            leeway_secs: leeway,
            ..ValidationConfig::default()
        };
        let result = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock);
        assert!(
            result.is_ok(),
            "token at exact nbf-leeway boundary must verify (kills `< → <=` on line 291): {result:?}"
        );

        // And one second before must reject.
        let clock_before = MockClock::at(Utc.timestamp_opt(now - 1, 0).single().unwrap());
        let result_before = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock_before);
        assert!(
            matches!(result_before, Err(JwtError::VerificationFailed(_))),
            "token one second before nbf-leeway must reject: {result_before:?}"
        );
    }

    /// Audience validation disabled when `expected_audience` is None.
    #[test]
    fn audience_none_skips_aud_check() {
        let (der, jwks, kid) = rsa_keypair();
        let token = sign_jwt(&sample_claims(), &kid, &der);

        let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            result.is_ok(),
            "audience=None must skip aud check: {result:?}"
        );
    }

    // ── Algorithm allowlist ────────────────────────────────────────────

    /// HS256 (symmetric) is rejected even if the token is otherwise valid.
    /// Pins the allowlist check against removal; without it a crafted HS256
    /// token could bypass asymmetric verification.
    #[test]
    fn disallowed_algorithm_rejected() {
        let (der, jwks, kid) = rsa_keypair();
        // Sign with RS256 but restrict allowlist to ES256 only
        let token = sign_jwt(&sample_claims(), &kid, &der);

        let result = verify_jwt_signature(&token, &jwks, None, &[Algorithm::ES256]);
        assert!(
            matches!(result, Err(JwtError::DisallowedAlgorithm(Algorithm::RS256))),
            "RS256 not in allowlist must be rejected: {result:?}"
        );
    }

    /// `ALLOWED_ALGORITHMS` contains exactly the expected asymmetric set.
    /// Pins against accidental inclusion of HS* or `none`.
    #[test]
    fn allowed_algorithms_are_asymmetric_only() {
        for alg in ALLOWED_ALGORITHMS {
            let name = format!("{alg:?}");
            assert!(
                !name.starts_with("HS"),
                "symmetric algorithm {name} must not be in ALLOWED_ALGORITHMS"
            );
        }
        assert!(
            ALLOWED_ALGORITHMS.contains(&Algorithm::RS256),
            "RS256 must be allowed"
        );
        assert!(
            ALLOWED_ALGORITHMS.contains(&Algorithm::ES256),
            "ES256 must be allowed"
        );
    }

    // ── KID handling ───────────────────────────────────────────────────

    /// JWT with no `kid` header is rejected. Pins the MissingKid branch.
    #[test]
    fn missing_kid_rejected() {
        let (der, jwks, _) = rsa_keypair();
        // Sign without kid
        let mut header = Header::new(Algorithm::RS256);
        header.kid = None;
        let key = EncodingKey::from_rsa_der(&der);
        let token = encode(&header, &sample_claims(), &key).expect("encode");

        let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::MissingKid)),
            "missing kid must be rejected: {result:?}"
        );
    }

    /// JWT with unknown `kid` is rejected. Pins the UnknownKid branch.
    #[test]
    fn unknown_kid_rejected() {
        let (der, jwks, _) = rsa_keypair();
        let token = sign_jwt(&sample_claims(), "nonexistent-kid", &der);

        let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::UnknownKid(ref k)) if k == "nonexistent-kid"),
            "unknown kid must be rejected: {result:?}"
        );
    }

    // ── Algorithm mismatch ─────────────────────────────────────────────

    /// JWK declares `alg: RS256` but JWT header says RS384 → rejected.
    /// Prevents key confusion attacks across a rotating JWKS with mixed key types.
    #[test]
    fn algorithm_mismatch_rejected() {
        let (der, jwks, kid) = rsa_keypair();
        // Sign with RS384 but JWK declares RS256
        let mut header = Header::new(Algorithm::RS384);
        header.kid = Some(kid);
        let key = EncodingKey::from_rsa_der(&der);
        let token = encode(&header, &sample_claims(), &key).expect("encode");

        let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::AlgorithmMismatch { .. })),
            "alg mismatch must be rejected: {result:?}"
        );
    }

    // ── Audience mismatch ──────────────────────────────────────────────

    /// Wrong audience is rejected by jsonwebtoken's aud validation.
    #[test]
    fn wrong_audience_rejected() {
        let (der, jwks, kid) = rsa_keypair();
        let token = sign_jwt(&sample_claims(), &kid, &der);

        let result = verify_jwt_signature(&token, &jwks, Some("wrong-client"), ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::VerificationFailed(_))),
            "wrong audience must be rejected: {result:?}"
        );
    }

    // ── Malformed input ────────────────────────────────────────────────

    /// Completely garbage input is rejected at the header decode stage.
    #[test]
    fn garbage_input_rejected() {
        let jwks = JwkSet { keys: vec![] };
        let result = verify_jwt_signature("not-a-jwt", &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::InvalidHeader(_))),
            "garbage input must fail at header decode: {result:?}"
        );
    }

    /// Expired JWT is rejected (jsonwebtoken validates `exp` by default).
    #[test]
    fn expired_jwt_rejected() {
        let (der, jwks, kid) = rsa_keypair();
        let mut claims = sample_claims();
        claims["exp"] = serde_json::json!(0); // epoch = long expired
        let token = sign_jwt(&claims, &kid, &der);

        let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::VerificationFailed(_))),
            "expired JWT must be rejected: {result:?}"
        );
    }

    // ── Signature tampering ────────────────────────────────────────────

    /// Tampered signature is rejected. Flips a byte in the signature
    /// segment to simulate an attacker modifying claims after signing.
    #[test]
    fn tampered_signature_rejected() {
        let (der, jwks, kid) = rsa_keypair();
        let token = sign_jwt(&sample_claims(), &kid, &der);

        // Flip a byte in the signature (last segment)
        let parts: Vec<&str> = token.split('.').collect();
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("b64 decode sig");
        sig_bytes[0] ^= 0xFF;
        let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

        let result = verify_jwt_signature(&tampered, &jwks, None, ALLOWED_ALGORITHMS);
        assert!(
            matches!(result, Err(JwtError::VerificationFailed(_))),
            "tampered signature must be rejected: {result:?}"
        );
    }
}
