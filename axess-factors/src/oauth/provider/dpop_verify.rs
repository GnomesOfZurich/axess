//! Server-side DPoP proof verification (RFC 9449).
//!
//! [`generate_dpop_proof`](super::fapi_flow::generate_dpop_proof) handles the
//! signing side; this module is the verifier the *resource server* uses to
//! validate a `DPoP` header on an inbound request.
//!
//! Per RFC 9449 §11.1 a complete verifier must check:
//!
//! 1. JWT structure (3 segments) and `typ: dpop+jwt` header.
//! 2. Embedded `jwk` header parses into a supported algorithm public key
//!    AND signs over the JWT signing input.
//! 3. `htm` claim equals the request method.
//! 4. `htu` claim equals the request URL (scheme + host + path, no
//!    query/fragment per spec recommendation).
//! 5. `iat` claim is within `max_iat_skew_secs` of now.
//! 6. `jti` claim is not present in the replay cache; insert it on success.
//! 7. (Optional) `ath` claim equals SHA-256(access_token) when an access
//!    token accompanies the DPoP-protected request.
//!
//! The bound `cnf.jkt` claim verification (proving the access token was
//! sender-constrained to the same key the DPoP proof signs with) is a
//! separate step the application performs against its access-token cache.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::super::types::OAuthError;

/// Outcome of verifying a single DPoP proof.
#[derive(Debug)]
pub struct DpopVerified {
    /// The RFC 7638 JWK thumbprint of the proof's signing key. Match
    /// against the access token's bound `cnf.jkt` claim to complete the
    /// sender-constrained-token check.
    pub thumbprint: String,
}

/// Pluggable replay-cache for DPoP `jti` claims.
///
/// `try_insert` returns `true` when the jti was inserted (proof is fresh),
/// `false` when the jti is already present (replay; reject the request).
/// Implementations are responsible for evicting entries past their `expires_at`.
pub trait DpopJtiCache: Send + Sync {
    /// Insert `jti` with the given expiration. Returns `true` when the entry
    /// was new (proof is fresh) and `false` when the `jti` was already present
    /// (replay; caller must reject the request).
    fn try_insert(&self, jti: &str, expires_at: DateTime<Utc>) -> bool;
}

/// Memory-backed jti cache with TTL eviction. Suitable for a single-process
/// resource server; for a fleet, replace with a Valkey-backed implementation.
#[derive(Clone)]
pub struct MemoryJtiCache {
    inner: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    // Source of wall-clock time for eviction. Defaults to
    // `SystemClock`; pass a `MockClock` via `with_clock` to pin time
    // under DST.
    clock: Arc<dyn axess_clock::Clock>,
}

impl Default for MemoryJtiCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            clock: Arc::new(axess_clock::SystemClock),
        }
    }
}

impl MemoryJtiCache {
    /// Create an empty in-memory `jti` replay cache.
    ///
    /// # Example
    ///
    /// ```
    /// use axess_factors::oauth::provider::dpop_verify::{DpopJtiCache, MemoryJtiCache};
    /// use chrono::{Duration, Utc};
    ///
    /// let cache = MemoryJtiCache::new();
    /// let expires = Utc::now() + Duration::seconds(60);
    ///
    /// assert!(cache.try_insert("jti-1", expires), "first use accepted");
    /// assert!(!cache.try_insert("jti-1", expires), "replay rejected");
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Swap the clock used for eviction. Defaults to
    /// [`SystemClock`](axess_clock::SystemClock). Pass a
    /// [`MockClock`](axess_clock::testing::MockClock) under DST so
    /// the TTL-eviction path is deterministic.
    pub fn with_clock(mut self, clock: Arc<dyn axess_clock::Clock>) -> Self {
        self.clock = clock;
        self
    }
}

/// Pure helper for [`MemoryJtiCache::try_insert`] with the eviction
/// `now` lifted to a parameter. Extracted so the boundary mutations
/// flagged on the body (`> with >=` on the `retain` predicate, etc.)
/// can be killed by direct unit tests without the `Utc::now()`
/// dependency on the trait method.
pub(crate) fn try_insert_at(
    map: &mut HashMap<String, DateTime<Utc>>,
    jti: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    // Lazy eviction; bounded scan keeps the map size proportional to
    // active proofs in the iat window. Strict `>` so an entry whose
    // `expires_at` lands exactly on `now` is evicted, not retained;
    // a stale jti must not block a fresh proof that the application
    // is willing to consider current.
    map.retain(|_, exp| *exp > now);
    if map.contains_key(jti) {
        return false;
    }
    map.insert(jti.to_string(), expires_at);
    true
}

/// Pure helper for the verify-side replay-window upper bound: the
/// `expires_at` value stored in the jti cache after a successful
/// verification. Spec rationale: window the entry by `2×` the
/// configured `iat` skew so a sliding `iat` re-presentation gets
/// caught by the still-cached entry rather than slipping past
/// eviction. Extracted so the multiplier mutation (`* with /`,
/// `* with +`) is pinned by a single-line unit test.
pub(crate) fn dpop_replay_window_expiry(
    iat_time: DateTime<Utc>,
    max_iat_skew_secs: i64,
) -> DateTime<Utc> {
    iat_time + chrono::Duration::seconds(max_iat_skew_secs * 2)
}

impl DpopJtiCache for MemoryJtiCache {
    fn try_insert(&self, jti: &str, expires_at: DateTime<Utc>) -> bool {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        try_insert_at(&mut map, jti, expires_at, self.clock.now())
    }
}

/// Inputs to [`verify_dpop_proof`].
pub struct DpopVerifyRequest<'a> {
    /// The raw `DPoP` header value (compact JWS).
    pub proof_jwt: &'a str,
    /// HTTP method of the request being protected (e.g. `"POST"`).
    pub htm: &'a str,
    /// Canonical request URL: scheme + authority + path, no query, no
    /// fragment. RFC 9449 §4.3 requires this normalisation.
    pub htu: &'a str,
    /// When the request carries an access token, supply it here so the
    /// verifier enforces the optional `ath` claim. `None` skips the
    /// access-token-hash check.
    pub access_token: Option<&'a str>,
    /// Maximum allowed clock skew for `iat`, in seconds. RFC 9449
    /// §11.1.2 suggests "a few seconds"; 60 is a typical operational
    /// upper bound.
    pub max_iat_skew_secs: i64,
    /// Replay cache instance.
    pub jti_cache: &'a dyn DpopJtiCache,
}

/// Verify a single DPoP proof. Returns the canonical JWK thumbprint of
/// the signing key on success.
pub fn verify_dpop_proof(
    req: DpopVerifyRequest<'_>,
    now: DateTime<Utc>,
) -> Result<DpopVerified, OAuthError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    // 1. Structural sanity.
    let parts: Vec<&str> = req.proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::IdTokenValidation(
            "DPoP proof must have 3 JWS segments".to_string(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP header b64 decode: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP header parse: {e}")))?;
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "dpop+jwt" {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `typ` header must be `dpop+jwt`, got `{typ}`"
        )));
    }
    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg_str != "ES256" {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `alg` must be ES256 (other algs not yet supported); got `{alg_str}`"
        )));
    }
    let jwk_value = header.get("jwk").ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP header missing required `jwk`".to_string())
    })?;

    // 2. Build the verifier from the embedded JWK.
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value.clone())
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP `jwk` invalid: {e}")))?;
    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP key build: {e}")))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_aud = false;
    validation.validate_exp = false;
    let token = decode::<serde_json::Value>(req.proof_jwt, &decoding_key, &validation)
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP signature verify: {e}")))?;

    // 3. Claim checks.
    let claims = token.claims;
    let claim_htm = claims.get("htm").and_then(|v| v.as_str()).unwrap_or("");
    if !claim_htm.eq_ignore_ascii_case(req.htm) {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `htm` mismatch; proof says `{claim_htm}`, request is `{}`",
            req.htm
        )));
    }
    let claim_htu = claims.get("htu").and_then(|v| v.as_str()).unwrap_or("");
    if claim_htu != req.htu {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `htu` mismatch; proof says `{claim_htu}`, request is `{}`",
            req.htu
        )));
    }

    let iat_secs = claims.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP missing required `iat` claim".to_string())
    })?;
    let iat_time = DateTime::from_timestamp(iat_secs, 0).ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP `iat` not a valid Unix timestamp".to_string())
    })?;
    let skew = (now - iat_time).num_seconds().abs();
    if skew > req.max_iat_skew_secs {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `iat` outside skew window (skew={skew}s, max={}s)",
            req.max_iat_skew_secs
        )));
    }

    // 4. Optional access-token hash binding.
    if let Some(at) = req.access_token {
        let claim_ath = claims.get("ath").and_then(|v| v.as_str()).ok_or_else(|| {
            OAuthError::IdTokenValidation(
                "access-token-bound request requires `ath` claim".to_string(),
            )
        })?;
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(at.as_bytes()));
        if claim_ath != expected {
            return Err(OAuthError::IdTokenValidation(
                "DPoP `ath` does not match SHA-256(access_token)".to_string(),
            ));
        }
    }

    // 5. Replay cache. Window the entry by 2x the skew so a sliding
    //    iat doesn't allow a previously-accepted jti to be re-presented.
    let jti = claims.get("jti").and_then(|v| v.as_str()).ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP missing required `jti` claim".to_string())
    })?;
    let expires_at = dpop_replay_window_expiry(iat_time, req.max_iat_skew_secs);
    if !req.jti_cache.try_insert(jti, expires_at) {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `jti` `{jti}` replayed within skew window; rejecting"
        )));
    }

    // 6. RFC 7638 JWK thumbprint of the signing key, returned for the
    //    application's `cnf.jkt` cross-check against the access token.
    let thumbprint = jwk_thumbprint_es256(jwk_value)?;

    Ok(DpopVerified { thumbprint })
}

/// Compute the RFC 7638 JWK thumbprint for an ES256 (P-256) JWK.
fn jwk_thumbprint_es256(jwk_value: &serde_json::Value) -> Result<String, OAuthError> {
    let crv = jwk_value
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OAuthError::IdTokenValidation("JWK thumbprint: missing `crv`".to_string())
        })?;
    let kty = jwk_value
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OAuthError::IdTokenValidation("JWK thumbprint: missing `kty`".to_string())
        })?;
    let x = jwk_value
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::IdTokenValidation("JWK thumbprint: missing `x`".to_string()))?;
    let y = jwk_value
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::IdTokenValidation("JWK thumbprint: missing `y`".to_string()))?;
    // RFC 7638 §3.2: lex-ordered required members for an EC key are
    // `crv`, `kty`, `x`, `y`.
    let canonical = format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

#[cfg(test)]
mod tests;
