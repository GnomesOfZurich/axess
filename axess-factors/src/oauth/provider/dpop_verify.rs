//! Server-side DPoP proof verification (RFC 9449).
//!
//! `generate_dpop_proof` handles the
//! signing side; this module is the verifier the *resource server* uses to
//! validate a `DPoP` header on an inbound request.
//!
//! Per RFC 9449 §11.1 a complete verifier must check:
//!
//! 1. JWT structure (3 segments) and `typ: dpop+jwt` header.
//! 2. Embedded `jwk` header parses into a supported algorithm public key,
//!    carries no private key member (RFC 9449 §4.2), AND signs over the JWT
//!    signing input.
//! 3. `htm` claim equals the request method, exactly (HTTP methods are
//!    case-sensitive).
//! 4. `htu` claim equals the request URL (scheme + host + path, no
//!    query/fragment per spec recommendation).
//! 5. `iat` claim is within `max_iat_skew_secs` of now.
//! 6. `jti` claim is 1 to [`MAX_JTI_BYTES`] bytes and not present in the
//!    replay cache; insert it on success. A full cache refuses the proof
//!    rather than forgetting a live `jti`. A proof over [`MAX_PROOF_BYTES`] is
//!    refused before it is decoded.
//! 7. (Optional) `ath` claim equals SHA-256(access_token) when an access
//!    token accompanies the DPoP-protected request.
//!
//! The bound `cnf.jkt` claim verification (proving the access token was
//! sender-constrained to the same key the DPoP proof signs with) is a
//! separate step the application performs against its access-token cache.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
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
/// `false` when the jti is already present (replay; reject the request) or
/// when the cache cannot take another live entry. Forgetting a live `jti` to
/// make room would let its proof replay, so a bounded cache refuses instead.
/// Implementations are responsible for evicting entries past their `expires_at`.
pub trait DpopJtiCache: Send + Sync {
    /// Insert `jti` with the given expiration. Returns `true` when the entry
    /// was new (proof is fresh) and `false` when the `jti` was already present
    /// (replay; caller must reject the request).
    fn try_insert(&self, jti: &str, expires_at: DateTime<Utc>) -> bool;
}

/// Live entries a [`MemoryJtiCache`] holds by default. A proof needs a valid
/// signature but any key will do, so without a bound a client could grow the
/// cache as fast as it can send requests. Each entry is a 32-byte digest of
/// the `jti` in each of two structures, whatever the `jti`'s length, so the
/// bound is a bound in bytes too.
pub const DEFAULT_JTI_CAPACITY: usize = 262_144;

/// Memory-backed jti cache with TTL eviction. Suitable for a single-process
/// resource server; for a fleet, replace with a Valkey-backed implementation.
///
/// Holds at most [`DEFAULT_JTI_CAPACITY`] live entries (change it with
/// [`with_capacity`](Self::with_capacity)). At the bound `try_insert` returns
/// `false`, so proofs are refused until entries expire: the cost of a flood is
/// availability for the length of the replay window, not memory.
#[derive(Clone)]
pub struct MemoryJtiCache {
    inner: Arc<Mutex<JtiStore>>,
    capacity: usize,
    // Source of wall-clock time for eviction. Defaults to
    // `SystemClock`; pass a `MockClock` via `with_clock` to pin time
    // under DST.
    clock: Arc<dyn axess_clock::Clock>,
}

/// The live `jti`s and, beside them, the same entries ordered by expiry.
///
/// Eviction pops the soonest expiry off the heap while it has passed, so a
/// call costs the number of entries it evicts rather than the number the
/// cache holds. Every live `jti` has exactly one heap entry: a `jti` is
/// inserted only when absent from the map, and its heap entry leaves with
/// it.
#[derive(Default)]
pub(crate) struct JtiStore {
    live: HashMap<JtiDigest, DateTime<Utc>>,
    by_expiry: BinaryHeap<Reverse<(DateTime<Utc>, JtiDigest)>>,
}

/// SHA-256 of a `jti`. The store keys on the digest so that an entry costs a
/// fixed 32 bytes in each structure however long the `jti` the sender chose.
pub(crate) type JtiDigest = [u8; 32];

/// The digest a [`JtiStore`] keys a `jti` by.
pub(crate) fn jti_digest(jti: &str) -> JtiDigest {
    Sha256::digest(jti.as_bytes()).into()
}

impl JtiStore {
    /// Drop every entry whose expiry is at or before `now`; return how many.
    ///
    /// The comparison is strict (`expires_at > now` keeps an entry), so an
    /// entry expiring exactly at `now` is gone: a stale `jti` must not
    /// block a proof the application is willing to consider current.
    fn evict_expired(&mut self, now: DateTime<Utc>) -> usize {
        let mut evicted = 0;
        while let Some(Reverse((expires_at, _))) = self.by_expiry.peek() {
            if *expires_at > now {
                break;
            }
            if let Some(Reverse((_, jti))) = self.by_expiry.pop() {
                self.live.remove(&jti);
                evicted += 1;
            }
        }
        evicted
    }
}

impl Default for MemoryJtiCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(JtiStore::default())),
            capacity: DEFAULT_JTI_CAPACITY,
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
    /// `MockClock` under DST so
    /// the TTL-eviction path is deterministic.
    ///
    /// Use the clock that supplies the `now` handed to
    /// [`verify_dpop_proof`]: that `now` stamps each entry's expiry, and
    /// this clock decides when the entry is evicted, so two different
    /// clocks make entries expire at the wrong moment.
    pub fn with_clock(mut self, clock: Arc<dyn axess_clock::Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Bound the number of live entries. Size it above the proofs a
    /// legitimate fleet presents in twice the `iat` skew.
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }
}

/// [`MemoryJtiCache::try_insert`] with the eviction `now` lifted to a
/// parameter, so the expiry boundary is testable to the exact tick. `false`
/// for a replay and for a store already holding `capacity` live entries.
pub(crate) fn try_insert_at(
    store: &mut JtiStore,
    jti: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    capacity: usize,
) -> bool {
    store.evict_expired(now);
    let digest = jti_digest(jti);
    if store.live.contains_key(&digest) || store.live.len() >= capacity {
        return false;
    }
    store.live.insert(digest, expires_at);
    store.by_expiry.push(Reverse((expires_at, digest)));
    true
}

/// Pure helper for the verify-side replay-window upper bound: the
/// `expires_at` value stored in the jti cache after a successful
/// verification. The window is `2 * skew + 1` seconds from `iat`: the skew
/// check truncates to whole seconds, so a proof is accepted up to
/// `iat + skew + 0.999 s`, and the entry must outlive that moment by the
/// whole of the span over which the proof stays acceptable. Without the
/// extra second a skew of zero stored an entry that expired at `iat`, and the
/// same proof was accepted again for the rest of that second.
///
/// `None` when the window does not fit the date range (an absurd skew), so
/// the caller refuses the proof instead of panicking on the addition.
pub(crate) fn dpop_replay_window_expiry(
    iat_time: DateTime<Utc>,
    max_iat_skew_secs: i64,
) -> Option<DateTime<Utc>> {
    let window = chrono::Duration::try_seconds(max_iat_skew_secs.checked_mul(2)?.checked_add(1)?)?;
    iat_time.checked_add_signed(window)
}

impl DpopJtiCache for MemoryJtiCache {
    fn try_insert(&self, jti: &str, expires_at: DateTime<Utc>) -> bool {
        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        try_insert_at(&mut store, jti, expires_at, self.clock.now(), self.capacity)
    }
}

/// Largest `max_iat_skew_secs` [`verify_dpop_proof`] accepts: one day.
pub const MAX_IAT_SKEW_SECS: i64 = 86_400;

/// Longest proof [`verify_dpop_proof`] reads, in bytes. A real proof (header
/// with an EC key, a handful of claims, a signature) is under 1 KiB; anything
/// past this is refused before it is split or decoded.
pub const MAX_PROOF_BYTES: usize = 8 * 1024;

/// Longest `jti` [`verify_dpop_proof`] accepts, in bytes. A UUID is 36.
pub const MAX_JTI_BYTES: usize = 256;

/// Members of a JWK that hold private key material (RFC 7517 §4, RFC 7518
/// §6): an EC or OKP `d`, the RSA `p`, `q`, `dp`, `dq`, `qi` and `oth`, and a
/// symmetric `k`. RFC 9449 §4.2 forbids them in a proof's `jwk` header.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

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
    /// upper bound. Must be within `0..=`[`MAX_IAT_SKEW_SECS`]; a value
    /// outside that range makes every verification fail, so a misconfigured
    /// "disable" value cannot switch the freshness check off.
    pub max_iat_skew_secs: i64,
    /// Replay cache instance.
    pub jti_cache: &'a dyn DpopJtiCache,
}

/// RFC 9449 §4.2: the proof's key is public. A header that carries the
/// private half has handed it to everyone who can read the request.
fn refuse_private_key_material(jwk_value: &serde_json::Value) -> Result<(), OAuthError> {
    let jwk_members = jwk_value.as_object().ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP `jwk` must be a JSON object".to_string())
    })?;
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| jwk_members.contains_key(*member))
    {
        return Err(OAuthError::IdTokenValidation(
            "DPoP `jwk` must not contain private key material".to_string(),
        ));
    }
    Ok(())
}

/// Verify a single DPoP proof. Returns the canonical JWK thumbprint of
/// the signing key on success.
pub fn verify_dpop_proof(
    req: DpopVerifyRequest<'_>,
    now: DateTime<Utc>,
) -> Result<DpopVerified, OAuthError> {
    use jsonwebtoken::{Algorithm, DecodingKey};
    use subtle::ConstantTimeEq;

    if !(0..=MAX_IAT_SKEW_SECS).contains(&req.max_iat_skew_secs) {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `max_iat_skew_secs` must be within 0..={MAX_IAT_SKEW_SECS}; got {}",
            req.max_iat_skew_secs
        )));
    }

    // 1. Structural sanity. A proof is self-signed, so anyone can mint one:
    // the size is bounded before anything is split or decoded.
    if req.proof_jwt.len() > MAX_PROOF_BYTES {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP proof exceeds {MAX_PROOF_BYTES} bytes"
        )));
    }
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

    refuse_private_key_material(jwk_value)?;

    // 2. Build the verifier from the embedded JWK.
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value.clone())
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP `jwk` invalid: {e}")))?;
    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP key build: {e}")))?;
    // The header is already parsed above and the payload is parsed once
    // below, so the signature is checked directly over the signing input
    // instead of handing the whole token to `decode`, which would parse
    // both again.
    crate::jwt::ensure_crypto_provider();
    let signing_input = &req.proof_jwt[..parts[0].len() + 1 + parts[1].len()];
    let signature_ok = jsonwebtoken::crypto::verify(
        parts[2],
        signing_input.as_bytes(),
        &decoding_key,
        Algorithm::ES256,
    )
    .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP signature verify: {e}")))?;
    if !signature_ok {
        return Err(OAuthError::IdTokenValidation(
            "DPoP signature verify: signature does not match".to_string(),
        ));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP payload b64 decode: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP payload parse: {e}")))?;

    // 3. Claim checks.
    let claim_htm = claims.get("htm").and_then(|v| v.as_str()).unwrap_or("");
    if claim_htm != req.htm {
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
        if !bool::from(claim_ath.as_bytes().ct_eq(expected.as_bytes())) {
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
    if jti.is_empty() || jti.len() > MAX_JTI_BYTES {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `jti` must be 1 to {MAX_JTI_BYTES} bytes"
        )));
    }
    let expires_at = dpop_replay_window_expiry(iat_time, req.max_iat_skew_secs)
        .ok_or_else(|| OAuthError::IdTokenValidation("DPoP skew window overflow".to_string()))?;
    if !req.jti_cache.try_insert(jti, expires_at) {
        // The `jti` is the sender's string and is not echoed back.
        return Err(OAuthError::IdTokenValidation(
            "DPoP `jti` replayed within skew window, or the replay cache is full; rejecting"
                .to_string(),
        ));
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

#[cfg(all(test, feature = "fapi"))]
mod hardening_tests;
#[cfg(test)]
mod tests;
