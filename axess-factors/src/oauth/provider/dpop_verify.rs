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
//! 5. `iat` claim is within `max_iat_skew` of now.
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
//!
//! # One algorithm
//!
//! A proof is accepted only when it is signed with `ES256` over a P-256
//! key ([`DPOP_SIGNING_ALG`]). That is a policy, not a gap to be filled:
//!
//! - RFC 9449 names no mandatory algorithm. It requires an asymmetric one
//!   and leaves the accepted set to the server, which announces it (the
//!   `algs` parameter of a `WWW-Authenticate: DPoP` challenge, or
//!   `dpop_signing_alg_values_supported` for an authorization server).
//!   `ES256` is in every set FAPI 2.0 allows.
//! - The key travels in the proof and is the sender's to choose, so a second
//!   algorithm adds nothing a server can rely on. It adds a second parser
//!   for a key an anonymous caller supplies: an RSA modulus of the caller's
//!   chosen size, another curve, another key type.
//! - The client half of this crate signs `ES256` and nothing else, so the
//!   two halves agree, and the thumbprint that binds a token (`cnf.jkt`) has
//!   one canonical form.
//!
//! A resource server that challenges with `WWW-Authenticate: DPoP` sends
//! `algs="ES256"`.

use axess_clock::{SignedDuration, Timestamp};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::types::OAuthError;

/// The most bytes a refusal quotes of one value the proof's sender chose: a
/// header value, a claim, or the method or URL of the request the proof came
/// with.
const REMOTE_VALUE_LOG_BYTES: usize = 64;

/// A value the proof's sender chose, as a refusal quotes it: every character
/// [`escapes`](crate::log_text::escapes) names (control characters, the line
/// and paragraph separators, bidirectional controls, zero-width characters,
/// the byte order mark, the Hangul fillers) escaped, and cut at
/// [`REMOTE_VALUE_LOG_BYTES`].
fn quoted(value: &str) -> String {
    crate::log_text::log_safe(value, REMOTE_VALUE_LOG_BYTES)
}

/// The one JWS algorithm [`verify_dpop_proof`] accepts, and the value a
/// resource server sends as `algs` in a `WWW-Authenticate: DPoP` challenge
/// (RFC 9449 section 7.1). See the module documentation for why there is one.
pub const DPOP_SIGNING_ALG: &str = super::dpop::DPOP_SIGNING_ALG;

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
    fn try_insert(&self, jti: &str, expires_at: Timestamp) -> bool;
}

/// Live entries a [`MemoryJtiCache`] holds by default. A proof needs a valid
/// signature but any key will do, so without a bound a client could grow the
/// cache as fast as it can send requests. Each entry is a 32-byte digest of
/// the `jti` in each of two structures, whatever the `jti`'s length, so the
/// bound is a bound in bytes too.
pub const DEFAULT_JTI_CAPACITY: usize = 262_144;

/// Memory-backed jti cache with TTL eviction. Suitable for a single-process
/// resource server; a fleet verifies with [`verify_dpop_proof_with_store`]
/// and a store every node reaches (`ValkeyJtiReplayStore` in axess-core).
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
    live: HashMap<JtiDigest, Timestamp>,
    by_expiry: BinaryHeap<Reverse<(Timestamp, JtiDigest)>>,
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
    fn evict_expired(&mut self, now: Timestamp) -> usize {
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
    /// use axess_clock::{Clock, SignedDuration, SystemClock};
    /// use axess_factors::oauth::provider::dpop_verify::{DpopJtiCache, MemoryJtiCache};
    ///
    /// // The cache judges expiry on its clock (`with_clock`), the system
    /// // clock unless one is given; the expiry is read from the same one.
    /// let cache = MemoryJtiCache::new();
    /// let expires = SystemClock
    ///     .now()
    ///     .checked_add(SignedDuration::seconds(60))
    ///     .expect("inside the range");
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

/// What became of a `jti` handed to the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JtiInsert {
    /// New: recorded.
    Recorded,
    /// Already held: a replay.
    Held,
    /// Not held, and not recorded: the cache is at its capacity.
    Full,
}

/// Record `jti` in `store` unless it is held or the store is full, after
/// evicting what has expired at `now`.
pub(crate) fn insert_at(
    store: &mut JtiStore,
    jti: &str,
    expires_at: Timestamp,
    now: Timestamp,
    capacity: usize,
) -> JtiInsert {
    store.evict_expired(now);
    let digest = jti_digest(jti);
    if store.live.contains_key(&digest) {
        return JtiInsert::Held;
    }
    if store.live.len() >= capacity {
        return JtiInsert::Full;
    }
    store.live.insert(digest, expires_at);
    store.by_expiry.push(Reverse((expires_at, digest)));
    JtiInsert::Recorded
}

/// [`MemoryJtiCache::try_insert`] with the eviction `now` lifted to a
/// parameter, so the expiry boundary is testable to the exact tick. `false`
/// for a replay and for a store already holding `capacity` live entries.
pub(crate) fn try_insert_at(
    store: &mut JtiStore,
    jti: &str,
    expires_at: Timestamp,
    now: Timestamp,
    capacity: usize,
) -> bool {
    insert_at(store, jti, expires_at, now, capacity) == JtiInsert::Recorded
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
/// `None` when the window does not fit the range of a `Timestamp` (an absurd
/// skew), so the caller refuses the proof. The skew is in whole seconds, as
/// the check counts it.
pub(crate) fn dpop_replay_window_expiry(
    iat_time: Timestamp,
    max_iat_skew_secs: i64,
) -> Option<Timestamp> {
    let window = SignedDuration::seconds(max_iat_skew_secs.checked_mul(2)?.checked_add(1)?);
    iat_time.checked_add(window)
}

impl MemoryJtiCache {
    /// Record `jti` until `expires_at`, saying which of the three outcomes
    /// it was.
    pub(crate) fn insert(&self, jti: &str, expires_at: Timestamp) -> JtiInsert {
        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        insert_at(&mut store, jti, expires_at, self.clock.now(), self.capacity)
    }
}

impl DpopJtiCache for MemoryJtiCache {
    fn try_insert(&self, jti: &str, expires_at: Timestamp) -> bool {
        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        try_insert_at(&mut store, jti, expires_at, self.clock.now(), self.capacity)
    }
}

/// Largest `max_iat_skew` [`verify_dpop_proof`] accepts: one day.
pub const MAX_IAT_SKEW: Duration = Duration::from_secs(86_400);

/// Longest proof [`verify_dpop_proof`] reads, in bytes. A real proof (header
/// with an EC key, a handful of claims, a signature) is under 1 KiB; anything
/// past this is refused before it is split or decoded.
pub const MAX_PROOF_BYTES: usize = 8 * 1024;

/// Longest `jti` [`verify_dpop_proof`] accepts, in bytes. A UUID is 36.
pub const MAX_JTI_BYTES: usize = 256;

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
    /// Maximum allowed clock skew for `iat`. RFC 9449 §11.1.2 suggests "a
    /// few seconds"; 60 seconds is a typical operational upper bound. It is
    /// counted in whole seconds, as `iat` is, so a fraction of a second in
    /// it changes nothing. At most [`MAX_IAT_SKEW`]; a longer one makes
    /// every verification fail, so a misconfigured "disable" value cannot
    /// switch the freshness check off.
    pub max_iat_skew: Duration,
    /// Replay cache instance.
    pub jti_cache: &'a dyn DpopJtiCache,
}

/// RFC 9449 §4.2: the proof's key is public. A header that carries the
/// private half has handed it to everyone who can read the request.
fn refuse_private_key_material(jwk_value: &serde_json::Value) -> Result<(), OAuthError> {
    crate::jwk_p256::refuse_private_members(jwk_value).map_err(jwk_refusal)
}

/// The words this verifier puts around a refused key.
fn jwk_refusal(refusal: crate::jwk_p256::JwkRefusal) -> OAuthError {
    use crate::jwk_p256::JwkRefusal;
    OAuthError::IdTokenValidation(match refusal {
        JwkRefusal::NotAnObject => "DPoP `jwk` must be a JSON object".to_string(),
        JwkRefusal::PrivateMaterial => {
            "DPoP `jwk` must not contain private key material".to_string()
        }
        JwkRefusal::Member { member, why } => format!("DPoP `jwk` member `{member}` {why}"),
    })
}

/// Check the proof's signature with the key its header carries. The header is
/// already parsed by the caller and the payload is parsed once after this, so
/// the signature is checked directly over the signing input instead of
/// handing the whole token to `decode`, which would parse both again.
fn verify_proof_signature(
    proof_jwt: &str,
    parts: &[&str],
    jwk_value: &serde_json::Value,
) -> Result<(), OAuthError> {
    use jsonwebtoken::{Algorithm, DecodingKey};

    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value.clone()).map_err(|e| {
        OAuthError::IdTokenValidation(format!(
            "DPoP `jwk` invalid: {}",
            crate::remote_text::parse_error(&e)
        ))
    })?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        OAuthError::IdTokenValidation(format!(
            "DPoP key build: {}",
            crate::remote_text::error_text(&e)
        ))
    })?;
    let signing_input = &proof_jwt[..parts[0].len() + 1 + parts[1].len()];
    let signature_ok = crate::jwt::verify(
        parts[2],
        signing_input.as_bytes(),
        &decoding_key,
        Algorithm::ES256,
    )
    .map_err(|e| {
        OAuthError::IdTokenValidation(format!(
            "DPoP signature verify: {}",
            crate::remote_text::error_text(&e)
        ))
    })?;
    if !signature_ok {
        return Err(OAuthError::IdTokenValidation(
            "DPoP signature verify: signature does not match".to_string(),
        ));
    }
    Ok(())
}

/// The proof's `htm` and `htu` claims against the method and the URL of the
/// request it arrived with. A mismatch quotes both sides cut and escaped:
/// the claim is the sender's, and so are the method and the URL.
fn check_method_and_url(
    claims: &serde_json::Value,
    htm: &str,
    htu: &str,
) -> Result<(), OAuthError> {
    let claim_htm = claims.get("htm").and_then(|v| v.as_str()).unwrap_or("");
    if claim_htm != htm {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `htm` mismatch; proof says `{}`, request is `{}`",
            quoted(claim_htm),
            quoted(htm)
        )));
    }
    let claim_htu = claims.get("htu").and_then(|v| v.as_str()).unwrap_or("");
    if claim_htu != htu {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `htu` mismatch; proof says `{}`, request is `{}`",
            quoted(claim_htu),
            quoted(htu)
        )));
    }
    Ok(())
}

/// Verify a single DPoP proof. Returns the canonical JWK thumbprint of
/// the signing key on success.
pub fn verify_dpop_proof(
    req: DpopVerifyRequest<'_>,
    now: Timestamp,
) -> Result<DpopVerified, OAuthError> {
    use subtle::ConstantTimeEq;

    if req.max_iat_skew > MAX_IAT_SKEW {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `max_iat_skew` must be at most {MAX_IAT_SKEW:?}; got {:?}",
            req.max_iat_skew
        )));
    }
    // Whole seconds, as `iat` and the skew below are: an integer is within
    // a span exactly when it is within the span's whole seconds. At most a
    // day here, so it fits.
    let max_skew = i64::try_from(req.max_iat_skew.as_secs()).unwrap_or(i64::MAX);

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
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        OAuthError::IdTokenValidation(format!(
            "DPoP header parse: {}",
            crate::remote_text::parse_error(&e)
        ))
    })?;
    // No extension is understood, so none may be marked critical (RFC 7515
    // section 4.1.11).
    if header.get("crit").is_some() {
        return Err(OAuthError::IdTokenValidation(
            "DPoP header carries `crit`; no critical extension is understood".to_string(),
        ));
    }
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "dpop+jwt" {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `typ` header must be `dpop+jwt`, got `{}`",
            quoted(typ)
        )));
    }
    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg_str != DPOP_SIGNING_ALG {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `alg` must be {DPOP_SIGNING_ALG}, the only algorithm this verifier accepts; \
             got `{}`",
            quoted(alg_str)
        )));
    }
    let jwk_value = header.get("jwk").ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP header missing required `jwk`".to_string())
    })?;

    refuse_private_key_material(jwk_value)?;

    // 2. The key is the sender's to choose, so it is checked to be what this
    // verifier signs over (ES256) before a key is built from it.
    let (x, y) = p256_coordinates(jwk_value)?;

    verify_proof_signature(req.proof_jwt, &parts, jwk_value)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OAuthError::IdTokenValidation(format!("DPoP payload b64 decode: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        OAuthError::IdTokenValidation(format!(
            "DPoP payload parse: {}",
            crate::remote_text::parse_error(&e)
        ))
    })?;

    // 3. Claim checks.
    check_method_and_url(&claims, req.htm, req.htu)?;

    let iat_secs = claims.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP missing required `iat` claim".to_string())
    })?;
    let iat_time = Timestamp::from_unix_seconds(iat_secs).ok_or_else(|| {
        OAuthError::IdTokenValidation("DPoP `iat` not a valid Unix timestamp".to_string())
    })?;
    let skew = now.since(iat_time).whole_seconds().abs();
    if skew > max_skew {
        return Err(OAuthError::IdTokenValidation(format!(
            "DPoP `iat` outside skew window (skew={skew}s, max={max_skew}s)"
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
    let expires_at = dpop_replay_window_expiry(iat_time, max_skew)
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
    let thumbprint = crate::jwk_p256::thumbprint_text(&x, &y);

    Ok(DpopVerified { thumbprint })
}

/// The coordinates of an EC P-256 public key given as a JWK, under the rules
/// every self-contained key is held to (`crate::jwk_p256`), refused in this
/// verifier's words.
fn p256_coordinates(jwk_value: &serde_json::Value) -> Result<([u8; 32], [u8; 32]), OAuthError> {
    crate::jwk_p256::coordinates(jwk_value).map_err(jwk_refusal)
}

mod shared;
pub use shared::{DpopProofRequest, verify_dpop_proof_with_store};

#[cfg(test)]
mod hardening_tests;
#[cfg(test)]
mod tests;
