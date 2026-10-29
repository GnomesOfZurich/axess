//! Fluent JWT verifier builder over [`super::validation::verify_jwt`].
//!
//! Adds typed claim deserialisation, `iss` pinning, clock-skew tuning,
//! `nbf` requirement, and an optional pluggable replay-store for `jti`
//! protection. Layered on top of the shared verification primitive so
//! existing consumers (OAuth, back-channel logout, future workload
//! identity) can opt in to the richer surface without re-implementing
//! signature plumbing.

use crate::jwt::validation::{ALLOWED_ALGORITHMS, JwtError, ValidationConfig, verify_jwt};
use axess_clock::{Clock, SystemClock};
use jsonwebtoken::Algorithm;
use jsonwebtoken::jwk::JwkSet;
use serde::de::DeserializeOwned;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Errors raised by a [`JtiReplayStore`].
#[derive(Debug, thiserror::Error)]
pub enum JtiReplayError {
    /// The token's `jti` has been seen within its acceptance window:
    /// replay detected, reject.
    #[error("JWT `jti` already used: {0}")]
    AlreadyUsed(String),

    /// Storage failure independent of replay detection (e.g. backend
    /// connection lost). Treated as a verification failure to fail closed.
    #[error("JTI replay store error: {0}")]
    Backend(String),
}

/// Pluggable backend that records `jti` claims and rejects re-use.
///
/// Implementations should atomically check whether `jti` is already
/// recorded (return [`JtiReplayError::AlreadyUsed`]) and, if not, persist
/// it with the supplied `ttl` so the entry can be GC'd after the token
/// expires. In-memory backends (`HashSet` keyed by jti) are fine for
/// single-process deployments; multi-instance services should back the
/// store on a shared key/value store (Valkey, etc.).
pub trait JtiReplayStore: Send + Sync {
    /// Record `jti` for at least `ttl` seconds; return
    /// [`JtiReplayError::AlreadyUsed`] if it was already present.
    fn check_and_record(
        &self,
        jti: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), JtiReplayError>> + Send;
}

/// No-op replay store. Used when a [`JwtVerifier`] is built without
/// `with_replay_store`. Every call returns `Ok(())`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReplay;

impl JtiReplayStore for NoReplay {
    async fn check_and_record(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplayError> {
        tracing::trace!(
            target: "axess::factors::jwt",
            %jti,
            ttl_secs = ttl.as_secs(),
            "NoReplay: replay detection disabled, accepting jti",
        );
        Ok(())
    }
}

/// Registered JWT claims surfaced alongside the typed custom claim
/// payload `C`.
#[derive(Debug)]
pub struct VerifiedClaims<C> {
    /// `iss` claim: issuer.
    pub iss: Option<String>,
    /// `sub` claim: subject.
    pub sub: Option<String>,
    /// `aud` claim normalised to a vector (single-string aud → 1 element).
    pub aud: Option<Vec<String>>,
    /// `exp` claim: expiration (Unix seconds).
    pub exp: Option<i64>,
    /// `iat` claim: issued-at (Unix seconds).
    pub iat: Option<i64>,
    /// `nbf` claim: not-before (Unix seconds).
    pub nbf: Option<i64>,
    /// `jti` claim: unique JWT ID.
    pub jti: Option<String>,
    /// Custom claims deserialised into `C`.
    pub custom: C,
}

/// Fluent JWT verifier.
///
/// Construct with [`JwtVerifier::new`] from a shared `Arc<RwLock<JwkSet>>`
/// (e.g. [`crate::oidc::JwksCache::handle`]) and refine with the
/// `with_*` setters. The replay-store type defaults to [`NoReplay`];
/// call [`with_replay_store`](Self::with_replay_store) to bind a concrete
/// store.
///
/// # Example
///
/// ```no_run
/// use axess_factors::jwt::verifier::JwtVerifier;
/// use jsonwebtoken::Algorithm;
/// use jsonwebtoken::jwk::JwkSet;
/// use std::sync::{Arc, RwLock};
/// use std::time::Duration;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// // Production wiring: pull the live JWKS from `JwksCache::handle()`.
/// // Below uses an empty set just to demonstrate construction.
/// let jwks: JwkSet = serde_json::from_value(serde_json::json!({ "keys": [] }))?;
/// let handle = Arc::new(RwLock::new(jwks));
///
/// let verifier = JwtVerifier::new(handle)
///     .with_issuer("https://idp.example.com")
///     .with_audience("my-svc")
///     .with_clock_skew(Duration::from_secs(30))
///     .require_nbf(true)
///     .with_algorithms([Algorithm::RS256, Algorithm::ES256]);
///
/// let token = "eyJ...";
/// let claims = verifier.verify::<serde_json::Value>(token).await?;
/// # let _ = claims;
/// # Ok(())
/// # }
/// ```
pub struct JwtVerifier<R = NoReplay> {
    jwks: Arc<RwLock<JwkSet>>,
    allowed_algorithms: Vec<Algorithm>,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    clock_skew: Duration,
    require_nbf: bool,
    /// Whether a token must carry `exp`. On by default: a token that never
    /// expires is a credential with no end, and the replay store cannot
    /// bound it.
    require_exp: bool,
    replay: Option<R>,
    /// The caller chose to accept any audience (see
    /// [`allow_any_audience`](JwtVerifier::allow_any_audience)).
    audience_waived: bool,
    /// Injected clock; drives `exp` / `nbf` validation and replay-store
    /// TTL computation. Defaults to [`SystemClock`]. Set a
    /// `MockClock`-backed `Arc<dyn Clock>` via `with_clock` for DST tests.
    clock: Arc<dyn Clock>,
}

impl JwtVerifier<NoReplay> {
    /// New verifier seeded from a shared JWKS handle. Algorithm allowlist
    /// defaults to [`ALLOWED_ALGORITHMS`] (asymmetric only) and clock
    /// skew to 60 s.
    pub fn new(jwks: Arc<RwLock<JwkSet>>) -> Self {
        Self {
            jwks,
            allowed_algorithms: ALLOWED_ALGORITHMS.to_vec(),
            expected_issuer: None,
            expected_audience: None,
            clock_skew: Duration::from_secs(60),
            require_nbf: false,
            require_exp: true,
            replay: None,
            audience_waived: false,
            clock: Arc::new(SystemClock),
        }
    }
}

impl<R> JwtVerifier<R> {
    /// Override the algorithm allowlist. The default
    /// [`ALLOWED_ALGORITHMS`] is the conservative asymmetric set
    /// (`RS*` + `ES256` / `ES384`); RSA-PSS (`PS*`) and Ed25519
    /// (`EdDSA`) require explicit opt-in via this method.
    ///
    /// Typical opt-in cases:
    /// - **FAPI 2.0** deployments: the spec prefers `PS256` over
    ///   `RS256`. Pass `[Algorithm::PS256]` (or
    ///   `[Algorithm::PS256, Algorithm::ES256]` for mixed JWKS).
    /// - **Microsoft Entra** in PSS-token configurations: same as
    ///   FAPI 2.0.
    /// - **Modern issuers using Ed25519**: pass `[Algorithm::EdDSA]`.
    ///
    /// The allowlist is intersected with each JWK's family at
    /// verification time, so passing a mixed RSA + EC allowlist
    /// against an RSA JWK only exercises the RSA half.
    ///
    /// Symmetric algorithms (`HS256`, `HS384`, `HS512`) are never accepted:
    /// listing one here does not make a token signed with it verify, it fails
    /// as a disallowed algorithm. A JWKS is public, and a shared-secret key in
    /// it proves nothing about who signed.
    pub fn with_algorithms(mut self, algs: impl Into<Vec<Algorithm>>) -> Self {
        self.allowed_algorithms = algs.into();
        self
    }

    /// Pin the expected `iss` claim; mismatches are rejected.
    pub fn with_issuer(mut self, iss: impl Into<String>) -> Self {
        self.expected_issuer = Some(iss.into());
        self
    }

    /// Pin the expected `aud` claim; jsonwebtoken validates against it.
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.expected_audience = Some(aud.into());
        self
    }

    /// Record that accepting a token for any audience is intended.
    ///
    /// Without an audience pin ([`with_audience`](Self::with_audience)) a
    /// token minted for any other service of the same issuer would verify
    /// here, so `verify` refuses a verifier built with neither. This call
    /// states the decision, for the verifier whose issuer is the application's
    /// alone. It does not make
    /// [`JwtSvidResolver`](crate::jwt::svid::JwtSvidResolver) accept the
    /// verifier: a JWT-SVID must be validated against an audience.
    #[must_use]
    pub fn allow_any_audience(mut self) -> Self {
        self.audience_waived = true;
        self
    }

    /// Whether an `iss` is pinned.
    pub fn has_issuer(&self) -> bool {
        self.expected_issuer.is_some()
    }

    /// Whether an `aud` is pinned.
    pub fn has_audience(&self) -> bool {
        self.expected_audience.is_some()
    }

    /// Override the clock-skew tolerance applied to `exp` and `nbf`.
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Require the `nbf` claim to be present.
    pub fn require_nbf(mut self, required: bool) -> Self {
        self.require_nbf = required;
        self
    }

    /// Require the `exp` claim (the default). Only a caller with another
    /// bound on a token's life turns this off; a token without `exp` is
    /// otherwise valid forever and replayable without limit.
    pub fn require_exp(mut self, required: bool) -> Self {
        self.require_exp = required;
        self
    }

    /// Attach a replay store. Tokens verified by the resulting verifier
    /// must carry a `jti` claim; if the store reports it already used
    /// the verification fails. Replaces any previously configured store.
    pub fn with_replay_store<R2: JtiReplayStore>(self, store: R2) -> JwtVerifier<R2> {
        JwtVerifier {
            jwks: self.jwks,
            allowed_algorithms: self.allowed_algorithms,
            expected_issuer: self.expected_issuer,
            expected_audience: self.expected_audience,
            clock_skew: self.clock_skew,
            require_nbf: self.require_nbf,
            require_exp: self.require_exp,
            replay: Some(store),
            audience_waived: self.audience_waived,
            clock: self.clock,
        }
    }

    /// Inject a clock for DST tests. Defaults to
    /// [`SystemClock`]; pass a `MockClock`-backed handle to drive
    /// `exp` / `nbf` validation and replay-store TTL computation
    /// deterministically.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl<R: JtiReplayStore> JwtVerifier<R> {
    /// Verify `token` and deserialise the custom claims into `C`.
    ///
    /// Returns [`VerifiedClaims<C>`] on success. Failures map to
    /// [`JwtError`]; replay-store errors are folded into
    /// [`JwtError::VerificationFailed`] so callers can treat them
    /// uniformly with signature failures.
    pub async fn verify<C: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<VerifiedClaims<C>, JwtError> {
        if self.expected_audience.is_none() && !self.audience_waived {
            return Err(JwtError::VerificationFailed(
                "no audience is pinned: a token minted for any other service of the same \
                 issuer would verify. Call with_audience, or allow_any_audience to state \
                 that accepting any audience is intended"
                    .to_string(),
            ));
        }
        let config = ValidationConfig {
            issuer: self.expected_issuer.clone(),
            audience: self.expected_audience.clone(),
            leeway_secs: self.clock_skew.as_secs(),
            require_nbf: self.require_nbf,
            require_exp: self.require_exp,
        };

        let raw = {
            // Hold the read lock only across the synchronous decode;
            // never across `.await`.
            let guard = self
                .jwks
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            verify_jwt(
                token,
                &guard,
                &config,
                &self.allowed_algorithms,
                &*self.clock,
            )?
        };

        let iss = raw.get("iss").and_then(|v| v.as_str()).map(String::from);
        let sub = raw.get("sub").and_then(|v| v.as_str()).map(String::from);
        let aud = match raw.get("aud") {
            Some(serde_json::Value::String(s)) => Some(vec![s.clone()]),
            Some(serde_json::Value::Array(arr)) => Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
            ),
            _ => None,
        };
        let exp = raw.get("exp").and_then(|v| v.as_i64());
        let iat = raw.get("iat").and_then(|v| v.as_i64());
        let nbf = raw.get("nbf").and_then(|v| v.as_i64());
        let jti = raw.get("jti").and_then(|v| v.as_str()).map(String::from);

        if let Some(store) = &self.replay {
            let jti_value = jti.as_deref().ok_or_else(|| {
                JwtError::VerificationFailed(
                    "replay store configured but token has no `jti` claim".into(),
                )
            })?;
            let ttl = compute_replay_ttl(exp, self.clock_skew, &*self.clock);
            store
                .check_and_record(jti_value, ttl)
                .await
                .map_err(|e| JwtError::VerificationFailed(format!("jti replay: {e}")))?;
        }

        let custom: C = serde_json::from_value(raw)
            .map_err(|e| JwtError::VerificationFailed(format!("deserialise custom claims: {e}")))?;

        Ok(VerifiedClaims {
            iss,
            sub,
            aud,
            exp,
            iat,
            nbf,
            jti,
            custom,
        })
    }
}

/// How long a token with no `exp` is held in the replay store. Reachable
/// only when a caller turned `require_exp` off, since the verifier refuses
/// such a token by default: a credential with no end cannot be bounded, so
/// its `jti` is remembered for a day rather than forgotten at once.
const REPLAY_TTL_WITHOUT_EXP: Duration = Duration::from_secs(24 * 60 * 60);

/// Compute the TTL for a replay store entry: time until the token stops
/// being accepted, which is `exp` PLUS the clock-skew leeway (the verifier
/// accepts a token until `exp + skew`), floored at zero. A TTL of `exp -
/// now` alone would forget a token's `jti` while the verifier still took
/// the token, so a replay inside the leeway window would pass.
///
/// `now` is sourced from the injected
/// [`Clock`](axess_clock::Clock) rather than a direct
/// `chrono::Utc::now()` call, so DST tests can drive the TTL
/// calculation deterministically.
fn compute_replay_ttl(exp: Option<i64>, skew: Duration, clock: &dyn Clock) -> Duration {
    let Some(exp) = exp else {
        return REPLAY_TTL_WITHOUT_EXP;
    };
    let now = clock.now().timestamp();
    let skew = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
    let secs = exp.saturating_add(skew).saturating_sub(now).max(0) as u64;
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests;

/// Whether `verifier` pins both `iss` and `aud`, which every resolver that
/// turns a JWT into a workload identity requires. Logs the refusal under the
/// resolver's name, so an operator sees which one rejected its verifier.
pub(crate) fn verifier_is_pinned<R: JtiReplayStore>(verifier: &JwtVerifier<R>, who: &str) -> bool {
    if verifier.has_audience() && verifier.has_issuer() {
        return true;
    }
    tracing::error!(
        has_issuer = verifier.has_issuer(),
        has_audience = verifier.has_audience(),
        "{who}: the verifier must pin both `iss` and `aud`; refusing"
    );
    false
}
