//! In-process IdP test fixture: mints workload-identity JWTs
//! against an in-memory keypair (ES256 unless asked otherwise) and exposes
//! the matching JWKS.
//!
//! **Scope: test / dev only.** This fixture is for adopters writing
//! integration tests that exercise the inbound JWT-SVID resolver,
//! the OAuth Resource Server resolver, or any of the
//! [`cloud_sts`](crate::workload::outbound::cloud_sts) adapters
//! without standing up a real OIDC IdP. It deliberately omits the
//! capabilities a production IdP would carry: persistent signing
//! keys, key rotation, audit log hooks, consent UX, refresh tokens.
//!
//! The primitive types (`LocalIdpSigningKey`, `MintClaims`,
//! `IssuanceEvent`, `IssuanceListener`, plus internal helpers) are
//! shared with the production [`LocalIdp`](crate::local_idp::LocalIdp)
//! and live in [`crate::local_idp::primitives`]. This module hosts
//! only the test fixture (`LocalIdpFixture`) and the
//! `MockIssuanceListener` / `RecordedIssuance` recording helpers.
//!
//! # Example: integrate with `JwtVerifier`
//!
//! ```rust,ignore
//! use axess::jwt::svid::JwtSvidResolver;
//! use axess::testing::MockClock;
//! use axess::testing::local_idp::{LocalIdpFixture, MintClaims};
//! use axess::Clock;
//! use axess_clock::SignedDuration;
//!
//! let clock = MockClock::at_reference();
//! let idp = LocalIdpFixture::new("https://test.idp.local").with_clock(clock.clone());
//! let token = idp.mint(
//!     &MintClaims::new("alice", clock.now().plus(SignedDuration::hours(1)))
//!         .with_audience("https://api.example.com"),
//! );
//!
//! // Verifier reads the fixture's JWKS handle and validates the
//! // signature + iss + exp, the expiry at the test's time.
//! let verifier = JwtVerifier::new(idp.jwks_handle())
//!     .with_issuer(idp.issuer())
//!     .with_audience("https://api.example.com")
//!     .with_clock(std::sync::Arc::new(clock));
//! let claims = verifier.verify::<MyClaims>(&token, "https://api.example.com").await?;
//! ```
//!
//! # Example: feed a cloud STS adapter
//!
//! ```rust,ignore
//! use axess::workload::outbound::cloud_sts::aws::{
//!     AssumeRoleWithWebIdentityRequest, AwsStsClient,
//! };
//!
//! let idp = LocalIdpFixture::new("https://oidc.test.local");
//! let token = idp.mint_jwt_svid(
//!     "test.example.org", "worker", "acme",
//!     "sts.amazonaws.com",
//!     SignedDuration::minutes(5),
//! );
//! // Point AwsStsClient at LocalStack (or wiremock) and call
//! // AssumeRoleWithWebIdentity with the minted token.
//! ```

use axess_clock::testing::Shift;
use std::sync::{Arc, Mutex, RwLock};

use axess_clock::{Clock, SystemClock};
use axess_clock::{SignedDuration, Timestamp};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, Header};

use crate::local_idp::primitives::LocalIdpKeyError;
use crate::local_idp::primitives::{
    IssuanceEvent, IssuanceListener, LocalIdpSigningKey, MintClaims, build_claims_json,
    enforce_max_ttl, key_algorithm_to_algorithm, rebuild_jwks,
};

// ── Issuance audit recording ─────────────────────────────────────────────────

/// Owned snapshot of an [`IssuanceEvent`], suitable for asserting on
/// after the fact. Captured by [`MockIssuanceListener`].
#[derive(Debug, Clone)]
pub struct RecordedIssuance {
    /// `iss` claim: the fixture's configured issuer.
    pub issuer: String,
    /// JWT header `kid`: the signing key's id.
    pub key_id: String,
    /// JWT header `alg`: the signing algorithm in effect.
    pub algorithm: Algorithm,
    /// `sub` claim.
    pub subject: String,
    /// `aud` claim values (empty `Vec` indicates the claim was omitted).
    pub audience: Vec<String>,
    /// `exp` claim.
    pub expires_at: Timestamp,
    /// `nbf` claim, if set.
    pub not_before: Option<Timestamp>,
    /// `iat` claim, if set.
    pub issued_at: Option<Timestamp>,
    /// `jti` claim, if set.
    pub jwt_id: Option<String>,
}

/// Test [`IssuanceListener`] that captures every mint into an in-memory
/// `Vec<RecordedIssuance>`. Share one instance via `Arc::clone` between
/// the fixture and the assertion site.
#[derive(Default)]
pub struct MockIssuanceListener {
    events: Mutex<Vec<RecordedIssuance>>,
}

impl MockIssuanceListener {
    /// Construct an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded events. Returns a clone so adopters can
    /// assert without holding the internal lock.
    pub fn events(&self) -> Vec<RecordedIssuance> {
        self.events
            .lock()
            .expect("MockIssuanceListener mutex never poisoned in tests")
            .clone()
    }

    /// Number of mints observed so far.
    pub fn count(&self) -> usize {
        self.events
            .lock()
            .expect("MockIssuanceListener mutex never poisoned in tests")
            .len()
    }

    /// Drop all recorded events.
    pub fn clear(&self) {
        self.events
            .lock()
            .expect("MockIssuanceListener mutex never poisoned in tests")
            .clear();
    }
}

impl std::fmt::Debug for MockIssuanceListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockIssuanceListener")
            .field("count", &self.count())
            .finish()
    }
}

impl IssuanceListener for MockIssuanceListener {
    fn on_mint(&self, event: &IssuanceEvent<'_>) {
        self.events
            .lock()
            .expect("MockIssuanceListener mutex never poisoned in tests")
            .push(RecordedIssuance {
                issuer: event.issuer.to_string(),
                key_id: event.key_id.to_string(),
                algorithm: event.algorithm,
                subject: event.claims.subject.clone(),
                audience: event.claims.audience.clone(),
                expires_at: event.claims.expires_at,
                not_before: event.claims.not_before,
                issued_at: event.claims.issued_at,
                jwt_id: event.claims.jwt_id.clone(),
            });
    }
}

// ── Fixture ──────────────────────────────────────────────────────────────────

/// In-process IdP fixture. Wraps a [`LocalIdpSigningKey`] and the
/// matching JWKS, and exposes the issuer string used as `iss` on
/// minted tokens.
///
/// `LocalIdpFixture` is `Clone` (the underlying state is `Arc`-shared)
/// so test setup can hand the same fixture to multiple consumers
/// (one mints tokens, another exposes the JWKS to a wiremock-served
/// `.well-known/jwks.json` endpoint).
#[derive(Clone)]
pub struct LocalIdpFixture {
    inner: Arc<LocalIdpInner>,
}

struct LocalIdpInner {
    /// The signing key used for **new mints**. Its public JWK is the
    /// first entry in [`Self::jwks`].
    signing_key: LocalIdpSigningKey,
    /// Historical signing keys retained for the verifier-side rotation
    /// grace window. Their public JWKs appear in [`Self::jwks`] (so
    /// tokens already in flight under those keys still verify), but
    /// they are never used to mint new tokens.
    historical_keys: Vec<LocalIdpSigningKey>,
    /// Public-only JWKs added by [`LocalIdpFixture::with_extra_public_jwk`]
    /// typically the public material from another IdP that this
    /// fixture's JWKS should present alongside its own.
    extra_public_jwks: Vec<Jwk>,
    issuer: String,
    /// Optional max-TTL policy: if set, [`LocalIdpFixture::mint`]
    /// panics when `exp - now` exceeds this
    /// duration. Models the production-side guardrail against
    /// mistakenly issuing year-long tokens.
    max_ttl: Option<std::time::Duration>,
    /// Optional adopter-supplied audit hook fired after every
    /// successful mint. See [`IssuanceListener`] for the contract.
    issuance_listener: Option<Arc<dyn IssuanceListener>>,
    /// Cached JWKS = current signing key + historical + extra (in that
    /// order). Rebuilt by [`rebuild_jwks`] whenever any contributing
    /// source changes.
    jwks: JwkSet,
    /// The time [`LocalIdpFixture::mint`] stamps and caps tokens at:
    /// [`SystemClock`] unless [`LocalIdpFixture::with_clock`] sets another.
    clock: Arc<dyn Clock>,
}

impl LocalIdpFixture {
    /// Generate a fresh P-256 keypair and configure the fixture to issue
    /// tokens with `iss = issuer` and `alg = ES256`.
    ///
    /// ES256 is the default because it is fast (about a millisecond), its
    /// tokens are small, and it needs no `rsa` crate, whose private-key
    /// operations leak timing (RUSTSEC-2023-0071, the Marvin attack). A
    /// verifier that cannot take ES256 gets RSA from `new_rsa` or
    /// [`with_algorithm`](Self::with_algorithm), with the `local-idp-rsa`
    /// feature. Adopters wanting a stable keypair across runs reach for
    /// [`with_signing_key`](Self::with_signing_key) instead.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self::with_signing_key(issuer, LocalIdpSigningKey::generate_es256())
    }

    /// Generate a fresh RSA-2048 keypair and configure the fixture to issue
    /// tokens with `iss = issuer` and `alg = RS256`, for a verifier that
    /// cannot take ES256. Key generation takes ~50-200ms; construct once
    /// and share via `Clone`. See [`new`](Self::new) for why RSA is not the
    /// default.
    #[cfg(feature = "local-idp-rsa")]
    pub fn new_rsa(issuer: impl Into<String>) -> Self {
        Self::with_signing_key(issuer, LocalIdpSigningKey::generate_rsa())
    }

    /// Construct with an explicit signing algorithm. Dispatches by
    /// algorithm family: `ES256` produces a fresh P-256 keypair (per
    /// [`LocalIdpSigningKey::generate_es256`]); with the `local-idp-rsa`
    /// feature, `RS256` / `RS384` / `RS512` produce a fresh RSA-2048 keypair
    /// (per `LocalIdpSigningKey::generate_rsa_with_algorithm`).
    ///
    /// # Panics
    ///
    /// On any other algorithm, and on an RSA algorithm without the
    /// `local-idp-rsa` feature; [`try_with_algorithm`](Self::try_with_algorithm)
    /// returns the error instead.
    pub fn with_algorithm(issuer: impl Into<String>, algorithm: Algorithm) -> Self {
        Self::try_with_algorithm(issuer, algorithm).unwrap_or_else(|e| {
            panic!(
                "LocalIdpFixture::with_algorithm supports ES256, and RS256/RS384/RS512 with the \
                 `local-idp-rsa` feature: {e}"
            )
        })
    }

    /// Like [`with_algorithm`](Self::with_algorithm), returning an error
    /// instead of panicking.
    ///
    /// # Errors
    ///
    /// [`LocalIdpKeyError::UnsupportedAlgorithm`] for an algorithm other
    /// than `ES256`, `RS256`, `RS384` or `RS512`, and for one of the three
    /// RSA algorithms in a build without the `local-idp-rsa` feature;
    /// [`LocalIdpKeyError::KeyGeneration`] if an RSA keypair could not be
    /// generated.
    pub fn try_with_algorithm(
        issuer: impl Into<String>,
        algorithm: Algorithm,
    ) -> Result<Self, LocalIdpKeyError> {
        let signing_key = match algorithm {
            Algorithm::ES256 => LocalIdpSigningKey::generate_es256(),
            #[cfg(feature = "local-idp-rsa")]
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                LocalIdpSigningKey::try_generate_rsa_with_algorithm(algorithm)?
            }
            #[cfg(not(feature = "local-idp-rsa"))]
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                return Err(LocalIdpKeyError::UnsupportedAlgorithm(format!(
                    "{algorithm:?} (an RSA key needs the `local-idp-rsa` feature)"
                )));
            }
            other => {
                return Err(LocalIdpKeyError::UnsupportedAlgorithm(format!(
                    "{other:?} (the fixture generates ES256 keys, and RS256, RS384 and RS512 keys \
                     with the `local-idp-rsa` feature)"
                )));
            }
        };
        Ok(Self::with_signing_key(issuer, signing_key))
    }

    /// Construct with an adopter-supplied [`LocalIdpSigningKey`]. Use
    /// this when tests need a stable keypair across runs (load PEM
    /// from a checked-in fixture file or env var) or when prototyping
    /// the production wiring where keys come from a real key
    /// provider.
    pub fn with_signing_key(issuer: impl Into<String>, signing_key: LocalIdpSigningKey) -> Self {
        let jwks = rebuild_jwks(&signing_key, &[], &[]);
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key,
                historical_keys: Vec::new(),
                extra_public_jwks: Vec::new(),
                issuer: issuer.into(),
                max_ttl: None,
                issuance_listener: None,
                jwks,
                clock: Arc::new(SystemClock),
            }),
        }
    }

    /// Add a **historical** signing key whose public JWK appears in
    /// the JWKS alongside the current key but which is never used to
    /// mint new tokens. Models a key-rotation grace window where a
    /// verifier may still see tokens signed under the previous key.
    ///
    /// Typical usage:
    ///
    /// ```rust,ignore
    /// // Snapshot under k1, then build a rotated fixture that still
    /// // verifies tokens minted under k1:
    /// let k1 = LocalIdpSigningKey::generate_es256().with_key_id("k1");
    /// let old_idp = LocalIdpFixture::with_signing_key("https://idp", k1.clone());
    /// let token_old = old_idp.mint(&claims);
    ///
    /// let k2 = LocalIdpSigningKey::generate_es256().with_key_id("k2");
    /// let rotated_idp = LocalIdpFixture::with_signing_key("https://idp", k2)
    ///     .with_historical_signing_key(k1);
    ///
    /// // Verifier dispatches by token's kid header against the JWKS.
    /// let verifier = JwtVerifier::new(rotated_idp.jwks_handle())
    ///     .with_issuer(rotated_idp.issuer())
    ///     .with_audience("https://api");
    /// verifier.verify::<()>(&token_old).await?; // hits historical k1
    /// verifier.verify::<()>(&rotated_idp.mint(&claims)).await?; // hits k2
    /// ```
    pub fn with_historical_signing_key(self, key: LocalIdpSigningKey) -> Self {
        let mut historical = self.inner.historical_keys.clone();
        historical.push(key);
        let jwks = rebuild_jwks(
            &self.inner.signing_key,
            &historical,
            &self.inner.extra_public_jwks,
        );
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: self.inner.signing_key.clone(),
                historical_keys: historical,
                extra_public_jwks: self.inner.extra_public_jwks.clone(),
                issuer: self.inner.issuer.clone(),
                max_ttl: self.inner.max_ttl,
                issuance_listener: self.inner.issuance_listener.clone(),
                jwks,
                clock: self.inner.clock.clone(),
            }),
        }
    }

    /// Add a public-only [`Jwk`] to the JWKS without registering a
    /// matching signing key. Use when a single `JwtVerifier` should
    /// trust tokens from this fixture **plus** another IdP whose
    /// public key you've imported separately.
    pub fn with_extra_public_jwk(self, jwk: Jwk) -> Self {
        let mut extra = self.inner.extra_public_jwks.clone();
        extra.push(jwk);
        let jwks = rebuild_jwks(&self.inner.signing_key, &self.inner.historical_keys, &extra);
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: self.inner.signing_key.clone(),
                historical_keys: self.inner.historical_keys.clone(),
                extra_public_jwks: extra,
                issuer: self.inner.issuer.clone(),
                max_ttl: self.inner.max_ttl,
                issuance_listener: self.inner.issuance_listener.clone(),
                jwks,
                clock: self.inner.clock.clone(),
            }),
        }
    }

    /// Rotate to a new current signing key. The previous current key
    /// is moved to the historical list so tokens already minted under
    /// it remain verifiable. New mints sign under `new_key`.
    ///
    /// Equivalent to building a fresh fixture with `new_key` as the
    /// current key and the previous current key passed through
    /// [`Self::with_historical_signing_key`], so adopters that prefer
    /// fresh construction over mutation can also model rotation by
    /// hand.
    pub fn rotate_signing_key(self, new_key: LocalIdpSigningKey) -> Self {
        let mut historical = self.inner.historical_keys.clone();
        historical.push(self.inner.signing_key.clone());
        let jwks = rebuild_jwks(&new_key, &historical, &self.inner.extra_public_jwks);
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: new_key,
                historical_keys: historical,
                extra_public_jwks: self.inner.extra_public_jwks.clone(),
                issuer: self.inner.issuer.clone(),
                max_ttl: self.inner.max_ttl,
                issuance_listener: self.inner.issuance_listener.clone(),
                jwks,
                clock: self.inner.clock.clone(),
            }),
        }
    }

    /// Cap the maximum lifetime of minted tokens. When set, [`mint`](Self::mint)
    /// / [`mint_with_header`](Self::mint_with_header) /
    /// [`mint_jwt_svid`](Self::mint_jwt_svid) panic if `exp - now`
    /// exceeds `ttl`. The lifetime is measured from now, never from a
    /// caller-supplied `iat`, so a future-dated `iat` cannot shrink it.
    ///
    /// Models the production guardrail against accidentally minting
    /// long-lived tokens. The production `LocalIdp` shape will surface
    /// this as a fallible API; the fixture panics so tests catch the
    /// misuse loudly rather than silently producing a token a
    /// production deployment would refuse.
    ///
    /// Unset (the default) means no cap.
    pub fn with_max_ttl(self, ttl: std::time::Duration) -> Self {
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: self.inner.signing_key.clone(),
                historical_keys: self.inner.historical_keys.clone(),
                extra_public_jwks: self.inner.extra_public_jwks.clone(),
                issuer: self.inner.issuer.clone(),
                max_ttl: Some(ttl),
                issuance_listener: self.inner.issuance_listener.clone(),
                jwks: self.inner.jwks.clone(),
                clock: self.inner.clock.clone(),
            }),
        }
    }

    /// Mint at `clock`'s time: [`mint`](Self::mint),
    /// [`mint_with_header`](Self::mint_with_header) and
    /// [`mint_jwt_svid`](Self::mint_jwt_svid) measure the max-TTL cap, and
    /// the JWT-SVID's `iat` and `exp`, from it instead of the system clock,
    /// so a test's tokens belong to the world its
    /// [`MockClock`](crate::testing::MockClock) runs.
    pub fn with_clock(self, clock: impl Clock + 'static) -> Self {
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: self.inner.signing_key.clone(),
                historical_keys: self.inner.historical_keys.clone(),
                extra_public_jwks: self.inner.extra_public_jwks.clone(),
                issuer: self.inner.issuer.clone(),
                max_ttl: self.inner.max_ttl,
                issuance_listener: self.inner.issuance_listener.clone(),
                jwks: self.inner.jwks.clone(),
                clock: Arc::new(clock),
            }),
        }
    }

    /// Borrow the configured max-TTL cap, if any.
    pub fn max_ttl(&self) -> Option<std::time::Duration> {
        self.inner.max_ttl
    }

    /// Install an [`IssuanceListener`] fired after every successful
    /// mint. The listener is shared via [`Arc`]; adopters keep a
    /// clone for assertion-side access while the fixture retains its
    /// own clone for invocation. Calling this builder again replaces
    /// the previous listener.
    ///
    /// Mints rejected by the [`with_max_ttl`](Self::with_max_ttl) cap
    /// panic *before* the listener fires, mirroring the production
    /// contract that audit logs only record successful issuance.
    ///
    /// ```rust,ignore
    /// let recorder = std::sync::Arc::new(MockIssuanceListener::new());
    /// let idp = LocalIdpFixture::new("https://idp")
    ///     .with_issuance_listener(recorder.clone());
    /// idp.mint(&MintClaims::new("alice", MockClock::reference_time().plus(SignedDuration::hours(1))));
    /// assert_eq!(recorder.count(), 1);
    /// ```
    pub fn with_issuance_listener(self, listener: Arc<dyn IssuanceListener>) -> Self {
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: self.inner.signing_key.clone(),
                historical_keys: self.inner.historical_keys.clone(),
                extra_public_jwks: self.inner.extra_public_jwks.clone(),
                issuer: self.inner.issuer.clone(),
                max_ttl: self.inner.max_ttl,
                issuance_listener: Some(listener),
                jwks: self.inner.jwks.clone(),
                clock: self.inner.clock.clone(),
            }),
        }
    }

    /// Borrow the installed [`IssuanceListener`], if any.
    pub fn issuance_listener(&self) -> Option<&Arc<dyn IssuanceListener>> {
        self.inner.issuance_listener.as_ref()
    }

    /// Override the key id used in both JWK and signed JWT
    /// headers. Adopters with multiple fixtures in one test exposing
    /// distinct keys via a single shared JWKS endpoint use this to
    /// keep them distinguishable. Historical and extra-public keys
    /// (if any) survive the rename.
    pub fn with_key_id(self, key_id: impl Into<String>) -> Self {
        let new_signing_key = self.inner.signing_key.clone().with_key_id(key_id);
        let jwks = rebuild_jwks(
            &new_signing_key,
            &self.inner.historical_keys,
            &self.inner.extra_public_jwks,
        );
        Self {
            inner: Arc::new(LocalIdpInner {
                signing_key: new_signing_key,
                historical_keys: self.inner.historical_keys.clone(),
                extra_public_jwks: self.inner.extra_public_jwks.clone(),
                issuer: self.inner.issuer.clone(),
                max_ttl: self.inner.max_ttl,
                issuance_listener: self.inner.issuance_listener.clone(),
                jwks,
                clock: self.inner.clock.clone(),
            }),
        }
    }

    /// Borrow the configured issuer string.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// Borrow the configured key id.
    pub fn key_id(&self) -> &str {
        self.inner.signing_key.key_id()
    }

    /// Borrow the signing algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.inner.signing_key.algorithm()
    }

    /// Algorithms the fixture's JWKS can verify: the union of the
    /// current signing key, every historical signing key, and any
    /// extra public JWKs that declare an `alg` field.
    ///
    /// Designed for the `JwtVerifier::with_algorithms(...)` call site:
    ///
    /// ```rust,ignore
    /// let verifier = JwtVerifier::new(idp.jwks_handle())
    ///     .with_issuer(idp.issuer())
    ///     .with_audience("https://api.example.com")
    ///     .with_algorithms(idp.verifier_algorithms());
    /// ```
    ///
    /// The default `JwtVerifier` allowlist is `RS256 / RS384 / RS512`
    /// only; adopters who mint ES256 tokens (or rotate through mixed
    /// RSA + EC keys) get silent verification failures without
    /// explicitly extending the allowlist. This accessor returns the
    /// exact set that the fixture's JWKS supports today, so the
    /// allowlist tracks rotations and cross-algorithm history
    /// automatically.
    ///
    /// Order: current signing key first (so the most-used algorithm
    /// is hit first when the verifier iterates), then historical, then
    /// extra. Each algorithm appears at most once. Extra JWKs with no
    /// `alg` field are skipped (the verifier dispatches by `kid` alone
    /// for those, and the algorithm is inferred from the JWT header).
    pub fn verifier_algorithms(&self) -> Vec<Algorithm> {
        let mut out = Vec::new();
        let push_unique = |a: Algorithm, out: &mut Vec<Algorithm>| {
            if !out.contains(&a) {
                out.push(a);
            }
        };
        push_unique(self.inner.signing_key.algorithm(), &mut out);
        for hk in &self.inner.historical_keys {
            push_unique(hk.algorithm(), &mut out);
        }
        for jwk in &self.inner.extra_public_jwks {
            if let Some(ka) = jwk.common.key_algorithm
                && let Some(alg) = key_algorithm_to_algorithm(ka)
            {
                push_unique(alg, &mut out);
            }
        }
        out
    }

    /// Borrow the underlying signing key.
    pub fn signing_key(&self) -> &LocalIdpSigningKey {
        &self.inner.signing_key
    }

    /// Borrow the public-key JWKS. Serve over HTTP at a
    /// `.well-known/jwks.json` endpoint in adopter test code, or
    /// pass to [`jwks_handle`](Self::jwks_handle) to plug into
    /// [`JwtVerifier`](axess_factors::jwt::verifier::JwtVerifier)
    /// directly.
    pub fn jwks(&self) -> &JwkSet {
        &self.inner.jwks
    }

    /// Serialize the JWKS as a JSON string; typically what an
    /// adopter would return from a wiremock-served
    /// `.well-known/jwks.json` endpoint.
    pub fn jwks_json(&self) -> String {
        serde_json::to_string(&self.inner.jwks).expect("JwkSet serialisation always succeeds")
    }

    /// Build a shared `Arc<RwLock<JwkSet>>` handle suitable for
    /// `JwtVerifier::new(...)`.
    pub fn jwks_handle(&self) -> Arc<RwLock<JwkSet>> {
        Arc::new(RwLock::new(self.inner.jwks.clone()))
    }

    /// Mint a signed JWT. The fixture sets `iss`, header `kid`, and
    /// header `alg` automatically; caller supplies the rest via
    /// [`MintClaims`].
    ///
    /// The max-TTL cap, when configured, is measured from the fixture's
    /// clock ([`with_clock`](Self::with_clock)); use
    /// [`mint_at`](Self::mint_at) to measure it from a chosen instant.
    pub fn mint(&self, claims: &MintClaims) -> String {
        self.mint_at(claims, self.inner.clock.now())
    }

    /// Like [`mint`](Self::mint) but measures the max-TTL cap from `now`
    /// instead of the fixture's clock, so a test driving a
    /// [`MockClock`](crate::testing::MockClock) gets exact behaviour.
    pub fn mint_at(&self, claims: &MintClaims, now: Timestamp) -> String {
        self.mint_with_header_at(
            claims,
            &mut Header::new(self.inner.signing_key.algorithm()),
            now,
        )
    }

    /// Mint with caller-supplied header. Adopters reach for this
    /// when they need to set unusual header fields (e.g. test
    /// `x5t` thumbprint matching). `kid` and `alg` are the signing key's,
    /// and the key-location fields `jku`, `jwk`, `x5u` and `x5c` are cleared,
    /// as the production `LocalIdp` does.
    pub fn mint_with_header(&self, claims: &MintClaims, header: &mut Header) -> String {
        self.mint_with_header_at(claims, header, self.inner.clock.now())
    }

    /// Like [`mint_with_header`](Self::mint_with_header) but measures the
    /// max-TTL cap from `now` instead of the fixture's clock.
    pub fn mint_with_header_at(
        &self,
        claims: &MintClaims,
        header: &mut Header,
        now: Timestamp,
    ) -> String {
        if let Some(max_ttl) = self.inner.max_ttl {
            enforce_max_ttl(claims, max_ttl, now);
        }
        header.kid = Some(self.inner.signing_key.key_id().to_string());
        header.alg = self.inner.signing_key.algorithm();
        // As the production IdP does: these name where a verifier may fetch,
        // or what key it may use instead of the IdP's own, and the IdP signs
        // with its own key.
        header.jku = None;
        header.jwk = None;
        header.x5u = None;
        header.x5c = None;
        let claims_json = build_claims_json(&self.inner.issuer, claims);
        let key = self.inner.signing_key.encoding_key();
        let token = axess_factors::jwt::encode(header, &claims_json, key)
            .expect("JWT encode never fails on valid inputs");
        if let Some(listener) = &self.inner.issuance_listener {
            let event = IssuanceEvent {
                issuer: &self.inner.issuer,
                key_id: self.inner.signing_key.key_id(),
                algorithm: self.inner.signing_key.algorithm(),
                claims,
            };
            listener.on_mint(&event);
        }
        token
    }

    /// Convenience wrapper to mint a SPIFFE-shaped JWT-SVID with
    /// `sub = "spiffe://<trust_domain>/<service>/<tenant>"` and
    /// the given audience + TTL. The fixture sets `iat = now`,
    /// `exp = now + ttl`, `iss = self.issuer()`, with `now` read from the
    /// fixture's clock; [`mint_jwt_svid_at`](Self::mint_jwt_svid_at) takes it
    /// as a parameter.
    pub fn mint_jwt_svid(
        &self,
        trust_domain: &str,
        service: &str,
        tenant: &str,
        audience: impl Into<String>,
        ttl: SignedDuration,
    ) -> String {
        self.mint_jwt_svid_at(
            trust_domain,
            service,
            tenant,
            audience,
            ttl,
            self.inner.clock.now(),
        )
    }

    /// Like [`mint_jwt_svid`](Self::mint_jwt_svid) with `iat = now`,
    /// `exp = now + ttl` and the max-TTL cap all taken from `now`.
    pub fn mint_jwt_svid_at(
        &self,
        trust_domain: &str,
        service: &str,
        tenant: &str,
        audience: impl Into<String>,
        ttl: SignedDuration,
        now: Timestamp,
    ) -> String {
        let exp = now.plus(ttl);
        let subject = format!("spiffe://{trust_domain}/{service}/{tenant}");
        let claims = MintClaims::new(subject, exp)
            .with_audience(audience)
            .with_issued_at(now);
        self.mint_at(&claims, now)
    }
}

impl std::fmt::Debug for LocalIdpFixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdpFixture")
            .field("issuer", &self.inner.issuer)
            .field("signing_key", &self.inner.signing_key)
            .finish()
    }
}

// Tests for `LocalIdpFixture`, split by topic. The whole `testing::local_idp`
// module is a test fixture, so the children sit alongside the fixture impl
// without a redundant `tests` intermediate.
#[cfg(test)]
mod audit_hook;
#[cfg(test)]
mod es256;
#[cfg(test)]
mod max_ttl;
#[cfg(test)]
mod mint_verify;
#[cfg(all(test, feature = "local-idp-rsa"))]
mod multi_key;
#[cfg(all(test, not(feature = "local-idp-rsa")))]
mod rsa_refused;
#[cfg(all(test, feature = "local-idp-rsa"))]
mod signing_key;
