//! Production in-process IdP. Mints workload-identity JWTs against an
//! adopter-supplied key store, serves the matching JWKS, and emits
//! issuance events through the same audit hook the test fixture uses.
//!
//! `LocalIdp` is the production counterpart to `LocalIdpFixture` (under
//! `crate::testing::local_idp`). The fixture generates a fresh keypair
//! per `new()` (test-only; tokens become unverifiable across restarts),
//! while production loads its current + historical signing keys from a
//! [`LocalIdpKeyStore`](crate::local_idp::LocalIdpKeyStore) implementation (file, Vault, KMS, ...). Both
//! variants share the primitives in [`primitives`](crate::local_idp::primitives), so tokens minted by
//! either are byte-identical when the same key drives them.
//!
//! Scope: issuance only. No authorization-code flow, refresh tokens,
//! end-session endpoint, or consent UX; those belong to a full OAuth
//! Authorization Server (Keycloak / Ory Hydra).
//!
//! # Example
//!
//! ```rust,ignore
//! use axess::local_idp::{LocalIdp, LocalIdpSigningKey, MemoryLocalIdpKeyStore, MintClaims};
//! use chrono::{Duration, Utc};
//!
//! let key = LocalIdpSigningKey::generate_es256().with_key_id("v1");
//! let store = MemoryLocalIdpKeyStore::with_current(key);
//! let idp = LocalIdp::from_key_store("https://idp.local", store)
//!     .await
//!     .expect("load keys");
//!
//! let token = idp
//!     .mint(
//!         &MintClaims::new("worker-1", Utc::now() + Duration::minutes(5))
//!             .with_audience("https://api")
//!             .with_issued_at(Utc::now()),
//!     )
//!     .await
//!     .expect("mint");
//! ```

use std::sync::{Arc, RwLock};

use axess_clock::{Clock, SystemClock};
use chrono::Duration;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, Header, encode};
use tokio::sync::RwLock as AsyncRwLock;

use self::primitives::{build_claims_json, enforce_max_ttl_fallible, key_algorithm_to_algorithm};

// Primitives live in `crate::local_idp::primitives`; the test fixture in
// `crate::testing::local_idp` imports them. Adopters write
// `use axess::local_idp::{LocalIdp, LocalIdpSigningKey, MintClaims}` and the
// facade resolves through the same re-export path.
pub use self::primitives::{IssuanceEvent, IssuanceListener, LocalIdpSigningKey, MintClaims};
#[cfg(any(test, feature = "testing"))]
pub use crate::testing::local_idp::{MockIssuanceListener, RecordedIssuance};

/// Primitive types (`LocalIdpSigningKey`, `MintClaims`, `IssuanceEvent`,
/// `IssuanceListener`, plus internal helpers) shared between the
/// production [`LocalIdp`] and the test
/// [`LocalIdpFixture`](crate::testing::local_idp::LocalIdpFixture). Lives
/// outside `crate::testing` so production code does not have to import
/// from a test module.
pub mod primitives;

/// RFC 8414 minimal discovery document + axum handlers for serving
/// it (`/.well-known/openid-configuration` + `/jwks.json`). Promoted
/// out of the parent module so the metadata struct and the handler
/// functions live near each other and can be re-exported together.
pub mod discovery;

pub use discovery::LocalIdpMetadata;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors from `LocalIdp` issuance and key-store operations.
///
/// Parameterised over the key store's error type so that backend
/// errors propagate with their original type, mirroring the shape of
/// [`crate::authn::error::AuthnError`].
#[derive(Debug, thiserror::Error)]
pub enum IssuanceError<KE: std::error::Error + Send + Sync + 'static> {
    /// The claim set's lifetime (`exp - iat`, or `exp - now` when
    /// `iat` is unset) exceeds the configured `max_ttl` cap. Production
    /// refuses the mint rather than producing a token a downstream
    /// verifier would honour despite the policy.
    #[error("token lifetime {observed} exceeds configured max-TTL {max}")]
    LifetimeExceedsCap {
        /// The computed lifetime of the proposed token.
        observed: Duration,
        /// The configured cap.
        max: Duration,
    },
    /// The claim set names no audience and the IdP was not told to allow
    /// that. A token without `aud` is accepted by every verifier that does
    /// not pin an audience, so minting one is an explicit choice
    /// ([`LocalIdp::allow_no_audience`]).
    #[error("refusing to mint a token with no audience")]
    MissingAudience,
    /// The key asked to be retired is the current signing key. Rotate to a
    /// new key first, then retire the old one.
    #[error("the current signing key cannot be retired")]
    RetireCurrentKey,
    /// The underlying `LocalIdpKeyStore` surfaced an error during
    /// load or rotation. The original backend error is preserved
    /// as `#[source]`.
    #[error("key store error")]
    KeyStore(#[source] KE),
    /// A rotation offered a key whose `kid` is already in the JWKS (the
    /// current key or a historical one). Two keys under one `kid` make
    /// verifiers pick either, so the rotation is refused and nothing
    /// changes.
    #[error("signing key id {kid:?} is already in use")]
    DuplicateKeyId {
        /// The `kid` that collided.
        kid: String,
    },
    /// JWT encoding failed. In practice this never fires for valid
    /// `LocalIdpSigningKey` material plus a well-formed `MintClaims`,
    /// but the `jsonwebtoken::encode` return type forces the path.
    #[error("JWT encoding error: {0}")]
    Encoding(String),
}

// ── Key store ────────────────────────────────────────────────────────────────

/// Atomic snapshot of a `LocalIdpKeyStore`'s contents.
///
/// Returned by [`LocalIdpKeyStore::load_all`] so the store can serve
/// its current + historical keys from a single consistent read
/// (single transaction for SQL backends, single MGET for Valkey,
/// single file read for file-backed stores). Per the design decision
/// (combined `load_all` over split `load_current` + `load_historical`)
/// this is the only shape adopter backends need to implement.
#[derive(Debug, Clone)]
pub struct LoadedKeys {
    /// The key that signs new mints. JWKS lists its public JWK first.
    pub current: LocalIdpSigningKey,
    /// Historical keys retained for the verifier-side rotation grace
    /// window. JWKS includes them so tokens already in flight under
    /// those keys still verify, but new mints never sign under them.
    pub historical: Vec<LocalIdpSigningKey>,
}

/// Persistent key storage trait for production [`LocalIdp`].
///
/// Adopters implement this against their key material (file on disk,
/// HashiCorp Vault, AWS KMS, GCP KMS, ...). The trait stays minimal:
/// `load_all` for the startup + JWKS-rebuild path and `rotate` for
/// admin-triggered key rotation.
///
/// Async-trait shape mirrors [`crate::SessionStore`]: explicit
/// `impl Future<Output = ...> + Send` rather than `#[async_trait]`,
/// per the workspace convention.
pub trait LocalIdpKeyStore: Send + Sync + 'static {
    /// The error type returned by storage operations. Surfaces through
    /// [`IssuanceError::KeyStore`] without being type-erased, so adopters
    /// can match on their backend's concrete error from the consumer
    /// side.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the full key set in one atomic snapshot.
    ///
    /// Backends MUST return current + historical from a single
    /// consistent read so the resulting JWKS reflects a coherent
    /// rotation state. Interleaving a separate `load_current` and
    /// `load_historical` could observe a rotation in progress and
    /// build a JWKS that's missing the just-rotated-out key.
    fn load_all(&self)
    -> impl std::future::Future<Output = Result<LoadedKeys, Self::Error>> + Send;

    /// Persist a new current signing key, demoting the previous
    /// current to historical (atomic). Used by L2's
    /// `LocalIdp::rotate_signing_key`. Not exercised by L1.
    fn rotate(
        &self,
        new_current: LocalIdpSigningKey,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Remove the historical key with this `kid` so it leaves the JWKS.
    /// Returns whether a historical key was removed; the current key is
    /// never removed by this call. Used by [`LocalIdp::retire_historical_key`]
    /// once no token signed under the key can still be valid.
    fn retire(
        &self,
        key_id: &str,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;
}

mod memory_store;
pub use memory_store::{MemoryLocalIdpKeyStore, MemoryLocalIdpKeyStoreError};

// ── LocalIdp ─────────────────────────────────────────────────────────────────

use discovery::RESERVED_METADATA_FIELDS;

/// Production-grade in-process IdP.
///
/// See module docs for the full architecture. `LocalIdp` is
/// parameterized over the [`LocalIdpKeyStore`] implementation so
/// backend errors surface with their original type through
/// [`IssuanceError::KeyStore`].
pub struct LocalIdp<K: LocalIdpKeyStore> {
    state: Arc<AsyncRwLock<LocalIdpState>>,
    key_store: Arc<K>,
    issuer: String,
    base_url: Option<String>,
    extra_metadata: Vec<(String, serde_json::Value)>,
    max_ttl: Option<Duration>,
    require_audience: bool,
    issuance_listener: Option<Arc<dyn IssuanceListener>>,
    clock: Arc<dyn Clock>,
}

/// Lifetime cap a new [`LocalIdp`] applies until
/// [`with_max_ttl`](LocalIdp::with_max_ttl) or
/// [`without_max_ttl`](LocalIdp::without_max_ttl) says otherwise.
pub const DEFAULT_MAX_TTL: Duration = Duration::hours(1);

impl<K: LocalIdpKeyStore> Clone for LocalIdp<K> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            key_store: self.key_store.clone(),
            issuer: self.issuer.clone(),
            base_url: self.base_url.clone(),
            extra_metadata: self.extra_metadata.clone(),
            max_ttl: self.max_ttl,
            require_audience: self.require_audience,
            issuance_listener: self.issuance_listener.clone(),
            clock: self.clock.clone(),
        }
    }
}

impl<K: LocalIdpKeyStore> std::fmt::Debug for LocalIdp<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdp")
            .field("issuer", &self.issuer)
            .field("base_url", &self.base_url)
            .field("extra_metadata_fields", &self.extra_metadata.len())
            .field("max_ttl", &self.max_ttl)
            .field(
                "issuance_listener",
                &self.issuance_listener.as_ref().map(|_| "<set>"),
            )
            .finish()
    }
}

struct LocalIdpState {
    signing_key: LocalIdpSigningKey,
    historical_keys: Vec<LocalIdpSigningKey>,
    extra_public_jwks: Vec<Jwk>,
    jwks: JwkSet,
}

impl LocalIdpState {
    /// Adopt the store's snapshot and rebuild the JWKS from it.
    fn replace_keys(&mut self, loaded: LoadedKeys) {
        self.signing_key = loaded.current;
        self.historical_keys = loaded.historical;
        self.rebuild();
    }

    fn rebuild(&mut self) {
        self.jwks = rebuild_jwks(
            &self.signing_key,
            &self.historical_keys,
            &self.extra_public_jwks,
        );
    }
}

impl<K: LocalIdpKeyStore> LocalIdp<K> {
    /// Construct from a key store. Loads the current + historical keys
    /// atomically, builds the initial JWKS, and is ready to mint.
    pub async fn from_key_store(
        issuer: impl Into<String>,
        key_store: K,
    ) -> Result<Self, IssuanceError<K::Error>> {
        let loaded = key_store
            .load_all()
            .await
            .map_err(IssuanceError::KeyStore)?;
        let jwks = rebuild_jwks(&loaded.current, &loaded.historical, &[]);
        Ok(Self {
            state: Arc::new(AsyncRwLock::new(LocalIdpState {
                signing_key: loaded.current,
                historical_keys: loaded.historical,
                extra_public_jwks: Vec::new(),
                jwks,
            })),
            key_store: Arc::new(key_store),
            issuer: issuer.into(),
            base_url: None,
            extra_metadata: Vec::new(),
            max_ttl: Some(DEFAULT_MAX_TTL),
            require_audience: true,
            issuance_listener: None,
            clock: Arc::new(SystemClock),
        })
    }

    /// Pin the absolute base URL the discovery handler advertises for
    /// the `jwks_uri` field. When unset, the issuer string is used as
    /// the base, which is typical for deployments where the issuer is
    /// the public-facing URL of the IdP. Adopters serving the IdP behind a
    /// reverse proxy or under a non-issuer URL set this explicitly.
    ///
    /// The trailing slash is stripped; handler paths are appended with
    /// a leading slash (`/jwks.json`).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Append an adopter-extension field to the discovery document.
    /// `name` is the JSON key; `value` is any `serde_json::Value`.
    /// Multiple calls accumulate. A name the document derives itself
    /// (`issuer`, `jwks_uri`, `id_token_signing_alg_values_supported`) or a
    /// name already added is refused: the call is ignored with a warning and
    /// the first value stays. Use for fields RFC 8414 / OIDC Core define but
    /// that `LocalIdp` does not auto-populate (e.g. `scopes_supported`,
    /// `claims_supported`, `subject_types_supported`, FAPI-specific
    /// fields).
    pub fn with_metadata_field(
        mut self,
        name: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        let name = name.into();
        // `issuer` and `jwks_uri` are the document's own, derived from the
        // issuer and base URL; an extra field under either name would
        // repoint relying parties and is not accepted.
        if RESERVED_METADATA_FIELDS.contains(&name.as_str()) {
            tracing::warn!(field = %name, "with_metadata_field ignored a reserved discovery field");
            return self;
        }
        if self.extra_metadata.iter().any(|(n, _)| *n == name) {
            tracing::warn!(field = %name, "with_metadata_field ignored a duplicate field");
            return self;
        }
        self.extra_metadata.push((name, value));
        self
    }

    /// Cap the maximum lifetime of minted tokens. When set, [`mint`](Self::mint)
    /// returns [`IssuanceError::LifetimeExceedsCap`] for over-cap
    /// claim sets. Contrast with
    /// [`crate::testing::local_idp::LocalIdpFixture::with_max_ttl`],
    /// which panics at the misuse site (fixture mints have no error
    /// channel because they're test-time).
    pub fn with_max_ttl(mut self, ttl: Duration) -> Self {
        self.max_ttl = Some(ttl);
        self
    }

    /// Remove the [`DEFAULT_MAX_TTL`] cap; only for intended long-lived tokens.
    pub fn without_max_ttl(mut self) -> Self {
        self.max_ttl = None;
        self
    }

    /// Allow minting tokens that carry no `aud`. By default such a mint is
    /// refused with [`IssuanceError::MissingAudience`]: a verifier that does
    /// not pin an audience would accept the token for any service.
    pub fn allow_no_audience(mut self) -> Self {
        self.require_audience = false;
        self
    }

    /// Install an [`IssuanceListener`] fired after every successful
    /// mint. Same trait the fixture uses; production wires this to a
    /// real audit sink, the fixture wires it to assertion-side
    /// recording.
    pub fn with_issuance_listener(mut self, listener: Arc<dyn IssuanceListener>) -> Self {
        self.issuance_listener = Some(listener);
        self
    }

    /// Inject a [`Clock`] (typically [`SystemClock`] for production,
    /// [`crate::testing::MockClock`] for tests). Drives the
    /// max-TTL reference time when claims omit `iat`.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Mint a signed JWT. The fixture sets `iss`, header `kid`, and
    /// header `alg` automatically; caller supplies the rest via
    /// [`MintClaims`]. Returns [`IssuanceError::LifetimeExceedsCap`]
    /// if the configured `max_ttl` is exceeded, instead of panicking:
    /// production must refuse rather than reject loudly.
    pub async fn mint(&self, claims: &MintClaims) -> Result<String, IssuanceError<K::Error>> {
        self.mint_with_header(claims, Header::default()).await
    }

    /// Mint with caller-supplied header. Adopters reach for this when
    /// they need to set unusual header fields (e.g. `typ`, `cty`,
    /// `x5t` thumbprint). The fixture's parallel method takes
    /// `&mut Header` for in-place mutation; the production shape
    /// takes `Header` by value since the caller's customization is
    /// always built up before mint, never amended after.
    pub async fn mint_with_header(
        &self,
        claims: &MintClaims,
        mut header: Header,
    ) -> Result<String, IssuanceError<K::Error>> {
        let state = self.state.read().await;

        if let Some(max_ttl) = self.max_ttl {
            let now = self.clock.now();
            enforce_max_ttl_fallible(claims, max_ttl, now)
                .map_err(|(observed, max)| IssuanceError::LifetimeExceedsCap { observed, max })?;
        }

        if self.require_audience && claims.audience.is_empty() {
            return Err(IssuanceError::MissingAudience);
        }
        header.kid = Some(state.signing_key.key_id().to_string());
        header.alg = state.signing_key.algorithm();
        let claims_json = build_claims_json(&self.issuer, claims);
        let key = state.signing_key.encoding_key();
        // This is the one place axess signs rather than verifies, and
        // `jsonwebtoken` needs a crypto provider for both. With one backend
        // compiled in it derives its own; with two (`--all-features`, or an
        // adopter and a dependency that chose differently) it cannot, and
        // would panic here.
        axess_factors::jwt::ensure_crypto_provider();
        let token = encode(&header, &claims_json, &key)
            .map_err(|e| IssuanceError::Encoding(e.to_string()))?;

        if let Some(listener) = &self.issuance_listener {
            let event = IssuanceEvent {
                issuer: &self.issuer,
                key_id: state.signing_key.key_id(),
                algorithm: state.signing_key.algorithm(),
                claims,
            };
            listener.on_mint(&event);
        }

        Ok(token)
    }

    /// Rotate to a new current signing key. The previous current key
    /// is demoted to historical (appended to the back of the list),
    /// so tokens already minted under it remain verifiable through
    /// the JWKS until the adopter chooses to retire the historical
    /// key from their key store.
    ///
    /// Persists through the configured [`LocalIdpKeyStore`] *first*;
    /// in-memory state and JWKS are only updated after the store's
    /// `rotate` call succeeds, and are then rebuilt from the store's own
    /// snapshot, so a rotation another replica made earlier is not lost. A
    /// failing key store leaves the previous current key in place, so a
    /// subsequent `mint` continues to produce verifiable tokens. The
    /// store's rotation is the unit of agreement between replicas, not the
    /// in-memory swap: see the multi-replica procedure in the local IdP
    /// guide.
    ///
    /// Concurrency: takes the internal write lock, so in-flight
    /// `mint` calls already past the read-lock acquisition complete
    /// against the previous key, and mints attempted while rotation
    /// is in progress block until the rotation is committed.
    ///
    /// No [`IssuanceListener`] event fires for rotations; adopters who
    /// need an audit trail can wrap their [`LocalIdpKeyStore`]
    /// implementation's `rotate` call. Subsequent mints fire `on_mint`
    /// with the new key's `kid` field, which is the observable rotation
    /// marker for verifier-side audit.
    pub async fn rotate_signing_key(
        &self,
        new_current: LocalIdpSigningKey,
    ) -> Result<(), IssuanceError<K::Error>> {
        // The write lock is taken before the store is touched, so a mint
        // never sees the store ahead of memory, and two rotations on one
        // instance run one after the other.
        let mut state = self.state.write().await;
        {
            let kid = new_current.key_id();
            if state.signing_key.key_id() == kid
                || state.historical_keys.iter().any(|k| k.key_id() == kid)
            {
                return Err(IssuanceError::DuplicateKeyId {
                    kid: kid.to_owned(),
                });
            }
        }
        self.key_store
            .rotate(new_current.clone())
            .await
            .map_err(IssuanceError::KeyStore)?;
        match self.key_store.load_all().await {
            Ok(loaded) => state.replace_keys(loaded),
            Err(e) => {
                // The rotation is durable; only the re-read failed. Apply it
                // locally; `reload` picks up anything another replica did.
                tracing::warn!(error = %e, "LocalIdp: key store re-read after rotation failed");
                let previous = std::mem::replace(&mut state.signing_key, new_current);
                state.historical_keys.push(previous);
                state.rebuild();
            }
        }
        Ok(())
    }

    /// Remove a historical key from the store and the JWKS. Call it once no
    /// token signed under the key can still be valid (the rotation time plus
    /// the longest lifetime this IdP mints). Returns whether a key was
    /// removed; an unknown `key_id` returns `Ok(false)`. The current signing
    /// key is refused with [`IssuanceError::RetireCurrentKey`].
    pub async fn retire_historical_key(
        &self,
        key_id: &str,
    ) -> Result<bool, IssuanceError<K::Error>> {
        let mut state = self.state.write().await;
        if state.signing_key.key_id() == key_id {
            return Err(IssuanceError::RetireCurrentKey);
        }
        let removed = self
            .key_store
            .retire(key_id)
            .await
            .map_err(IssuanceError::KeyStore)?;
        let loaded = self
            .key_store
            .load_all()
            .await
            .map_err(IssuanceError::KeyStore)?;
        state.replace_keys(loaded);
        Ok(removed)
    }

    /// Re-read the current and historical keys from the store and rebuild
    /// the JWKS. A replica calls this to pick up a rotation or retirement
    /// another replica performed; the store is the single source of truth.
    pub async fn reload(&self) -> Result<(), IssuanceError<K::Error>> {
        let mut state = self.state.write().await;
        let loaded = self
            .key_store
            .load_all()
            .await
            .map_err(IssuanceError::KeyStore)?;
        state.replace_keys(loaded);
        Ok(())
    }

    /// Borrow the configured issuer string.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Borrow the configured max-TTL cap, if any.
    pub fn max_ttl(&self) -> Option<Duration> {
        self.max_ttl
    }

    /// Algorithm in use for new mints (the current signing key's
    /// algorithm). Async because the state is behind an async lock.
    pub async fn algorithm(&self) -> Algorithm {
        self.state.read().await.signing_key.algorithm()
    }

    /// Algorithms the fixture's JWKS can verify: the union of the
    /// current signing key, every historical signing key, and any
    /// extra public JWKs that declare an `alg` field. Mirrors
    /// [`crate::testing::local_idp::LocalIdpFixture::verifier_algorithms`].
    pub async fn verifier_algorithms(&self) -> Vec<Algorithm> {
        let state = self.state.read().await;
        let mut out = Vec::new();
        let push_unique = |a: Algorithm, out: &mut Vec<Algorithm>| {
            if !out.contains(&a) {
                out.push(a);
            }
        };
        push_unique(state.signing_key.algorithm(), &mut out);
        for hk in &state.historical_keys {
            push_unique(hk.algorithm(), &mut out);
        }
        for jwk in &state.extra_public_jwks {
            if let Some(ka) = jwk.common.key_algorithm
                && let Some(alg) = key_algorithm_to_algorithm(ka)
            {
                push_unique(alg, &mut out);
            }
        }
        out
    }

    /// Borrow the current public-key JWKS as a clone. Use this to
    /// serve over HTTP at a `.well-known/jwks.json` endpoint
    /// (L3 will ship an Axum handler for this).
    pub async fn jwks(&self) -> JwkSet {
        self.state.read().await.jwks.clone()
    }

    /// Serialize the current JWKS as a JSON string.
    pub async fn jwks_json(&self) -> String {
        serde_json::to_string(&self.state.read().await.jwks)
            .expect("JwkSet serialisation always succeeds")
    }

    /// Build a shared `Arc<RwLock<JwkSet>>` handle suitable for
    /// `JwtVerifier::new(...)`. The handle is a snapshot at call
    /// time: a rotation, a retirement or a reload does NOT propagate into
    /// a handle previously handed out. Call this again (and build a new
    /// verifier, or write the new set into the verifier's own handle) after
    /// any change to the key set.
    pub async fn jwks_handle(&self) -> Arc<RwLock<JwkSet>> {
        Arc::new(RwLock::new(self.state.read().await.jwks.clone()))
    }

    /// The absolute base URL the discovery handler uses to construct
    /// `jwks_uri`. Equals [`with_base_url`](Self::with_base_url)'s
    /// argument when set, the issuer string otherwise.
    pub fn base_url(&self) -> &str {
        self.base_url.as_deref().unwrap_or(&self.issuer)
    }

    /// The absolute URL the discovery handler is mounted at:
    /// `{base_url}/.well-known/openid-configuration`. Useful for
    /// adopters wiring upstream verifiers / DNS / TLS configuration.
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.base_url().trim_end_matches('/')
        )
    }

    /// The absolute URL the JWKS handler is mounted at:
    /// `{base_url}/jwks.json`. This is the value advertised in the
    /// discovery document's `jwks_uri` field.
    pub fn jwks_url(&self) -> String {
        format!("{}/jwks.json", self.base_url().trim_end_matches('/'))
    }

    /// Build the discovery metadata document advertising this IdP.
    ///
    /// Auto-populated fields: `issuer`, `jwks_uri`,
    /// `id_token_signing_alg_values_supported` (derived from
    /// [`verifier_algorithms`](Self::verifier_algorithms)). Adopter
    /// fields registered via [`with_metadata_field`](Self::with_metadata_field)
    /// are appended.
    ///
    /// Async because the underlying state read is async: the JWKS
    /// algorithm list depends on the current + historical key set,
    /// which lives behind the rotation lock.
    pub async fn metadata(&self) -> discovery::LocalIdpMetadata {
        let algs = self
            .verifier_algorithms()
            .await
            .into_iter()
            .map(|a| {
                serde_json::to_value(a)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .expect("jsonwebtoken::Algorithm serialises as a JSON string")
            })
            .collect();
        discovery::LocalIdpMetadata {
            issuer: self.issuer.clone(),
            jwks_uri: self.jwks_url(),
            id_token_signing_alg_values_supported: algs,
            extra: self.extra_metadata.clone(),
        }
    }

    /// Convenience `axum::Router` mounting both discovery endpoints at
    /// their standard paths:
    /// - `GET /.well-known/openid-configuration`
    /// - `GET /jwks.json`
    ///
    /// Adopters `nest` or `merge` this into their app router. For
    /// custom paths, use the standalone handlers in
    /// [`discovery::handlers`] directly.
    pub fn router(&self) -> axum::Router<()>
    where
        K: 'static,
    {
        axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(discovery::handlers::openid_configuration::<K>),
            )
            .route(
                "/jwks.json",
                axum::routing::get(discovery::handlers::jwks::<K>),
            )
            .with_state(self.clone())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn rebuild_jwks(
    current: &LocalIdpSigningKey,
    historical: &[LocalIdpSigningKey],
    extra: &[Jwk],
) -> JwkSet {
    let mut keys = Vec::with_capacity(1 + historical.len() + extra.len());
    keys.push(current.jwk().clone());
    keys.extend(historical.iter().map(|k| k.jwk().clone()));
    keys.extend(extra.iter().cloned());
    JwkSet { keys }
}

#[cfg(test)]
mod tests;
