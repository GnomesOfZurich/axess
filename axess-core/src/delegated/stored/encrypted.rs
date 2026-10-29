//! Encryption-at-rest wrapper for [`DelegatedCredentialStore`].
//!
//! Wraps any inner `DelegatedCredentialStore` and transparently
//! encrypts the `access_token` and (when present) `refresh_token`
//! fields of [`StoredDelegation`] before they touch the inner store.
//! On load, decryption is performed before the credential is handed
//! back to the runtime. The inner store sees only opaque ciphertext
//! envelopes in those string fields; the non-secret metadata
//! (`provider`, `expires_at`, `scopes`, `token_type`) passes through
//! unchanged so adopters can still run operational queries over it.
//!
//! # Threat model
//!
//! Designed to defeat **storage-layer compromise**: an attacker with
//! read access to the inner store's bytes (stolen DB dump, leaked
//! backup, hot-path replication into an unauthorised store) cannot
//! recover any user's refresh token without also obtaining the
//! current encryption key from [`KeyProvider`]. Cipher choice is
//! AES-256-GCM with a random 12-byte nonce per encryption.
//!
//! The AAD (Additional Authenticated Data) on every ciphertext binds
//! the encrypted blob to `(provider, tenant_id, user_id, field_tag)`,
//! so a row-swap attack, moving the ciphertext for user A into
//! user B's row, produces an authentication failure at decrypt time
//! rather than silently surfacing the wrong user's token. The field
//! tag separates `access_token` and `refresh_token` ciphertexts
//! within the same row so they cannot be cross-substituted.
//!
//! # Envelope format
//!
//! Each encrypted string is encoded as
//!
//! ```text
//! v2.{key_id}.{base64url-no-pad(nonce ‖ ciphertext‖tag)}
//! ```
//!
//! - `v2`: format version. New versions get a new tag and explicit
//!   decode dispatch; the decoder rejects unknown versions. `v1` (whose
//!   AAD lacks `scopes` and `token_type`) is still read; every save
//!   writes `v2`. In `v2` the AAD also covers the row's `scopes` and
//!   `token_type`, so a store that rewrites those metadata fields
//!   (widening the granted scopes, say) fails authentication on load
//!   instead of changing what the runtime believes it holds.
//! - `key_id`: opaque adopter-chosen identifier (e.g. `"2026-05"`,
//!   a KMS key ARN, an HSM label). Must not contain `.`; the
//!   [`KeyProvider`] is responsible for storing and resolving the
//!   correspondence between id and 32-byte key material.
//! - The remaining base64 payload is `nonce (12B) ‖ AES-256-GCM(ct‖tag)`.
//!
//! # Key rotation
//!
//! [`KeyProvider::current`] returns the key used for new writes;
//! [`KeyProvider::resolve`] returns the key for a historical
//! `key_id` (read during decrypt). Rotation is therefore lazy: rows
//! re-encrypt under the new key whenever they're saved (each refresh
//! cycle, every `complete_grant`), and a row read under a retired key or in
//! the `v1` format is re-sealed by the read that found it. That rewrite is a
//! compare-and-swap ([`DelegatedCredentialStore::save_if_unchanged`]), so it
//! cannot overwrite a refresh token another request rotated in between; a
//! store that does not implement the swap is left as it is.
//! [`without_reseal_on_load`](EncryptedDelegatedCredentialStore::without_reseal_on_load)
//! turns the rewrite off.
//!
//! # Envelopes from before scope binding
//!
//! `v1` envelopes authenticate no `scopes` or `token_type`, so a store that
//! rewrites those fields is not noticed. They are read by default and
//! re-sealed as `v2` on load.
//! [`with_legacy_envelopes`](EncryptedDelegatedCredentialStore::with_legacy_envelopes)
//! takes the same [`LegacyBlobs`] choice as the session crypto: set
//! [`Reject`](LegacyBlobs::Reject) once the rows have been re-sealed, and a
//! `v1` row then reads as a decryption failure.
//!
//! # Usage bound
//!
//! Every field takes a random 96-bit nonce under the key in force. With
//! random nonces AES-GCM must stay below about 2^32 encryptions per key
//! (NIST SP 800-38D section 8.3, collision probability near 2^-32);
//! rotate the key well before that many token writes. At one million
//! writes a day that is more than ten years, but a bulk re-seal pass
//! counts against the same budget.
//!
//! # Not a substitute for…
//!
//! - **Transport encryption.** Tokens leaving the process to call the
//!   downstream API are protected by HTTPS / mTLS, not this wrapper.
//! - **Memory protection.** Plaintext tokens still live in
//!   [`ZeroizedString`] in-memory while a request is in flight;
//!   `zeroize` reduces the window but doesn't eliminate it.
//! - **Key custody.** The wrapper has no opinion on where keys come
//!   from (env var, file, KMS, HSM); that's the [`KeyProvider`]
//!   impl's job. A poor key custody story defeats the whole feature.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_identity::{TenantId, UserId};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::delegated::stored::credential::{
    CredentialSwap, DelegatedCredentialStore, StoredDelegation,
};
use crate::session::crypto::LegacyBlobs;
use axess_clock::{Clock, SystemClock};
use axess_factors::ZeroizedString;
use axess_rng::SecureRng;

/// Version written by this release. `v2` binds the row's `scopes` and
/// `token_type` into the AAD as well; `v1` rows are still read.
const ENVELOPE_VERSION: &str = "v2";
const LEGACY_ENVELOPE_VERSION: &str = "v1";
const NONCE_LEN: usize = 12;
const FIELD_ACCESS: &[u8] = b"access_token";
const FIELD_REFRESH: &[u8] = b"refresh_token";
const AAD_SEP: u8 = 0x1f; // ASCII unit separator

// ── EncryptionKey ────────────────────────────────────────────────────────────

/// A 32-byte AES-256 key. Held inside an `Arc` by [`KeyProvider`]
/// implementations so cloning the key handle is cheap; the underlying
/// bytes are zeroized when the last `Arc` drops.
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Construct from a 32-byte slice.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl core::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncryptionKey(***)")
    }
}

// ── KeyProvider ──────────────────────────────────────────────────────────────

/// Resolves encryption keys for the [`EncryptedDelegatedCredentialStore`].
///
/// Two access patterns:
///
/// - [`current`](Self::current): supplies the key used to encrypt
///   *new* writes. Called once per save.
/// - [`resolve`](Self::resolve): looks up a historical key by its
///   id, used when decrypting an envelope that was written under a
///   prior key.
///
/// Lazy rotation: rows re-encrypt under the new current key whenever
/// they're saved. To force rotation across the whole dataset,
/// adopters can run a maintenance pass that loads then saves each
/// row.
///
/// Implementors must keep historical keys available for as long as
/// any envelope encrypted under them is still in the store.
pub trait KeyProvider: Send + Sync + 'static {
    /// Key used for new encryptions. Returns the `(key_id, key)` pair
    /// embedded in the resulting envelope.
    fn current(&self) -> Result<CurrentKey, KeyProviderError>;

    /// Resolve a historical `key_id` to its key material.
    ///
    /// `Ok(None)` means "this id is not known to me" and surfaces as
    /// a decrypt failure. `Err(_)` is reserved for provider-level
    /// failures (KMS unreachable, etc.) so adopters can distinguish
    /// "unknown id" from "transient infrastructure failure".
    fn resolve(&self, key_id: &str) -> Result<Option<Arc<EncryptionKey>>, KeyProviderError>;
}

/// Pair returned by [`KeyProvider::current`].
#[derive(Clone)]
pub struct CurrentKey {
    /// Opaque identifier embedded in the envelope so future loads
    /// can route back to the right key. Must not contain `.`
    /// (envelope-format delimiter).
    pub key_id: Arc<str>,
    /// Key material.
    pub key: Arc<EncryptionKey>,
}

/// Error from a [`KeyProvider`] operation.
#[derive(Debug, thiserror::Error)]
pub enum KeyProviderError {
    /// Underlying key-resolution failed (e.g. KMS error, missing
    /// environment variable).
    #[error("key provider failed: {0}")]
    Failed(String),
    /// `key_id` contains a `.`, which would collide with the envelope
    /// delimiter.
    #[error("key id contains '.', which is reserved by the envelope format: {0:?}")]
    InvalidKeyId(String),
}

// ── MemoryKeyProvider ────────────────────────────────────────────────────────

/// In-memory [`KeyProvider`] for dev, test, and small single-node
/// deployments where keys are loaded from configuration at startup.
///
/// Holds one current key plus zero or more historical keys for
/// rotation. **Key material is not encrypted at rest in this
/// provider**; it lives in process memory in plaintext (zeroized on
/// drop via [`EncryptionKey`]). Production deployments at scale
/// should plug in a KMS / HSM-backed provider instead.
#[derive(Clone, Debug)]
pub struct MemoryKeyProvider {
    current_id: Arc<str>,
    current_key: Arc<EncryptionKey>,
    historical: HashMap<String, Arc<EncryptionKey>>,
}

impl MemoryKeyProvider {
    /// Construct with a current `(key_id, key)`. Returns an error if
    /// `key_id` contains the envelope delimiter `.`.
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Result<Self, KeyProviderError> {
        let id = key_id.into();
        validate_key_id(&id)?;
        Ok(Self {
            current_id: Arc::from(id),
            current_key: Arc::new(EncryptionKey::from_bytes(key)),
            historical: HashMap::new(),
        })
    }

    /// Register an additional historical key. Calls to
    /// [`KeyProvider::resolve`] for `key_id` will return this key,
    /// allowing decrypt of envelopes written before rotation.
    /// Returns an error if `key_id` contains `.`.
    pub fn with_historical(
        mut self,
        key_id: impl Into<String>,
        key: [u8; 32],
    ) -> Result<Self, KeyProviderError> {
        let id = key_id.into();
        validate_key_id(&id)?;
        self.historical
            .insert(id, Arc::new(EncryptionKey::from_bytes(key)));
        Ok(self)
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn current(&self) -> Result<CurrentKey, KeyProviderError> {
        Ok(CurrentKey {
            key_id: self.current_id.clone(),
            key: self.current_key.clone(),
        })
    }

    fn resolve(&self, key_id: &str) -> Result<Option<Arc<EncryptionKey>>, KeyProviderError> {
        if key_id == &*self.current_id {
            return Ok(Some(self.current_key.clone()));
        }
        Ok(self.historical.get(key_id).cloned())
    }
}

fn validate_key_id(id: &str) -> Result<(), KeyProviderError> {
    if id.is_empty() || id.contains('.') {
        return Err(KeyProviderError::InvalidKeyId(id.to_string()));
    }
    Ok(())
}

// ── EncryptedDelegatedCredentialStore ────────────────────────────────────────

/// Wraps an inner [`DelegatedCredentialStore`] to encrypt token
/// strings at rest.
///
/// See the [module-level docs](self) for threat model, envelope
/// format, and the lazy-rotation strategy.
///
/// # Construction
///
/// ```rust,ignore
/// use axess::delegated::stored::encrypted::{
///     EncryptedDelegatedCredentialStore, MemoryKeyProvider,
/// };
/// use axess::delegated::stored::MemoryDelegatedCredentialStore;
///
/// let keys = MemoryKeyProvider::new("2026-05", [0u8; 32])?;
/// let inner = MemoryDelegatedCredentialStore::new();
/// let store = EncryptedDelegatedCredentialStore::new(inner, keys);
/// ```
///
/// The wrapper implements [`DelegatedCredentialStore`] itself, so it
/// plugs into [`StoredDelegationSession`](super::session::StoredDelegationSession)
/// transparently; no changes to call-site code.
pub struct EncryptedDelegatedCredentialStore<S, K> {
    inner: S,
    keys: K,
    rng: Arc<dyn SecureRng>,
    reseal_on_load: bool,
    legacy: LegacyBlobs,
    clock: Arc<dyn Clock>,
    seals: AtomicU64,
}

impl<S, K> EncryptedDelegatedCredentialStore<S, K>
where
    S: DelegatedCredentialStore,
    K: KeyProvider,
{
    /// Construct with the given inner store and key provider.
    ///
    /// Envelope nonces come from [`SystemRng`](axess_rng::SystemRng); use
    /// [`with_rng`](Self::with_rng) to supply another source.
    pub fn new(inner: S, keys: K) -> Self {
        Self {
            inner,
            keys,
            rng: Arc::new(axess_rng::SystemRng),
            reseal_on_load: true,
            legacy: LegacyBlobs::default(),
            clock: Arc::new(SystemClock),
            seals: AtomicU64::new(0),
        }
    }

    /// Envelopes this instance has sealed since it started: the number to
    /// meter against the per-key random-nonce budget described in the module
    /// docs. Per process; add the counts of every instance sharing the key.
    pub fn seals(&self) -> u64 {
        self.seals.load(Ordering::Relaxed)
    }

    /// Leave a row as it is when it is read under a retired key or in the
    /// `v1` format. By default such a row is re-sealed by the read that found
    /// it, through [`DelegatedCredentialStore::save_if_unchanged`].
    pub fn without_reseal_on_load(mut self) -> Self {
        self.reseal_on_load = false;
        self
    }

    /// Choose whether `v1` envelopes (sealed before `scopes` and `token_type`
    /// were authenticated) are read. See [`LegacyBlobs`]; the default is
    /// [`LegacyBlobs::Reject`], and [`LegacyBlobs::AcceptUntil`] opens a
    /// migration window on the clock set by [`with_clock`](Self::with_clock).
    /// A refused envelope reads as a decryption failure.
    pub fn with_legacy_envelopes(mut self, policy: LegacyBlobs) -> Self {
        self.legacy = policy;
        self
    }

    /// Inject the clock that [`LegacyBlobs::AcceptUntil`] is checked against
    /// (default: [`SystemClock`]).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// True while `v1` envelopes may still be read.
    fn legacy_readable(&self) -> bool {
        match self.legacy {
            LegacyBlobs::Reject => false,
            LegacyBlobs::AcceptUntil(until) => self.clock.now() < until,
            LegacyBlobs::Accept => true,
        }
    }

    /// Replace the RNG that draws each envelope's 96-bit nonce.
    ///
    /// Every encrypted field takes a fresh draw, so a seeded RNG makes the
    /// stored envelopes reproducible. Production wiring keeps the default.
    pub fn with_rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Borrow the inner store. Provided for adopter ops (e.g.
    /// counting rows for metrics); never use this to bypass
    /// encryption on the read path.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S, K> EncryptedDelegatedCredentialStore<S, K>
where
    S: DelegatedCredentialStore,
    K: KeyProvider,
{
    /// Encrypt the token fields of `credential` under the current key.
    fn seal(
        &self,
        tenant: &TenantId,
        user: &UserId,
        credential: StoredDelegation,
    ) -> Result<StoredDelegation, String> {
        let StoredDelegation {
            provider,
            access_token,
            refresh_token,
            expires_at,
            scopes,
            token_type,
        } = credential;

        let current = self.keys.current().map_err(|e| e.to_string())?;
        self.seals
            .fetch_add(1 + u64::from(refresh_token.is_some()), Ordering::Relaxed);

        let aad_access = build_aad_v2(&provider, tenant, user, FIELD_ACCESS, &scopes, &token_type);
        let access_env = encrypt_envelope(&current, &*self.rng, &access_token, &aad_access)
            .map_err(|e| format!("encrypt access_token: {e}"))?;

        let refresh_env = match refresh_token.as_deref() {
            Some(rt) => {
                let aad_refresh =
                    build_aad_v2(&provider, tenant, user, FIELD_REFRESH, &scopes, &token_type);
                Some(ZeroizedString::from(
                    encrypt_envelope(&current, &*self.rng, rt, &aad_refresh)
                        .map_err(|e| format!("encrypt refresh_token: {e}"))?,
                ))
            }
            None => None,
        };

        Ok(StoredDelegation {
            provider,
            access_token: ZeroizedString::from(access_env),
            refresh_token: refresh_env,
            expires_at,
            scopes,
            token_type,
        })
    }

    /// Rewrite a row that was read in an older form, only if the stored row
    /// is still the one that was read. A failure is logged and does not fail
    /// the load.
    async fn reseal(
        &self,
        tenant: &TenantId,
        user: &UserId,
        read_as: &StoredDelegation,
        plain: &StoredDelegation,
    ) {
        let sealed = match self.seal(tenant, user, plain.clone()) {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::warn!(error = %e, "delegated credential re-seal on load failed");
                return;
            }
        };
        match self
            .inner
            .save_if_unchanged(tenant, user, read_as, sealed)
            .await
        {
            Ok(CredentialSwap::Saved) => {}
            Ok(CredentialSwap::Changed) => tracing::debug!(
                "delegated credential changed since it was read; re-seal left to a later load"
            ),
            Ok(CredentialSwap::Unsupported) => tracing::debug!(
                "the inner store has no compare-and-swap; delegated credential not re-sealed"
            ),
            Err(e) => tracing::warn!(error = %e, "delegated credential re-seal on load failed"),
        }
    }
}

impl<S, K> DelegatedCredentialStore for EncryptedDelegatedCredentialStore<S, K>
where
    S: DelegatedCredentialStore,
    K: KeyProvider,
{
    async fn load(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> Result<Option<StoredDelegation>, String> {
        let Some(cred) = self.inner.load(tenant, user, provider).await? else {
            return Ok(None);
        };

        let current_id = if self.reseal_on_load {
            Some(self.keys.current().map_err(|e| e.to_string())?.key_id)
        } else {
            None
        };
        let mut stale = false;

        let access = self
            .open_field(
                provider,
                &cred,
                &cred.access_token,
                FIELD_ACCESS,
                tenant,
                user,
            )
            .map_err(|e| format!("decrypt access_token: {e}"))?;
        stale |= access.is_stale(current_id.as_deref());
        let access_plain = access.plain;

        let refresh_plain = match cred.refresh_token.as_deref() {
            Some(rt) => {
                let opened = self
                    .open_field(provider, &cred, rt, FIELD_REFRESH, tenant, user)
                    .map_err(|e| format!("decrypt refresh_token: {e}"))?;
                stale |= opened.is_stale(current_id.as_deref());
                Some(ZeroizedString::from(opened.plain))
            }
            None => None,
        };

        let plain = StoredDelegation {
            provider: cred.provider.clone(),
            access_token: ZeroizedString::from(access_plain),
            refresh_token: refresh_plain,
            expires_at: cred.expires_at,
            scopes: cred.scopes.clone(),
            token_type: cred.token_type.clone(),
        };
        if stale {
            self.reseal(tenant, user, &cred, &plain).await;
        }
        Ok(Some(plain))
    }

    async fn save(
        &self,
        tenant: &TenantId,
        user: &UserId,
        credential: StoredDelegation,
    ) -> Result<(), String> {
        let wrapped = self.seal(tenant, user, credential)?;
        self.inner.save(tenant, user, wrapped).await
    }

    async fn revoke(&self, tenant: &TenantId, user: &UserId, provider: &str) -> Result<(), String> {
        self.inner.revoke(tenant, user, provider).await
    }
}

// ── AAD ──────────────────────────────────────────────────────────────────────

fn build_aad(provider: &str, tenant: &TenantId, user: &UserId, field: &[u8]) -> Vec<u8> {
    let provider_bytes = provider.as_bytes();
    let tenant_bytes = tenant.as_bytes();
    let user_bytes = user.as_bytes();
    let mut buf = Vec::with_capacity(provider_bytes.len() + 16 + 16 + field.len() + 3);
    buf.extend_from_slice(provider_bytes);
    buf.push(AAD_SEP);
    buf.extend_from_slice(tenant_bytes);
    buf.push(AAD_SEP);
    buf.extend_from_slice(user_bytes);
    buf.push(AAD_SEP);
    buf.extend_from_slice(field);
    buf
}

/// `v2` AAD: the `v1` fields, then the token type and the scope set, each
/// length-prefixed so no value can bleed into its neighbour. Scopes are
/// sorted and de-duplicated so a store that reorders a set does not break
/// authentication; changing the set does.
fn build_aad_v2(
    provider: &str,
    tenant: &TenantId,
    user: &UserId,
    field: &[u8],
    scopes: &[String],
    token_type: &str,
) -> Vec<u8> {
    fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    let mut buf = build_aad(provider, tenant, user, field);
    buf.push(AAD_SEP);
    put(&mut buf, b"v2");
    put(&mut buf, token_type.as_bytes());
    let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for scope in sorted {
        put(&mut buf, scope.as_bytes());
    }
    buf
}

/// One decrypted field and what it was sealed under.
struct Opened {
    plain: String,
    version: String,
    key_id: String,
}

impl Opened {
    fn is_stale(&self, current_key_id: Option<&str>) -> bool {
        current_key_id.is_some_and(|c| self.version != ENVELOPE_VERSION || self.key_id != c)
    }
}

impl<S, K> EncryptedDelegatedCredentialStore<S, K>
where
    S: DelegatedCredentialStore,
    K: KeyProvider,
{
    fn open_field(
        &self,
        provider: &str,
        row: &StoredDelegation,
        envelope: &str,
        field: &[u8],
        tenant: &TenantId,
        user: &UserId,
    ) -> Result<Opened, EnvelopeError> {
        if envelope.starts_with(concat!("v1", ".")) && !self.legacy_readable() {
            return Err(EnvelopeError::LegacyRefused);
        }
        let aad_for = |version: &str| match version {
            ENVELOPE_VERSION => Some(build_aad_v2(
                provider,
                tenant,
                user,
                field,
                &row.scopes,
                &row.token_type,
            )),
            LEGACY_ENVELOPE_VERSION => Some(build_aad(provider, tenant, user, field)),
            _ => None,
        };
        open_envelope(&self.keys, envelope, &aad_for)
    }
}

// ── Envelope codec ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum EnvelopeError {
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("unknown envelope version {0:?}; store written by a newer axess?")]
    UnknownVersion(String),
    #[error("a v1 envelope is refused (legacy envelopes are rejected)")]
    LegacyRefused,
    #[error("unknown key id {0:?}")]
    UnknownKeyId(String),
    #[error("key provider error: {0}")]
    KeyProvider(#[from] KeyProviderError),
    #[error("decryption failed (wrong key, corrupted ciphertext, or AAD mismatch)")]
    Decrypt,
    #[error("base64 decode failed")]
    Base64,
    #[error("encryption failed")]
    Encrypt,
}

fn encrypt_envelope(
    current: &CurrentKey,
    rng: &dyn SecureRng,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, EnvelopeError> {
    let cipher =
        Aes256Gcm::new_from_slice(current.key.as_array()).map_err(|_| EnvelopeError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| EnvelopeError::Encrypt)?;

    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Encrypt)?;

    let mut body = Vec::with_capacity(NONCE_LEN + ct.len());
    body.extend_from_slice(&nonce_bytes);
    body.extend_from_slice(&ct);

    let b64 = URL_SAFE_NO_PAD.encode(&body);
    Ok(format!("{ENVELOPE_VERSION}.{}.{}", &*current.key_id, b64))
}

/// Open a `v1` envelope under the given AAD. Kept as the narrow entry the
/// codec tests drive; the store reads through [`open_envelope`].
#[cfg(test)]
fn decrypt_envelope<K: KeyProvider>(
    keys: &K,
    envelope: &str,
    aad: &[u8],
) -> Result<String, EnvelopeError> {
    let aad_for = |version: &str| (version == LEGACY_ENVELOPE_VERSION).then(|| aad.to_vec());
    open_envelope(keys, envelope, &aad_for).map(|o| o.plain)
}

fn open_envelope<K: KeyProvider>(
    keys: &K,
    envelope: &str,
    aad_for_version: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<Opened, EnvelopeError> {
    // Strictly three parts: version, key_id, body. key_id is
    // adopter-chosen but we forbid `.` at construction, so two splits
    // from the left is sufficient.
    let mut parts = envelope.splitn(3, '.');
    let version = parts.next().ok_or(EnvelopeError::Malformed("no version"))?;
    let key_id = parts.next().ok_or(EnvelopeError::Malformed("no key id"))?;
    let body_b64 = parts.next().ok_or(EnvelopeError::Malformed("no body"))?;

    let aad = aad_for_version(version)
        .ok_or_else(|| EnvelopeError::UnknownVersion(version.to_string()))?;
    if key_id.is_empty() {
        return Err(EnvelopeError::Malformed("empty key id"));
    }

    let body = URL_SAFE_NO_PAD
        .decode(body_b64)
        .map_err(|_| EnvelopeError::Base64)?;
    if body.len() <= NONCE_LEN {
        return Err(EnvelopeError::Malformed("body shorter than nonce"));
    }
    let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);

    let key = keys
        .resolve(key_id)?
        .ok_or_else(|| EnvelopeError::UnknownKeyId(key_id.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(key.as_array()).map_err(|_| EnvelopeError::Decrypt)?;
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| EnvelopeError::Decrypt)?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    let plain = String::from_utf8(plaintext)
        .map_err(|_| EnvelopeError::Malformed("plaintext not utf-8"))?;
    Ok(Opened {
        plain,
        version: version.to_string(),
        key_id: key_id.to_string(),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod legacy_tests;
#[cfg(test)]
mod rng_tests;
#[cfg(test)]
mod tests;
