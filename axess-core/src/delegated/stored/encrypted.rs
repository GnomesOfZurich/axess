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
//! v1.{key_id}.{base64url-no-pad(nonce ‖ ciphertext‖tag)}
//! ```
//!
//! - `v1`: format version. New versions get a new tag and explicit
//!   decode dispatch; current decoder rejects unknown versions.
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
//! cycle, every `complete_grant`). To force rotation, adopters can
//! load + save each row in a maintenance pass.
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

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_identity::{TenantId, UserId};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::delegated::stored::credential::{DelegatedCredentialStore, StoredDelegation};
use axess_factors::ZeroizedString;
use axess_rng::SecureRng;

const ENVELOPE_VERSION: &str = "v1";
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
}

impl<S, K> EncryptedDelegatedCredentialStore<S, K>
where
    S: DelegatedCredentialStore,
    K: KeyProvider,
{
    /// Construct with the given inner store and key provider.
    pub fn new(inner: S, keys: K) -> Self {
        Self { inner, keys }
    }

    /// Borrow the inner store. Provided for adopter ops (e.g.
    /// counting rows for metrics); never use this to bypass
    /// encryption on the read path.
    pub fn inner(&self) -> &S {
        &self.inner
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

        let aad_access = build_aad(provider, tenant, user, FIELD_ACCESS);
        let access_plain = decrypt_envelope(&self.keys, &cred.access_token, &aad_access)
            .map_err(|e| format!("decrypt access_token: {e}"))?;

        let refresh_plain = match cred.refresh_token.as_deref() {
            Some(rt) => {
                let aad_refresh = build_aad(provider, tenant, user, FIELD_REFRESH);
                let plain = decrypt_envelope(&self.keys, rt, &aad_refresh)
                    .map_err(|e| format!("decrypt refresh_token: {e}"))?;
                Some(ZeroizedString::from(plain))
            }
            None => None,
        };

        Ok(Some(StoredDelegation {
            provider: cred.provider,
            access_token: ZeroizedString::from(access_plain),
            refresh_token: refresh_plain,
            expires_at: cred.expires_at,
            scopes: cred.scopes,
            token_type: cred.token_type,
        }))
    }

    async fn save(
        &self,
        tenant: &TenantId,
        user: &UserId,
        credential: StoredDelegation,
    ) -> Result<(), String> {
        let StoredDelegation {
            provider,
            access_token,
            refresh_token,
            expires_at,
            scopes,
            token_type,
        } = credential;

        let current = self.keys.current().map_err(|e| e.to_string())?;

        let aad_access = build_aad(&provider, tenant, user, FIELD_ACCESS);
        let access_env = encrypt_envelope(&current, &access_token, &aad_access)
            .map_err(|e| format!("encrypt access_token: {e}"))?;

        let refresh_env = match refresh_token.as_deref() {
            Some(rt) => {
                let aad_refresh = build_aad(&provider, tenant, user, FIELD_REFRESH);
                Some(ZeroizedString::from(
                    encrypt_envelope(&current, rt, &aad_refresh)
                        .map_err(|e| format!("encrypt refresh_token: {e}"))?,
                ))
            }
            None => None,
        };

        let wrapped = StoredDelegation {
            provider,
            access_token: ZeroizedString::from(access_env),
            refresh_token: refresh_env,
            expires_at,
            scopes,
            token_type,
        };
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

// ── Envelope codec ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum EnvelopeError {
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("unknown envelope version {0:?}; store written by a newer axess?")]
    UnknownVersion(String),
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
    plaintext: &str,
    aad: &[u8],
) -> Result<String, EnvelopeError> {
    let cipher =
        Aes256Gcm::new_from_slice(current.key.as_array()).map_err(|_| EnvelopeError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    axess_rng::SystemRng.fill_bytes(&mut nonce_bytes);
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

fn decrypt_envelope<K: KeyProvider>(
    keys: &K,
    envelope: &str,
    aad: &[u8],
) -> Result<String, EnvelopeError> {
    // Strictly three parts: version, key_id, body. key_id is
    // adopter-chosen but we forbid `.` at construction, so two splits
    // from the left is sufficient.
    let mut parts = envelope.splitn(3, '.');
    let version = parts.next().ok_or(EnvelopeError::Malformed("no version"))?;
    let key_id = parts.next().ok_or(EnvelopeError::Malformed("no key id"))?;
    let body_b64 = parts.next().ok_or(EnvelopeError::Malformed("no body"))?;

    if version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnknownVersion(version.to_string()));
    }
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
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    String::from_utf8(plaintext).map_err(|_| EnvelopeError::Malformed("plaintext not utf-8"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
