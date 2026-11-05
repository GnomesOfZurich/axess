//! The keys an encrypted delegated-credential store seals under: the key
//! material, the [`KeyProvider`] seam that supplies it, and the in-memory
//! provider.

use std::collections::HashMap;
use std::sync::Arc;

use crate::session::weak_key::{is_constant_key, warn_if_constant_key};

// ── EncryptionKey ────────────────────────────────────────────────────────────

/// A 32-byte AES-256 key. Held inside an `Arc` by [`KeyProvider`]
/// implementations so cloning the key handle is cheap; the underlying
/// bytes are zeroized when the last `Arc` drops.
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Construct from a 32-byte slice. A key that is a single repeated byte
    /// (a placeholder, not random key material) is logged at `error`;
    /// [`MemoryKeyProvider::new`] refuses one as its current key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        warn_if_constant_key("delegated credential encryption key", &bytes);
        Self(bytes)
    }

    pub(super) fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn is_constant(&self) -> bool {
        is_constant_key(&self.0)
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

/// Resolves encryption keys for the
/// [`EncryptedDelegatedCredentialStore`](crate::delegated::stored::encrypted::EncryptedDelegatedCredentialStore).
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
    /// The current key is a single repeated byte: a placeholder, not random
    /// key material.
    #[error(transparent)]
    WeakKey(#[from] crate::session::WeakKeyError),
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
    /// Construct with a current `(key_id, key)`.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::InvalidKeyId`] if `key_id` contains the envelope
    /// delimiter `.`; [`KeyProviderError::WeakKey`] if `key` is a single
    /// repeated byte, a placeholder that would seal every credential under
    /// guessable key material.
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Result<Self, KeyProviderError> {
        let id = key_id.into();
        validate_key_id(&id)?;
        if is_constant_key(&key) {
            return Err(crate::session::WeakKeyError.into());
        }
        Ok(Self {
            current_id: Arc::from(id),
            current_key: Arc::new(EncryptionKey::from_bytes(key)),
            historical: HashMap::new(),
        })
    }

    /// Register an additional historical key. Calls to
    /// [`KeyProvider::resolve`] for `key_id` will return this key,
    /// allowing decrypt of envelopes written before rotation.
    /// Returns an error if `key_id` contains `.`. A historical key only
    /// opens rows already sealed under it, so a constant one is logged at
    /// `error` (by [`EncryptionKey::from_bytes`]) rather than refused.
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

pub(super) fn validate_key_id(id: &str) -> Result<(), KeyProviderError> {
    if id.is_empty() || id.contains('.') {
        return Err(KeyProviderError::InvalidKeyId(id.to_string()));
    }
    Ok(())
}
