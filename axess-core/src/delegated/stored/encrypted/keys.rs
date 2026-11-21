//! The keys an encrypted delegated-credential store seals under: the key
//! material, the [`KeyProvider`] seam that supplies it, and the in-memory
//! provider.

use std::collections::HashMap;
use std::sync::Arc;

use crate::session::weak_key::{is_constant_key, warn_if_constant_key};
use zeroize::{Zeroize, Zeroizing};

// ── EncryptionKey ────────────────────────────────────────────────────────────

/// A 32-byte AES-256 key. Held inside an `Arc` by [`KeyProvider`]
/// implementations so cloning the key handle is cheap; the bytes live in a
/// buffer that is zeroized when the last `Arc` drops.
pub struct EncryptionKey(Zeroizing<[u8; 32]>);

impl EncryptionKey {
    /// Construct from 32 bytes. A key that is a single repeated byte
    /// (a placeholder, not random key material) is logged at `error`;
    /// [`MemoryKeyProvider::new`] refuses one as its current key.
    ///
    /// The bytes are copied into a buffer that is zeroed on drop, and the
    /// copy handed to this call is zeroed before it returns. The caller's
    /// own copy is the caller's to wipe.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let key = Self::from_array(&bytes);
        bytes.zeroize();
        key
    }

    /// [`from_bytes`](Self::from_bytes) for a key read through a reference:
    /// the only copy this makes is the one in the key's own buffer.
    fn from_array(bytes: &[u8; 32]) -> Self {
        warn_if_constant_key("delegated credential encryption key", bytes);
        Self(Zeroizing::new(*bytes))
    }

    pub(super) fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn is_constant(&self) -> bool {
        is_constant_key(&self.0)
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
    pub fn new(key_id: impl Into<String>, mut key: [u8; 32]) -> Result<Self, KeyProviderError> {
        let provider = Self::from_key(key_id.into(), &key);
        key.zeroize();
        provider
    }

    /// [`new`](Self::new) with the key read through a reference, so the
    /// caller zeroes the copy it was handed whichever way this returns.
    fn from_key(id: String, key: &[u8; 32]) -> Result<Self, KeyProviderError> {
        validate_key_id(&id)?;
        if is_constant_key(key) {
            return Err(crate::session::WeakKeyError.into());
        }
        Ok(Self {
            current_id: Arc::from(id),
            current_key: Arc::new(EncryptionKey::from_array(key)),
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
        mut key: [u8; 32],
    ) -> Result<Self, KeyProviderError> {
        let id = key_id.into();
        let checked = validate_key_id(&id);
        if checked.is_ok() {
            self.historical
                .insert(id, Arc::new(EncryptionKey::from_array(&key)));
        }
        key.zeroize();
        checked.map(|()| self)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The key is a `Zeroizing` buffer, which wipes itself when the last
    /// handle to it is dropped. The key type has no `Drop` of its own to
    /// keep in step with its field: taking the buffer out of it compiles
    /// only while it has none.
    #[test]
    fn the_key_is_held_in_a_zeroizing_buffer() {
        let EncryptionKey(held) = EncryptionKey::from_bytes(crate::testing::test_key(7));
        let held: &Zeroizing<[u8; 32]> = &held;
        assert_eq!(**held, crate::testing::test_key(7));
    }
}
