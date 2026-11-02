//! The in-memory key store: a `LoadedKeys` behind a lock, for tests and
//! single-process deployments that accept losing keys on restart.

use std::sync::{Arc, RwLock};

use super::{LoadedKeys, LocalIdpKeyStore, LocalIdpSigningKey};

/// Default in-memory [`LocalIdpKeyStore`] for prototyping and tests.
///
/// Mirrors [`crate::MemorySessionStore`] in shape: `Arc<RwLock<...>>`
/// interior, `Clone` to share between the `LocalIdp` instance and
/// any operator-side rotation logic that still needs to inspect
/// the store. Not for production deployments (the keys live in process
/// memory only; restart loses them).
///
/// Constructors require a current key up front; there is no empty state
/// to model. Adopters who need a "key-less startup" path should
/// implement their own [`LocalIdpKeyStore`] with whatever recovery
/// semantics fit (e.g. blocking on a key-management notification).
#[derive(Debug, Clone)]
pub struct MemoryLocalIdpKeyStore {
    inner: Arc<RwLock<LoadedKeys>>,
}

/// Error type for [`MemoryLocalIdpKeyStore`].
#[derive(Debug, thiserror::Error)]
pub enum MemoryLocalIdpKeyStoreError {
    /// Never returned. Kept from the releases in which no operation of the
    /// store could fail, so a match on the enum still compiles.
    #[error("memory key store error (never returned)")]
    Infallible,
    /// `rotate` was offered a key whose `kid` the store already holds, as
    /// the current key or a historical one. The store is unchanged.
    #[error("key id {kid:?} is already in the key set")]
    DuplicateKeyId {
        /// The `kid` offered twice.
        kid: String,
    },
}

impl MemoryLocalIdpKeyStore {
    /// Construct with the supplied key as the initial current key
    /// and no historical keys. Production stores should prefer this
    /// constructor; `load_all` is infallible from this entry point.
    pub fn with_current(current: LocalIdpSigningKey) -> Self {
        Self {
            inner: Arc::new(RwLock::new(LoadedKeys {
                current,
                historical: Vec::new(),
            })),
        }
    }

    /// Construct with explicit current + historical keys (useful when
    /// rehydrating from a backed-up state).
    pub fn with_keys(current: LocalIdpSigningKey, historical: Vec<LocalIdpSigningKey>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(LoadedKeys {
                current,
                historical,
            })),
        }
    }
}

impl LocalIdpKeyStore for MemoryLocalIdpKeyStore {
    type Error = MemoryLocalIdpKeyStoreError;

    fn load_all(
        &self,
    ) -> impl std::future::Future<Output = Result<LoadedKeys, Self::Error>> + Send {
        let inner = self.inner.clone();
        async move {
            let guard = inner
                .read()
                .expect("MemoryLocalIdpKeyStore lock never poisoned");
            // We deliberately clone here; the LoadedKeys snapshot is
            // owned by the LocalIdp from this point and the store
            // remains free to be rotated/inspected independently.
            Ok(LoadedKeys {
                current: guard.current.clone(),
                historical: guard.historical.clone(),
            })
        }
    }

    fn rotate(
        &self,
        new_current: LocalIdpSigningKey,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let inner = self.inner.clone();
        async move {
            let mut guard = inner
                .write()
                .expect("MemoryLocalIdpKeyStore lock never poisoned");
            // The store is the one place that sees every replica's keys, so
            // the duplicate check is made here under the write lock, not
            // only against the caller's own snapshot.
            let kid = new_current.key_id();
            if guard.current.key_id() == kid || guard.historical.iter().any(|k| k.key_id() == kid) {
                return Err(MemoryLocalIdpKeyStoreError::DuplicateKeyId {
                    kid: kid.to_owned(),
                });
            }
            // Demote previous current → historical at the back of the
            // list, matching the fixture's `rotate_signing_key` order so
            // JWKS layouts (current first, then historical oldest→newest)
            // match across the two surfaces.
            let previous = std::mem::replace(&mut guard.current, new_current);
            guard.historical.push(previous);
            Ok(())
        }
    }

    fn retire(
        &self,
        key_id: &str,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        async move {
            let mut guard = inner
                .write()
                .expect("MemoryLocalIdpKeyStore lock never poisoned");
            let before = guard.historical.len();
            guard.historical.retain(|k| k.key_id() != key_id);
            Ok(guard.historical.len() != before)
        }
    }
}
