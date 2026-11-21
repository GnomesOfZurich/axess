//! The key a [`SessionCrypto`] seals under, and the constructors that take
//! one.
//!
//! A key is copied once, into a buffer that is zeroed on drop. A public
//! constructor takes the 32 bytes by value and zeroes the copy it was handed
//! before it returns. The constructors of this crate that build a
//! `SessionCrypto` for a store hand their key on by reference, so no frame
//! between the caller and that buffer keeps a copy. The caller's own copy is
//! the caller's to wipe.

use super::{LegacyBlobs, SessionCrypto, WeakKeyError, is_constant_key};
use crate::session::weak_key::refuse_constant_key;
use axess_clock::SystemClock;
use axess_rng::SystemRng;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use zeroize::{Zeroize, Zeroizing};

/// A 32-byte AES key, held in a buffer that is zeroed when it is dropped.
#[derive(Clone)]
pub struct EncryptionKey(pub(crate) Zeroizing<[u8; 32]>);

impl EncryptionKey {
    /// Reads the key through a reference: the only copy this makes is the
    /// one in the key's own buffer.
    pub(super) fn new(key: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*key))
    }
}

impl SessionCrypto {
    /// Create a new crypto config with the given 32-byte key. Uses
    /// [`SystemRng`] for nonce generation; tests under DST should use
    /// [`SessionCrypto::with_rng`] to inject a deterministic RNG.
    ///
    /// The key is copied into a buffer that is zeroed on drop, and the copy
    /// handed to this call is zeroed before it returns. The caller's own
    /// copy is the caller's to wipe.
    ///
    /// # Panics
    ///
    /// On a key that is a single repeated byte (all zeros, a test
    /// placeholder). Use [`try_new`](Self::try_new) to handle the refusal.
    #[track_caller]
    pub fn new(mut key: [u8; 32]) -> Self {
        let crypto = Self::from_key(&key);
        key.zeroize();
        crypto
    }

    /// [`new`](Self::new) for a key read through a reference, so a
    /// constructor in this crate hands its key on without another copy.
    ///
    /// # Panics
    ///
    /// As [`new`](Self::new).
    #[track_caller]
    pub(crate) fn from_key(key: &[u8; 32]) -> Self {
        refuse_constant_key("session encryption key", key);
        Self::new_unchecked_inner(key)
    }

    /// [`new`](Self::new) without the constant-key check, for tests that use a
    /// placeholder key.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_unchecked(mut key: [u8; 32]) -> Self {
        let crypto = Self::new_unchecked_inner(&key);
        key.zeroize();
        crypto
    }

    fn new_unchecked_inner(key: &[u8; 32]) -> Self {
        Self {
            current: Arc::new(EncryptionKey::new(key)),
            previous: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            legacy: LegacyBlobs::default(),
            seals: Arc::new(AtomicU64::new(0)),
            metrics: Arc::new(crate::metrics::NoopMetrics),
        }
    }

    /// Like [`new`](Self::new), refusing a key that is a single repeated byte.
    ///
    /// # Errors
    ///
    /// [`WeakKeyError`] for such a key.
    pub fn try_new(mut key: [u8; 32]) -> Result<Self, WeakKeyError> {
        if is_constant_key(&key) {
            return Err(WeakKeyError);
        }
        let crypto = Self::new_unchecked_inner(&key);
        key.zeroize();
        Ok(crypto)
    }

    /// Enable key rotation: on decrypt, try the current key first, then this
    /// previous key as a fallback.
    ///
    /// # Panics
    ///
    /// On a previous key that is a single repeated byte, or that equals the
    /// current key (a rotation that takes the old key out of use never
    /// happens).
    #[track_caller]
    pub fn with_previous_key(self, mut key: [u8; 32]) -> Self {
        let crypto = self.with_previous_key_from(&key);
        key.zeroize();
        crypto
    }

    /// [`with_previous_key`](Self::with_previous_key) for a key read through
    /// a reference.
    ///
    /// # Panics
    ///
    /// As [`with_previous_key`](Self::with_previous_key).
    #[track_caller]
    pub(crate) fn with_previous_key_from(mut self, key: &[u8; 32]) -> Self {
        refuse_constant_key("previous session encryption key", key);
        assert!(
            !bool::from(subtle::ConstantTimeEq::ct_eq(
                key.as_slice(),
                self.current.0.as_slice(),
            )),
            "previous session encryption key equals the current key; the rotation protects nothing"
        );
        self.previous = Some(Arc::new(EncryptionKey::new(key)));
        self
    }
}
