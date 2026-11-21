//! AES-256-GCM encryption for session data at rest.
//!
//! Shared by the SQLite, Postgres, MySQL and Valkey session stores and by
//! the device stores. A blob a store writes carries a four-byte marker and
//! a random 16-byte salt and is sealed under a key derived for that one
//! record (see "Usage bound" below); only the direct
//! [`SessionCrypto::encrypt_with_aad`] form prefixes a random 12-byte nonce.
//!
//! # Key rotation
//!
//! [`SessionCrypto`] accepts an optional previous key. On decrypt, the current
//! key is tried first; if it fails, the previous key is attempted. Writes always
//! use the current key. A row sealed under the previous key is re-sealed
//! under the current one by the store that reads it (a conditional write of
//! the exact bytes it read) and by its next write, so rows move to the new
//! key as they are used. Keep the previous key configured for at least one
//! session lifetime after the rotation, and retire it after that.
//!
//! # Usage bound
//!
//! The blobs the stores write (session data, device rows, device bindings)
//! are sealed under a key derived for each record from the configured key, a
//! fresh 16-byte salt and the record's row identity, so each derived key
//! encrypts exactly one message and AES-GCM's random-nonce limit (about 2^32
//! seals per key) does not apply to them. The master key still wants rotating
//! on the usual schedule; it has no write budget. A device blob in
//! the earlier layout (the key used directly, a random nonce per seal) is a
//! legacy blob: read only while [`LegacyBlobs`] reads them, and then re-sealed
//! in the new layout by the same paths that re-seal any other stale blob. A
//! session blob in that layout is not read at all (see "Sessions are read in
//! the current form only" below). [`SessionCrypto::encrypt_with_aad`] keeps the
//! direct layout for callers that use it themselves, and
//! [`SessionCrypto::seals`] meters those calls.
//!
//! # Sessions are read in the current form only
//!
//! A session blob is sealed under the label `axess.session.v2` and bound to
//! its session's key: the additional authenticated data is the label, a zero
//! byte and the 32 bytes of the key. The session stores open a blob through
//! `SessionCrypto::open_current`, which reads that form (under the current
//! key, then the previous one) and nothing else. No [`LegacyBlobs`] policy
//! changes that: a blob without a binding opens under any row, and reading
//! one as a session would let whoever can write the store move a session
//! from one row to another. Sessions stored by an earlier release are not
//! carried over; their users sign in again.
//!
//! # Device blobs from before row binding
//!
//! Every blob the stores write names the row it belongs to in its AAD (the
//! additional authenticated data of the AES-GCM seal). A device blob written
//! by an earlier release carries no marker and no binding, so it opens under
//! any row id, which is exactly what an attacker with write access to the store
//! (or a restored backup) needs to move a sealed row from one id to another.
//! The 0.11.0 device formats (`DEVICE_BINDINGS_V1`, `DEVICE_ROW_V1`) join the
//! tenant and device id with a zero byte, so two id pairs can share one AAD.
//! [`LegacyBlobs`] says what to do with both kinds:
//!
//! - [`Reject`](LegacyBlobs::Reject), the default, refuses them. A refused row
//!   reads as a decryption failure and the user signs in again (a refused
//!   device row is a decryption error from the device store).
//! - [`AcceptUntil`](LegacyBlobs::AcceptUntil) reads them until an instant
//!   (checked against the crypto's clock, see
//!   [`with_clock`](SessionCrypto::with_clock)) and refuses them afterwards.
//!   Use it for the upgrade window: the longest device lifetime you care to
//!   keep.
//! - [`Accept`](LegacyBlobs::Accept) reads them with no end date.
//!
//! The stores re-seal an accepted blob in the current format the next time the
//! row is written; a read re-seals a blob that is bound to its row and merely
//! in an older layout or under the previous key, and leaves one with no
//! binding as it is. A Valkey device row carries its own tenant and
//! device id, so one that was read through a legacy blob is also refused when
//! the ids it names differ from the key it was stored under, and it is never
//! re-sealed under the wrong key. SQL device bindings carry no identity of
//! their own, so for them the cutoff is the only protection.

pub use super::legacy_blobs::LegacyBlobs;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_clock::Clock;
use axess_rng::SecureRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::aead::TAG_LEN;

/// The per-record subkey seal of the bound formats, compiled exactly where
/// [`BoundFormat`] and the bound seal and open are: with a store, and in a
/// test build of this module (which `delegated-stored-encrypted` compiles
/// without a store).
#[cfg(any(
    test,
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
mod subkey;

const NONCE_LEN: usize = 12;

mod keys;
pub use keys::EncryptionKey;

/// AES-256-GCM encryption configuration with optional key rotation.
#[derive(Clone)]
pub struct SessionCrypto {
    current: Arc<EncryptionKey>,
    previous: Option<Arc<EncryptionKey>>,
    rng: Arc<dyn SecureRng>,
    clock: Arc<dyn Clock>,
    legacy: LegacyBlobs,
    seals: Arc<AtomicU64>,
    metrics: Arc<dyn crate::metrics::RotationMetrics>,
}

pub use super::weak_key::{WeakKeyError, is_constant_key};

/// Error from encrypt/decrypt operations.
#[derive(Debug, thiserror::Error)]
#[error("session encryption/decryption error")]
pub struct CryptoError;

impl SessionCrypto {
    /// Choose whether blobs written before row binding are read. See
    /// [`LegacyBlobs`]; the default is [`LegacyBlobs::Reject`].
    pub fn with_legacy_blobs(mut self, policy: LegacyBlobs) -> Self {
        self.legacy = policy;
        self
    }

    /// Report to `sink` each time a blob opens only under the previous key
    /// (see [`RotationMetrics::encryption_key_fallback`](crate::metrics::RotationMetrics::encryption_key_fallback)).
    /// Get the sink from
    /// [`MetricSinks::rotation`](crate::metrics::MetricSinks::rotation).
    pub fn with_metrics(mut self, sink: Arc<dyn crate::metrics::RotationMetrics>) -> Self {
        self.metrics = sink;
        self
    }

    /// Inject the clock that [`LegacyBlobs::AcceptUntil`] is checked against
    /// (default: [`axess_clock::SystemClock`]).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// True while blobs from before row binding may still be read. Only the
    /// device stores ask: a session is read in the current form only.
    #[cfg(any(
        test,
        all(
            feature = "device",
            any(
                feature = "sqlite",
                feature = "sqlite-unbundled",
                feature = "postgres",
                feature = "mysql",
                feature = "valkey"
            )
        )
    ))]
    fn legacy_blobs_readable(&self) -> bool {
        match self.legacy {
            LegacyBlobs::Reject => false,
            LegacyBlobs::AcceptUntil(until) => self.clock.now() < until,
            LegacyBlobs::Accept => true,
        }
    }

    /// Seals made with [`encrypt_with_aad`](Self::encrypt_with_aad) since this
    /// configuration was created, shared by its clones: the number to meter
    /// against the random-nonce budget described there.
    ///
    /// The stores' own blobs (sessions and device rows) are sealed under a
    /// per-record subkey and are not counted, because the budget does not
    /// apply to them; only a caller that uses `encrypt_with_aad` directly
    /// spends it. Per process: add the counts of every replica sharing the key.
    pub fn seals(&self) -> u64 {
        self.seals.load(Ordering::Relaxed)
    }

    /// Swap the RNG used for nonce generation. Production code keeps the
    /// default [`axess_rng::SystemRng`]; DST suites pass a seeded `MockRng` to drive
    /// nonce sequences deterministically.
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// Seal with an empty AAD. Kept for writing pre-binding fixtures; a blob
    /// sealed this way is not bound to its row.
    #[cfg(test)]
    pub(crate) fn encrypt_unbound(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seal_direct(&[], plaintext)
    }

    /// Encrypt plaintext with AES-256-GCM, authenticating `aad` alongside it.
    /// Returns `nonce || ciphertext`. The same `aad` must be supplied to
    /// [`decrypt_with_aad`](Self::decrypt_with_aad); the AAD itself is not
    /// stored in the output.
    ///
    /// Each call draws a random 96-bit nonce under the one session key. NIST
    /// SP 800-38D (section 8.3) caps random-nonce AES-GCM at 2^32
    /// invocations per key, where the probability that any two nonces
    /// collide is about 2^-32; a repeated nonce reveals the XOR of two
    /// plaintexts and lets an attacker forge tags. At 1,000 calls a second
    /// the budget lasts about 50 days. Count calls with
    /// [`seals`](Self::seals) and rotate the key (`with_previous_key` keeps
    /// old rows readable) well inside that window; the budget is per key, not
    /// per process, so every replica sharing the key draws on it. The stores
    /// do not spend it: their session and device blobs are sealed under a
    /// per-record subkey (see the module documentation). The `aes-gcm` crate
    /// performs constant-time authentication tag comparison internally during
    /// decryption.
    ///
    /// An empty `aad` is refused: a blob sealed with none opens as a
    /// pre-binding row of any id wherever legacy blobs are read.
    pub fn encrypt_with_aad(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if aad.is_empty() {
            return Err(CryptoError);
        }
        self.seal_direct(aad, plaintext)
    }

    /// The seal behind [`encrypt_with_aad`](Self::encrypt_with_aad), which
    /// accepts any `aad` including the empty one, for fixtures that write
    /// pre-binding blobs.
    pub(crate) fn seal_direct(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seals.fetch_add(1, Ordering::Relaxed);
        let cipher = Aes256Gcm::new_from_slice(&self.current.0[..]).map_err(|_| CryptoError)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| CryptoError)?;

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a pre-binding blob (empty AAD). Used only for the legacy read
    /// path of the device formats.
    #[cfg(any(
        test,
        all(
            feature = "device",
            any(
                feature = "sqlite",
                feature = "sqlite-unbundled",
                feature = "postgres",
                feature = "mysql",
                feature = "valkey"
            )
        )
    ))]
    pub(crate) fn decrypt_unbound(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_aad(&[], data)
    }

    /// Decrypt `nonce || ciphertext` that was sealed with the same `aad`.
    /// Tries the current key first, then the previous key. A mismatched
    /// `aad` fails authentication exactly like a wrong key. A blob shorter
    /// than a nonce and a tag (28 bytes, what an empty plaintext seals to)
    /// is refused before either key is tried.
    pub fn decrypt_with_aad(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_aad_reporting(aad, data)
            .map(|(plaintext, _)| plaintext)
    }

    /// [`decrypt_with_aad`](Self::decrypt_with_aad), and whether the plaintext
    /// was opened with the previous key rather than the current one.
    ///
    /// A blob that needed the previous key is not at rest under the current
    /// one; the caller re-seals it, so the previous key can be dropped once
    /// every blob has been read or written.
    pub(crate) fn decrypt_with_aad_reporting(
        &self,
        aad: &[u8],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool), CryptoError> {
        // The shortest blob a seal produces is a nonce and the tag of an
        // empty plaintext. Anything shorter was never sealed, so it is
        // refused here, before a key is tried or a rotation fallback logged.
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError);
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError)?;

        let cipher = Aes256Gcm::new_from_slice(&self.current.0[..]).map_err(|_| CryptoError)?;

        if let Ok(plaintext) = cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        ) {
            return Ok((plaintext, false));
        }

        if let Some(prev) = &self.previous {
            tracing::warn!(
                "session decryption failed with current key; trying previous key (rotation fallback)"
            );
            let old_cipher = Aes256Gcm::new_from_slice(&prev.0[..]).map_err(|_| CryptoError)?;

            if let Ok(plaintext) = old_cipher.decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ) {
                tracing::debug!("session decrypted with previous (rotated) key");
                self.metrics.encryption_key_fallback();
                return Ok((plaintext, true));
            }
            tracing::warn!(
                "session decryption also failed with previous key; possible data corruption or key mismatch"
            );
        } else {
            tracing::warn!(
                "session decryption failed with current key and no previous key configured"
            );
        }

        Err(CryptoError)
    }
}

#[cfg(any(
    test,
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
/// A storage context whose encrypted blobs are bound to the row they live in.
///
/// A sealed blob is `magic' || salt || ciphertext`, under a key derived for
/// the record (see `subkey`), where `magic'` is the format's marker with the
/// top bit of its last byte set and the AES-GCM
/// additional authenticated data is `label || 0x00 || row_id`. The earlier
/// layout, `magic || nonce || ciphertext` under the key itself, is a legacy
/// blob. The row id is
/// not stored in the blob; it is supplied again on open, so a blob copied into
/// a row with a different id fails authentication. A row id made of several
/// parts is length-prefixed (see `device_row_id`) so two different part
/// lists can never concatenate to the same bytes.
#[derive(Clone, Copy)]
pub(crate) struct BoundFormat {
    /// Four-byte format marker. A sealed blob starts with it, with the top
    /// bit of the last byte set for the per-record-subkey layout.
    magic: [u8; 4],
    /// Domain-separation label authenticated as part of the AAD.
    label: &'static [u8],
}

#[cfg(any(
    test,
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
impl BoundFormat {
    /// Session data, bound to the 32 bytes of the session's key.
    ///
    /// The second session format. The first (`AXS\x01`,
    /// `axess.session.v1`) bound a blob to the 16 bytes of the session id;
    /// what the row id is has changed, so the label and the marker moved
    /// with it, as they did for the device formats below. A blob of the
    /// first format is not a session: the stores open sessions through
    /// [`SessionCrypto::open_current`], which reads this format only.
    pub(crate) const SESSION: Self = Self {
        magic: *b"AXS\x02",
        label: b"axess.session.v2",
    };

    /// The first session format, which bound a blob to the 16 bytes of the
    /// session id. No code reads it; tests plant it as an earlier release
    /// wrote it.
    #[cfg(test)]
    pub(crate) const SESSION_V1: Self = Self {
        magic: *b"AXS\x01",
        label: b"axess.session.v1",
    };

    /// Device bindings, bound to the tenant and device id (length-prefixed).
    #[cfg(any(
        test,
        all(
            feature = "device",
            any(
                feature = "sqlite",
                feature = "sqlite-unbundled",
                feature = "postgres",
                feature = "mysql"
            )
        )
    ))]
    pub(crate) const DEVICE_BINDINGS: Self = Self {
        magic: *b"AXD\x02",
        label: b"axess.device-bindings.v2",
    };

    /// The device-bindings format of 0.11.0: the tenant and device id were
    /// joined with a single zero byte. Still read, and replaced by
    /// [`DEVICE_BINDINGS`](Self::DEVICE_BINDINGS) on the next write.
    #[cfg(any(
        test,
        all(
            feature = "device",
            any(
                feature = "sqlite",
                feature = "sqlite-unbundled",
                feature = "postgres",
                feature = "mysql"
            )
        )
    ))]
    pub(crate) const DEVICE_BINDINGS_V1: Self = Self {
        magic: *b"AXD\x01",
        label: b"axess.device-bindings.v1",
    };

    /// A whole device row in the Valkey store, bound to the tenant and
    /// device id (length-prefixed).
    #[cfg(all(feature = "device", feature = "valkey"))]
    pub(crate) const DEVICE_ROW: Self = Self {
        magic: *b"AXR\x02",
        label: b"axess.device-row.v2",
    };

    /// The device-row format of 0.11.0 (zero-byte joined ids). Still read.
    #[cfg(all(feature = "device", feature = "valkey"))]
    pub(crate) const DEVICE_ROW_V1: Self = Self {
        magic: *b"AXR\x01",
        label: b"axess.device-row.v1",
    };

    /// The marker of the per-record-subkey layout: this format's marker with
    /// the top bit of its last byte set.
    fn subkeyed_magic(&self) -> [u8; 4] {
        let mut magic = self.magic;
        magic[3] |= 0x80;
        magic
    }

    /// True when `data` starts with this format's marker, in either layout.
    #[cfg(test)]
    pub(crate) fn marks(&self, data: &[u8]) -> bool {
        data.starts_with(&self.magic) || data.starts_with(&self.subkeyed_magic())
    }

    /// AAD bytes: `label || 0x00 || row_id`.
    pub(crate) fn aad(&self, row_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.label.len() + 1 + row_id.len());
        aad.extend_from_slice(self.label);
        aad.push(0);
        aad.extend_from_slice(row_id);
        aad
    }
}

/// Row identity of a device row: each of the tenant and device id as a
/// big-endian `u32` length followed by its UTF-8 bytes.
#[cfg(any(
    test,
    all(
        feature = "device",
        any(
            feature = "sqlite",
            feature = "sqlite-unbundled",
            feature = "postgres",
            feature = "mysql",
            feature = "valkey"
        )
    )
))]
pub(crate) fn device_row_id(tenant: &str, device: &str) -> Vec<u8> {
    let mut id = Vec::with_capacity(8 + tenant.len() + device.len());
    for part in [tenant, device] {
        id.extend_from_slice(&crate::length_prefix::length_prefix(part.len()));
        id.extend_from_slice(part.as_bytes());
    }
    id
}

/// The row identity the 0.11.0 device formats bound: tenant and device id
/// joined with one zero byte. Kept only to read those rows.
#[cfg(any(
    test,
    all(
        feature = "device",
        any(
            feature = "sqlite",
            feature = "sqlite-unbundled",
            feature = "postgres",
            feature = "mysql",
            feature = "valkey"
        )
    )
))]
pub(crate) fn device_row_id_v1(tenant: &str, device: &str) -> Vec<u8> {
    let mut id = Vec::with_capacity(tenant.len() + 1 + device.len());
    id.extend_from_slice(tenant.as_bytes());
    id.push(0);
    id.extend_from_slice(device.as_bytes());
    id
}

#[cfg(any(
    test,
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
/// Result of [`SessionCrypto::open_current`] and
/// [`SessionCrypto::open_bound`].
pub(crate) struct Opened {
    /// The decrypted plaintext.
    pub(crate) plaintext: Vec<u8>,
    /// True when the blob is not at rest in the current form: a
    /// current-format blob that only the previous key opened, and for
    /// `open_bound` also an earlier bound format or no marker and no binding
    /// at all. The caller re-seals it, unless its `binding` is
    /// [`Binding::Unbound`].
    pub(crate) stale: bool,
    /// How the blob was bound to its row when it was sealed. Read by the
    /// device stores, which also read earlier forms.
    #[cfg(any(
        test,
        all(
            feature = "device",
            any(
                feature = "sqlite",
                feature = "sqlite-unbundled",
                feature = "postgres",
                feature = "mysql",
                feature = "valkey"
            )
        )
    ))]
    pub(crate) binding: Binding,
}

/// How a blob [`SessionCrypto::open_bound`] opened was bound to its row.
#[cfg(any(
    test,
    all(
        feature = "device",
        any(
            feature = "sqlite",
            feature = "sqlite-unbundled",
            feature = "postgres",
            feature = "mysql",
            feature = "valkey"
        )
    )
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    /// Sealed under the current format's binding for this row.
    Current,
    /// Sealed under an earlier bound format, whose row ids can be ambiguous.
    /// The blob carries no proof of which row it was sealed for, so a caller
    /// that can read the row's identity out of the plaintext must compare it
    /// with the key the row was stored under.
    Earlier,
    /// Sealed under the empty AAD: no binding at all, so it opens under any
    /// row id. A read must not re-seal it, because that would bind a blob
    /// copied from another row to the row it was found under for good; the
    /// row's next write seals what the application holds. A caller that can
    /// check the row's identity in the plaintext (as for
    /// [`Earlier`](Self::Earlier)) may re-seal after the check.
    Unbound,
}

/// The seal and the opens of the bound formats, compiled where
/// [`BoundFormat`] is.
#[cfg(any(
    test,
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
mod bound;

#[cfg(test)]
mod tests {
    use super::*;

    fn mixed_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::try_from(i * 7 % 251).unwrap_or(0);
        }
        key
    }

    #[test]
    fn try_new_refuses_a_key_of_one_repeated_byte() {
        assert!(SessionCrypto::try_new([0u8; 32]).is_err());
        assert!(SessionCrypto::try_new([0x42u8; 32]).is_err());
        assert!(SessionCrypto::try_new(mixed_key()).is_ok());
        assert!(is_constant_key(&[9u8; 32]) && !is_constant_key(&mixed_key()));
    }

    #[test]
    #[should_panic(expected = "session encryption key is a single repeated byte")]
    fn new_refuses_a_constant_key() {
        let _ = SessionCrypto::new([0u8; 32]);
    }

    #[test]
    #[should_panic(expected = "previous session encryption key is a single repeated byte")]
    fn with_previous_key_refuses_a_constant_key() {
        let _ = SessionCrypto::new(mixed_key()).with_previous_key([0u8; 32]);
    }

    #[test]
    #[should_panic(expected = "equals the current key")]
    fn with_previous_key_refuses_the_current_key() {
        let _ = SessionCrypto::new(mixed_key()).with_previous_key(mixed_key());
    }

    #[test]
    fn new_unchecked_accepts_a_constant_key_and_new_a_mixed_one() {
        let _ = SessionCrypto::new_unchecked([0u8; 32]);
        let _ = SessionCrypto::new(mixed_key());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = SessionCrypto::new(crate::testing::test_key(42));
        let plaintext = b"hello session data";
        let encrypted = crypto.encrypt_unbound(plaintext).unwrap();
        let decrypted = crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let crypto1 = SessionCrypto::new(crate::testing::test_key(1));
        let crypto2 = SessionCrypto::new(crate::testing::test_key(2));
        let encrypted = crypto1.encrypt_unbound(b"secret").unwrap();
        assert!(crypto2.decrypt_unbound(&encrypted).is_err());
    }

    #[test]
    fn key_rotation_decrypt_with_previous() {
        let old_key = crate::testing::test_key(1);
        let new_key = crate::testing::test_key(2);

        let old_crypto = SessionCrypto::new(old_key);
        let encrypted = old_crypto.encrypt_unbound(b"rotated data").unwrap();

        // New config with rotation: current = new_key, previous = old_key.
        let new_crypto = SessionCrypto::new(new_key).with_previous_key(old_key);
        let decrypted = new_crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, b"rotated data");
    }

    #[test]
    fn short_data_fails() {
        let crypto = SessionCrypto::new(crate::testing::test_key(42));
        assert!(crypto.decrypt_unbound(&[0u8; 5]).is_err());
    }

    /// `decrypt` with a configured previous key still uses the current
    /// key first when current succeeds. Pins against an "always fall
    /// through to previous" mutation that would silently re-encrypt
    /// everything under the old key on the next write.
    #[test]
    fn key_rotation_current_key_wins_when_valid() {
        let current = crate::testing::test_key(9);
        let prev = crate::testing::test_key(1);
        let crypto = SessionCrypto::new(current).with_previous_key(prev);
        let encrypted = crypto.encrypt_unbound(b"current-key data").unwrap();
        let decrypted = crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, b"current-key data");
    }

    /// A blob shorter than a nonce and a tag is refused, and one shorter
    /// than the nonce alone is refused rather than split at a nonce it does
    /// not have (which would panic). Where between those lengths the bound
    /// sits, and that the shortest sealed blob opens, is pinned by
    /// `tests/session_crypto_short_blob.rs`.
    #[test]
    fn a_blob_shorter_than_a_nonce_and_a_tag_is_refused_without_a_panic() {
        let crypto = SessionCrypto::new(crate::testing::test_key(7));
        for length in [0, NONCE_LEN - 1, NONCE_LEN, NONCE_LEN + TAG_LEN - 1] {
            assert!(
                crypto.decrypt_unbound(&vec![0u8; length]).is_err(),
                "{length} bytes"
            );
        }
    }

    /// `with_previous_key` must store the supplied key in `previous`,
    /// not overwrite `current`. Pins the assignment direction.
    #[test]
    fn with_previous_key_does_not_replace_current_key() {
        let current = crate::testing::test_key(3);
        let prev = crate::testing::test_key(4);
        // Configure with prev, then encrypt; encryption uses CURRENT.
        let crypto = SessionCrypto::new(current).with_previous_key(prev);
        let encrypted = crypto.encrypt_unbound(b"under-current").unwrap();

        // A standalone instance keyed by `current` (no rotation) must
        // decrypt the ciphertext, proving encryption used `current`.
        let just_current = SessionCrypto::new(current);
        assert_eq!(
            just_current.decrypt_unbound(&encrypted).unwrap(),
            b"under-current"
        );

        // And an instance keyed only by `prev` must FAIL to decrypt;
        // confirming `with_previous_key` did not move `prev` into the
        // current slot.
        let just_prev = SessionCrypto::new(prev);
        assert!(just_prev.decrypt_unbound(&encrypted).is_err());
    }
}

#[cfg(test)]
mod bound_tests;

#[cfg(test)]
mod subkey_tests;

#[cfg(test)]
mod metrics_tests;

#[cfg(test)]
mod key_tests;

#[cfg(test)]
mod short_body_tests;
