//! AES-256-GCM encryption for session data at rest.
//!
//! Shared between the Valkey and SQLite session stores. Each encrypted payload
//! is prefixed with a random 12-byte nonce.
//!
//! # Key rotation
//!
//! [`SessionCrypto`] accepts an optional previous key. On decrypt, the current
//! key is tried first; if it fails, the previous key is attempted. Writes always
//! use the current key. A row sealed under the previous key is re-sealed only
//! when it is next written: reading it does not rewrite it, so a row that is
//! only ever read stays under the previous key until it expires. Keep the
//! previous key configured for at least one session lifetime after the
//! rotation, and retire it after that.
//!
//! # Usage bound
//!
//! The blobs the stores write (session data, device rows, device bindings)
//! are sealed under a key derived for each record from the configured key, a
//! fresh 16-byte salt and the record's row identity, so each derived key
//! encrypts exactly one message and AES-GCM's random-nonce limit (about 2^32
//! seals per key) does not apply to them. The master key still wants rotating
//! on the usual schedule; it no longer has a write budget. A blob in the
//! earlier layout (the key used directly, a random nonce per seal) is still
//! read and is re-sealed in the new layout by the same paths that re-seal
//! any other stale blob. [`SessionCrypto::encrypt_with_aad`] keeps the
//! direct layout for callers that use it themselves, and
//! [`SessionCrypto::seals`] meters those calls.
//!
//! # Blobs from before row binding
//!
//! Every blob the stores write names the row it belongs to in its AAD (the
//! additional authenticated data of the AES-GCM seal). A blob written by an
//! earlier release carries no marker and no binding, so it opens under any
//! row id, which is exactly what an attacker with write access to the store
//! (or a restored backup) needs to move a sealed row from one id to another.
//! The 0.11.0 device formats (`DEVICE_BINDINGS_V1`, `DEVICE_ROW_V1`) join the
//! tenant and device id with a zero byte, so two id pairs can share one AAD.
//! [`LegacyBlobs`] says what to do with both kinds:
//!
//! - [`Reject`](LegacyBlobs::Reject), the default, refuses them. A refused row
//!   reads as a decryption failure and the user signs in again (a device row
//!   is read as missing).
//! - [`AcceptUntil`](LegacyBlobs::AcceptUntil) reads them until an instant
//!   (checked against the crypto's clock, see
//!   [`with_clock`](SessionCrypto::with_clock)) and refuses them afterwards.
//!   Use it for the upgrade window: one session lifetime for sessions, and
//!   the longest device lifetime you care to keep for devices.
//! - [`Accept`](LegacyBlobs::Accept) reads them with no end date.
//!
//! The stores re-seal an accepted blob in the current format the next time the
//! row is read or written. A Valkey device row carries its own tenant and
//! device id, so one that was read through a legacy blob is also refused when
//! the ids it names differ from the key it was stored under, and it is never
//! re-sealed under the wrong key. Session data and SQL device bindings carry
//! no identity of their own, so for them the cutoff is the only protection.

pub use super::legacy_blobs::LegacyBlobs;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(
    test,
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
use crate::subkey;

const NONCE_LEN: usize = 12;

/// Zeroize-on-drop wrapper for a 32-byte AES key.
#[derive(Clone)]
pub struct EncryptionKey(pub(crate) [u8; 32]);

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// AES-256-GCM encryption configuration with optional key rotation.
#[derive(Clone)]
pub struct SessionCrypto {
    current: Arc<EncryptionKey>,
    previous: Option<Arc<EncryptionKey>>,
    rng: Arc<dyn SecureRng>,
    clock: Arc<dyn Clock>,
    legacy: LegacyBlobs,
    seals: Arc<AtomicU64>,
}

pub(crate) use super::weak_key::warn_if_constant_key;
pub use super::weak_key::{WeakKeyError, is_constant_key};

/// Error from encrypt/decrypt operations.
#[derive(Debug, thiserror::Error)]
#[error("session encryption/decryption error")]
pub struct CryptoError;

impl SessionCrypto {
    /// Create a new crypto config with the given 32-byte key. Uses
    /// [`SystemRng`] for nonce generation; tests under DST should use
    /// [`SessionCrypto::with_rng`] to inject a deterministic RNG.
    ///
    /// A key that is a single repeated byte (all zeros, a test placeholder)
    /// is logged at `error`; use [`try_new`](Self::try_new) to refuse it.
    pub fn new(key: [u8; 32]) -> Self {
        warn_if_constant_key("session encryption key", &key);
        Self {
            current: Arc::new(EncryptionKey(key)),
            previous: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            legacy: LegacyBlobs::default(),
            seals: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Like [`new`](Self::new), refusing a key that is a single repeated byte.
    ///
    /// # Errors
    ///
    /// [`WeakKeyError`] for such a key.
    pub fn try_new(key: [u8; 32]) -> Result<Self, WeakKeyError> {
        if is_constant_key(&key) {
            return Err(WeakKeyError);
        }
        Ok(Self::new(key))
    }

    /// Choose whether blobs written before row binding are read. See
    /// [`LegacyBlobs`]; the default is [`LegacyBlobs::Reject`].
    pub fn with_legacy_blobs(mut self, policy: LegacyBlobs) -> Self {
        self.legacy = policy;
        self
    }

    /// Inject the clock that [`LegacyBlobs::AcceptUntil`] is checked against
    /// (default: [`SystemClock`]).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// True while blobs from before row binding may still be read.
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
    /// default [`SystemRng`]; DST suites pass a seeded `MockRng` to drive
    /// nonce sequences deterministically.
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// Enable key rotation: on decrypt, try the current key first, then this
    /// previous key as a fallback.
    pub fn with_previous_key(mut self, key: [u8; 32]) -> Self {
        warn_if_constant_key("previous session encryption key", &key);
        if bool::from(subtle::ConstantTimeEq::ct_eq(
            key.as_slice(),
            self.current.0.as_slice(),
        )) {
            tracing::error!(
                target: "axess::session::crypto",
                "previous session encryption key equals the current key; \
                 the rotation protects nothing"
            );
        }
        self.previous = Some(Arc::new(EncryptionKey(key)));
        self
    }

    /// Seal with an empty AAD. Kept for writing pre-binding fixtures; a blob
    /// sealed this way is not bound to its row.
    #[cfg(test)]
    pub(crate) fn encrypt_unbound(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_with_aad(&[], plaintext)
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
    pub fn encrypt_with_aad(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seals.fetch_add(1, Ordering::Relaxed);
        let cipher = Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| CryptoError)?;

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
    /// path of the bound formats.
    pub(crate) fn decrypt_unbound(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_aad(&[], data)
    }

    /// Decrypt `nonce || ciphertext` that was sealed with the same `aad`.
    /// Tries the current key first, then the previous key. A mismatched
    /// `aad` fails authentication exactly like a wrong key.
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
        if data.len() < NONCE_LEN {
            return Err(CryptoError);
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError)?;

        let cipher = Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| CryptoError)?;

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
            let old_cipher = Aes256Gcm::new_from_slice(&prev.0).map_err(|_| CryptoError)?;

            if let Ok(plaintext) = old_cipher.decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ) {
                tracing::debug!("session decrypted with previous (rotated) key");
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
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
/// A storage context whose encrypted blobs are bound to the row they live in.
///
/// A sealed blob is `magic || nonce || ciphertext`, where the AES-GCM
/// additional authenticated data is `label || 0x00 || row_id`. The row id is
/// not stored in the blob; it is supplied again on open, so a blob copied into
/// a row with a different id fails authentication. A row id made of several
/// parts is length-prefixed (see `device_row_id`) so two different part
/// lists can never concatenate to the same bytes.
#[derive(Clone, Copy)]
pub(crate) struct BoundFormat {
    /// Four-byte format marker written at the start of every sealed blob.
    magic: [u8; 4],
    /// Domain-separation label authenticated as part of the AAD.
    label: &'static [u8],
}

#[cfg(any(
    test,
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
impl BoundFormat {
    /// Session data, bound to the session id.
    pub(crate) const SESSION: Self = Self {
        magic: *b"AXS\x01",
        label: b"axess.session.v1",
    };

    /// Device bindings, bound to the tenant and device id (length-prefixed).
    #[cfg(any(test, feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub(crate) const DEVICE_BINDINGS: Self = Self {
        magic: *b"AXD\x02",
        label: b"axess.device-bindings.v2",
    };

    /// The device-bindings format of 0.11.0: the tenant and device id were
    /// joined with a single zero byte. Still read, and replaced by
    /// [`DEVICE_BINDINGS`](Self::DEVICE_BINDINGS) on the next write.
    #[cfg(any(test, feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub(crate) const DEVICE_BINDINGS_V1: Self = Self {
        magic: *b"AXD\x01",
        label: b"axess.device-bindings.v1",
    };

    /// A whole device row in the Valkey store, bound to the tenant and
    /// device id (length-prefixed).
    #[cfg(any(test, feature = "valkey"))]
    pub(crate) const DEVICE_ROW: Self = Self {
        magic: *b"AXR\x02",
        label: b"axess.device-row.v2",
    };

    /// The device-row format of 0.11.0 (zero-byte joined ids). Still read.
    #[cfg(any(test, feature = "valkey"))]
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
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub(crate) fn device_row_id(tenant: &str, device: &str) -> Vec<u8> {
    let mut id = Vec::with_capacity(8 + tenant.len() + device.len());
    for part in [tenant, device] {
        id.extend_from_slice(&(part.len() as u32).to_be_bytes());
        id.extend_from_slice(part.as_bytes());
    }
    id
}

/// The row identity the 0.11.0 device formats bound: tenant and device id
/// joined with one zero byte. Kept only to read those rows.
#[cfg(any(
    test,
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
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
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
/// Result of [`SessionCrypto::open_bound`].
pub(crate) struct Opened {
    /// The decrypted plaintext.
    pub(crate) plaintext: Vec<u8>,
    /// True when the blob is not at rest in the current form: an earlier
    /// bound format, no marker and no binding at all, or a current-format
    /// blob that only the previous key opened. The caller re-seals it.
    pub(crate) stale: bool,
    /// True when the blob was opened without the current format's binding:
    /// an earlier format (whose ids can be ambiguous) or no marker at all.
    /// The blob carries no proof of which row it was sealed for, so a caller
    /// that can read the row's identity out of the plaintext must compare it
    /// with the key the row was stored under.
    pub(crate) legacy: bool,
}

#[cfg(any(
    test,
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
impl SessionCrypto {
    /// Open a subkeyed body under the current key, then the previous key.
    fn open_subkeyed(&self, aad: &[u8], body: &[u8]) -> Result<Opened, CryptoError> {
        if let Ok(plaintext) = subkey::open(&self.current.0, aad, body) {
            return Ok(Opened {
                plaintext,
                stale: false,
                legacy: false,
            });
        }
        if let Some(prev) = &self.previous
            && let Ok(plaintext) = subkey::open(&prev.0, aad, body)
        {
            tracing::debug!("blob opened with the previous (rotated) key");
            return Ok(Opened {
                plaintext,
                stale: true,
                legacy: false,
            });
        }
        tracing::warn!("blob decryption failed with the configured keys");
        Err(CryptoError)
    }

    /// Encrypt `plaintext` bound to `row_id`: `magic' || salt || ciphertext`
    /// under a subkey derived for this record, with AAD
    /// `label || 0x00 || row_id` (see [`BoundFormat`] and the module
    /// documentation).
    pub(crate) fn seal_bound(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let marker = format.subkeyed_magic();
        let body = subkey::seal(&self.current.0, &*self.rng, &format.aad(row_id), plaintext)
            .map_err(|_| CryptoError)?;
        let mut out = Vec::with_capacity(marker.len() + body.len());
        out.extend_from_slice(&marker);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Open a blob for `row_id`.
    ///
    /// A blob that starts with the current format's marker is tried under
    /// that format's AAD. A blob that starts with the marker of one of the
    /// `earlier` formats is tried under that format's AAD and the row id it
    /// paired with (an earlier release derived the id differently), and is
    /// flagged `stale` and `legacy`. A blob with none of these markers is a
    /// pre-binding blob, tried under the empty AAD and flagged the same way.
    ///
    /// Both of the last two kinds are refused unless the crypto's
    /// [`LegacyBlobs`] policy reads them. Under a policy that reads them, a
    /// blob whose first four bytes happen to equal a marker but which does not
    /// open under that format (a pre-binding nonce is random, so this is about
    /// one blob in 2^32) is tried under the empty AAD as a whole. That cannot
    /// open a smuggled marked blob: the marker and the nonce that follow it
    /// would have to authenticate under the empty AAD. Under a policy that
    /// refuses them the ambiguous blob is refused, which fails closed.
    pub(crate) fn open_bound(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        earlier: &[(BoundFormat, Vec<u8>)],
        data: &[u8],
    ) -> Result<Opened, CryptoError> {
        let legacy_readable = self.legacy_blobs_readable();
        if let Some(body) = data.strip_prefix(&format.subkeyed_magic()[..]) {
            return self.open_subkeyed(&format.aad(row_id), body);
        }
        if let Some(body) = data.strip_prefix(&format.magic[..]) {
            // The earlier layout of the current format: the key used
            // directly. Readable, and stale so that it is re-sealed under a
            // subkey. A failure here is final unless legacy blobs are still
            // read, because a legacy blob's random nonce can begin with this
            // marker (about one in 2^32), and then it is tried as one below.
            match self.decrypt_with_aad_reporting(&format.aad(row_id), body) {
                Ok((plaintext, _used_previous)) => {
                    return Ok(Opened {
                        plaintext,
                        stale: true,
                        legacy: false,
                    });
                }
                Err(error) if !legacy_readable => return Err(error),
                Err(_) => {}
            }
        } else {
            for (old, old_id) in earlier {
                if let Some(body) = data.strip_prefix(&old.magic[..]) {
                    if !legacy_readable {
                        tracing::warn!(
                            "refusing a blob in an earlier row-bound format (legacy blobs are not read)"
                        );
                        return Err(CryptoError);
                    }
                    if let Ok(plaintext) = self.decrypt_with_aad(&old.aad(old_id), body) {
                        return Ok(Opened {
                            plaintext,
                            stale: true,
                            legacy: true,
                        });
                    }
                }
            }
        }
        if !legacy_readable {
            tracing::warn!("refusing a blob without a row binding (legacy blobs are not read)");
            return Err(CryptoError);
        }
        Ok(Opened {
            plaintext: self.decrypt_unbound(data)?,
            stale: true,
            legacy: true,
        })
    }
}

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

    #[cfg(feature = "testing")]
    #[test]
    fn a_constant_or_repeated_key_is_logged_at_error() {
        let capture = crate::testing::mock_tracing::TracingCapture::install();
        let _ = SessionCrypto::new(mixed_key());
        assert!(capture.events().is_empty(), "a mixed key is not reported");
        let _ = SessionCrypto::new([0u8; 32]);
        assert!(capture.contains_at_level(tracing::Level::ERROR, "single repeated byte"));
        let capture = crate::testing::mock_tracing::TracingCapture::install();
        let _ = SessionCrypto::new(mixed_key()).with_previous_key(mixed_key());
        assert!(capture.contains_at_level(tracing::Level::ERROR, "equals the current key"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = SessionCrypto::new([42u8; 32]);
        let plaintext = b"hello session data";
        let encrypted = crypto.encrypt_unbound(plaintext).unwrap();
        let decrypted = crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let crypto1 = SessionCrypto::new([1u8; 32]);
        let crypto2 = SessionCrypto::new([2u8; 32]);
        let encrypted = crypto1.encrypt_unbound(b"secret").unwrap();
        assert!(crypto2.decrypt_unbound(&encrypted).is_err());
    }

    #[test]
    fn key_rotation_decrypt_with_previous() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];

        let old_crypto = SessionCrypto::new(old_key);
        let encrypted = old_crypto.encrypt_unbound(b"rotated data").unwrap();

        // New config with rotation: current = new_key, previous = old_key.
        let new_crypto = SessionCrypto::new(new_key).with_previous_key(old_key);
        let decrypted = new_crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, b"rotated data");
    }

    #[test]
    fn short_data_fails() {
        let crypto = SessionCrypto::new([42u8; 32]);
        assert!(crypto.decrypt_unbound(&[0u8; 5]).is_err());
    }

    /// `decrypt` with a configured previous key still uses the current
    /// key first when current succeeds. Pins against an "always fall
    /// through to previous" mutation that would silently re-encrypt
    /// everything under the old key on the next write.
    #[test]
    fn key_rotation_current_key_wins_when_valid() {
        let current = [9u8; 32];
        let prev = [1u8; 32];
        let crypto = SessionCrypto::new(current).with_previous_key(prev);
        let encrypted = crypto.encrypt_unbound(b"current-key data").unwrap();
        let decrypted = crypto.decrypt_unbound(&encrypted).unwrap();
        assert_eq!(decrypted, b"current-key data");
    }

    /// Boundary: payload of exactly NONCE_LEN (12) bytes has no
    /// ciphertext to authenticate and must fail. Pins `< NONCE_LEN`
    /// against `<=` (which would also reject 12-byte payloads but allow
    /// 12-byte-only nonce splits to attempt decryption) and `==` /
    /// `delete` mutants.
    #[test]
    fn decrypt_payload_at_nonce_length_boundary_fails() {
        let crypto = SessionCrypto::new([7u8; 32]);
        assert!(crypto.decrypt_unbound(&[0u8; NONCE_LEN]).is_err());
    }

    /// `with_previous_key` must store the supplied key in `previous`,
    /// not overwrite `current`. Pins the assignment direction.
    #[test]
    fn with_previous_key_does_not_replace_current_key() {
        let current = [3u8; 32];
        let prev = [4u8; 32];
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
