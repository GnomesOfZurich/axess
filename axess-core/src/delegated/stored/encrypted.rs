//! Encryption-at-rest wrapper for [`DelegatedCredentialStore`].
//!
//! Wraps any inner `DelegatedCredentialStore` and transparently
//! encrypts the `access_token` and (when present) `refresh_token`
//! fields of [`StoredDelegation`] before they touch the inner store.
//! On load, decryption is performed before the credential is handed
//! back to the runtime. The inner store sees only opaque ciphertext
//! envelopes in those string fields; the non-secret metadata
//! (`provider`, `expires_at`, `scopes`, `token_type`) passes through
//! in clear so adopters can still run operational queries over it, and
//! is authenticated by the envelopes so a rewrite of it is noticed.
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
//! v3.{key_id}.{base64url-no-pad(nonce ‖ ciphertext‖tag)}
//! ```
//!
//! - `v3`: format version. New versions get a new tag and explicit
//!   decode dispatch; the decoder rejects unknown versions. Every save
//!   writes `v3`, whose AAD covers the row's `scopes`, `token_type` and
//!   `expires_at` (eight big-endian bytes of Unix seconds, or an empty
//!   value for `None`) as well as the identity fields, so a store that
//!   rewrites any of that metadata (widening the granted scopes, or
//!   moving the expiry so a stale token looks fresh and is never
//!   refreshed) fails authentication on load instead of changing what
//!   the runtime believes it holds. `v2` (whose AAD lacks `expires_at`)
//!   is still read, but its stored expiry is unauthenticated, so the row
//!   loads as expired and is not re-sealed: the refresh that follows saves a
//!   `v3` row from the provider's answer (a `v2` row with no refresh token
//!   asks the user to reconnect). `v1` (whose AAD also lacks `scopes` and
//!   `token_type`) is read only under the legacy policy below and is
//!   treated the same way.
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
//! cycle, every `complete_grant`), and a `v3` row read under a retired key is
//! re-sealed by the read that found it. A `v2` row, or a `v1` row inside the
//! legacy window, is read as expired and replaced by the refresh instead. That rewrite is a
//! compare-and-swap ([`DelegatedCredentialStore::save_if_unchanged`]), so it
//! cannot overwrite a refresh token another request rotated in between; a
//! store that does not implement the swap is left as it is.
//! [`without_reseal_on_load`](EncryptedDelegatedCredentialStore::without_reseal_on_load)
//! turns the rewrite off.
//!
//! # Envelopes from before scope binding
//!
//! `v1` envelopes authenticate no `scopes` or `token_type`, so a store that
//! rewrites those fields is not noticed. They are refused by default: the
//! policy is [`LegacyBlobs::Reject`], and a `v1` row then reads as a
//! decryption failure (`a v1 envelope is refused`), which fails the load
//! without exposing anything. A deployment upgrading from a release that
//! wrote `v1` opens a migration window with
//! [`with_legacy_envelopes`](EncryptedDelegatedCredentialStore::with_legacy_envelopes)
//! and [`LegacyBlobs::AcceptUntil`]`(cutoff)`, the same choice the session
//! crypto takes: inside the window a `v1` row is read (as expired) and
//! replaced in the current format by the refresh that follows. Drop back to
//! `Reject` once the rows have been refreshed, or let the cutoff pass.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axess_identity::{TenantId, UserId};

use crate::delegated::stored::credential::{
    CredentialSwap, DelegatedCredentialStore, StoredDelegation,
};
use crate::session::crypto::LegacyBlobs;
use axess_clock::{Clock, SystemClock};
use axess_factors::ZeroizedString;
use axess_rng::SecureRng;

mod envelope;
mod keys;

pub use keys::{CurrentKey, EncryptionKey, KeyProvider, KeyProviderError, MemoryKeyProvider};

use envelope::{
    EnvelopeError, Opened, build_aad, build_aad_v2, build_aad_v3, encrypt_envelope, open_envelope,
};

/// Version written by this release. `v3` binds the row's `expires_at` into
/// the AAD as well as its `scopes` and `token_type`; `v2` rows (no expiry
/// bound) are read as expired and left as they are, `v1` rows follow
/// [`LegacyBlobs`].
const ENVELOPE_VERSION: &str = "v3";
const SCOPED_ENVELOPE_VERSION: &str = "v2";
const LEGACY_ENVELOPE_VERSION: &str = "v1";
const NONCE_LEN: usize = 12;
const FIELD_ACCESS: &[u8] = b"access_token";
const FIELD_REFRESH: &[u8] = b"refresh_token";
const AAD_SEP: u8 = 0x1f; // ASCII unit separator

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
/// // 32 random bytes from your secret store; a placeholder such as
/// // `[0u8; 32]` is refused with `KeyProviderError::WeakKey`.
/// let key: [u8; 32] = load_delegation_key()?;
/// let keys = MemoryKeyProvider::new("2026-05", key)?;
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

/// A stored row with its fields opened.
struct OpenedRow {
    plain: StoredDelegation,
    /// Some field is sealed under a key other than the current one.
    stale: bool,
    /// Every field's envelope covers the expiry.
    expiry_bound: bool,
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

    /// Leave a row as it is when it is read under a retired key. By default
    /// such a row is re-sealed by the read that found it, through [`DelegatedCredentialStore::save_if_unchanged`].
    /// The re-seal needs [`KeyProvider::current`]; when that fails the load
    /// is still served under the key the row names, the failure is logged
    /// and the re-seal is left to a later load.
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
        // A provider of its own can name any id or hand over any key; the
        // envelope would then be written and never read back.
        keys::validate_key_id(&current.key_id).map_err(|e| e.to_string())?;
        if current.key.is_constant() {
            return Err(KeyProviderError::from(crate::session::WeakKeyError).to_string());
        }
        self.seals
            .fetch_add(1 + u64::from(refresh_token.is_some()), Ordering::Relaxed);

        let aad_access = build_aad_v3(
            &provider,
            tenant,
            user,
            FIELD_ACCESS,
            &scopes,
            &token_type,
            expires_at,
        );
        let access_env = encrypt_envelope(&current, &*self.rng, &access_token, &aad_access)
            .map_err(|e| format!("encrypt access_token: {e}"))?;

        let refresh_env = match refresh_token.as_deref() {
            Some(rt) => {
                let aad_refresh = build_aad_v3(
                    &provider,
                    tenant,
                    user,
                    FIELD_REFRESH,
                    &scopes,
                    &token_type,
                    expires_at,
                );
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

    /// Open every field of a stored row, under the key each names.
    fn open_row(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
        cred: &StoredDelegation,
        current_id: Option<&str>,
    ) -> Result<OpenedRow, String> {
        let mut stale = false;
        let mut expiry_bound = true;

        let access = self
            .open_field(
                provider,
                cred,
                &cred.access_token,
                FIELD_ACCESS,
                tenant,
                user,
            )
            .map_err(|e| format!("decrypt access_token: {e}"))?;
        stale |= access.is_stale(current_id);
        expiry_bound &= access.binds_expiry();
        let access_plain = access.plain;

        let refresh_plain = match cred.refresh_token.as_deref() {
            Some(rt) => {
                let opened = self
                    .open_field(provider, cred, rt, FIELD_REFRESH, tenant, user)
                    .map_err(|e| format!("decrypt refresh_token: {e}"))?;
                stale |= opened.is_stale(current_id);
                expiry_bound &= opened.binds_expiry();
                Some(ZeroizedString::from(opened.plain))
            }
            None => None,
        };

        let plain = StoredDelegation {
            provider: cred.provider.clone(),
            access_token: ZeroizedString::from(access_plain),
            refresh_token: refresh_plain,
            // An envelope older than the current version does not cover the
            // expiry, so a store writer could have moved it. The row reads as
            // expired: the refresh that follows saves a current row from the
            // provider's answer. It is not re-sealed, which would vouch for
            // the unauthenticated value.
            expires_at: if expiry_bound {
                cred.expires_at
            } else {
                Some(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
            },
            scopes: cred.scopes.clone(),
            token_type: cred.token_type.clone(),
        };
        Ok(OpenedRow {
            plain,
            stale,
            expiry_bound,
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
        if cred.provider != provider {
            return Err(format!(
                "stored credential is labelled {:?}, not the requested provider",
                cred.provider
            ));
        }

        // The row is opened under the key it names; the current key is
        // wanted only to tell whether the row is due a re-seal. A provider
        // that cannot name one (a KMS that answers reads and refuses the
        // write-key call) still serves the load; the re-seal waits.
        let current_id = match self.reseal_on_load.then(|| self.keys.current()) {
            Some(Ok(current)) => Some(current.key_id),
            Some(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    "delegated credential load: no current key; read under the stored key, \
                     re-seal skipped"
                );
                None
            }
            None => None,
        };
        let opened = self.open_row(tenant, user, provider, &cred, current_id.as_deref())?;
        if opened.stale && opened.expiry_bound {
            self.reseal(tenant, user, &cred, &opened.plain).await;
        }
        Ok(Some(opened.plain))
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

    async fn save_if_unchanged(
        &self,
        tenant: &TenantId,
        user: &UserId,
        expected: &StoredDelegation,
        replacement: StoredDelegation,
    ) -> Result<CredentialSwap, String> {
        // The inner store compares sealed rows, and the caller holds the
        // plaintext it read: read the sealed row, open it, and swap against
        // the sealed row only if it opens to what the caller expected. The
        // swap is atomic exactly when the inner store's is.
        let Some(row) = self.inner.load(tenant, user, &expected.provider).await? else {
            return Ok(CredentialSwap::Changed);
        };
        let opened = self.open_row(tenant, user, &expected.provider, &row, None)?;
        if !opened.plain.same_as(expected) {
            return Ok(CredentialSwap::Changed);
        }
        let sealed = self.seal(tenant, user, replacement)?;
        self.inner
            .save_if_unchanged(tenant, user, &row, sealed)
            .await
    }

    async fn revoke(&self, tenant: &TenantId, user: &UserId, provider: &str) -> Result<(), String> {
        self.inner.revoke(tenant, user, provider).await
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
            ENVELOPE_VERSION => Some(build_aad_v3(
                provider,
                tenant,
                user,
                field,
                &row.scopes,
                &row.token_type,
                row.expires_at,
            )),
            SCOPED_ENVELOPE_VERSION => Some(build_aad_v2(
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

/// A non-constant 32-byte key for tests, distinct per `seed`.
#[cfg(test)]
fn test_key(seed: u8) -> [u8; 32] {
    std::array::from_fn(|i| seed.wrapping_add(i as u8))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod key_id_tests;
#[cfg(test)]
mod legacy_tests;
#[cfg(test)]
mod rng_tests;
#[cfg(test)]
mod tests;
