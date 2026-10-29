//! Encrypting OTP secrets at rest.
//!
//! A TOTP or HOTP secret is a shared key: whoever reads the row can mint
//! every code the user will ever need. [`FactorSecretCipher`] seals it with
//! AES-256-GCM before the store sees it, binding the ciphertext to the tenant,
//! user and factor it belongs to, so a sealed secret copied onto another
//! user's row is refused rather than accepted.
//!
//! The cipher is built from 32-byte keys the application supplies, with an
//! optional previous key for rotation (the same shape as
//! [`SessionCrypto`](crate::session::SessionCrypto)), and handed to the
//! service with
//! [`with_factor_secret_cipher`](crate::authn::service::AuthnServiceBuilder::with_factor_secret_cipher).
//! The service then opens a sealed secret to verify a code and keeps it
//! sealed when it writes the row back.
//!
//! # Moving existing rows
//!
//! A row written before the cipher existed holds a plain secret. Whether it is
//! still read is the [`LegacyBlobs`] policy given to
//! [`with_plain_secrets`](FactorSecretCipher::with_plain_secrets): the default,
//! [`Reject`](LegacyBlobs::Reject), refuses it; [`AcceptUntil`](LegacyBlobs::AcceptUntil)
//! reads it until an instant on the cipher's clock. A plain secret that is
//! read and verifies is sealed and saved in the same login, so the move costs
//! one login per user inside the window. A secret sealed under the previous
//! key is re-sealed under the current one the same way.
//!
//! # Nonces
//!
//! Each seal draws a random 96-bit nonce. A secret is sealed once at
//! enrolment and once per move, not once per login, so the count stays far
//! below the NIST SP 800-38D random-nonce bound for any realistic user base.

use crate::authn::factor::{FactorConfig, FactorKind};
use crate::authn::types::AuthnScope;
use crate::session::legacy_blobs::LegacyBlobs;
use crate::session::weak_key::{WeakKeyError, is_constant_key, warn_if_constant_key};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_clock::{Clock, SystemClock};
use axess_factors::{FactorSecret, SealedFactorSecret, ZeroizedString};
use axess_rng::{SecureRng, SystemRng};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const NONCE_LEN: usize = 12;

/// A 32-byte AES key, zeroed when dropped.
struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
const AAD_LABEL: &[u8] = b"axess.factor-secret.v1";

/// Why a secret could not be sealed or opened.
///
/// The text never contains key material or the secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FactorSecretError {
    /// The secret is sealed and the service has no cipher to open it.
    #[error(
        "the factor secret is sealed but no FactorSecretCipher is configured \
         (AuthnServiceBuilder::with_factor_secret_cipher)"
    )]
    NoCipher,
    /// The secret is plain, a cipher is configured, and the legacy policy no
    /// longer reads plain secrets.
    #[error(
        "the factor secret is stored in plain text and the cipher no longer reads plain secrets \
         (FactorSecretCipher::with_plain_secrets)"
    )]
    PlainRefused,
    /// The sealed secret names a key this cipher does not hold.
    #[error("the factor secret was sealed under a key this cipher does not hold")]
    UnknownKey,
    /// Authentication failed: wrong key, a different row, or a damaged blob.
    #[error("the factor secret did not authenticate for this tenant, user and factor")]
    Open,
    /// The secret could not be encrypted.
    #[error("the factor secret could not be sealed")]
    Seal,
}

/// What a sealed secret is bound to: the scope it is stored at and the factor.
///
/// A secret sealed for one binding does not open under another, so a row
/// copied between users, tenants or factors fails to authenticate.
#[derive(Debug, Clone, Copy)]
pub struct FactorSecretBinding<'a> {
    scope: &'a AuthnScope,
    kind: &'a FactorKind,
}

impl<'a> FactorSecretBinding<'a> {
    /// Bind to the row at `scope` holding the `kind` factor.
    pub fn new(scope: &'a AuthnScope, kind: &'a FactorKind) -> Self {
        Self { scope, kind }
    }

    /// The additional authenticated data: the label, then the tenant id, the
    /// user id (empty above user scope) and the factor id, each preceded by
    /// its length so no two bindings share one byte string.
    fn aad(&self) -> Vec<u8> {
        let columns = self.scope.as_columns();
        let tenant = columns.tenant_id.to_string();
        let user = columns
            .user_id
            .map(|user_id| user_id.to_string())
            .unwrap_or_default();
        let mut aad = Vec::with_capacity(AAD_LABEL.len() + 64);
        aad.extend_from_slice(AAD_LABEL);
        for part in [tenant.as_str(), user.as_str(), self.kind.as_str()] {
            aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
            aad.extend_from_slice(part.as_bytes());
        }
        aad
    }
}

/// A secret opened by [`FactorSecretCipher::open`].
pub struct OpenedSecret {
    /// The secret text.
    pub secret: ZeroizedString,
    /// True when it was sealed under the previous key, so the caller should
    /// seal it again under the current one.
    pub rotated: bool,
}

/// Seals and opens OTP secrets. See the module documentation.
#[derive(Clone)]
pub struct FactorSecretCipher {
    current: Arc<Key>,
    current_id: String,
    previous: Option<(Arc<Key>, String)>,
    rng: Arc<dyn SecureRng>,
    clock: Arc<dyn Clock>,
    plain: LegacyBlobs,
}

impl FactorSecretCipher {
    /// A cipher sealing under `key`. A key that is a single repeated byte is
    /// logged at `error`; use [`try_new`](Self::try_new) to refuse it.
    pub fn new(key: [u8; 32]) -> Self {
        warn_if_constant_key("factor secret encryption key", &key);
        let current_id = key_id(&key);
        Self {
            current: Arc::new(Key(key)),
            current_id,
            previous: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            plain: LegacyBlobs::default(),
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

    /// Keep secrets sealed under `key` readable, for a key rotation. They are
    /// sealed again under the current key the next time they verify.
    pub fn with_previous_key(mut self, key: [u8; 32]) -> Self {
        warn_if_constant_key("previous factor secret encryption key", &key);
        let id = key_id(&key);
        if id == self.current_id {
            tracing::error!(
                target: "axess::authn::factor_secret",
                "previous factor secret key equals the current key; the rotation protects nothing"
            );
        }
        self.previous = Some((Arc::new(Key(key)), id));
        self
    }

    /// Whether a secret still stored in plain text is read, and until when.
    /// Default [`LegacyBlobs::Reject`]; use [`LegacyBlobs::AcceptUntil`] for
    /// the window in which existing rows are moved.
    pub fn with_plain_secrets(mut self, policy: LegacyBlobs) -> Self {
        self.plain = policy;
        self
    }

    /// The clock [`LegacyBlobs::AcceptUntil`] is checked against.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The RNG nonces are drawn from (tests inject a seeded one).
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// True while a plain secret may still be read.
    pub fn plain_secrets_readable(&self) -> bool {
        match self.plain {
            LegacyBlobs::Reject => false,
            LegacyBlobs::AcceptUntil(until) => self.clock.now() < until,
            LegacyBlobs::Accept => true,
        }
    }

    /// Whether `sealed` is at rest under the current key.
    pub fn is_current(&self, sealed: &SealedFactorSecret) -> bool {
        sealed.key_id == self.current_id
    }

    /// Seal `secret` for the row `binding` names.
    ///
    /// # Errors
    ///
    /// [`FactorSecretError::Seal`] if encryption fails.
    pub fn seal(
        &self,
        secret: &str,
        binding: FactorSecretBinding<'_>,
    ) -> Result<SealedFactorSecret, FactorSecretError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.current.0).map_err(|_| FactorSecretError::Seal)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| FactorSecretError::Seal)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: secret.as_bytes(),
                    aad: &binding.aad(),
                },
            )
            .map_err(|_| FactorSecretError::Seal)?;
        Ok(SealedFactorSecret {
            key_id: self.current_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    /// Open `sealed` for the row `binding` names.
    ///
    /// # Errors
    ///
    /// [`FactorSecretError::UnknownKey`] when the key id is neither the
    /// current nor the previous key, and [`FactorSecretError::Open`] when the
    /// blob does not authenticate for this binding.
    pub fn open(
        &self,
        sealed: &SealedFactorSecret,
        binding: FactorSecretBinding<'_>,
    ) -> Result<OpenedSecret, FactorSecretError> {
        let (key, rotated) = if sealed.key_id == self.current_id {
            (&self.current, false)
        } else {
            match &self.previous {
                Some((key, id)) if *id == sealed.key_id => (key, true),
                _ => return Err(FactorSecretError::UnknownKey),
            }
        };
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(&sealed.nonce)
            .map_err(|_| FactorSecretError::Open)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&sealed.ciphertext)
            .map_err(|_| FactorSecretError::Open)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(FactorSecretError::Open);
        }
        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| FactorSecretError::Open)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| FactorSecretError::Open)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &binding.aad(),
                },
            )
            .map_err(|_| FactorSecretError::Open)?;
        let text = String::from_utf8(plaintext).map_err(|_| FactorSecretError::Open)?;
        Ok(OpenedSecret {
            secret: ZeroizedString::new(text),
            rotated,
        })
    }

    /// Seal the OTP secret inside `config` for the row at `scope`, leaving any
    /// other factor and an already sealed secret untouched. Use it at
    /// enrolment, and in a migration that seals existing rows ahead of the
    /// window.
    ///
    /// # Errors
    ///
    /// [`FactorSecretError::Seal`] if encryption fails.
    pub fn seal_config(
        &self,
        config: FactorConfig,
        scope: &AuthnScope,
    ) -> Result<FactorConfig, FactorSecretError> {
        match config {
            FactorConfig::Totp(mut cfg) => {
                self.seal_in_place(&mut cfg.secret, scope, &FactorKind::Totp)?;
                Ok(FactorConfig::Totp(cfg))
            }
            FactorConfig::Hotp(mut cfg) => {
                self.seal_in_place(&mut cfg.secret, scope, &FactorKind::Hotp)?;
                Ok(FactorConfig::Hotp(cfg))
            }
            other => Ok(other),
        }
    }

    fn seal_in_place(
        &self,
        secret: &mut FactorSecret,
        scope: &AuthnScope,
        kind: &FactorKind,
    ) -> Result<(), FactorSecretError> {
        if let FactorSecret::Plain(text) = secret {
            let sealed = self.seal(text, FactorSecretBinding::new(scope, kind))?;
            *secret = FactorSecret::Sealed(sealed);
        }
        Ok(())
    }
}

impl std::fmt::Debug for FactorSecretCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactorSecretCipher")
            .field("current_key_id", &self.current_id)
            .field("has_previous_key", &self.previous.is_some())
            .field("plain", &self.plain)
            .finish()
    }
}

/// A short public fingerprint of a key: the first eight bytes of a labelled
/// SHA-256, hex encoded. It names the key without helping recover it.
fn key_id(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"axess.factor-secret.key-id.v1");
    hasher.update(key);
    let digest = hasher.finalize();
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_identity::testing::{tenant, user};
    use chrono::Utc;

    const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";
    const OTHER: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

    fn scope(t: &str, u: &str) -> AuthnScope {
        AuthnScope::User {
            tenant_id: tenant(t),
            user_id: user(u),
        }
    }

    #[test]
    fn a_sealed_secret_opens_for_its_own_binding() {
        let cipher = FactorSecretCipher::new(KEY);
        let scope = scope("t1", "u1");
        let sealed = cipher
            .seal(
                "JBSWY3DPEHPK3PXP",
                FactorSecretBinding::new(&scope, &FactorKind::Totp),
            )
            .unwrap();
        let opened = cipher
            .open(&sealed, FactorSecretBinding::new(&scope, &FactorKind::Totp))
            .unwrap();
        assert_eq!(&*opened.secret, "JBSWY3DPEHPK3PXP");
        assert!(!opened.rotated);
        assert!(!sealed.ciphertext.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn each_part_of_the_binding_is_authenticated() {
        let cipher = FactorSecretCipher::new(KEY);
        let sealed = cipher
            .seal(
                "JBSWY3DPEHPK3PXP",
                FactorSecretBinding::new(&scope("t1", "u1"), &FactorKind::Totp),
            )
            .unwrap();
        for (other, kind) in [
            (scope("t1", "u2"), FactorKind::Totp),
            (scope("t2", "u1"), FactorKind::Totp),
            (scope("t1", "u1"), FactorKind::Hotp),
            (AuthnScope::Tenant(tenant("t1")), FactorKind::Totp),
        ] {
            assert_eq!(
                cipher
                    .open(&sealed, FactorSecretBinding::new(&other, &kind))
                    .err(),
                Some(FactorSecretError::Open),
                "{other:?} {kind}"
            );
        }
    }

    #[test]
    fn a_damaged_blob_and_a_foreign_key_are_refused() {
        let cipher = FactorSecretCipher::new(KEY);
        let scope = scope("t1", "u1");
        let binding = FactorSecretBinding::new(&scope, &FactorKind::Totp);
        let mut sealed = cipher.seal("JBSWY3DPEHPK3PXP", binding).unwrap();
        let foreign = FactorSecretCipher::new(OTHER);
        assert_eq!(
            foreign.open(&sealed, binding).err(),
            Some(FactorSecretError::UnknownKey)
        );
        sealed.ciphertext.insert(0, 'A');
        assert_eq!(
            cipher.open(&sealed, binding).err(),
            Some(FactorSecretError::Open)
        );
    }

    #[test]
    fn the_previous_key_opens_and_reports_the_rotation() {
        let old = FactorSecretCipher::new(KEY);
        let scope = scope("t1", "u1");
        let binding = FactorSecretBinding::new(&scope, &FactorKind::Totp);
        let sealed = old.seal("JBSWY3DPEHPK3PXP", binding).unwrap();
        let rotated = FactorSecretCipher::new(OTHER).with_previous_key(KEY);
        let opened = rotated.open(&sealed, binding).unwrap();
        assert!(opened.rotated);
        assert!(!rotated.is_current(&sealed));
    }

    #[test]
    fn a_constant_key_is_refused_by_try_new() {
        assert!(FactorSecretCipher::try_new([0u8; 32]).is_err());
        assert!(FactorSecretCipher::try_new([7u8; 32]).is_err());
        assert!(FactorSecretCipher::try_new(KEY).is_ok());
    }

    #[test]
    fn seal_config_seals_otp_secrets_and_leaves_the_rest() {
        let cipher = FactorSecretCipher::new(KEY);
        let scope = scope("t1", "u1");
        let totp = FactorConfig::Totp(axess_factors::TotpConfig {
            secret: "JBSWY3DPEHPK3PXP".into(),
            ..Default::default()
        });
        let sealed = cipher.seal_config(totp, &scope).unwrap();
        let FactorConfig::Totp(cfg) = &sealed else {
            unreachable!()
        };
        assert!(cfg.secret.is_sealed());
        let again = cipher.seal_config(sealed.clone(), &scope).unwrap();
        assert_eq!(
            serde_json::to_value(&again).unwrap(),
            serde_json::to_value(&sealed).unwrap(),
            "an already sealed secret is left alone"
        );
    }

    #[test]
    fn the_plain_window_follows_the_policy_and_the_clock() {
        let clock = axess_clock::testing::MockClock::at(Utc::now());
        let until = clock.now() + chrono::Duration::hours(1);
        let cipher = FactorSecretCipher::new(KEY)
            .with_clock(Arc::new(clock.clone()))
            .with_plain_secrets(LegacyBlobs::AcceptUntil(until));
        assert!(cipher.plain_secrets_readable());
        clock.advance(chrono::Duration::hours(2));
        assert!(!cipher.plain_secrets_readable());
        assert!(!FactorSecretCipher::new(KEY).plain_secrets_readable());
        assert!(
            FactorSecretCipher::new(KEY)
                .with_plain_secrets(LegacyBlobs::Accept)
                .plain_secrets_readable()
        );
    }
}
