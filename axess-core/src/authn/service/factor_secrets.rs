//! Opening an OTP secret for verification and sealing it again for the store.
//!
//! The verifiers work on plain text. This module sits between the store and
//! them: [`open`] turns a stored config into one a verifier can read, and
//! [`close`] turns the config a verification produced back into what the store
//! should hold, which is the stored secret untouched when nothing about its
//! sealing changed, and a fresh seal when it did.

use crate::authn::factor::{FactorConfig, FactorKind};
use crate::authn::factor_secret::{FactorSecretBinding, FactorSecretCipher, FactorSecretError};
use crate::authn::types::AuthnScope;
use axess_factors::FactorSecret;

/// A config ready to verify, and what is needed to store its successor.
pub(super) struct OpenedFactor {
    /// The config with its secret in plain text. For a factor with no OTP
    /// secret, and for a plain secret with no cipher configured, the stored
    /// config unchanged.
    pub verify: FactorConfig,
    /// The secret as it was stored, `None` when this factor has none or no
    /// cipher is configured (nothing to restore or seal).
    stored: Option<FactorSecret>,
    /// True when the stored secret is not at rest the way this user's row
    /// should hold it: plain, sealed under the previous key, or sealed for a
    /// broader scope than the user row that will be written.
    rebind: bool,
}

fn secret_of(config: &FactorConfig) -> Option<&FactorSecret> {
    match config {
        FactorConfig::Totp(cfg) => Some(&cfg.secret),
        FactorConfig::Hotp(cfg) => Some(&cfg.secret),
        _ => None,
    }
}

fn secret_of_mut(config: &mut FactorConfig) -> Option<&mut FactorSecret> {
    match config {
        FactorConfig::Totp(cfg) => Some(&mut cfg.secret),
        FactorConfig::Hotp(cfg) => Some(&mut cfg.secret),
        _ => None,
    }
}

/// Prepare `config`, read from `from`, for verification. Its successor will be
/// written at `user_scope`.
pub(super) fn open(
    cipher: Option<&FactorSecretCipher>,
    config: &FactorConfig,
    from: &AuthnScope,
    user_scope: &AuthnScope,
    kind: &FactorKind,
) -> Result<OpenedFactor, FactorSecretError> {
    let untouched = || OpenedFactor {
        verify: config.clone(),
        stored: None,
        rebind: false,
    };
    let Some(stored) = secret_of(config) else {
        return Ok(untouched());
    };
    match (stored, cipher) {
        (FactorSecret::Plain(_), None) => Ok(untouched()),
        (FactorSecret::Sealed(_), None) => Err(FactorSecretError::NoCipher),
        (FactorSecret::Plain(_), Some(cipher)) => {
            if !cipher.plain_secrets_readable() {
                return Err(FactorSecretError::PlainRefused);
            }
            Ok(OpenedFactor {
                verify: config.clone(),
                stored: Some(stored.clone()),
                rebind: true,
            })
        }
        (FactorSecret::Sealed(sealed), Some(cipher)) => {
            let opened = cipher.open(sealed, FactorSecretBinding::new(from, kind))?;
            let mut verify = config.clone();
            if let Some(slot) = secret_of_mut(&mut verify) {
                *slot = FactorSecret::Plain(opened.secret);
            }
            Ok(OpenedFactor {
                verify,
                stored: Some(stored.clone()),
                rebind: opened.rotated || from != user_scope,
            })
        }
    }
}

/// The config to store for `updated`, the successor of `opened`, at
/// `user_scope`.
pub(super) fn close(
    cipher: Option<&FactorSecretCipher>,
    opened: &OpenedFactor,
    mut updated: FactorConfig,
    user_scope: &AuthnScope,
    kind: &FactorKind,
) -> Result<FactorConfig, FactorSecretError> {
    let (Some(cipher), Some(stored)) = (cipher, &opened.stored) else {
        return Ok(updated);
    };
    let Some(slot) = secret_of_mut(&mut updated) else {
        return Ok(updated);
    };
    if opened.rebind {
        if let FactorSecret::Plain(text) = slot {
            let sealed = cipher.seal(text, FactorSecretBinding::new(user_scope, kind))?;
            *slot = FactorSecret::Sealed(sealed);
        }
    } else {
        *slot = stored.clone();
    }
    Ok(updated)
}
