//! Replacing a password hash made under outdated Argon2 parameters.
//!
//! The pinned parameter set only governs new hashes; a stored hash keeps
//! verifying under the parameters written into it. A successful password
//! check is the one moment the plaintext is in hand, so it is the moment to
//! hash it again under the current set.
//!
//! The new config carries the password's identity over (see
//! [`password_identity`]), so the credential epoch every half-finished login
//! of the user is stamped with does not move: the password did not change.

use super::super::RequestAuthnService;
use super::flow::password_identity;
use crate::authn::{
    factor::{FactorConfig, FactorCredential, ZeroizedString},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Hash the password that just verified again when its stored hash was
    /// made under parameters other than the current ones.
    ///
    /// `verified` is the config the password was checked against and
    /// `resolved_from` the scope it came from. Only a hash stored in the
    /// user's own scope is replaced (an inherited template is not the user's
    /// to rewrite). The write is a compare-and-swap against `verified`, so a
    /// password changed meanwhile is never overwritten with the old one.
    ///
    /// The new config keeps the password's identity, which is what the login
    /// flow's credential epoch covers, so this login and any other
    /// half-finished one of the user go on unchanged.
    ///
    /// Best effort: a failure to hash or to store is logged and the login
    /// goes on, since the old hash is still valid and the next login tries
    /// again.
    pub(super) async fn rehash_outdated_password(
        &self,
        credential: &FactorCredential,
        verified: &FactorConfig,
        resolved_from: &AuthnScope,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) {
        let (FactorCredential::Password(password), FactorConfig::Password(cfg)) =
            (credential, verified)
        else {
            return;
        };
        let user_scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        if resolved_from != &user_scope || !axess_factors::password_needs_rehash(cfg.hash.as_ref())
        {
            return;
        }
        // The salt is drawn here, in order, and only owned bytes move onto
        // the executor.
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let plaintext: &str = password.as_ref();
        let candidate = zeroize::Zeroizing::new(plaintext.to_owned());
        let hash = match self
            .inner
            .kdf
            .run(move || axess_factors::hash_password_with_salt(candidate.as_bytes(), &salt))
            .await
        {
            Ok(hash) => hash,
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "password rehash could not run");
                return;
            }
        };
        let mut next = cfg.clone();
        next.password_id = Some(password_identity(Some(cfg)));
        next.hash = ZeroizedString::new(hash);
        match self
            .inner
            .factors
            .compare_and_save_factor(&user_scope, verified, FactorConfig::Password(next))
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(user_id = %user_id, "password changed during the login; not rehashing");
            }
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "password rehash could not be stored");
            }
        }
    }
}
