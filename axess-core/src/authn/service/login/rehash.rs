//! Replacing a password hash made under outdated Argon2 parameters.
//!
//! The pinned parameter set only governs new hashes; a stored hash keeps
//! verifying under the parameters written into it. A successful password
//! check is the one moment the plaintext is in hand, so it is the moment to
//! hash it again under the current set.

use super::super::RequestAuthnService;
use crate::authn::{
    factor::{FactorConfig, FactorCredential, ZeroizedString},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

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
    /// The password hash feeds the login flow's credential epoch, so after a
    /// successful swap the flow in `session` is re-stamped; otherwise the
    /// very login that caused the rehash would be dropped at its next step.
    ///
    /// Best effort: a failure to hash or to store is logged and the login
    /// goes on, since the old hash is still valid and the next login tries
    /// again.
    pub(super) async fn rehash_outdated_password(
        &self,
        session: &AuthSession,
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
        next.hash = ZeroizedString::new(hash);
        match self
            .inner
            .factors
            .compare_and_save_factor(&user_scope, verified, FactorConfig::Password(next))
            .await
        {
            Ok(true) => {
                self.restamp_flow_epoch(session, user_id, tenant_id).await;
            }
            Ok(false) => {
                tracing::debug!(user_id = %user_id, "password changed during the login; not rehashing");
            }
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "password rehash could not be stored");
            }
        }
    }
}
