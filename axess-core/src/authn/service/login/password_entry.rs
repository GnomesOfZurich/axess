//! The combined identifier-and-password entry point.

use super::super::outcomes::{FactorOutcome, LoginOutcome};
use crate::authn::{
    error::AuthnError,
    factor::{FactorCredential, FactorKind},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

impl<I, F> super::super::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Log in with an identifier and a password in one call.
    ///
    /// For a combined username-and-password form. [`begin_login`](Self::begin_login)
    /// alone equalises store queries but not the password hash: a known user
    /// goes on to a [`verify_factor`](Self::verify_factor) (an Argon2id run,
    /// tens of milliseconds) while an unknown identifier returns at once, so
    /// the body is identical and the latency separates the two. This method
    /// closes that: on every path that does not reach a password check (an
    /// unknown identifier or tenant, a locked or non-active account, a
    /// refused address, a method that does not begin with a password) it
    /// runs exactly one Argon2id verification against a fixed dummy hash, on
    /// the same executor, and answers [`FactorOutcome::InvalidCredential`].
    ///
    /// A locked account is answered `InvalidCredential` here, not `Locked`:
    /// telling a caller who has not yet proved anything that the account
    /// exists and is locked is the enumeration this method exists to avoid.
    /// The audit row still records the lockout. Use `begin_login` and
    /// `verify_factor` directly when the lock should be shown.
    ///
    /// Otherwise the result is that of `verify_factor` on the password:
    /// [`Authenticated`](FactorOutcome::Authenticated),
    /// [`FactorRequired`](FactorOutcome::FactorRequired) for the next step,
    /// or `InvalidCredential`, with the failure counter and audit row of any
    /// wrong password. The session is left `Authenticating` only while a
    /// further factor is required.
    #[tracing::instrument(skip(self, identifier, password, session), fields(tenant = %tenant_identifier))]
    pub async fn login_with_password(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        password: &str,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        match self
            .begin_login(identifier, tenant_identifier, session)
            .await?
        {
            LoginOutcome::FactorRequired(FactorKind::Password) => {
                let credential =
                    FactorCredential::Password(crate::authn::factor::ZeroizedString::new(password));
                self.verify_factor(&credential, session).await
            }
            other => {
                // A first factor other than a password leaves the session
                // `Authenticating`; this entry point does not continue it.
                if matches!(other, LoginOutcome::FactorRequired(_)) {
                    session.clear().await;
                }
                self.burn_password_check(password).await?;
                Ok(FactorOutcome::InvalidCredential)
            }
        }
    }

    /// Spend one Argon2id verification of `password` against a fixed dummy
    /// hash, on the service's KDF executor, and discard the result.
    ///
    /// What [`login_with_password`](Self::login_with_password) runs on the
    /// paths that have no stored hash to check, so their cost matches the
    /// path that has one. The dummy hash is made once with the library's
    /// default parameters, inside the first call, which is therefore still
    /// one executor job.
    pub async fn burn_password_check(&self, password: &str) -> Result<(), AuthnError<I::Error>> {
        static DUMMY_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let candidate = zeroize::Zeroizing::new(password.to_owned());
        self.inner
            .kdf
            .run(move || {
                let dummy = DUMMY_HASH.get_or_init(|| {
                    axess_factors::hash_password_with_salt("axess dummy password", &salt)
                });
                let _ = axess_factors::verify_password(candidate.as_str(), dummy);
            })
            .await?;
        Ok(())
    }
}
