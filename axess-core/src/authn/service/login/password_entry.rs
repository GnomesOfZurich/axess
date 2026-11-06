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
    /// The audit row still records the lockout. `begin_login` conceals the
    /// lock the same way unless the service was built with
    /// [`with_lockout_revealed_on_begin`](crate::authn::AuthnServiceBuilder::with_lockout_revealed_on_begin);
    /// use it and `verify_factor` directly when the lock should be shown.
    /// A throttled guess (see [`LockoutPolicy::throttle`](crate::authn::types::LockoutPolicy::throttle))
    /// is answered `InvalidCredential` for the same reason, with the one
    /// dummy hash, since only an identifier that exists can be throttled;
    /// the audit row says `throttled`, and `verify_factor` answers
    /// [`Throttled`](FactorOutcome::Throttled) with the delay where the
    /// form may show it.
    ///
    /// Otherwise the result is that of `verify_factor` on the password:
    /// [`Authenticated`](FactorOutcome::Authenticated),
    /// [`FactorRequired`](FactorOutcome::FactorRequired) for the next step,
    /// or `InvalidCredential`, with the failure counter and audit row of any
    /// wrong password. The session is left `Authenticating` only while a
    /// further factor is required.
    ///
    /// What is equalised is the hash: the store round trips of the two
    /// paths differ. A known user's password check reads the factor,
    /// writes the failure counter and the audit row, where the paths above
    /// make `begin_login`'s calls alone; a dummy counter write and audit row
    /// for a user that does not exist would equalise them at the cost of
    /// rows in every deployment's stores, and the difference is a few
    /// store round trips beside an Argon2id run of tens of milliseconds.
    /// A deployment that must close it puts the same fixed delay on every
    /// answer in front of the route.
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
                match self.verify_factor(&credential, session).await? {
                    // Refused before any hash ran: spend the one hash every
                    // other path spends, and say what a wrong password says.
                    FactorOutcome::Throttled { .. } => {
                        self.burn_password_check(password).await?;
                        Ok(FactorOutcome::InvalidCredential)
                    }
                    outcome => Ok(outcome),
                }
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
