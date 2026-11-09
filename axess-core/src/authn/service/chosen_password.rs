//! The service's admission of a password a person has just chosen: the
//! tenant's rules, then the breached-password check the service was built
//! with, under its policy for an outage.
//!
//! The password reset runs this; an application that sets a password itself
//! (signup, a change form, an enrolment) calls
//! [`AuthnService::check_chosen_password`] or
//! [`AuthnService::hash_chosen_password`] so the one configured check and
//! policy hold on every path, and the application carries no copy of either.

use super::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::blocking::KdfError;
use axess_factors::{MAX_PASSWORD_BYTES, NewPasswordError, PasswordRules};
use std::fmt;

/// Why [`AuthnService::hash_chosen_password`] produced no hash.
#[derive(Debug)]
pub enum ChosenPasswordError {
    /// The password was refused; the inner value says why, and its
    /// `Display` is the sentence to show the person.
    Refused(NewPasswordError),
    /// The password was admitted, and the executor that hashes passwords
    /// could not run the job.
    Executor(KdfError),
}

impl fmt::Display for ChosenPasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(reason) => reason.fmt(f),
            Self::Executor(error) => write!(f, "password hashing did not run: {error}"),
        }
    }
}

impl std::error::Error for ChosenPasswordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(reason) => Some(reason),
            Self::Executor(error) => Some(error),
        }
    }
}

impl From<NewPasswordError> for ChosenPasswordError {
    fn from(reason: NewPasswordError) -> Self {
        Self::Refused(reason)
    }
}

impl From<KdfError> for ChosenPasswordError {
    fn from(error: KdfError) -> Self {
        Self::Executor(error)
    }
}

/// The audit reason a password flow writes for a refused chosen password.
pub(crate) fn chosen_password_refusal_reason(refusal: NewPasswordError) -> &'static str {
    match refusal {
        NewPasswordError::TooLong | NewPasswordError::RulesNotMet => "password_rules",
        NewPasswordError::Breached => "password_breached",
        NewPasswordError::BreachCheckUnavailable => "breach_check_unavailable",
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    /// Whether a password a person has just chosen is admitted under
    /// `rules` and the service's breached-password check.
    ///
    /// Refuses a password over `MAX_PASSWORD_BYTES`
    /// ([`NewPasswordError::TooLong`]) or outside the rules
    /// ([`NewPasswordError::RulesNotMet`]) before anything leaves the host;
    /// then, when the service was built with
    /// [`with_breached_password_check`](super::AuthnServiceBuilder::with_breached_password_check)
    /// and `rules.breached_check` holds, asks the check and refuses a
    /// password it knows ([`NewPasswordError::Breached`]) or, under the
    /// default policy, one it could not screen
    /// ([`NewPasswordError::BreachCheckUnavailable`]). History reuse needs
    /// the stored hashes and is the reset's own concern. Each refusal's
    /// `Display` is a sentence fit to show the person; nothing in it says
    /// what the check saw. Call it from a signup or change form before the
    /// account is touched, so a refused password creates nothing.
    pub async fn check_chosen_password(
        &self,
        password: &str,
        rules: &PasswordRules,
    ) -> Result<(), NewPasswordError> {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(NewPasswordError::TooLong);
        }
        if !crate::validation::meets_password_rules(password, rules) {
            return Err(NewPasswordError::RulesNotMet);
        }
        self.screen_chosen_password_breached(password, rules).await
    }

    /// The breach half of [`check_chosen_password`](Self::check_chosen_password)
    /// alone, for a flow that has already applied the rules and wants the
    /// remote question asked at its own moment (the reset asks it after the
    /// token has been checked, so an unauthenticated caller cannot make the
    /// server call the check).
    pub(crate) async fn screen_chosen_password_breached(
        &self,
        password: &str,
        rules: &PasswordRules,
    ) -> Result<(), NewPasswordError> {
        axess_factors::check_password_breached(
            password,
            rules,
            self.inner.breached_password_check.as_deref(),
            self.inner.on_breach_check_unavailable,
        )
        .await
    }

    /// Admit a password a person has just chosen, as
    /// [`check_chosen_password`](Self::check_chosen_password) does, and hash
    /// it with Argon2id on the service's KDF executor with a salt from the
    /// service's RNG.
    ///
    /// The hash is what a `PasswordConfig` stores. Refuses with
    /// [`ChosenPasswordError::Refused`] for every reason the check refuses,
    /// and with [`ChosenPasswordError::Executor`] when the executor is busy
    /// or gone; nothing is hashed for a refused password. History reuse is
    /// not checked: the reset does that against the stored hashes.
    pub async fn hash_chosen_password(
        &self,
        password: &str,
        rules: &PasswordRules,
    ) -> Result<String, ChosenPasswordError> {
        self.check_chosen_password(password, rules).await?;
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let candidate = zeroize::Zeroizing::new(password.to_owned());
        let cost = self.inner.hardening.argon2_cost;
        let hash = self
            .inner
            .kdf
            .run(move || {
                axess_factors::hash_password_with_salt_and_cost(candidate.as_str(), &salt, cost)
            })
            .await?;
        Ok(hash)
    }
}
