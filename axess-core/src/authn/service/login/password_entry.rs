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
    /// That holds for the guess that reaches the limit and for a request
    /// that races into a lock after `begin_login`, whichever way the
    /// lockout is reported (as an outcome or as an error).
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
    /// Every other answer that is not `Authenticated`, an error included,
    /// ends the login this call began: the session is cleared to a fresh
    /// guest and its id rotated ([`AuthSession::clear`]), for an identifier
    /// that exists and for one that does not. A wrong password for a real
    /// account would otherwise leave that account's login open in the
    /// session, under a rotated id, where an unknown identifier leaves the
    /// session untouched: the session's state, and the cookie the session
    /// layer sets for a changed session, would say which identifiers exist.
    /// It follows that a refused attempt on a session that was signed in
    /// signs it out, whoever the attempt named.
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
    #[tracing::instrument(
        skip(self, identifier, tenant_identifier, password, session),
        fields(tenant = %crate::authn::service::log_text::logged_request_text(tenant_identifier))
    )]
    pub async fn login_with_password(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        password: &str,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let outcome = self
            .verify_password_entry(identifier, tenant_identifier, password, session)
            .await;
        // The login this call began is this call's to end. Only an answer
        // that continues it keeps the session; every other one leaves the
        // same fresh guest, whichever path refused.
        let continues = matches!(
            outcome,
            Ok(FactorOutcome::Authenticated | FactorOutcome::FactorRequired(_))
        );
        if !continues {
            session.clear().await;
        }
        outcome
    }

    /// The body of [`login_with_password`](Self::login_with_password): begin
    /// the login and verify the password, spending one hash on every path.
    /// What it leaves in the session on a refusal is for the caller to end.
    async fn verify_password_entry(
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
                match self.verify_factor(&credential, session).await {
                    // Refused before any hash ran: spend the one hash every
                    // other path spends, and say what a wrong password says.
                    Ok(FactorOutcome::Throttled { .. }) | Err(AuthnError::Locked { .. }) => {
                        self.burn_password_check(password).await?;
                        Ok(FactorOutcome::InvalidCredential)
                    }
                    // `NotActive` comes from the check before the step,
                    // which leaves the flow in place and ran no hash, or
                    // from the status read after a right password
                    // registered the session, which cleared it: only the
                    // first spends the hash, so neither spends two.
                    Err(AuthnError::NotActive(_)) => {
                        if session.authenticating_state().await.is_some() {
                            self.burn_password_check(password).await?;
                        }
                        Ok(FactorOutcome::InvalidCredential)
                    }
                    // The attempt that crossed the limit, or one that raced
                    // past `begin_login` into a lock: only an account that
                    // exists can be locked, so it answers as a wrong
                    // password does. The audit row carries the lockout.
                    Ok(FactorOutcome::Locked { .. }) => Ok(FactorOutcome::InvalidCredential),
                    result => result,
                }
            }
            // An unknown identifier, a refused one, or a first factor other
            // than a password, which this entry point does not continue.
            LoginOutcome::FactorRequired(_)
            | LoginOutcome::Locked { .. }
            | LoginOutcome::InvalidCredentials
            | LoginOutcome::StepUpRequired { .. } => {
                self.burn_password_check(password).await?;
                Ok(FactorOutcome::InvalidCredential)
            }
        }
    }

    /// Spend the Argon2id work of a password refusal on `password`: one
    /// verification against a fixed dummy hash at the configured
    /// [`Argon2Cost`](axess_factors::Argon2Cost), and one at the previous
    /// cost when the service has one (see
    /// [`with_previous_argon2_cost`](crate::authn::AuthnServiceBuilder::with_previous_argon2_cost)),
    /// each its own job on the service's KDF executor; the results are
    /// discarded.
    ///
    /// What [`login_with_password`](Self::login_with_password) runs on the
    /// paths that have no stored hash to check, so their cost matches the
    /// path that has one. A password over
    /// [`MAX_PASSWORD_BYTES`](crate::validation::MAX_PASSWORD_BYTES) runs no
    /// Argon2 in its jobs, as the stored-hash path refuses it before Argon2
    /// runs. Each dummy hash is made once per service, inside
    /// the first job that needs it, which is therefore still one job.
    pub async fn burn_password_check(&self, password: &str) -> Result<(), AuthnError<I::Error>> {
        self.spend_dummy_check(password, false).await?;
        if self.inner.hardening.previous_argon2_cost().is_some() {
            self.spend_dummy_check(password, true).await?;
        }
        Ok(())
    }

    /// After a wrong password was checked against `verified_hash`, spend
    /// the rest of a refusal's work (see
    /// [`burn_password_check`](Self::burn_password_check)): a run at each of
    /// the current and the previous cost but the one the check itself ran
    /// at. A hash under neither cost spends both, and is reported once.
    pub(crate) async fn burn_password_work_after(
        &self,
        password: &str,
        verified_hash: &str,
    ) -> Result<(), AuthnError<I::Error>> {
        let hardening = &self.inner.hardening;
        let under = |cost| !axess_factors::password_needs_rehash_for(verified_hash, cost);
        let current = under(hardening.argon2_cost);
        let previous = hardening.previous_argon2_cost();
        let at_previous = previous.is_some_and(under);
        if !current
            && !at_previous
            && !hardening
                .unknown_cost_reported
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::warn!(
                "a wrong password was checked against a hash under an Argon2 cost that is \
                 neither the current nor the previous one, so that refusal costs more than \
                 the others; name the cost with AuthnServiceBuilder::with_previous_argon2_cost \
                 (reported once per service)"
            );
        }
        if !current {
            self.spend_dummy_check(password, false).await?;
        }
        if previous.is_some() && !at_previous {
            self.spend_dummy_check(password, true).await?;
        }
        Ok(())
    }

    /// One verification of `password` against the dummy hash at the current
    /// cost, or at the previous one, as one executor job.
    async fn spend_dummy_check(
        &self,
        password: &str,
        previous: bool,
    ) -> Result<(), AuthnError<I::Error>> {
        let hardening = &self.inner.hardening;
        let (dummy_hash, cost) = match (previous, hardening.previous_argon2_cost()) {
            (true, Some(cost)) => (
                std::sync::Arc::clone(&hardening.previous_dummy_password_hash),
                cost,
            ),
            _ => (
                std::sync::Arc::clone(&hardening.dummy_password_hash),
                hardening.argon2_cost,
            ),
        };
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let candidate = zeroize::Zeroizing::new(password.to_owned());
        self.inner
            .kdf
            .run(move || {
                let dummy = dummy_hash.get_or_init(|| {
                    axess_factors::hash_password_with_salt_and_cost(
                        "axess dummy password",
                        &salt,
                        cost,
                    )
                });
                // The stored-hash path refuses a password over
                // `MAX_PASSWORD_BYTES` before Argon2 runs, so the dummy
                // refuses it the same way, in the same job: an over-length
                // password costs a known user and an unknown one alike.
                if candidate.len() <= crate::validation::MAX_PASSWORD_BYTES {
                    let _ = axess_factors::verify_password(candidate.as_str(), dummy);
                }
            })
            .await?;
        Ok(())
    }
}
