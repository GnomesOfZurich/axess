//! The new password of a reset: its check against the history (and its
//! hash), and the writes that install it.

use crate::authn::service::AuthnService;
use crate::authn::{
    error::AuthnError,
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, IdentityPasswordHistory, IdentityPasswordReset, IdentityStore},
    types::AuthnScope,
};

impl<I, F> AuthnService<I, F>
where
    // Same bounds as the request-scoped block of the parent module, for the
    // same reason: these are its helpers, and a store that cannot persist a
    // reset token has no business reaching them.
    I: IdentityStore + IdentityPasswordReset + IdentityPasswordHistory,
    F: FactorStore<Error = I::Error>,
{
    /// The password hash a reset is about to replace, when the history does
    /// not hold it yet and installing the new password must record it.
    ///
    /// Every change records the hash it installs, so the replaced hash is
    /// normally already the newest entry, and this is `None`. It is `Some`
    /// for the first change of an account that had no history; recording
    /// it then, and only then, keeps each hash in the history once, so a
    /// check over the last N passwords covers N. `None` too when the
    /// account has no password factor.
    pub(super) async fn replaced_hash_to_record(
        &self,
        user_id: &crate::authn::ids::UserId,
        user_scope: &AuthnScope,
    ) -> Result<Option<String>, AuthnError<I::Error>> {
        let Some(FactorConfig::Password(old_config)) = self
            .inner
            .factors
            .load_factor(user_scope, FactorKind::Password)
            .await
            .map_err(AuthnError::Store)?
        else {
            return Ok(None);
        };
        let old_hash: &str = &old_config.hash;
        let latest = self
            .inner
            .identity
            .password_history(user_id, 1)
            .await
            .map_err(AuthnError::Store)?;
        Ok((latest.first().map(String::as_str) != Some(old_hash)).then(|| old_hash.to_owned()))
    }

    /// Record the replaced hash (`replaced`, see
    /// [`replaced_hash_to_record`](Self::replaced_hash_to_record)) and the
    /// new one in history, then make the new one the live password.
    ///
    /// Called only once the reset is admitted and its token spent, so a
    /// refused reset writes nothing. The order is the guarantee: see the
    /// comment on the writes.
    pub(super) async fn install_new_password(
        &self,
        user_id: &crate::authn::ids::UserId,
        user_scope: &AuthnScope,
        replaced: Option<String>,
        new_password_hash: String,
        rules: crate::authn::factor::PasswordRules,
    ) -> Result<(), AuthnError<I::Error>> {
        // Order the writes so that the worst partial failure is benign.
        //
        //   * Record the new hash in history before activating it via
        //     `save_factor`. If the history write fails, the reset stops
        //     with the old password still live; no policy bypass.
        //   * If the history write succeeds and `save_factor` fails, the
        //     new hash is in history but not active. The user retries with
        //     a different password (the same one fails the history check).
        //     The other order could leave a live new password missing from
        //     history, so the next reset could reuse it.
        //
        // The history and the factor live in two traits, possibly two
        // stores, so no transaction spans them; the order is the bound.
        if let Some(replaced) = replaced {
            self.inner
                .identity
                .record_password_hash(user_id, &replaced)
                .await
                .map_err(AuthnError::Store)?;
        }
        self.inner
            .identity
            .record_password_hash(user_id, &new_password_hash)
            .await
            .map_err(AuthnError::Store)?;

        let new_config = FactorConfig::Password(crate::authn::factor::PasswordConfig {
            hash: crate::authn::factor::ZeroizedString::new(new_password_hash),
            rules,
            password_id: None,
        });
        self.inner
            .factors
            .save_factor(user_scope, new_config)
            .await
            .map_err(AuthnError::Store)?;
        Ok(())
    }

    /// Check `new_password` (plaintext) against the user's last
    /// `rules.history_count` passwords and, when it is not among them,
    /// return its Argon2id hash. The last passwords are `replaced` (the
    /// current hash, when the history does not hold it yet) and the stored
    /// history after it, so the current password always counts.
    ///
    /// Returns `Ok(None)` if the password was previously used (caller rejects
    /// the reset) and `Ok(Some(hash))` if it is safe to use. With
    /// `rules.history_count == 0` the history check is disabled and the hash
    /// is returned directly.
    ///
    /// The whole job (up to `history_count` verifications and one hash) is
    /// one task on the service's [`KdfExecutor`](crate::blocking::KdfExecutor),
    /// so a reset holds neither a runtime worker nor more than one blocking
    /// slot. The salt is drawn from the service's RNG before the task starts.
    ///
    /// **Security invariant, preserve on every refactor:** the loop
    /// iterates ALL history entries to constant time, even after a match
    /// is found. The naïve `if reused { break; }` would leak the position
    /// of the matched hash via response time: a 5-deep history with the
    /// recent password reused returns measurably faster than a 5-deep
    /// history with the oldest reused, telling an attacker who's
    /// iterating candidate passwords roughly *which* historical password
    /// they hit. The `let mut reused = false;` accumulator + full scan +
    /// post-loop check is load-bearing for that timing equalisation. Do
    /// NOT "optimise" by short-circuiting the loop.
    ///
    /// `axess_factors::verify_password` itself uses constant-time Argon2
    /// verification per hash, so the per-iteration cost is constant
    /// regardless of whether that single iteration matches.
    ///
    /// **Plaintext-not-hash invariant:** `new_password` MUST be the
    /// plaintext candidate. Argon2's verify routine recomputes the hash
    /// of `new_password` against each old hash's embedded salt and
    /// parameters; feeding an already-hashed PHC string here means
    /// Argon2 hashes the PHC string itself, which never matches anything
    /// real and silently disables the entire history-reuse check.
    pub(super) async fn check_history_and_hash(
        &self,
        user_id: &crate::authn::ids::UserId,
        new_password: &str,
        replaced: Option<&str>,
        rules: &crate::authn::factor::PasswordRules,
    ) -> Result<Option<String>, AuthnError<I::Error>> {
        let history = match (rules.history_count, replaced) {
            (0, _) => Vec::new(),
            (n, replaced) => {
                let stored = n - usize::from(replaced.is_some());
                let mut history: Vec<String> = replaced.map(str::to_owned).into_iter().collect();
                if stored > 0 {
                    history.extend(
                        self.inner
                            .identity
                            .password_history(user_id, stored)
                            .await
                            .map_err(AuthnError::Store)?,
                    );
                }
                history
            }
        };
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let candidate = zeroize::Zeroizing::new(new_password.to_owned());
        let outcome = self
            .inner
            .kdf
            .run(move || {
                let mut reused = false;
                for old_hash in &history {
                    if axess_factors::verify_password(candidate.as_str(), old_hash).is_ok() {
                        reused = true;
                    }
                }
                (!reused).then(|| axess_factors::hash_password_with_salt(candidate.as_str(), &salt))
            })
            .await?;
        Ok(outcome)
    }
}
