//! Email one-time-code issuing for the `EmailOtp` login step.

use super::super::outcomes::PrepareOutcome;
use super::super::verification::generate_otp_code;
use crate::authn::{
    error::AuthnError,
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};

/// How long an unfinished claim holds the cooldown slot, in seconds.
const CLAIM_LEASE_SECS: i64 = 30;

/// Swaps attempted to store an issued code on its claimed row.
const STORE_ATTEMPTS: usize = 3;

impl<I, F> super::super::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Issue an email one-time code for the current `EmailOtp` step.
    ///
    /// Claims the cooldown slot first, with one compare-and-swap that
    /// records the new expiry and no hash yet. Only the request that wins the
    /// claim draws and hashes a code and has it delivered; every concurrent
    /// request sees a live slot and gets
    /// [`PrepareOutcome::AlreadySent`], however long the hashing takes. The
    /// hash is then stored with a second swap on the claimed row. A claim
    /// whose hashing or storing fails is released (best effort; an unreleased
    /// one lapses at its expiry) so a failure does not lock the user out of
    /// a code for a full TTL.
    pub(super) async fn prepare_email_otp(
        &self,
        tenant_id: &crate::authn::ids::TenantId,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        // Load the EmailOtp config to get the destination and parameters.
        let user_scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        let resolved = self
            .inner
            .factors
            .resolve_factor(&user_scope, FactorKind::EmailOtp)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        // Take ownership of the inner cfg up front so we don't
        // need a second destructure (which used to require an
        // unreachable arm for "config changed kind mid-function").
        let FactorConfig::EmailOtp(cfg) = &resolved.config else {
            return Err(AuthnError::NoFlow);
        };

        // Cooldown: reject if a pending code hasn't expired yet.
        // This prevents email bombing; the application can only trigger
        // one send per TTL window.
        let now = self.inner.clock.now();
        let already_sent = || PrepareOutcome::AlreadySent {
            destination: super::super::outcomes::mask_email(&cfg.email),
        };
        if cfg.pending_until.is_some_and(|until| now < until) {
            return Ok(already_sent());
        }

        let email = cfg.email.clone();
        let code_length = cfg.code_length as usize;

        // Reject unreasonable code lengths to prevent DoS via
        // misconfigured factor config.
        if !(4..=8).contains(&code_length) {
            tracing::error!(code_length, "email OTP code_length out of bounds (4–8)");
            return Err(AuthnError::NoFlow);
        }

        // `ttl_secs` is a `u32`, far inside the range `chrono::Duration`
        // and the timestamp type represent, so neither step can overflow.
        let expires = now + chrono::Duration::seconds(i64::from(cfg.ttl_secs));

        // Claim the slot with a SHORT lease, not the code's full expiry. The
        // claimed row carries no hash, so a code submitted before the hash
        // lands fails verification; and if this request is cancelled between
        // the claim and the store (a dropped connection, a timeout) the lease
        // lapses in seconds, where a claim for the full TTL blocked the user
        // from any code for up to that long. The stored code gets the full
        // expiry.
        let lease = chrono::Duration::seconds(i64::from(cfg.ttl_secs).min(CLAIM_LEASE_SECS));
        let mut claimed_cfg = cfg.clone();
        claimed_cfg.pending_hash = None;
        // A new code starts with a fresh allowance of guesses: the count the
        // previous code left behind must not burn this one on first use.
        claimed_cfg.attempt_count = 0;
        claimed_cfg.pending_until = Some(now + lease);
        let claimed = FactorConfig::EmailOtp(claimed_cfg.clone());
        let won = if resolved.resolved_from == user_scope {
            self.inner
                .factors
                .compare_and_save_factor(&user_scope, &resolved.config, claimed.clone())
                .await
        } else {
            // The config came from a broader scope: the user's own row does
            // not exist yet, and only one insert can create it.
            self.inner
                .factors
                .insert_factor_if_absent(&user_scope, claimed.clone())
                .await
        }
        .map_err(AuthnError::Store)?;
        if !won {
            return Ok(already_sent());
        }

        match self.issue_claimed_otp(claimed_cfg, code_length).await {
            Ok((code, mut final_cfg)) => {
                final_cfg.pending_until = Some(expires);
                let final_cfg = FactorConfig::EmailOtp(final_cfg);
                if self
                    .store_issued_otp(&user_scope, &claimed, &final_cfg)
                    .await?
                {
                    Ok(PrepareOutcome::SendOtp {
                        code,
                        destination: email,
                    })
                } else {
                    Err(AuthnError::ExternalService(
                        "email OTP claim was replaced before the code was stored; retry"
                            .to_string(),
                    ))
                }
            }
            Err(e) => {
                self.release_otp_claim(&user_scope, &claimed).await;
                Err(e)
            }
        }
    }

    /// Store the hashed code on the claimed row, tolerating a benign change
    /// to it.
    ///
    /// The swap compares the whole row, so any unrelated write to the claim
    /// (another request bumping `attempt_count`, say) loses it although the
    /// claim is still ours. A lost swap therefore reloads the row and, when
    /// it is still this request's claim (no hash, the lease's expiry), swaps
    /// again against what is there now, a few times. Only a row that is no
    /// longer this claim is a real loss. Returns `Ok(false)` for that, with
    /// nothing delivered; the claim is released first when it is still ours
    /// to release.
    async fn store_issued_otp(
        &self,
        user_scope: &AuthnScope,
        claimed: &FactorConfig,
        final_cfg: &FactorConfig,
    ) -> Result<bool, AuthnError<I::Error>> {
        let FactorConfig::EmailOtp(claimed_cfg) = claimed else {
            return Ok(false);
        };
        let mut expected = claimed.clone();
        for _ in 0..STORE_ATTEMPTS {
            match self
                .inner
                .factors
                .compare_and_save_factor(user_scope, &expected, final_cfg.clone())
                .await
            {
                Ok(true) => return Ok(true),
                Err(e) => {
                    self.release_otp_claim(user_scope, &expected).await;
                    return Err(AuthnError::Store(e));
                }
                Ok(false) => {}
            }
            let reloaded = self
                .inner
                .factors
                .load_factor(user_scope, FactorKind::EmailOtp)
                .await
                .map_err(AuthnError::Store)?;
            match reloaded {
                Some(FactorConfig::EmailOtp(now_cfg))
                    if now_cfg.pending_hash.is_none()
                        && now_cfg.pending_until == claimed_cfg.pending_until =>
                {
                    expected = FactorConfig::EmailOtp(now_cfg);
                }
                _ => return Ok(false),
            }
        }
        self.release_otp_claim(user_scope, &expected).await;
        Ok(false)
    }

    /// Draw a code and hash it, off the executor, for a claimed cooldown
    /// slot. The salt is drawn from the injected RNG, so a deterministic RNG
    /// pins the stored hash; only owned bytes move into the blocking task.
    /// The plaintext is wrapped so it is cleared from memory after use.
    async fn issue_claimed_otp(
        &self,
        mut cfg: crate::authn::factor::EmailOtpConfig,
        code_length: usize,
    ) -> Result<
        (
            crate::authn::factor::ZeroizedString,
            crate::authn::factor::EmailOtpConfig,
        ),
        AuthnError<I::Error>,
    > {
        let code = crate::authn::factor::ZeroizedString::new(generate_otp_code(
            &self.inner.rng,
            code_length,
        ));
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let to_hash = zeroize::Zeroizing::new(code.to_string());
        let hash = self
            .inner
            .kdf
            .run(move || axess_factors::hash_password_with_salt(to_hash.as_str(), &salt))
            .await?;
        cfg.pending_hash = Some(crate::authn::factor::ZeroizedString::new(hash));
        Ok((code, cfg))
    }

    /// Give back a claimed cooldown slot: the row is swapped to one with no
    /// pending code. A failure here is logged and left to the claim's
    /// expiry.
    async fn release_otp_claim(&self, user_scope: &AuthnScope, claimed: &FactorConfig) {
        let FactorConfig::EmailOtp(cfg) = claimed else {
            return;
        };
        let mut released = cfg.clone();
        released.pending_hash = None;
        released.pending_until = None;
        if let Err(e) = self
            .inner
            .factors
            .compare_and_save_factor(user_scope, claimed, FactorConfig::EmailOtp(released))
            .await
        {
            tracing::warn!(error = %e, "could not release an email OTP claim; it lapses at its expiry");
        }
    }
}
