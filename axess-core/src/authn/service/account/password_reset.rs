//! Password reset flow: `begin_password_reset` + `complete_password_reset`
//! plus the tenant-scoped `complete_password_reset_in_tenant` rail.
//!
//! Two-step ceremony with single-use, hashed-on-disk token:
//!
//! - [`RequestAuthnService::begin_password_reset`] generates a 32-byte URL-safe
//!   token, stores `SHA-256(token)`, returns the plaintext for the
//!   application to deliver out-of-band (email link, SMS, etc.).
//! - [`RequestAuthnService::complete_password_reset`] verifies the token,
//!   enforces the tenant's history-reuse rule against the new plaintext,
//!   Argon2id-hashes it, updates the password factor, records audit
//!   events, and invalidates other live sessions for the user.
//! - [`RequestAuthnService::complete_password_reset_in_tenant`] adds a
//!   cross-tenant rail before `complete_password_reset` does the
//!   expensive Argon2id-flavoured rest of the flow.

use crate::authn::service::{AuthnService, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, IdentityPasswordHistory, IdentityPasswordReset, IdentityStore},
    types::AuthnScope,
};

impl<I, F> RequestAuthnService<I, F>
where
    // `IdentityPasswordReset` is required here and nowhere else: a store
    // that cannot persist a reset token cannot reach this flow, so the
    // omission is a compile error rather than a panic on an
    // unauthenticated route. See the trait for why it has no defaults.
    I: IdentityStore + IdentityPasswordReset + IdentityPasswordHistory,
    F: FactorStore<Error = I::Error>,
{
    /// Begin a password-reset flow for a user.
    ///
    /// Generates a single-use reset token (SHA-256 hash stored, plaintext
    /// returned exactly once). The application is responsible for delivering
    /// the token to the user (email link, SMS, etc.).
    ///
    /// The token expires after `ttl`. Returns the plaintext token that the
    /// application should embed in a reset link.
    ///
    /// A `ttl` of zero, or one longer than seven days, is refused with
    /// [`AuthnError::Internal`] before anything is looked up, so a bad value
    /// fails the same way for a registered and an unregistered identifier.
    ///
    /// An identifier that does not resolve (unknown tenant, inactive tenant
    /// or unknown user) makes the same store round trips as one that does:
    /// one tenant lookup, one user lookup, one token write and one audit
    /// write. The write goes to a reserved user id and carries an already
    /// expired token whose plaintext is discarded, so it can never be
    /// redeemed; the audit row is a failure with no user attributed.
    ///
    /// # Arguments
    ///
    /// * `identifier`: the user's login identifier (email, username).
    /// * `tenant_identifier`: the tenant slug/domain.
    /// * `ttl`: how long the token is valid.
    #[tracing::instrument(skip(self, identifier, ttl), fields(tenant = %tenant_identifier))]
    pub async fn begin_password_reset(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<String>, AuthnError<I::Error>> {
        let now = self.inner.clock.now();
        let expires_at = chrono::Duration::from_std(ttl)
            .ok()
            .filter(|d| *d > chrono::Duration::zero() && *d <= chrono::Duration::days(7))
            .and_then(|d| now.checked_add_signed(d))
            .ok_or_else(|| {
                AuthnError::Internal(
                    "password reset ttl must be positive and at most seven days".to_string(),
                )
            })?;

        // The same input limits `begin_login` applies. An identifier or
        // tenant outside them is looked up as the empty string, which no
        // store matches, so the call makes the same round trips as any
        // unknown identifier and answers the same way.
        use crate::validation::MAX_IDENTIFIER_BYTES;
        let in_limits = !identifier.is_empty()
            && identifier.len() <= MAX_IDENTIFIER_BYTES
            && !tenant_identifier.is_empty()
            && tenant_identifier.len() <= MAX_IDENTIFIER_BYTES;
        let (identifier, tenant_identifier) = if in_limits {
            (identifier, tenant_identifier)
        } else {
            ("", "")
        };

        // The cooldown is keyed on the identifier as typed, for a registered
        // one and an unregistered one alike, so being inside it says nothing
        // about whether an account exists. It runs after the input limits,
        // which map an over-long identifier to the empty string.
        if self
            .inner
            .reset_requests
            .as_ref()
            .is_some_and(|r| r.already_asked(tenant_identifier, identifier))
        {
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::PasswordResetRequested)
                    .with_error(AuthFailureReason::Other("cooldown".into())),
            )
            .await?;
            return Ok(None);
        }

        // Look up the user. If not found, return Ok(None) to avoid
        // leaking whether the identifier exists.
        let tenant = self
            .inner
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?;
        let tenant_active = tenant.as_ref().is_some_and(|t| t.status.is_active());
        let tenant_id = tenant.map_or(crate::authn::ids::TenantId::SYSTEM, |t| t.id);

        // The user lookup runs for every tenant outcome so the number of
        // round trips does not depend on it.
        let user = self
            .inner
            .identity
            .find_user(identifier, &tenant_id)
            .await
            .map_err(AuthnError::Store)?
            .filter(|u| tenant_active && u.validate().is_ok());

        // Generate token: 32 random bytes → URL-safe base64. Done
        // unconditionally so the not-found path performs the same RNG +
        // SHA-256 work as the found path.
        let mut token_bytes = [0u8; 32];
        self.inner.rng.fill_bytes(&mut token_bytes);
        use base64::Engine as _;
        let plaintext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let hash = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(plaintext.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };

        let Some(user) = user else {
            // The same two writes the found path makes. The token is
            // already expired and its plaintext is dropped, so nothing
            // can redeem it; its store error is ignored, since a store
            // may reject a row for a user that does not exist.
            let _ = self
                .inner
                .identity
                .store_reset_token(&crate::authn::ids::UserId::SYSTEM, &hash, now)
                .await;
            self.emit_audit(AuthEventBuilder::failure(
                AuthEventType::PasswordResetRequested,
            ))
            .await?;
            return Ok(None);
        };

        // A store that cannot write the token answers like an unknown
        // identifier: the caller gets `None`, as the unknown path does when
        // its write fails, so a store fault is not a way to tell a
        // registered identifier from an unregistered one. The fault is
        // logged for the operator, and the audit row records the failure.
        if let Err(e) = self
            .inner
            .identity
            .store_reset_token(&user.id, &hash, expires_at)
            .await
        {
            tracing::error!(
                user_id = %user.id,
                error = %e,
                "could not store a password reset token; answering as for an unknown identifier"
            );
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::PasswordResetRequested)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_error(AuthFailureReason::Other("token_store_error".into())),
            )
            .await?;
            return Ok(None);
        }

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::PasswordResetRequested)
                .attributed_to(&user.id, &user.tenant_id),
        )
        .await?;

        Ok(Some(plaintext))
    }

    /// Tenant-scoped password-reset variant.
    ///
    /// Same as [`complete_password_reset`](Self::complete_password_reset) but
    /// the user is resolved within `expected_tenant` only. A user id that
    /// belongs to another tenant answers exactly as an unknown id does,
    /// `Ok(false)`: refusing it with a distinct error told a caller holding a
    /// reset link which user ids exist in other tenants. The attempt is
    /// logged at warn level and audited as a failure. Use this from any
    /// password-reset handler whose authorisation scope is a single tenant.
    pub async fn complete_password_reset_in_tenant(
        &self,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
        token: &str,
        new_password: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        self.complete_password_reset_inner(user_id, Some(expected_tenant), token, new_password)
            .await
    }

    /// Complete a password-reset flow by verifying the token and setting a new password.
    ///
    /// The token is single-use, consumed on verification. Returns `Ok(true)`
    /// if the reset succeeded, `Ok(false)` if the token was invalid, expired,
    /// the new password does not meet the tenant's
    /// [`PasswordRules`](crate::authn::factor::PasswordRules) (minimum length
    /// and complexity), or it violates the tenant's history-reuse rule. A
    /// password refused for either reason leaves the token unspent, so the
    /// person can pick another with the same link. A tenant that is missing
    /// or not active refuses the reset the same way. An unknown `user_id`
    /// answers `Ok(false)` as a bad token does. Every refusal writes a
    /// failed `PasswordReset` audit row naming the reason.
    ///
    /// A lockout the failure counter imposes does not block a reset (the
    /// account is still active and the reset is how its owner recovers);
    /// the counter is cleared when the reset succeeds.
    ///
    /// On success the password is replaced, every registered session of the
    /// user is invalidated and, when the service was given a refresh token
    /// store with
    /// [`with_refresh_store`](crate::authn::service::AuthnServiceBuilder::with_refresh_store),
    /// every refresh token of the user is revoked, so a stolen refresh token
    /// does not outlive the reset.
    ///
    /// # Arguments
    ///
    /// * `user_id`: the user's opaque ID (from the reset link context).
    /// * `token`: the plaintext reset token.
    /// * `new_password`: the plaintext new password. Hashed internally with
    ///   Argon2id (salt from the service's RNG, on the service's KDF
    ///   executor) *after* the history-reuse check passes, so passing the
    ///   hash here would defeat the check.
    #[tracing::instrument(skip(self, token, new_password))]
    pub async fn complete_password_reset(
        &self,
        user_id: &crate::authn::ids::UserId,
        token: &str,
        new_password: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        self.complete_password_reset_inner(user_id, None, token, new_password)
            .await
    }

    /// Audit a refused reset and answer `Ok(false)`.
    ///
    /// The row is attributed to the user and the tenant the user resolved
    /// to when there is one, and carries `reason`. A caller cannot tell the
    /// reasons apart: they all return the same value.
    async fn refuse_password_reset(
        &self,
        user: Option<&crate::authn::types::User>,
        reason: &'static str,
    ) -> Result<bool, AuthnError<I::Error>> {
        let builder = AuthEventBuilder::failure(AuthEventType::PasswordReset)
            .maybe_attributed_to(user.map(|u| &u.id), user.map(|u| &u.tenant_id))
            .with_error(AuthFailureReason::Other(reason.into()));
        self.emit_audit(builder).await?;
        Ok(false)
    }

    /// Why a reset for this user must be refused before the token is read,
    /// if it must: the account is not active, or the tenant is missing or
    /// not active (a token issued before a suspension must not outlive it).
    /// Refused before the token is read, so the token is not spent and works
    /// once the account is active again.
    async fn reset_refusal_reason(
        &self,
        user: &crate::authn::types::User,
    ) -> Result<Option<&'static str>, AuthnError<I::Error>> {
        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            tracing::warn!(user_id = %user.id, status = ?status, "password reset refused: account is not active");
            return Ok(Some("not_active"));
        }
        let tenant_active = self
            .inner
            .identity
            .get_tenant(&user.tenant_id)
            .await
            .map_err(AuthnError::Store)?
            .is_some_and(|t| t.status.is_active());
        if !tenant_active {
            tracing::warn!(user_id = %user.id, tenant = %user.tenant_id, "password reset refused: tenant is missing or not active");
            return Ok(Some("tenant_not_active"));
        }
        Ok(None)
    }

    async fn complete_password_reset_inner(
        &self,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: Option<&crate::authn::ids::TenantId>,
        token: &str,
        new_password: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        // Resolve the user FIRST. A backend whose `account_status` errors
        // for an unknown user would otherwise turn an unknown id into an
        // error, where the contract is `Ok(false)` like a bad token. With a
        // tenant named, the lookup is scoped to it, so another tenant's user
        // is indistinguishable from none.
        let user = match expected_tenant {
            Some(tenant) => {
                self.inner
                    .identity
                    .get_user_in_tenant(user_id, tenant)
                    .await
            }
            None => self.inner.identity.get_user(user_id).await,
        }
        .map_err(AuthnError::Store)?;
        let Some(user) = user else {
            if let Some(tenant) = expected_tenant {
                tracing::warn!(
                    user_id = %user_id,
                    expected_tenant = %tenant,
                    "password reset refused: no such user in the expected tenant"
                );
            }
            return self.refuse_password_reset(None, "unknown_user").await;
        };

        // A stored row that fails validation cannot log in
        // (`begin_login` answers it as unknown), and `begin_password_reset`
        // refuses it, so a token issued earlier cannot finish the reset.
        if user.validate().is_err() {
            tracing::error!(user_id = %user_id, "password reset refused: stored user failed validation");
            return self
                .refuse_password_reset(Some(&user), "invalid_user")
                .await;
        }

        if let Some(reason) = self.reset_refusal_reason(&user).await? {
            return self.refuse_password_reset(Some(&user), reason).await;
        }
        let rules = self
            .inner
            .identity
            .password_rules_for_tenant(&user.tenant_id)
            .await
            .map_err(AuthnError::Store)?;

        // The new password must satisfy the tenant's rules, the same ones
        // the factor is stored with. Checked before the token is read so a
        // refused password does not spend the single-use token: the person
        // can pick another and use the same link.
        if !crate::validation::meets_password_rules(new_password, &rules) {
            tracing::warn!(
                user_id = %user_id,
                "password reset refused: new password does not meet the tenant's password rules"
            );
            return self
                .refuse_password_reset(Some(&user), "password_rules")
                .await;
        }

        // Look at the token without spending it: a token that does not
        // match stops the flow before any costly work, and one that does is
        // spent only after the new password has passed the history check, so
        // a refused password leaves the link usable.
        if !self.reset_token_matches(user_id, token, false).await? {
            return self
                .refuse_password_reset(Some(&user), "token_mismatch")
                .await;
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };

        self.record_replaced_hash(user_id, &user_scope).await?;

        // One blocking task checks the new password against every stored
        // hash and, when it is not a reuse, hashes it. The check verifies the
        // new plaintext against each old Argon2 hash, so it MUST receive
        // plaintext; hashing earlier would feed a PHC string into Argon2's
        // plaintext slot and the check would never match.
        let Some(new_password_hash) = self
            .check_history_and_hash(user_id, new_password, &rules)
            .await?
        else {
            // Password was used before; the token is kept.
            return self
                .refuse_password_reset(Some(&user), "password_reused")
                .await;
        };

        // The hashing above took tens of milliseconds, and the status was
        // read before it. Read it again at the commit, before the token is
        // spent and the password installed, so a suspension that landed in
        // between is honoured and the unspent token works once the account
        // is active again.
        let status = self.current_account_status(user_id).await?;
        if !status.allows_login() {
            tracing::warn!(
                user_id = %user_id,
                status = ?status,
                "password reset refused at commit: account is no longer active"
            );
            return self.refuse_password_reset(Some(&user), "not_active").await;
        }

        // Spend the token. Of two requests that both got this far, exactly
        // one wins; the other changes nothing.
        if !self.reset_token_matches(user_id, token, true).await? {
            return self
                .refuse_password_reset(Some(&user), "token_mismatch")
                .await;
        }

        self.install_new_password(user_id, &user_scope, new_password_hash, rules)
            .await?;

        self.finish_password_reset(&user).await
    }

    /// Everything after the new password is installed: sessions,
    /// counter, refresh tokens, audit.
    async fn finish_password_reset(
        &self,
        user: &crate::authn::types::User,
    ) -> Result<bool, AuthnError<I::Error>> {
        let user_id = &user.id;
        // Everything below runs because the password is already replaced:
        // each step is attempted, in order of how much a skipped one costs.
        //
        // Invalidate all live sessions for this user FIRST. A stolen session
        // cookie must not survive a password change, and the longer the
        // window between the install and this call (a failing store write
        // below, a cancelled request) the longer it does.
        // A registry that fails is returned after the audit row below, like
        // a refresh-token revocation that fails.
        let sessions_ended = self.end_user_sessions(user_id).await;
        if sessions_ended.is_ok() && self.inner.registry.is_some() {
            tracing::info!(
                user_id = %user_id,
                "password reset: invalidated all sessions for user"
            );
        }

        // The reset succeeded, so the failure counter (and any lockout
        // derived from it) is cleared. A counter store that is down must not
        // fail a reset that has already happened: log and carry on.
        if let Err(e) = self.inner.identity.reset_failed_attempts(user_id).await {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "password reset: could not clear the failed-attempt counter; \
                 it clears on the next successful login"
            );
        }

        // Revoke refresh tokens: they are not sessions, and `invalidate_user`
        // does not reach them. A failure is returned to the caller, but only
        // after the audit row is written.
        let revoked = self.revoke_refresh_tokens(user_id).await;

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::PasswordReset)
                .attributed_to(&user.id, &user.tenant_id),
        )
        .await?;

        sessions_ended?;
        revoked?;
        Ok(true)
    }
}

impl<I, F> AuthnService<I, F>
where
    // Same bounds as the request-scoped block above, for the same reason:
    // these are its helpers, and a store that cannot persist a reset token
    // has no business reaching them.
    I: IdentityStore + IdentityPasswordReset + IdentityPasswordHistory,
    F: FactorStore<Error = I::Error>,
{
    /// Hash the supplied plaintext token via SHA-256 and compare it with the
    /// store's per-user reset-token record, spending the record when `spend`
    /// is set.
    ///
    /// Returns `Ok(true)` when the token matches the current outstanding
    /// reset token for `user_id`. Returns `Ok(false)` when it doesn't
    /// (consumed, expired, never issued, or simply wrong): caller maps to
    /// "reset failed." Errors only on store outage.
    ///
    /// SHA-256 (rather than HMAC or Argon2) matches the begin-side
    /// `record_reset_token` storage shape: the token is high-entropy
    /// (32 random bytes from `SecureRng`, base64-encoded) and
    /// single-use, so a fast hash is appropriate. If begin-side
    /// hashing changes, this must change in lockstep.
    async fn reset_token_matches(
        &self,
        user_id: &crate::authn::ids::UserId,
        token: &str,
        spend: bool,
    ) -> Result<bool, AuthnError<I::Error>> {
        use base64::Engine as _;
        let hash = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(token.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };
        let now = self.inner.clock.now();
        if spend {
            self.inner
                .identity
                .verify_reset_token(user_id, &hash, now)
                .await
        } else {
            self.inner
                .identity
                .check_reset_token(user_id, &hash, now)
                .await
        }
        .map_err(AuthnError::Store)
    }

    /// Record the hash about to be replaced in the password history.
    ///
    /// Nothing is recorded when the account has no password factor, or when
    /// the replaced hash is already the newest history entry.
    async fn record_replaced_hash(
        &self,
        user_id: &crate::authn::ids::UserId,
        user_scope: &AuthnScope,
    ) -> Result<(), AuthnError<I::Error>> {
        // Record the old hash in password history.
        //
        // Unconditional, and the guard below is about whether an *old
        // password exists*, not about whether the backend keeps history.
        // That distinction used to matter a great deal: the method carried
        // a default body that panicked, so a backend which had not
        // overridden it unwound here on the first password change any user
        // made. It now lives on `IdentityPasswordHistory`, which has no
        // defaults, and this flow is bounded on that trait, so a store
        // without history cannot reach this line at all.
        if let Some(FactorConfig::Password(ref old_config)) = self
            .inner
            .factors
            .load_factor(user_scope, FactorKind::Password)
            .await
            .map_err(AuthnError::Store)?
        {
            // Every change records the hash it installs, so the replaced
            // hash is normally already the newest entry. Record it only
            // when it is not (the first change of an account that had no
            // history), or each hash would count twice and a check over the
            // last N passwords would cover about N/2.
            let old_hash: &str = &old_config.hash;
            let latest = self
                .inner
                .identity
                .password_history(user_id, 1)
                .await
                .map_err(AuthnError::Store)?;
            if latest.first().map(String::as_str) != Some(old_hash) {
                self.inner
                    .identity
                    .record_password_hash(user_id, old_hash)
                    .await
                    .map_err(AuthnError::Store)?;
            }
        }
        Ok(())
    }

    /// Record the new hash in history, then make it the live password.
    ///
    /// The order is the guarantee: see the comment on the writes.
    async fn install_new_password(
        &self,
        user_id: &crate::authn::ids::UserId,
        user_scope: &AuthnScope,
        new_password_hash: String,
        rules: crate::authn::factor::PasswordRules,
    ) -> Result<(), AuthnError<I::Error>> {
        // Order the writes so that the *worst* possible partial
        // failure is benign.
        //
        //   * Record the NEW hash in history BEFORE activating it via
        //     `save_factor`. If the history write fails, we abort with
        //     the old password still live; no policy bypass.
        //   * If the history write succeeds and `save_factor` fails, the
        //     new hash is in history but not active. The user retries
        //     with a different password (or the same password; which
        //     will fail the history check, prompting them to pick a new
        //     one). This is strictly better than the prior order, which
        //     could leave a *live new password* missing from history,
        //     letting the user re-use it on the next reset and silently
        //     violate the password-rotation policy.
        //
        // Production backends should override `record_password_hash` and
        // `save_factor` to share a single SQL transaction; until then,
        // this ordering minimises blast radius.
        self.inner
            .identity
            .record_password_hash(user_id, &new_password_hash)
            .await
            .map_err(AuthnError::Store)?;

        let new_config = FactorConfig::Password(crate::authn::factor::PasswordConfig {
            hash: crate::authn::factor::ZeroizedString::new(new_password_hash),
            rules,
        });
        self.inner
            .factors
            .save_factor(user_scope, new_config)
            .await
            .map_err(AuthnError::Store)?;
        Ok(())
    }

    /// Check `new_password` (plaintext) against the user's last
    /// `rules.history_count` stored hashes and, when it is not among them,
    /// return its Argon2id hash.
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
    async fn check_history_and_hash(
        &self,
        user_id: &crate::authn::ids::UserId,
        new_password: &str,
        rules: &crate::authn::factor::PasswordRules,
    ) -> Result<Option<String>, AuthnError<I::Error>> {
        let history = if rules.history_count == 0 {
            Vec::new()
        } else {
            self.inner
                .identity
                .password_history(user_id, rules.history_count)
                .await
                .map_err(AuthnError::Store)?
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
