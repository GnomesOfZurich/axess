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

use crate::authn::service::RequestAuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    store::{FactorStore, IdentityPasswordHistory, IdentityPasswordReset, IdentityStore},
    types::AuthnScope,
};

/// The id the dummy token of an unknown identifier is stored under, so the
/// not-found path writes as the found path does without touching a real
/// user's token. It is not [`UserId::SYSTEM`](crate::authn::ids::UserId::SYSTEM),
/// which may hold a real reset token of its own, and no store has a user
/// under it (a store that refuses the row for that is ignored, as before).
const DUMMY_TOKEN_USER: crate::authn::ids::UserId = crate::authn::ids::UserId::from_uuid(
    uuid::Uuid::from_u128(0x6178_6573_7300_4000_8000_6475_6d6d_7900),
);

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
    /// one tenant lookup, one user lookup, one account status read, one
    /// token write and one audit write. The write goes to a reserved user
    /// id and carries an already expired token whose plaintext is
    /// discarded, so it can never be redeemed; the audit row is a failure
    /// with no user attributed. An account that may not log in (suspended,
    /// locked, terminated) is answered the same way, `Ok(None)` after the
    /// same work, since [`complete_password_reset`](Self::complete_password_reset)
    /// would refuse its token; its audit row names the account with
    /// `NotActive`.
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
        let expires_at = Self::reset_token_expiry(now, ttl)?;

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

        // The cooldown is keyed on the normalised identifier (case folded,
        // invisible characters dropped), for a registered one and an
        // unregistered one alike, so being inside it says nothing about
        // whether an account exists. It runs after the input limits, which
        // map an over-long identifier to the empty string.
        if self
            .inner
            .reset_requests
            .as_ref()
            .is_some_and(|r| r.already_asked(tenant_identifier, identifier))
        {
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::PasswordResetRequested)
                    .with_error(AuthFailureReason::from("cooldown")),
            )
            .await?;
            return Ok(None);
        }

        let (user, refused) = self
            .resolve_reset_requester(identifier, tenant_identifier)
            .await?;

        // Generate token: 32 random bytes → URL-safe base64. Done
        // unconditionally so the not-found path performs the same RNG +
        // SHA-256 work as the found path.
        let (plaintext, hash) = self.mint_reset_token();

        let Some(user) = user else {
            // The same two writes the found path makes. The token is
            // already expired and its plaintext is dropped, so nothing
            // can redeem it; its store error is ignored, since a store
            // may reject a row for a user that does not exist.
            let _ = self
                .inner
                .identity
                .store_reset_token(&DUMMY_TOKEN_USER, &hash, now)
                .await;
            // The row of a refused account names it; an unknown identifier
            // has nobody to name.
            let mut builder = AuthEventBuilder::failure(AuthEventType::PasswordResetRequested);
            if let Some(refused) = &refused {
                builder = builder
                    .attributed_to(&refused.id, &refused.tenant_id)
                    .with_error(AuthFailureReason::NotActive);
            }
            self.emit_audit(builder).await?;
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
                    .with_error(AuthFailureReason::from("token_store_error")),
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

    /// When a reset token issued at `now` for `ttl` expires. A `ttl` of zero,
    /// or one longer than seven days, is refused.
    fn reset_token_expiry(
        now: chrono::DateTime<chrono::Utc>,
        ttl: std::time::Duration,
    ) -> Result<chrono::DateTime<chrono::Utc>, AuthnError<I::Error>> {
        chrono::Duration::from_std(ttl)
            .ok()
            .filter(|d| *d > chrono::Duration::zero() && *d <= chrono::Duration::days(7))
            .and_then(|d| now.checked_add_signed(d))
            .ok_or_else(|| {
                AuthnError::Internal(
                    "password reset ttl must be positive and at most seven days".to_string(),
                )
            })
    }

    /// Resolve the account a reset is asked for: the tenant, the user in it
    /// and the account's status, with the same round trips whether the
    /// identifier is registered or not. Returns the user a token may be
    /// issued to and, apart from it, the user of an account that may not log
    /// in, so the refusal's audit row can name them; at most one is `Some`.
    async fn resolve_reset_requester(
        &self,
        identifier: &str,
        tenant_identifier: &str,
    ) -> Result<
        (
            Option<crate::authn::types::User>,
            Option<crate::authn::types::User>,
        ),
        AuthnError<I::Error>,
    > {
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

        // An account that may not log in gets no token: the commit would
        // refuse it, so the mail would go out for nothing. The status read
        // runs on the unknown path too, against the system id, so the
        // round trips do not say whether the identifier is registered. A
        // status the store cannot answer refuses as well, logged for the
        // operator, since the unknown path shows nothing of its outage.
        let refused = match &user {
            Some(u) => match self.current_account_status(&u.id).await {
                Ok(status) if status.allows_login() => None,
                Ok(status) => {
                    tracing::warn!(user_id = %u.id, status = ?status, "password reset refused: account is not active");
                    Some(u.clone())
                }
                Err(e) => {
                    tracing::error!(user_id = %u.id, error = %e, "password reset: the account status could not be read; refusing");
                    Some(u.clone())
                }
            },
            None => {
                let _ = self
                    .inner
                    .identity
                    .account_status(&crate::authn::ids::UserId::SYSTEM)
                    .await;
                None
            }
        };
        let user = user.filter(|_| refused.is_none());
        Ok((user, refused))
    }

    /// A fresh reset token: the plaintext to deliver and the SHA-256 digest
    /// of it to store, both URL-safe base64.
    fn mint_reset_token(&self) -> (String, String) {
        let mut token_bytes = [0u8; 32];
        self.inner.rng.fill_bytes(&mut token_bytes);
        use base64::Engine as _;
        let plaintext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let hash = reset_token_hash(&plaintext);
        (plaintext, hash)
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
            .with_error(AuthFailureReason::from(reason));
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
        let user = self.find_reset_user(user_id, expected_tenant).await?;
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
        if !self.peek_reset_token(user_id, token).await? {
            return self
                .refuse_password_reset(Some(&user), "token_mismatch")
                .await;
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };

        // Read, not written: the hash this reset replaces is recorded in the
        // history only when the new password is installed, so a reset
        // refused below writes nothing.
        let replaced = self.replaced_hash_to_record(user_id, &user_scope).await?;

        // One blocking task checks the new password against every stored
        // hash and, when it is not a reuse, hashes it. The check verifies the
        // new plaintext against each old Argon2 hash, so it MUST receive
        // plaintext; hashing earlier would feed a PHC string into Argon2's
        // plaintext slot and the check would never match.
        let Some(new_password_hash) = self
            .check_history_and_hash(user_id, new_password, replaced.as_deref(), &rules)
            .await?
        else {
            // Password was used before; the token is kept.
            return self
                .refuse_password_reset(Some(&user), "password_reused")
                .await;
        };

        // The hashing above took tens of milliseconds, and the account and
        // tenant were checked before it. Check both again at the commit,
        // before the token is spent and the password installed, so a
        // suspension of either that landed in between is honoured and the
        // unspent token works once they are active again.
        if let Some(reason) = self.reset_refusal_reason(&user).await? {
            tracing::warn!(
                user_id = %user_id,
                reason,
                "password reset refused at commit: no longer admitted"
            );
            return self.refuse_password_reset(Some(&user), reason).await;
        }

        // Spend the token. Of two requests that both got this far, exactly
        // one wins; the other changes nothing.
        if !self.spend_reset_token(user_id, token).await? {
            return self
                .refuse_password_reset(Some(&user), "token_mismatch")
                .await;
        }

        self.commit_password_reset(
            user_id,
            &user,
            user_scope,
            replaced,
            new_password_hash,
            rules,
        )
        .await
    }

    /// Whether `token` is the user's outstanding reset token, leaving it
    /// unspent. `false` for a token consumed, expired, never issued or
    /// wrong; an error only on a store outage.
    async fn peek_reset_token(
        &self,
        user_id: &crate::authn::ids::UserId,
        token: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        self.inner
            .identity
            .check_reset_token(user_id, &reset_token_hash(token), self.inner.clock.now())
            .await
            .map_err(AuthnError::Store)
    }

    /// Spend `token` when it is the user's outstanding reset token: of two
    /// requests spending one token, exactly one gets `true`.
    async fn spend_reset_token(
        &self,
        user_id: &crate::authn::ids::UserId,
        token: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        self.inner
            .identity
            .verify_reset_token(user_id, &reset_token_hash(token), self.inner.clock.now())
            .await
            .map_err(AuthnError::Store)
    }

    /// The user a reset names, looked up within `expected_tenant` when one
    /// is given.
    async fn find_reset_user(
        &self,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: Option<&crate::authn::ids::TenantId>,
    ) -> Result<Option<crate::authn::types::User>, AuthnError<I::Error>> {
        match expected_tenant {
            Some(tenant) => {
                self.inner
                    .identity
                    .get_user_in_tenant(user_id, tenant)
                    .await
            }
            None => self.inner.identity.get_user(user_id).await,
        }
        .map_err(AuthnError::Store)
    }

    /// Install the new password and finish the reset once the token is spent.
    async fn commit_password_reset(
        &self,
        user_id: &crate::authn::ids::UserId,
        user: &crate::authn::types::User,
        user_scope: AuthnScope,
        replaced: Option<String>,
        new_password_hash: String,
        rules: crate::authn::factor::PasswordRules,
    ) -> Result<bool, AuthnError<I::Error>> {
        // From here the token is spent, so what follows must run to the end
        // whatever the caller does: a client that hangs up or a timeout
        // drops this future, and an install without the session invalidation
        // behind it would leave a stolen cookie valid against the new
        // password. The commit runs on its own task, owning a handle to the
        // service, and this future only waits for it.
        let service = self.clone();
        let committing = {
            let user = user.clone();
            let user_id = *user_id;
            tokio::spawn(async move {
                service
                    .install_new_password(&user_id, &user_scope, replaced, new_password_hash, rules)
                    .await?;
                service.finish_password_reset(&user).await
            })
        };
        match committing.await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(
                    user_id = %user_id,
                    error = %e,
                    "the password reset commit task did not finish"
                );
                Err(AuthnError::Internal(format!(
                    "the password reset commit task did not finish: {e}"
                )))
            }
        }
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

        let audited = self
            .emit_audit(
                AuthEventBuilder::success(AuthEventType::PasswordReset)
                    .attributed_to(&user.id, &user.tenant_id),
            )
            .await;

        // Every failure is logged, whichever is returned: the one the
        // caller gets is the costliest left undone, the sessions still
        // open, then the refresh tokens, then the row.
        for (step, outcome) in [
            ("ending the user's sessions", &sessions_ended),
            ("revoking the user's refresh tokens", &revoked),
            ("writing the audit row", &audited),
        ] {
            if let Err(e) = outcome {
                tracing::error!(
                    user_id = %user_id,
                    step,
                    error = %e,
                    "password reset: a step after the install failed"
                );
            }
        }
        sessions_ended?;
        revoked?;
        audited?;
        Ok(true)
    }
}

/// The stored form of a reset token: SHA-256, base64url, for the token
/// minted and for every token checked. A fast hash is right for it: the
/// token is 32 random bytes from the service's RNG and single-use.
fn reset_token_hash(token: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token.as_bytes()))
}

mod install;
