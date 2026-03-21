//! Authentication service — orchestrates identity lookup, factor verification,
//! and session management.
//!
//! Hold an `Arc<AuthnService<…>>` in Axum state. Login handlers call
//! [`AuthnService::begin_login`] then [`AuthnService::verify_factor`].

use crate::{
    authn::{
        error::AuthnError,
        event::{AuthEventBuilder, AuthEventStatus, AuthEventType},
        factor::{FactorConfig, FactorCredential, FactorKind},
        store::{FactorStore, IdentityStore},
        types::{AuthnScope, EntityState},
    },
    session::{
        extractor::AuthSession,
        store::SessionRegistry,
    },
    utils::{
        random::{SecureRng, SystemRng},
        time::{Clock, SystemClock},
    },
};
use std::{sync::Arc, time::Duration};

// ── Outcome types ─────────────────────────────────────────────────────────────

/// Result of beginning a login attempt.
pub enum LoginOutcome {
    /// Single-factor method complete — session is now `Authenticated`.
    Authenticated,
    /// Multi-factor — first factor passed, session is `Authenticating`.
    /// The UI should present the next factor.
    FactorRequired(FactorKind),
    /// The account is locked out.
    Locked { until: Option<chrono::DateTime<chrono::Utc>> },
    /// Bad credentials. Deliberately vague — do NOT distinguish user-not-found
    /// from wrong-password to prevent user enumeration.
    InvalidCredentials,
}

/// Result of verifying a factor step.
pub enum FactorOutcome {
    /// This was the last factor — session is now `Authenticated`.
    Authenticated,
    /// More factors remain — present the next factor UI.
    FactorRequired(FactorKind),
    /// The credential was wrong.
    InvalidCredential,
    /// Too many failed attempts — the account is now locked.
    Locked { until: Option<chrono::DateTime<chrono::Utc>> },
}

// ── AuthnService ──────────────────────────────────────────────────────────────

/// Authentication service — orchestrates identity lookup, factor verification,
/// and session management.
///
/// Generic over:
/// - `I`: [`IdentityStore`]
/// - `F`: [`FactorStore`] (same error type as `I`)
/// - `Rng`: [`SecureRng`] (default: `SystemRng`)
/// - `C`: [`Clock`] (default: `SystemClock`)
pub struct AuthnService<I, F, Rng = SystemRng, C = SystemClock>
where
    I: IdentityStore,
    F: FactorStore,
    Rng: SecureRng,
    C: Clock,
{
    identity: Arc<I>,
    factors: Arc<F>,
    registry: Option<Arc<dyn ErasedRegistry>>,
    rng: Rng,
    clock: C,
}

// Trait-object-safe wrapper for SessionRegistry to avoid generic bleed.
trait ErasedRegistry: Send + Sync + 'static {
    fn is_valid_blocking(
        &self,
        user_id: &str,
        session_id: &crate::session::id::SessionId,
    ) -> bool;
    fn invalidate_user_blocking(&self, user_id: &str);
    fn register_blocking(
        &self,
        user_id: &str,
        session_id: &crate::session::id::SessionId,
    );
}

struct RegistryWrapper<R: SessionRegistry>(R);

impl<R: SessionRegistry + 'static> ErasedRegistry for RegistryWrapper<R> {
    fn is_valid_blocking(
        &self,
        user_id: &str,
        session_id: &crate::session::id::SessionId,
    ) -> bool {
        // Use tokio's block_in_place to run async in a sync context.
        // This is safe only when called from a tokio thread (which handlers are).
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.0.is_valid(user_id, session_id).await.unwrap_or(false)
            })
        })
    }

    fn invalidate_user_blocking(&self, user_id: &str) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let _ = self.0.invalidate_user(user_id).await;
            })
        });
    }

    fn register_blocking(
        &self,
        user_id: &str,
        session_id: &crate::session::id::SessionId,
    ) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let _ = self.0.register(user_id, session_id).await;
            })
        });
    }
}

impl<I, F> AuthnService<I, F, SystemRng, SystemClock>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Create a new service with OS RNG and system clock.
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            identity: Arc::new(identity),
            factors: Arc::new(factors),
            registry: None,
            rng: SystemRng,
            clock: SystemClock,
        }
    }
}

impl<I, F, Rng, C> AuthnService<I, F, Rng, C>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
    Rng: SecureRng,
    C: Clock,
{
    /// Replace the RNG (for DST).
    pub fn with_rng<R: SecureRng>(self, rng: R) -> AuthnService<I, F, R, C> {
        AuthnService {
            identity: self.identity,
            factors: self.factors,
            registry: self.registry,
            rng,
            clock: self.clock,
        }
    }

    /// Replace the clock (for DST).
    pub fn with_clock<Cl: Clock>(self, clock: Cl) -> AuthnService<I, F, Rng, Cl> {
        AuthnService {
            identity: self.identity,
            factors: self.factors,
            registry: self.registry,
            rng: self.rng,
            clock,
        }
    }

    /// Attach a session registry for forced-logout support.
    pub fn with_registry(mut self, registry: impl SessionRegistry + 'static) -> Self {
        self.registry = Some(Arc::new(RegistryWrapper(registry)));
        self
    }

    // ── Public methods ─────────────────────────────────────────────────────────

    /// Begin the login flow for an identifier (username/email) within a tenant.
    ///
    /// Looks up the user, checks account status, and begins the first factor.
    /// Updates the session to `Identifying` or `Authenticating` as appropriate.
    ///
    /// Returns a [`LoginOutcome`] describing what the UI should do next.
    pub async fn begin_login(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        session: &AuthSession,
    ) -> Result<LoginOutcome, AuthnError<I::Error>> {
        // 1. Find tenant.
        let tenant = self
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NotActive(EntityState::Guest))?;

        // 2. Find user — constant-time: do NOT short-circuit on user-not-found.
        let user_opt = self
            .identity
            .find_user(identifier, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        let user = match user_opt {
            Some(u) => u,
            None => {
                // Record attempt but return generic error (no user enumeration).
                return Ok(LoginOutcome::InvalidCredentials);
            }
        };

        // 3. Check account status.
        let status = self
            .identity
            .account_status(&user.id)
            .await
            .map_err(AuthnError::Store)?;

        if !status.allows_login() {
            if status.is_locked() {
                return Ok(LoginOutcome::Locked { until: None });
            }
            return Err(AuthnError::NotActive(status));
        }

        // 4. Load available authentication methods.
        let methods = self
            .factors
            .available_methods(&user.id, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        let method = methods.into_iter().next().ok_or(AuthnError::NoFlow)?;

        if method.factors.is_empty() {
            return Ok(LoginOutcome::InvalidCredentials);
        }

        let first_kind = method.factors[0].clone();

        // 5. Begin the flow in the session.
        if method.factors.len() == 1 {
            // Single-factor: pre-set to authenticating with one step.
            session
                .begin_authenticating(
                    user.id.clone(),
                    tenant.id.clone(),
                    method.name.clone(),
                    method.factors.clone(),
                )
                .await;
        } else {
            session
                .begin_authenticating(
                    user.id.clone(),
                    tenant.id.clone(),
                    method.name.clone(),
                    method.factors.clone(),
                )
                .await;
        }

        // Record login attempt event.
        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    tenant.id.clone(),
                    AuthEventType::LoginAttempt,
                    AuthEventStatus::Success,
                )
                .with_factor(first_kind.clone())
                .build_at(self.clock.now()),
            )
            .await;

        Ok(LoginOutcome::FactorRequired(first_kind))
    }

    /// Verify a factor credential during an in-progress authentication flow.
    ///
    /// The session must be in [`AuthState::Authenticating`].
    /// Returns a [`FactorOutcome`] describing the next step.
    pub async fn verify_factor(
        &self,
        credential: &FactorCredential,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let auth_state = session.auth_state().await;

        let (user_id, tenant_id, remaining) = match &auth_state {
            crate::session::data::AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                attempt_count,
                last_attempt,
                ..
            } => {
                let policy = self.identity.lockout_policy();
                // Check lockout.
                if let (true, Some(last)) =
                    (*attempt_count >= policy.max_attempts, last_attempt)
                {
                    if let Some(dur) = policy.duration {
                        let elapsed = (self.clock.now() - *last)
                            .to_std()
                            .unwrap_or(Duration::ZERO);
                        if elapsed < dur {
                            let until = Some(*last + chrono::Duration::from_std(dur).unwrap());
                            return Ok(FactorOutcome::Locked { until });
                        }
                        // Lockout expired — reset attempt count conceptually by continuing.
                    }
                }
                (user_id.clone(), tenant_id.clone(), remaining.clone())
            }
            _ => return Err(AuthnError::NoFlow),
        };

        let current_kind = remaining.first().ok_or(AuthnError::NoFlow)?.clone();

        // Load factor config.
        let scope = AuthnScope::User {
            tenant_id: tenant_id.clone(),
            user_id: user_id.clone(),
        };
        let config_opt = self
            .factors
            .load_factor(&scope, current_kind.clone())
            .await
            .map_err(AuthnError::Store)?;

        let config = match config_opt {
            Some(c) => c,
            None => {
                // Try tenant scope.
                let tenant_scope = AuthnScope::Tenant(tenant_id.clone());
                self.factors
                    .load_factor(&tenant_scope, current_kind.clone())
                    .await
                    .map_err(AuthnError::Store)?
                    .ok_or(AuthnError::NoFlow)?
            }
        };

        // Verify the credential.
        let verified = verify_credential(credential, &config, &current_kind);

        if !verified {
            // Record failed attempt.
            let count = self
                .identity
                .record_failed_attempt(&user_id)
                .await
                .map_err(AuthnError::Store)?;

            session.record_attempt().await;

            let _ = self
                .identity
                .record_event(
                    AuthEventBuilder::new(
                        user_id.clone(),
                        tenant_id.clone(),
                        AuthEventType::FactorVerified,
                        AuthEventStatus::Failure,
                    )
                    .with_factor(current_kind.clone())
                    .build_at(self.clock.now()),
                )
                .await;

            let policy = self.identity.lockout_policy();
            if count >= policy.max_attempts {
                return Ok(FactorOutcome::Locked { until: None });
            }

            return Ok(FactorOutcome::InvalidCredential);
        }

        // Success — reset attempt counter.
        let _ = self
            .identity
            .reset_failed_attempts(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        // Advance the factor in the session.
        let now = self.clock.now();
        session.advance_factor(&current_kind, now).await;

        // After advance, check if we're fully authenticated.
        let new_state = session.auth_state().await;
        if new_state.is_authenticated() {
            // Register session in registry.
            let sid = session.session_id().await;
            if let Some(reg) = &self.registry {
                reg.register_blocking(&user_id, &sid);
            }

            let _ = self
                .identity
                .record_event(
                    AuthEventBuilder::new(
                        user_id.clone(),
                        tenant_id.clone(),
                        AuthEventType::Authenticated,
                        AuthEventStatus::Success,
                    )
                    .with_session(sid)
                    .build_at(now),
                )
                .await;

            return Ok(FactorOutcome::Authenticated);
        }

        // More factors remain.
        let next_kind = match &session.auth_state().await {
            crate::session::data::AuthState::Authenticating { remaining, .. } => {
                remaining.first().cloned()
            }
            _ => None,
        };

        if let Some(kind) = next_kind {
            Ok(FactorOutcome::FactorRequired(kind))
        } else {
            Ok(FactorOutcome::Authenticated)
        }
    }

    /// Check whether the current session is valid (consults the registry if installed).
    pub async fn check_session(&self, session: &AuthSession) -> bool {
        if !session.is_authenticated().await {
            return false;
        }
        let user_id = match session.user_id().await {
            Some(id) => id,
            None => return false,
        };
        let sid = session.session_id().await;
        if let Some(reg) = &self.registry {
            reg.is_valid_blocking(&user_id, &sid)
        } else {
            true
        }
    }

    /// Log out the current user: clear the session and invalidate in the registry.
    pub async fn logout(
        &self,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        if let Some(user_id) = session.user_id().await {
            let sid = session.session_id().await;
            if let Some(reg) = &self.registry {
                reg.invalidate_user_blocking(&user_id);
            }
            let tenant_id = session
                .tenant_id()
                .await
                .unwrap_or_else(|| "".into());
            let _ = self
                .identity
                .record_event(
                    AuthEventBuilder::new(
                        user_id,
                        tenant_id,
                        AuthEventType::LogoutAttempt,
                        AuthEventStatus::Success,
                    )
                    .with_session(sid)
                    .build_at(self.clock.now()),
                )
                .await;
        }
        session.clear().await;
        Ok(())
    }
}

// ── Credential verification ────────────────────────────────────────────────────

/// Dispatch credential verification to the appropriate factor implementation.
///
/// Returns `true` on success, `false` on any failure.
fn verify_credential(credential: &FactorCredential, config: &FactorConfig, kind: &FactorKind) -> bool {
    match (credential, config, kind) {
        (FactorCredential::Password(pwd), FactorConfig::Password(cfg), FactorKind::Password) => {
            // verify_password(password: &str, hash: &str) -> Result<(), VerifyError>
            let pwd_str: &str = pwd.as_ref();
            let hash_str: &str = cfg.hash.as_ref();
            axess_factors::verify_password(pwd_str, hash_str).is_ok()
        }
        (FactorCredential::OtpCode(code), FactorConfig::Totp(cfg), FactorKind::Totp) => {
            // verify_totp returns Option<u64> (the matched step)
            axess_factors::verify_totp(
                cfg.secret.as_ref(),
                code.as_ref(),
                std::time::SystemTime::now(),
                Some(cfg.digits as usize),
                Some(cfg.period_secs as u64),
                Some(cfg.past_window as u64),
                Some(cfg.future_window as u64),
            )
            .is_some()
        }
        (FactorCredential::OtpCode(code), FactorConfig::Hotp(cfg), FactorKind::Hotp) => {
            // verify_hotp returns Option<u64> (the matched counter)
            axess_factors::verify_hotp(
                cfg.secret.as_ref(),
                code.as_ref(),
                cfg.counter,
                cfg.digits as usize,
                cfg.lookahead_window as u64,
            )
            .is_some()
        }
        (FactorCredential::Fido2Assertion(_), FactorConfig::Fido2(_), FactorKind::Fido2) => {
            // FIDO2 is a placeholder — always fail until implemented.
            false
        }
        _ => false,
    }
}

