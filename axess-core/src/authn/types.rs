//! Authentication-layer view of users and tenants.
//!
//! These are thin, auth-focused structs, not the application's domain models.
//! Application data (preferences, profile) lives in the app's own storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

use super::ids::{IdError, TenantId, UserId};

/// A principal (user) as seen by the authentication layer.
///
/// This is a thin auth-layer view, not the application's domain user type.
/// Application domain data (profile, preferences) lives in the app's own models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Opaque unique user identifier.
    pub id: UserId,
    /// The tenant this user belongs to. [`TenantId::system()`] names the
    /// tenant that owns platform-operator principals.
    pub tenant_id: TenantId,
    /// The login identifier used for lookup (username, email, etc.).
    pub identifier: Arc<str>,
    /// Display name shown in UIs.
    pub display_name: Arc<str>,
    /// Current lifecycle state of the user account.
    pub status: EntityState,
    /// Stable opaque user handle for WebAuthn (FIDO2).
    ///
    /// Must be a random UUID assigned once at user creation and persisted.
    /// The WebAuthn spec requires this to be non-PII and stable across
    /// multiple credential registrations for the same user.
    /// `None` if the user has never been involved in a FIDO2 flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn_id: Option<uuid::Uuid>,
    /// Actor that created this user row. Typically [`UserId::system()`]
    /// for platform-seeded users, or the admin / signup user for
    /// self-service accounts.
    pub created_by: UserId,
    /// Wall-clock time of creation (from an injected `Clock`, not
    /// `Utc::now`, so deterministic-simulation tests control the value).
    pub created_at: DateTime<Utc>,
    /// Actor that last updated this row. Equals `created_by` immediately
    /// after creation; mutated by account-lifecycle operations.
    pub updated_by: UserId,
    /// Timestamp of the last update. Equals `created_at` immediately
    /// after creation.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new `User` with validation.
    ///
    /// `id` and `tenant_id` accept anything `UserId::try_new` / `TenantId::try_new`
    /// accept (non-empty, no control characters). `created_by` + `created_at`
    /// are captured as the audit metadata; `updated_by` / `updated_at`
    /// initialise to the same values.
    pub fn new(
        id: impl AsRef<str>,
        tenant_id: impl AsRef<str>,
        identifier: impl Into<Arc<str>>,
        display_name: impl Into<Arc<str>>,
        status: EntityState,
        created_by: UserId,
        created_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let user = Self {
            id: UserId::try_new(id).map_err(|e: IdError| format!("User.id: {e}"))?,
            tenant_id: TenantId::try_new(tenant_id)
                .map_err(|e: IdError| format!("User.tenant_id: {e}"))?,
            identifier: identifier.into(),
            display_name: display_name.into(),
            status,
            webauthn_id: None,
            created_by,
            created_at,
            updated_by: created_by,
            updated_at: created_at,
        };
        user.validate_new()?;
        Ok(user)
    }

    /// [`validate`](Self::validate) and the extra terms for a user being
    /// created: the identifier is held to
    /// [`is_acceptable_new_identifier`](crate::validation::is_acceptable_new_identifier)
    /// (NFKC-stable, no surrounding or non-ASCII whitespace). `validate`
    /// alone stays the rule for rows read back.
    pub fn validate_new(&self) -> Result<(), String> {
        self.validate()?;
        if !crate::validation::is_acceptable_new_identifier(&self.identifier) {
            return Err(
                "User.identifier has surrounding or non-ASCII whitespace or is not in NFKC"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Validate that the free-form fields are well-formed.
    ///
    /// The identifier and display-name fields are still `Arc<str>` (they can
    /// legitimately hold emails, display strings, etc.) so they still need
    /// runtime validation. The typed `id` and `tenant_id` fields are guaranteed
    /// non-empty by construction, so they are not re-checked here.
    ///
    /// The identifier is held to
    /// [`is_acceptable_identifier`](crate::validation::is_acceptable_identifier):
    /// printable, free of invisible format characters and noncharacters, and
    /// in NFC. The login path treats a stored user that fails this as
    /// unknown, so a row with a confusable identifier, whichever path wrote
    /// it, cannot be logged into until it is corrected.
    pub fn validate(&self) -> Result<(), String> {
        if self.identifier.is_empty() {
            return Err("User.identifier must be non-empty".to_string());
        }
        if self.identifier.contains(|c: char| c.is_control()) {
            return Err("User.identifier contains control characters".to_string());
        }
        if !crate::validation::is_acceptable_identifier(&self.identifier) {
            return Err(
                "User.identifier contains an invisible format character or is not in NFC"
                    .to_string(),
            );
        }
        if self.display_name.contains('\0') {
            return Err("User.display_name contains null byte".to_string());
        }
        Ok(())
    }

    /// Classify the user by scope: platform operator ([`AuthnScope::System`])
    /// or tenant member ([`AuthnScope::Tenant`]).
    ///
    /// Prefer this over direct comparison against [`TenantId::system`].
    pub fn scope(&self) -> AuthnScope {
        if self.tenant_id.is_system() {
            AuthnScope::System
        } else {
            AuthnScope::Tenant(self.tenant_id)
        }
    }
}

/// A tenant as seen by the authentication layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Opaque unique tenant identifier.
    pub id: TenantId,
    /// Slug or domain used for lookup.
    pub identifier: Arc<str>,
    /// Display name shown in UIs.
    pub display_name: Arc<str>,
    /// Current lifecycle state of the tenant.
    pub status: EntityState,
    /// Actor that created this tenant row. For self-service signups
    /// this is typically the first tenant admin; for operator-onboarded
    /// tenants it is [`UserId::system()`].
    pub created_by: UserId,
    /// Wall-clock time of creation.
    pub created_at: DateTime<Utc>,
    /// Actor that last updated this row.
    pub updated_by: UserId,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// Create a new `Tenant` with validation.
    pub fn new(
        id: impl AsRef<str>,
        identifier: impl Into<Arc<str>>,
        display_name: impl Into<Arc<str>>,
        status: EntityState,
        created_by: UserId,
        created_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let tenant = Self {
            id: TenantId::try_new(id).map_err(|e: IdError| format!("Tenant.id: {e}"))?,
            identifier: identifier.into(),
            display_name: display_name.into(),
            status,
            created_by,
            created_at,
            updated_by: created_by,
            updated_at: created_at,
        };
        tenant.validate_new()?;
        Ok(tenant)
    }

    /// [`validate`](Self::validate) and the extra terms for a tenant being
    /// created: the identifier is held to
    /// [`is_acceptable_new_identifier`](crate::validation::is_acceptable_new_identifier)
    /// (no invisible format characters, NFKC-stable, no surrounding or
    /// non-ASCII whitespace). [`validate`](Self::validate), which runs on a row
    /// read back, does not apply it, so an existing tenant is never locked out.
    pub fn validate_new(&self) -> Result<(), String> {
        self.validate()?;
        if !crate::validation::is_acceptable_new_identifier(&self.identifier) {
            return Err(
                "Tenant.identifier has an invisible format character, surrounding or \
                 non-ASCII whitespace, or is not in NFKC"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Validate the free-form fields (`identifier`, `display_name`).
    ///
    /// The typed `id` field is guaranteed non-empty by construction.
    pub fn validate(&self) -> Result<(), String> {
        if self.identifier.is_empty() {
            return Err("Tenant.identifier must be non-empty".to_string());
        }
        if self.identifier.contains(|c: char| c.is_control()) {
            return Err("Tenant.identifier contains control characters".to_string());
        }
        Ok(())
    }
}

/// Account / tenant lifecycle state.
///
/// Follows the pattern: Guest → Candidate → Pending → Active,
/// with suspension/termination/archival as adverse transitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EntityState {
    /// Unauthenticated visitor; no account.
    #[default]
    Guest,
    /// Account created but not yet fully provisioned.
    Candidate,
    /// Provisioned but awaiting activation (e.g. email verification). The
    /// detail's cause is [`StatusCause::Verification`].
    Pending(StatusDetail),
    /// Fully active and operational.
    Active,
    /// Disabled for now, and the detail's [`cause`](StatusDetail::cause)
    /// says by what: an operator ([`StatusCause::Administrative`]), or a
    /// store that materialises a lockout as a state
    /// ([`StatusCause::Lockout`]; the library's own lockout is derived from
    /// the failure counter and is never this state).
    Suspended(StatusDetail),
    /// Permanently closed ([`StatusCause::Closure`]).
    Terminated(StatusDetail),
    /// Inactive and kept only for historical/audit purposes
    /// ([`StatusCause::Closure`]).
    Archived(StatusDetail),
}

impl EntityState {
    /// Return `true` if the account is in the `Active` state.
    pub fn is_active(&self) -> bool {
        matches!(self, EntityState::Active)
    }

    /// Return `true` if the account is `Suspended`, whatever the cause
    /// (`is_locked` until 0.16.0, a name that read as the counter's lockout). A
    /// login refuses such an account as `Locked`; an eligibility check asks
    /// [`is_administratively_disabled`](Self::is_administratively_disabled)
    /// or [`can_self_recover`](Self::can_self_recover) instead.
    pub fn is_suspended(&self) -> bool {
        matches!(self, EntityState::Suspended(_))
    }

    /// The detail a non-nominal state carries; `None` for `Guest`,
    /// `Candidate` and `Active`.
    fn detail(&self) -> Option<&StatusDetail> {
        match self {
            EntityState::Pending(d)
            | EntityState::Suspended(d)
            | EntityState::Terminated(d)
            | EntityState::Archived(d) => Some(d),
            EntityState::Guest | EntityState::Candidate | EntityState::Active => None,
        }
    }

    /// Did an operator put this account out of service?
    ///
    /// `true` for a `Pending`, `Suspended`, `Terminated` or `Archived` state
    /// whose cause is [`StatusCause::Administrative`]; `false` for every
    /// other cause and for `Guest`, `Candidate` and `Active`. A lockout, a
    /// pending verification and a closure are not an operator's act, and an
    /// unspecified cause is not presumed to be one. Ask it of
    /// [`effective_at`](Self::effective_at) so a timed suspension that has
    /// ended answers `false`.
    pub fn is_administratively_disabled(&self) -> bool {
        self.detail()
            .is_some_and(|d| d.cause == StatusCause::Administrative)
    }

    /// May the person start a recovery themselves: a second-factor reset, a
    /// password reset that bypasses the login?
    ///
    /// `true` for `Active`, and for `Suspended` with cause
    /// [`StatusCause::Lockout`]: the account a lockout holds is exactly who
    /// recovery exists for. `false` for everything else: an administrative
    /// suspension, a closure, a pending verification, a `Guest` or
    /// `Candidate`, and a `Suspended` state whose cause is `Other`
    /// (including the `unspecified` an old row reads as). A refusal here is
    /// fail-closed: the account an operator disabled must never pass. Ask it
    /// of [`effective_at`](Self::effective_at) so a timed lockout that has
    /// ended answers as the active account it is.
    ///
    /// ```
    /// use axess_core::authn::types::{EntityState, StatusDetail};
    /// use chrono::Utc;
    ///
    /// /// The eligibility rail of a self-service second-factor reset.
    /// fn may_start_recovery(status: EntityState, now: chrono::DateTime<Utc>) -> bool {
    ///     status.effective_at(now).can_self_recover()
    /// }
    ///
    /// let now = Utc::now();
    /// assert!(may_start_recovery(EntityState::Active, now));
    /// // A store that keeps its lockout as a state: recovery is for them.
    /// assert!(may_start_recovery(
    ///     EntityState::Suspended(StatusDetail::lockout("too many attempts", now)),
    ///     now,
    /// ));
    /// // An operator's hold: only an operator ends it.
    /// assert!(!may_start_recovery(
    ///     EntityState::Suspended(StatusDetail::administrative("fraud review", now)),
    ///     now,
    /// ));
    /// assert!(!may_start_recovery(
    ///     EntityState::Terminated(StatusDetail::closure("left the firm", now)),
    ///     now,
    /// ));
    /// ```
    pub fn can_self_recover(&self) -> bool {
        match self {
            EntityState::Active => true,
            EntityState::Suspended(d) => d.cause == StatusCause::Lockout,
            EntityState::Guest
            | EntityState::Candidate
            | EntityState::Pending(_)
            | EntityState::Terminated(_)
            | EntityState::Archived(_) => false,
        }
    }

    /// The state as it stands at `now`: a suspension whose `until` has
    /// passed is over, so it reads as [`Active`](Self::Active). Every other
    /// state, and a suspension with no `until` or a future one, is returned
    /// unchanged.
    ///
    /// Stores record the suspension and its end time; nothing else ends it,
    /// so the services read a user's status through this method with their
    /// injected clock.
    #[must_use]
    pub fn effective_at(self, now: DateTime<Utc>) -> Self {
        match self {
            EntityState::Suspended(StatusDetail {
                until: Some(until), ..
            }) if until <= now => EntityState::Active,
            other => other,
        }
    }

    /// Return `true` if the account allows login.
    ///
    /// Only `Active` accounts can authenticate. `Candidate` accounts must be
    /// explicitly activated by the application before login is permitted.
    pub fn allows_login(&self) -> bool {
        matches!(self, EntityState::Active)
    }
}

mod status;
pub use status::{StatusCause, StatusDetail};

/// Three-tier configuration scope, ordered from narrowest to broadest.
///
/// - [`User`](Self::User): a specific user in a specific tenant.
/// - [`Tenant`](Self::Tenant): every user in a specific tenant.
/// - [`System`](Self::System): platform-owned defaults that tenants adopt
///   explicitly at provisioning (or fork later). Storage-wise, System
///   rows live under the reserved [`TenantId::SYSTEM`] tenant: there is
///   no NULL-tenant encoding for configuration scope anywhere in axess.
///
/// Runtime resolution walks [`resolution_chain`](Self::resolution_chain)
/// from narrowest to broadest and returns the first hit. Backends
/// implementing [`FactorStore::resolve_factor`](super::store::FactorStore::resolve_factor)
/// do this in one query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthnScope {
    /// Platform-owned defaults, keyed under [`TenantId::SYSTEM`].
    System,
    /// Tenant-owned config; applies to every user in the tenant.
    Tenant(TenantId),
    /// User-owned config within a tenant.
    User {
        /// Tenant containing the user.
        tenant_id: TenantId,
        /// User the scope is bound to.
        user_id: UserId,
    },
}

impl AuthnScope {
    /// Return a stable string key for use as a map key.
    pub fn key(&self) -> String {
        match self {
            AuthnScope::System => "system".to_string(),
            AuthnScope::Tenant(t) => format!("tenant:{t}"),
            AuthnScope::User { tenant_id, user_id } => {
                format!("user:{tenant_id}:{user_id}")
            }
        }
    }

    /// Storage projection of this scope: `(tenant_id, user_id)` where
    /// `tenant_id` is ALWAYS populated (with [`TenantId::SYSTEM`] for
    /// [`AuthnScope::System`]) and `user_id` is populated only for
    /// [`AuthnScope::User`].
    ///
    /// There is no NULL-tenant encoding for configuration scope anywhere
    /// in axess. Rows always belong to a real tenant; the system tenant
    /// is what "platform-wide" means. FK integrity works uniformly and
    /// SQL callers never need `tenant_id IS NULL` special-cases.
    ///
    /// This is distinct from audit-event storage, where NULL `tenant_id`
    /// means "tenant not yet known" (pre-authenticated event), never
    /// "system scope."
    pub fn as_columns(&self) -> ScopeColumns {
        match self {
            AuthnScope::System => ScopeColumns {
                tenant_id: TenantId::SYSTEM,
                user_id: None,
            },
            AuthnScope::Tenant(t) => ScopeColumns {
                tenant_id: *t,
                user_id: None,
            },
            AuthnScope::User { tenant_id, user_id } => ScopeColumns {
                tenant_id: *tenant_id,
                user_id: Some(*user_id),
            },
        }
    }

    /// Ordered scope chain for runtime configuration resolution.
    ///
    /// Callers walking the chain in application code should generally
    /// prefer [`FactorStore::resolve_factor`](super::store::FactorStore::resolve_factor),
    /// which pushes the walk into the storage backend (one query
    /// instead of N sequential trips). Use this helper for admin/UI
    /// paths that need to enumerate the scopes explicitly.
    ///
    /// Order is narrowest → broadest. For a `User` scope: `[User, Tenant, System]`.
    /// For `Tenant`: `[Tenant, System]`. For `System`: `[System]`.
    pub fn resolution_chain(&self) -> Vec<AuthnScope> {
        match self {
            AuthnScope::System => vec![AuthnScope::System],
            AuthnScope::Tenant(t) => vec![AuthnScope::Tenant(*t), AuthnScope::System],
            AuthnScope::User { tenant_id, user_id } => vec![
                AuthnScope::User {
                    tenant_id: *tenant_id,
                    user_id: *user_id,
                },
                AuthnScope::Tenant(*tenant_id),
                AuthnScope::System,
            ],
        }
    }
}

/// Storage-layer projection of an [`AuthnScope`] onto `(tenant_id, user_id)`
/// columns for scope-applicability data (factor configs, auth methods).
///
/// `tenant_id` is always populated ([`TenantId::SYSTEM`] for
/// [`AuthnScope::System`]); only `user_id` can be absent: `None` means
/// "applies to any user at the tenant or system level". SQL callers never
/// need `tenant_id IS NULL` special-cases for configuration scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeColumns {
    /// Tenant column; always populated ([`TenantId::SYSTEM`] for the
    /// [`AuthnScope::System`] row).
    pub tenant_id: TenantId,
    /// User column; `None` encodes "applies to any user at the tenant or system level".
    pub user_id: Option<UserId>,
}

/// What to do when the failed-attempt counter store is unavailable.
///
/// [`IdentityAuthnLog::record_failed_attempt`](super::store::IdentityAuthnLog::record_failed_attempt)
/// can fail independently of the reads that got the login this far: the
/// read-replica split this library encourages puts reads on a replica and
/// this write on the primary, so a primary outage leaves logins working and
/// the counter dead. While that lasts, the count never rises and
/// `max_attempts` is never reached.
///
/// Neither choice below changes the response an attacker sees for a
/// *nonexistent* user: those are rejected at `begin_login` with timing
/// equalization and never reach the counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CounterUnavailable {
    /// Treat the attempt as locked. Brute force stays bounded during the
    /// outage; a user who mistypes their password is told they are locked
    /// and can retry once `duration` elapses. The default, because an
    /// authentication library should fail closed.
    ///
    /// Note the interaction with `duration: None`: an indefinite lockout
    /// plus a persistently broken counter store needs an administrator to
    /// clear each affected account. Deployments running indefinite lockouts
    /// should either monitor [`FactorMetrics::factor_counter_store_outage`](crate::metrics::FactorMetrics::factor_counter_store_outage)
    /// or choose [`Allow`](Self::Allow) knowingly.
    #[default]
    Lock,
    /// Treat the attempt as an ordinary failure. Logins keep working and
    /// lockout is disabled for the duration of the outage, which is an
    /// unbounded brute-force window precisely when monitoring is degraded.
    /// Choose this only with a compensating control, such as a
    /// `KeyExtractor::LoginIdentifier` rate limiter in front of the route.
    Allow,
}

/// Lockout policy configuration.
///
/// Applied when verifying credentials to prevent brute-force attacks.
///
/// # The lock is per account
///
/// The default (five failures in an hour, locked for fifteen minutes) counts
/// failures against the account, so anyone who knows a username can keep that
/// account locked. A service built with
/// [`with_device_store`](crate::authn::service::AuthnServiceBuilder::with_device_store)
/// narrows that: while the failure counter has an account locked, a login
/// from a device the account has already used (the device store's
/// [`Seen`](crate::device::DeviceTrustLevel::Seen) or
/// [`Trusted`](crate::device::DeviceTrustLevel::Trusted) for that user) still
/// works, and the lock keeps every other origin out. The device is the one the
/// session layer's device resolver bound to the session, so the guarantee is
/// that of the device cookie and fingerprint; an administrator's suspension
/// is not affected.
///
/// # The throttle is per guesser
///
/// [`throttle`](Self::throttle), on by default, answers the same attack
/// from the other side: consecutive wrong guesses under one key (the
/// account and the client address) are refused for a delay that doubles
/// per failure, one second to sixty-four, as
/// [`FactorOutcome::Throttled`](crate::authn::service::FactorOutcome::Throttled)
/// (or [`AuthnError::Throttled`](crate::authn::error::AuthnError::Throttled)
/// from `prepare_factor`) with the time left. A right guess clears the key,
/// and a known device is not throttled, as it is not locked. The lock stays
/// the ceiling. [`without_throttle`](Self::without_throttle) is the opt-out.
#[derive(Debug, Clone)]
pub struct LockoutPolicy {
    /// Maximum consecutive failed attempts within `attempt_window` before lockout.
    pub max_attempts: u32,
    /// Duration of the lockout. `None` means permanent until an admin resets.
    pub duration: Option<Duration>,
    /// Sliding window over which failed attempts accumulate. Implementations
    /// of [`IdentityAuthnLog::record_failed_attempt`](super::store::IdentityAuthnLog::record_failed_attempt)
    /// should treat any earlier failures as expired and not count them
    /// toward `max_attempts`. Without this a user who legitimately fails
    /// `max_attempts - 1` times today and once tomorrow gets locked, even
    /// though the failures are unrelated. Default: 1 hour.
    pub attempt_window: Duration,
    /// What to do when the counter store itself is unavailable.
    /// Default: [`CounterUnavailable::Lock`].
    pub on_counter_unavailable: CounterUnavailable,
    /// How consecutive wrong guesses under one key are slowed down before
    /// the lock is reached; `None` throttles nothing. Default:
    /// [`Throttle::default`] (one second doubling to sixty-four, keyed on
    /// account and address). Set it with
    /// [`without_throttle`](Self::without_throttle) rather than by hand
    /// when turning it off, so the choice reads as one.
    pub throttle: Option<Throttle>,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            duration: Some(Duration::from_secs(15 * 60)),
            attempt_window: Duration::from_secs(60 * 60),
            on_counter_unavailable: CounterUnavailable::Lock,
            throttle: Some(Throttle::default()),
        }
    }
}

/// A lockout derived from the failure counter and the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedLockout {
    /// When the lockout ends; `None` means it lasts until an administrator
    /// resets the counter.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
}

impl LockoutPolicy {
    /// The named opt-out of the throttle: this policy with
    /// [`throttle`](Self::throttle) set to `None`, so consecutive wrong
    /// guesses are refused only by the per-account lock. Choose it where a
    /// limiter in front of the route already slows a guesser down, and say
    /// so where the policy is built.
    pub fn without_throttle(mut self) -> Self {
        self.throttle = None;
        self
    }

    /// The failure threshold in force: `max_attempts`, with zero read as the
    /// default of five. Zero used to lock an account on its first failure
    /// (and, once the lockout is derived from the counter, would lock every
    /// account before any failure), where the OTP attempt limits already
    /// read zero as the default.
    pub fn effective_max_attempts(&self) -> u32 {
        if self.max_attempts == 0 {
            Self::default().max_attempts
        } else {
            self.max_attempts
        }
    }

    /// Whether `failed_attempts`, the last of which happened at
    /// `last_failure_at`, locks the account at `now` under this policy.
    ///
    /// Locked means at least [`effective_max_attempts`](Self::effective_max_attempts)
    /// failures and either no `duration` (a lockout that lasts until an
    /// administrator resets the counter) or a last failure less than
    /// `duration` ago. A store that cannot say when the last failure was
    /// (`None`) cannot have a timed lockout expire, so it stays locked:
    /// the safe reading of a missing timestamp.
    ///
    /// `attempt_window` is not consulted here. It bounds how long failures
    /// accumulate, which is the store's job when it increments; it must not
    /// unlock an account whose lockout is longer than the window.
    pub fn derived_lockout(
        &self,
        failed_attempts: u32,
        last_failure_at: Option<chrono::DateTime<chrono::Utc>>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<DerivedLockout> {
        if failed_attempts < self.effective_max_attempts() {
            return None;
        }
        let Some(duration) = self.duration else {
            return Some(DerivedLockout { until: None });
        };
        let Some(last) = last_failure_at else {
            return Some(DerivedLockout { until: None });
        };
        let until = chrono::Duration::from_std(duration)
            .ok()
            .and_then(|d| last.checked_add_signed(d));
        match until {
            Some(until) if now >= until => None,
            Some(until) => Some(DerivedLockout { until: Some(until) }),
            // A duration too large to represent never ends.
            None => Some(DerivedLockout { until: None }),
        }
    }
}

mod ip_policy;
pub use ip_policy::IpPolicy;

mod throttle;
pub use throttle::{Throttle, ThrottleKey, ThrottleState, ThrottleSubject};

#[cfg(test)]
mod authn_types_tests;

#[cfg(test)]
mod new_identifier_tests {
    use super::*;

    #[test]
    fn a_new_user_refuses_what_a_stored_one_still_reads() {
        let now = chrono::Utc::now();
        let make = |ident: &str| {
            User::new(
                "1f0a7b2e-4c91-4e3f-9b2a-8d0123456789",
                "2f0a7b2e-4c91-4e3f-9b2a-8d0123456789",
                ident,
                "Name",
                EntityState::Active,
                UserId::system(),
                now,
            )
        };
        assert!(make("admin").is_ok());
        assert!(make("admin ").is_err());
        assert!(make("admin\u{00A0}").is_err());
        // The same value read back from a store still validates.
        let mut stored = make("admin").unwrap();
        stored.identifier = "admin ".into();
        assert!(stored.validate().is_ok());
    }
}

#[cfg(test)]
mod new_tenant_identifier_tests {
    use super::*;

    fn make(identifier: &str) -> Result<Tenant, String> {
        Tenant::new(
            "2f0a7b2e-4c91-4e3f-9b2a-8d0123456789",
            identifier,
            "Tenant",
            EntityState::Active,
            UserId::system(),
            chrono::Utc::now(),
        )
    }

    #[test]
    fn a_new_tenant_refuses_look_alike_identifiers_but_a_stored_one_still_reads() {
        assert!(make("acme").is_ok());
        for bad in [
            "acme\u{200B}",
            "cafe\u{0301}",
            "acme ",
            "acme\u{00A0}",
            "\u{FF41}cme",
        ] {
            assert!(make(bad).is_err(), "{bad:?}");
        }
        let mut stored = make("acme").unwrap();
        stored.identifier = "acme ".into();
        assert!(stored.validate().is_ok(), "read-back stays lenient");
    }
}
