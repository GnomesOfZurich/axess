//! Core storage traits for authentication: `IdentityStore` and `FactorStore`.
//!
//! These replace the monolithic `AuthnBackend` trait. They use native `async fn`
//! (Rust 1.75+), no `async-trait`, and typed [`UserId`]/[`TenantId`] for identifiers.

use crate::authn::{
    event::AuthEvent,
    factor::{FactorConfig, FactorKind, PasswordRules},
    ids::{TenantId, UserId},
    types::{AuthnScope, EntityState, LockoutPolicy, StatusDetail, Tenant, User},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── AuditQuery (capability trait) ─────────────────────────────────────────────

/// Optional filters for [`AuditQuery::query_events`].
///
/// All fields are optional and combined with AND. The outer `tenant_id`
/// is supplied as a separate argument and is always required.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQueryFilter {
    /// Restrict to events for this user. Cross-checked against
    /// `tenant_id` at query time; an out-of-tenant `user_id` returns
    /// an empty result rather than leaking events.
    pub user_id: Option<UserId>,
    /// Restrict to events of this type. `None` means all types.
    pub event_type: Option<crate::authn::event::AuthEventType>,
    /// Restrict to events with this status. `None` means all statuses.
    pub status: Option<crate::authn::event::AuthEventStatus>,
    /// Inclusive lower bound on `event_time`.
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// Exclusive upper bound on `event_time`.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    /// When `true`, also return events with `tenant_id IS NULL`
    /// (platform-level rail events, e.g. login attempts for unknown
    /// users that never resolved a tenant). Default `true` so the trait
    /// matches the SQL most operators want for tenant audit screens.
    /// Flip to `false` for views that should hide platform noise.
    pub include_unscoped: bool,
    /// Maximum number of rows to return (newest-first). 0 means
    /// "backend default"; implementations should pick a safe cap
    /// (e.g. 1000) so a forgotten limit cannot scan the whole table.
    pub limit: u32,
}

/// Tenant-scoped audit-log query, exposed as an opt-in
/// capability trait separate from [`IdentityStore`].
///
/// `IdentityStore` is required of every backend (mock, in-memory,
/// SQLite, etc). Most of those backends have no audit table and no
/// way to answer a query, and putting the method on `IdentityStore`
/// with a default `Ok(Vec::new())` would silently turn unsupported
/// backends into "no events found" lies on a SOC dashboard. The
/// capability split makes support explicit: an application generic
/// over `S: IdentityStore + AuditQuery` won't compile against a
/// store that lacks audit support, and a runtime caller can probe
/// via downcast or trait-object dispatch.
///
/// # Tenant scoping
///
/// Every returned event MUST satisfy
/// `event.tenant_id == Some(tenant_id)
/// OR (filter.include_unscoped AND event.tenant_id IS NULL)`.
/// The outer `tenant_id` is required: this trait centralises the
/// `WHERE tenant_id = ? OR tenant_id IS NULL` rail so applications
/// no longer hand-roll it (the common bug: dropping the second
/// clause hides platform-level events; dropping the first clause
/// leaks events across tenants; both seen in the wild).
pub trait AuditQuery: Send + Sync + 'static {
    /// Backend error type. Typically aliased to the matching
    /// `IdentityStore::Error` so downstream `Result` types stay
    /// homogeneous.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Tenant-scoped query over the audit log. Newest first, capped
    /// at `filter.limit` (or the backend's safe default when 0).
    fn query_events(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> impl std::future::Future<Output = Result<Vec<AuthEvent>, Self::Error>> + Send;
}

// ── Identity trait tier ──────────────────────────────────────────────────────
//
// The identity-storage role is split into three traits that form a linear
// tower of capabilities:
//
//   IdentityLookup     pure read methods. Sufficient for middleware,
//                      route guards, and read-only validators that take
//                      `Arc<dyn IdentityLookup>` without dragging the
//                      full write surface through their generics.
//
//   IdentityAuthnLog   extends IdentityLookup with the per-authn-attempt
//                      writes (audit emit, lockout counter, last-login
//                      timestamp). Required for any backend that drives
//                      a live login pipeline; `AuthnService::new`
//                      bounds on this tier.
//
//   IdentityAdmin      extends IdentityAuthnLog with the privileged
//                      write surface: tenant/user provisioning,
//                      password history, reset-token storage,
//                      suspension, GDPR erasure. Adopters that provision
//                      users out-of-band (SCIM, ops scripts,
//                      read-replicas) skip this tier and lose only the
//                      admin entry points on `AuthnService`; login and
//                      audit keep working.
//
// `IdentityStore` is preserved as an umbrella alias for the all-three-tier
// case (the typical production backend); the blanket impl below lets any
// `T: IdentityAdmin` satisfy `IdentityStore` automatically. Most production
// code that takes `T: IdentityStore` keeps compiling unchanged.

/// Base read-only identity lookup. Every authentication path
/// (middleware, validators, login flows, admin operations) needs at
/// least this much.
///
/// **Dyn-compatibility.** This trait uses `impl Future` returns and is
/// therefore *not* `dyn`-compatible; `Arc<dyn IdentityLookup>` will not
/// compile. Middleware that wants to drop the `<I: IdentityStore>`
/// generic should reach for [`SessionValidator`](super::service::SessionValidator)
/// (and its `session_validator_with_identity_check` constructor), which
/// erases the identity store behind a private dyn-safe wrapper trait.
/// Custom middleware that needs the same trick should mirror that
/// pattern: a local trait with `Pin<Box<dyn Future>>` returns and a
/// blanket impl over `T: IdentityLookup + 'static`.
pub trait IdentityLookup: Send + Sync + 'static {
    /// Error type returned by storage operations. Reused by the
    /// extension traits ([`IdentityAuthnLog`] / [`IdentityAdmin`])
    /// via `Self::Error` so adopters declare the type exactly once
    /// on their `IdentityLookup` impl.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Look up a user by their login identifier within a tenant.
    ///
    /// # Latency must not depend on whether the identifier exists
    ///
    /// `begin_login` equalises response time between known and unknown
    /// identifiers by running the same store calls against a dummy id on
    /// the unknown path. That defence assumes this lookup costs roughly
    /// the same either way, and the dummy is a **fresh random UUID**, so
    /// it can never hit a cache.
    ///
    /// An implementation that caches positive lookups and not negative
    /// ones therefore does not merely weaken the equalisation, it
    /// **inverts** it: a known identifier answers from cache while an
    /// unknown one goes to the database, and probing a known identifier
    /// warms its entry and widens the gap. That is a user-enumeration
    /// oracle, restored by a change that looks purely like an
    /// optimisation.
    ///
    /// If you cache, cache misses on the same terms as hits. The same
    /// applies to [`account_status`](Self::account_status), which the
    /// equalisation also calls.
    fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send;

    /// Look up a user by their opaque ID.
    ///
    /// **Tenant scope is the caller's responsibility.** This
    /// method does NOT filter by tenant; consumers must check
    /// `user.tenant_id` against the caller's expected tenant before
    /// acting on the result, or use the
    /// [`get_user_in_tenant`](Self::get_user_in_tenant) convenience
    /// wrapper which encodes the tenant guard at the trait surface.
    /// The unscoped form remains available for system-tenant admin paths
    /// (platform-operator console) where cross-tenant access is the
    /// intent.
    fn get_user(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send;

    /// Look up a user by ID, requiring the result's `tenant_id` to match
    /// `expected_tenant`. Returns `Ok(None)` when the user does not exist
    /// OR when the user exists in a different tenant; the caller cannot
    /// distinguish "no such user" from "wrong tenant", which is the
    /// intended IDOR-mitigation behaviour. Use
    /// [`get_user`](Self::get_user) only when cross-tenant lookup is
    /// explicitly the intent.
    fn get_user_in_tenant(
        &self,
        user_id: &UserId,
        expected_tenant: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send {
        async move {
            match self.get_user(user_id).await? {
                Some(u) if &u.tenant_id == expected_tenant => Ok(Some(u)),
                _ => Ok(None),
            }
        }
    }

    /// Look up a tenant by its identifier (slug, domain, etc.).
    fn find_tenant(
        &self,
        identifier: &str,
    ) -> impl std::future::Future<Output = Result<Option<Tenant>, Self::Error>> + Send;

    /// Return the default tenant. Used when the application is single-tenant.
    fn default_tenant(
        &self,
    ) -> impl std::future::Future<Output = Result<Tenant, Self::Error>> + Send;

    /// Return the current account status for a user. Called before each factor step.
    fn account_status(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<EntityState, Self::Error>> + Send;

    /// Return the global lockout policy. Default: 5 attempts, 15-minute lockout.
    fn lockout_policy(&self) -> LockoutPolicy {
        LockoutPolicy::default()
    }

    /// Return the lockout policy for a specific tenant.
    ///
    /// Override this to support per-tenant lockout configuration (e.g., Tenant A
    /// allows 3 attempts, Tenant B allows 10). Falls back to the global
    /// [`lockout_policy`](Self::lockout_policy) by default.
    fn lockout_policy_for_tenant(&self, tenant_id: &TenantId) -> LockoutPolicy {
        let _ = tenant_id;
        self.lockout_policy()
    }

    /// Return the password rules for a specific tenant.
    ///
    /// Override this to support per-tenant password policies (e.g., Tenant A
    /// requires 16-char passwords, Tenant B allows 12). Returns the global
    /// default `PasswordRules` by default.
    fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<PasswordRules, Self::Error>> + Send {
        let _ = tenant_id;
        std::future::ready(Ok(PasswordRules::default()))
    }

    /// Return the IP access policy for a tenant.
    ///
    /// Override to load per-tenant allowlists/denylists from your database.
    /// Default: empty policy (all IPs allowed).
    fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<crate::authn::types::IpPolicy, Self::Error>> + Send
    {
        let _ = tenant_id;
        std::future::ready(Ok(crate::authn::types::IpPolicy::default()))
    }
}

// ── IdentityAuthnLog ─────────────────────────────────────────────────────────

/// What an audit sink did with an event.
///
/// Distinguishes "I deliberately dropped this" from "I am broken", which
/// `Result<(), E>` alone cannot express: an `Err` fails the login, and an
/// `Ok(())` claims a write that may not have happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditOutcome {
    /// The event was durably recorded.
    #[default]
    Recorded,
    /// The event was deliberately dropped under load.
    ///
    /// The flow continues and `AuthnMetrics::audit_event_shed` fires. A
    /// gap in the trail is the cost; it is bounded and observable, where
    /// an exhausted store is neither.
    Shed,
}

/// Per-authn-attempt writes the login pipeline emits: audit events,
/// failed-attempt lockout counter, last-login timestamp.
///
/// Required by `AuthnService::new`; any backend that drives a live login
/// flow must implement this tier. SCIM-provisioned deployments that handle
/// user lifecycle out-of-band still implement this so login can record
/// audit + enforce lockout, but skip [`IdentityAdmin`] entirely.
///
/// Adopters that explicitly do NOT want audit / lockout / last-login can
/// wrap their [`IdentityLookup`] in [`NoopAuthnLog`] (see the testing
/// module) to satisfy the bound with no-op behaviour.
pub trait IdentityAuthnLog: IdentityLookup {
    /// Record an authentication event (audit log).
    ///
    /// Returning `Err` **fails the authentication**: an authentication that
    /// leaves no evidence has not, for evidence purposes, happened. Reserve
    /// it for a sink that is genuinely broken.
    ///
    /// Returning [`AuditOutcome::Shed`] says the event was deliberately
    /// dropped under load, and the flow continues. That is the valve for
    /// the one hazard this design creates: every failed login writes a row,
    /// including for identifiers that do not exist, so an unauthenticated
    /// caller can drive writes at your storage, and with no way to shed,
    /// exhausting it turns every login into a failure for every user.
    ///
    /// **Shed on a criterion independent of the identifier**: a global
    /// rate, a queue depth, a disk watermark. Shedding based on anything
    /// derived from *which* identifier was tried makes the drop observable
    /// per-identifier and reintroduces the user-enumeration oracle that
    /// emitting unattributed events exists to close.
    ///
    /// Note what shedding costs under attack: the flood that triggers it
    /// is the thing you least want unrecorded. If you shed selectively,
    /// prefer dropping by
    /// [`event_status`](crate::authn::event::AuthEvent::event_status) or
    /// [`event_type`](crate::authn::event::AuthEvent::event_type)
    /// successes before failures, say, because both are independent of
    /// the identifier and keep the security-relevant signal. Dropping
    /// uniformly is safe too, and simpler.
    fn record_event(
        &self,
        event: AuthEvent,
    ) -> impl std::future::Future<Output = Result<AuditOutcome, Self::Error>> + Send;

    /// Increment the failed attempt counter for a user. Returns the new count.
    ///
    /// The returned value is compared directly against
    /// [`LockoutPolicy::max_attempts`](crate::authn::types::LockoutPolicy),
    /// so the increment and the read **MUST** be atomic with respect to other
    /// writes: a single `UPDATE ... SET n = n + 1 RETURNING n`, or an
    /// equivalent the backend guarantees. A read-modify-write that loads the
    /// count, adds one and stores it back loses updates under concurrent
    /// failures, and an attacker running parallel attempts gets more of them
    /// than the policy allows.
    fn record_failed_attempt(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<u32, Self::Error>> + Send;

    /// Reset the failed attempt counter (call after successful authentication).
    fn reset_failed_attempts(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Record the timestamp of a successful authentication for a user.
    ///
    /// Called automatically by `complete_factor_step` when all factors pass.
    /// Default: no-op. Override to populate a "last login" column.
    fn record_last_login(
        &self,
        user_id: &UserId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let _ = (user_id, at);
        std::future::ready(Ok(()))
    }
}

// ── IdentityAdmin ────────────────────────────────────────────────────────────

/// Privileged write surface: tenant + user provisioning, password
/// history, reset-token storage, suspension, and GDPR erasure.
///
/// Required by admin entry points on [`AuthnService`](crate::authn::AuthnService) (signup, activate,
/// password reset, suspend, delete). Adopters whose user lifecycle is
/// managed out-of-band (SCIM, ops scripts, externally-provisioned
/// directories) skip this tier; login + audit + lockout still work
/// through [`IdentityAuthnLog`].
pub trait IdentityAdmin: IdentityAuthnLog {
    /// Insert a new tenant row.
    ///
    /// Returns an error if a tenant with the same `id` or `identifier`
    /// already exists. Callers typically invoke this through
    /// [`create_tenant`](crate::authn::provisioning::create_tenant) so
    /// factor and method rows are provisioned atomically alongside.
    fn create_tenant(
        &self,
        tenant: Tenant,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Create a new user. The user should typically be in [`EntityState::Candidate`]
    /// or [`EntityState::Pending`] state.
    ///
    /// Returns an error if a user with the same identifier already exists in the tenant.
    ///
    /// # Reserved IDs
    ///
    /// Implementations MUST reject calls where `user.id == UserId::system()`
    /// or `user.tenant_id == TenantId::system()` from any code path
    /// reachable by untrusted input (self-service signup, OAuth user
    /// upsert, etc.). The reserved system UUIDs identify the platform
    /// operator and must not be claimable through the same surface that
    /// regular tenants/users use. axess provides
    /// [`ensure_user_id_not_reserved`](super::ids::ensure_user_id_not_reserved)
    /// as a convenience guard for the common case.
    fn create_user(
        &self,
        user: User,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Transition a user to [`EntityState::Active`].
    ///
    /// Called after completing a signup workflow (e.g. email verification).
    fn activate_user(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Transition a user to [`EntityState::Suspended`] with the given reason.
    ///
    /// Existing authenticated sessions are not automatically
    /// invalidated; use middleware that checks
    /// [`account_status`](IdentityLookup::account_status) on each
    /// request, or combine with
    /// [`SessionRegistry::invalidate_user`](crate::session::store::SessionRegistry::invalidate_user).
    fn suspend_user(
        &self,
        user_id: &UserId,
        detail: StatusDetail,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Permanently erase a user and all directly-attributable personal
    /// data: the GDPR Article 17 "right to erasure" primitive.
    /// Implementations MUST delete (or irreversibly anonymise) the user
    /// row, all factor configs under `AuthnScope::User`, refresh tokens,
    /// persisted sessions, recorded password history, and any
    /// application-level rows whose retention basis is the user's
    /// (now-withdrawn) consent. Audit logs and regulated records (KYC,
    /// transactions) MAY be retained under independent lawful bases,
    /// with user-identifying columns pseudonymised. After `Ok(())`,
    /// `get_user` / `find_user` / `account_status` MUST report the user
    /// gone and any in-flight session MUST fail its next `is_valid`
    /// check. The default impl panics so a missing override surfaces
    /// loudly the first time an admin tries to honour an erasure
    /// request; production backends serving EU/UK users MUST override.
    fn delete_user(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let _ = user_id;
        async {
            unimplemented!(
                "IdentityAdmin::delete_user is required for GDPR Article 17 \
                 (right to erasure). Override this method on your backend to \
                 delete the user row, factor configs, refresh tokens, sessions, \
                 and password history. See the trait method docs for the full \
                 contract."
            )
        }
    }
}

// ── IdentityStore (umbrella) ─────────────────────────────────────────────────

/// Umbrella alias for the all-three-tier identity store: the typical
/// production-backend shape. The blanket impl below makes any
/// `T: IdentityAdmin` satisfy `IdentityStore` automatically, so any
/// adopter that implements all three tiers (`IdentityLookup` +
/// `IdentityAuthnLog` + `IdentityAdmin`) is automatically an
/// `IdentityStore`. Most existing code that takes `T: IdentityStore`
/// keeps compiling unchanged.
pub trait IdentityStore: IdentityAdmin {}
impl<T: IdentityAdmin> IdentityStore for T {}

// ── IdentityPasswordReset ────────────────────────────────────────────────────

/// Persistence for the out-of-band password-recovery flow.
///
/// Deliberately separate from [`IdentityAdmin`], and deliberately
/// without default bodies, because neither possible default is safe.
///
/// A default that panics turns
/// [`AuthnService::begin_password_reset`](crate::authn::service::AuthnService::begin_password_reset)
/// into a user-enumeration oracle. That function answers `Ok(None)` for
/// an identifier it cannot find and reaches the store only for one it
/// can, so an unattended backend would answer an unauthenticated
/// "forgot password" request with 200 for an address that is not
/// registered and a panic for one that is. The function equalizes its
/// timing precisely to avoid leaking that, and a panicking default gives
/// it away on the status code.
///
/// A default that silently succeeds is worse: recovery appears to work,
/// no token is ever stored, and every subsequent verification fails for
/// a reason nothing explains.
///
/// So the requirement is moved into the type system. A store that does
/// not implement this trait cannot call the reset flow, and the failure
/// is a compile error naming the two methods rather than a runtime
/// panic on an unauthenticated route.
pub trait IdentityPasswordReset: IdentityLookup {
    /// Persist `(user_id, token_hash, expires_at)`, replacing any token
    /// already outstanding for that user. Implementations MUST write
    /// atomically (a single-row upsert), so two concurrent requests
    /// cannot leave two live tokens for one account.
    ///
    /// Store the **hash**, never the token: a database reader must not be
    /// able to complete a reset.
    fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Look up the stored hash for `user_id`, compare it against
    /// `token_hash` in **constant time**, check the expiry, and delete the
    /// row on a successful match so the token is single-use.
    ///
    /// Return `Ok(false)` for absent, expired and mismatched alike; the
    /// caller does not distinguish them and neither should the response.
    fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;
}

/// Storage for password-reuse prevention: the write and read sides of a
/// per-user password history.
///
/// Carved out of [`IdentityAdmin`], where both methods had default bodies
/// that panicked. The write side is called on **every** password change,
/// unguarded, so a backend that had not overridden it unwound the first
/// time any user changed their password, and the method looked optional,
/// because a defaulted trait method does.
///
/// With no defaults here, a store that cannot keep history simply does not
/// implement this trait, and the password-change flow is unavailable to it
/// at compile time rather than at the worst moment. This is the same
/// treatment [`IdentityPasswordReset`] received, for the same reason.
///
/// Required by SOC2, PCI-DSS, and NIST SP 800-63B §5.1.1.2 for regulated
/// deployments; a deployment with no reuse policy can skip it entirely.
pub trait IdentityPasswordHistory: IdentityLookup {
    /// Store a password hash in the user's password history.
    ///
    /// Called after a successful password change, with the hash being
    /// *replaced* and then with the new one, so the history reflects what
    /// was actually in force.
    ///
    /// Store the hash, never the password. Implementations should bound
    /// the history they retain; nothing here evicts for you.
    fn record_password_hash(
        &self,
        user_id: &UserId,
        hash: &str,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Return the last `count` password hashes for a user, most recent
    /// first.
    ///
    /// The read side of the reuse check: the caller compares a candidate
    /// against each entry. Returning fewer than `count` is fine and means
    /// the user has no longer history; returning them out of order is not,
    /// because a bounded check would then test the wrong ones.
    fn password_history(
        &self,
        user_id: &UserId,
        count: usize,
    ) -> impl std::future::Future<Output = Result<Vec<String>, Self::Error>> + Send;
}

// ── NoopAuthnLog adopter helper ──────────────────────────────────────────────

/// Wraps an [`IdentityLookup`] backend with a no-op [`IdentityAuthnLog`]
/// impl on top, so it satisfies the `AuthnService::new` bound without
/// the adopter writing audit + lockout impls.
///
/// **Semantics, read carefully before reaching for this:**
///
/// - `record_event` silently discards every audit event. No SOC trail.
/// - `record_failed_attempt` always returns `Ok(1)`. Lockout policy is
///   effectively disabled; the counter never accumulates beyond 1, so
///   `max_attempts` thresholds are never crossed regardless of how
///   many failures occur.
/// - `reset_failed_attempts` is a no-op.
/// - `record_last_login` inherits the trait default no-op.
///
/// Appropriate uses:
///
/// - Integration tests / fixtures that don't exercise the lockout or
///   audit paths.
/// - Read-replica integrations where audit goes through a separate
///   pipeline (e.g. database CDC, a sidecar log forwarder).
/// - Prototypes that want login working before the audit table is
///   designed.
///
/// **Production deployments must override `IdentityAuthnLog` directly.**
/// Routing failed attempts to `Ok(1)` is a security regression on any
/// surface accepting untrusted input.
pub struct NoopAuthnLog<L>(pub L);

impl<L: IdentityLookup + Clone> Clone for NoopAuthnLog<L> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<L: IdentityLookup> IdentityLookup for NoopAuthnLog<L> {
    type Error = L::Error;

    fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send {
        self.0.find_user(identifier, tenant_id)
    }

    fn get_user(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send {
        self.0.get_user(user_id)
    }

    fn find_tenant(
        &self,
        identifier: &str,
    ) -> impl std::future::Future<Output = Result<Option<Tenant>, Self::Error>> + Send {
        self.0.find_tenant(identifier)
    }

    fn default_tenant(
        &self,
    ) -> impl std::future::Future<Output = Result<Tenant, Self::Error>> + Send {
        self.0.default_tenant()
    }

    fn account_status(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<EntityState, Self::Error>> + Send {
        self.0.account_status(user_id)
    }

    fn lockout_policy(&self) -> LockoutPolicy {
        self.0.lockout_policy()
    }

    fn lockout_policy_for_tenant(&self, tenant_id: &TenantId) -> LockoutPolicy {
        self.0.lockout_policy_for_tenant(tenant_id)
    }

    fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<PasswordRules, Self::Error>> + Send {
        self.0.password_rules_for_tenant(tenant_id)
    }

    fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<crate::authn::types::IpPolicy, Self::Error>> + Send
    {
        self.0.ip_policy_for_tenant(tenant_id)
    }
}

impl<L: IdentityLookup> IdentityAuthnLog for NoopAuthnLog<L> {
    async fn record_event(&self, event: AuthEvent) -> Result<AuditOutcome, Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            "NoopAuthnLog: event discarded (no SOC trail wired up)",
        );
        // Honest rather than convenient: this sink drops every event, so
        // it reports every event as shed. `Recorded` would claim a write
        // that never happens.
        Ok(AuditOutcome::Shed)
    }

    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            %user_id,
            "NoopAuthnLog: failed attempt not persisted; lockout policy disabled",
        );
        Ok(1)
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        tracing::trace!(
            target: "axess::authn::noop_log",
            %user_id,
            "NoopAuthnLog: reset_failed_attempts is a no-op",
        );
        Ok(())
    }
}

// ── ResolvedFactor ────────────────────────────────────────────────────────────

/// A factor config together with the scope it was resolved from.
///
/// Returned by [`FactorStore::resolve_factor`]. Callers use `resolved_from`
/// to CAS at the correct scope (as the internal factor-verification
/// pipeline does) and to log which tier of the User → Tenant → System
/// chain served the request.
#[derive(Debug, Clone)]
pub struct ResolvedFactor {
    /// The factor configuration.
    pub config: FactorConfig,
    /// The scope where `config` was found (never broader than the scope
    /// the caller passed to `resolve_factor`).
    pub resolved_from: AuthnScope,
}

// ── FactorStore ───────────────────────────────────────────────────────────────

/// Factor credential storage. Implement alongside [`IdentityStore`] (usually same DB struct).
///
/// Provides typed [`FactorConfig`], not `HashMap<String, JsonValue>`.
///
/// # Two loaders, two intents
///
/// Configuration lookup in axess separates the runtime auth path from the
/// admin/display path. Mixing the two on one method invites the bug where
/// admin code silently walks a fallback chain, or auth code returns a
/// system default when the caller wanted "no config at this exact scope."
///
/// - [`resolve_factor`](Self::resolve_factor): RUNTIME auth. Walks
///   the User → Tenant → System resolution chain (see
///   [`AuthnScope::resolution_chain`]) and returns the first hit as
///   [`ResolvedFactor`], carrying the config AND the scope it lives at.
///   Backends should implement this as a single storage query that
///   walks the chain in one round trip.
///
/// - [`load_factor`](Self::load_factor): ADMIN / display. Fetches
///   the config at EXACTLY the requested scope with no fallback. Use for
///   configuration UIs, provisioning tooling, migration scripts, and
///   anything answering "what did this tenant / user explicitly configure?"
///
/// The service layer's authentication code path uses
/// [`resolve_factor`](Self::resolve_factor) exclusively;
/// [`load_factor`](Self::load_factor) is never on the auth hot path.
///
/// # System-scope semantics
///
/// [`AuthnScope::System`] holds platform-owned defaults. Tenants adopt
/// system defaults explicitly (at provisioning or later reconfiguration);
/// nothing silent about it. Storage-wise, System rows live under the
/// reserved [`TenantId::system`] tenant: there is no NULL-tenant
/// encoding for configuration scope. See `docs/authentication/scope.md`.
pub trait FactorStore: Send + Sync + 'static {
    /// Error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Runtime factor-config resolution: walk User → Tenant → System and
    /// return the first hit, or `Ok(None)` if the chain is empty end to end.
    ///
    /// The returned [`ResolvedFactor`] carries both the config and the
    /// scope it was resolved from. Callers use `resolved_from` to CAS
    /// at the right scope (a config that resolved from Tenant scope must
    /// not be CAS-swapped against a User-scope row).
    ///
    /// Backends SHOULD implement this as a single query that walks the
    /// resolution chain in-storage (e.g. `ORDER BY` with a `CASE` on
    /// scope narrowness). A naïve implementation that iterates over
    /// [`AuthnScope::resolution_chain`] and issues one
    /// [`load_factor`](Self::load_factor) call per tier is correct
    /// but pays N storage round trips per authentication step.
    fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> impl std::future::Future<Output = Result<Option<ResolvedFactor>, Self::Error>> + Send;

    /// Admin / display factor-config lookup: fetch the config at EXACTLY
    /// this scope, with no fallback. Returns `Ok(None)` if no row matches.
    ///
    /// Use for configuration UIs answering "what did this tenant
    /// explicitly configure?", for provisioning tooling that needs to
    /// know whether a User-scope override exists before writing, and
    /// for admin export / migration. Never on the runtime auth path:
    /// use [`resolve_factor`](Self::resolve_factor) there.
    fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> impl std::future::Future<Output = Result<Option<FactorConfig>, Self::Error>> + Send;

    /// Persist an updated factor configuration (e.g., after TOTP counter increment or HOTP advance).
    fn save_factor(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically replace the stored factor config with `updated` only if the
    /// currently stored config matches `prior`. Returns `Ok(true)` on
    /// successful swap and `Ok(false)` if the stored value has changed since
    /// it was loaded (indicating a concurrent update; for TOTP/HOTP this
    /// means the credential has already been spent in another request).
    ///
    /// This method is **required**: implementations MUST make the conditional
    /// update atomic with respect to other writes; typically a single
    /// `UPDATE ... WHERE` statement using the prior values as a guard, or
    /// an equivalent single-transaction primitive on the backend. A
    /// non-atomic load-compare-save would re-open the TOTP/HOTP replay
    /// window the trait exists to close.
    ///
    /// **Comparison semantic is backend-defined**, not byte-equality on the
    /// serialized blob. SQL backends SHOULD compare on a monotonic
    /// generation/version column, or on the specific mutable columns the
    /// factor advances (`last_step` for TOTP, `counter`+`attempt_count` for
    /// HOTP, etc.), not on the full serialized `FactorConfig`. Byte-equality
    /// on the serialized form couples in-flight CAS attempts to the
    /// serialized shape of every `FactorConfig` variant; a serde-compatible
    /// change to an unrelated field would invalidate a concurrent
    /// verification's CAS, masquerading as replay. The `prior` argument is
    /// the value the caller loaded earlier; the backend decides what
    /// "matches" means in its storage model.
    fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;

    /// Return the ordered list of **enabled** authentication methods
    /// available for a user.
    ///
    /// Implementations MUST exclude methods whose `enabled` column is
    /// `false`; a disabled method is not a valid login path, whether the
    /// disable is temporary (rollout / maintenance) or permanent.
    fn available_methods(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Vec<AuthMethod>, Self::Error>> + Send;

    /// Persist an authentication method at the given scope. Idempotent on
    /// `(scope, method.name)`; inserting a method with the same name
    /// replaces the previous config.
    ///
    /// Implementations SHOULD set `enabled = true` for newly persisted
    /// methods unless the `method`'s shape carries an explicit enabled
    /// flag (axess-core's `AuthMethod` does not currently have one; the
    /// enabled bit lives at the storage level in implementations such
    /// as the example SQLite backend's `auth_methods.enabled` column).
    fn save_method(
        &self,
        scope: &AuthnScope,
        method: AuthMethod,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Remove an authentication method identified by `(scope, name)`.
    ///
    /// Returns `Ok(())` whether or not a matching row existed. For soft
    /// lifecycle management (disable instead of delete), use
    /// [`set_method_enabled`](Self::set_method_enabled).
    fn remove_method(
        &self,
        scope: &AuthnScope,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Toggle an authentication method's `enabled` flag without
    /// deleting the row. Used for maintenance windows, staged rollouts,
    /// and as one of the operator levers for "lock this tenant out"
    /// (see `docs/identity/tenancy.md`).
    ///
    /// Returns `Ok(false)` if no method matched, `Ok(true)` on update.
    fn set_method_enabled(
        &self,
        scope: &AuthnScope,
        name: &str,
        enabled: bool,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;
}

// ── AuthMethod ────────────────────────────────────────────────────────────────

/// An authentication method: a named sequence of factor steps.
///
/// Each step is either a required factor or a choice among alternatives.
///
/// # Examples
///
/// Sequential MFA (password then TOTP):
/// ```text
/// AuthMethod {
///     name: "password+totp",
///     steps: vec![FactorStep::Required(Password), FactorStep::Required(Totp)],
///     ..
/// }
/// ```
///
/// Factor choice (FIDO2 or password):
/// ```text
/// AuthMethod {
///     name: "passkey-or-password",
///     steps: vec![FactorStep::AnyOf(vec![Fido2, Password])],
///     ..
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    /// Human-readable method name, e.g. `"password"`, `"password+totp"`.
    pub name: Arc<str>,
    /// Factor steps in the order they must be completed.
    ///
    /// Each step is either [`FactorStep::Required`](crate::authn::factor::FactorStep::Required) (exactly one factor) or
    /// [`FactorStep::AnyOf`](crate::authn::factor::FactorStep::AnyOf) (user chooses one from the list).
    ///
    /// For backward compatibility, use the [`factors`](AuthMethod::factors)
    /// convenience method if you only need simple sequential flows.
    pub steps: Vec<crate::authn::factor::FactorStep>,
    /// The scope at which this method is defined.
    pub scope: AuthnScope,
}

impl AuthMethod {
    /// Convenience: create a method from a flat list of required factors (sequential MFA).
    pub fn sequential(
        name: impl Into<Arc<str>>,
        factors: Vec<FactorKind>,
        scope: AuthnScope,
    ) -> Self {
        Self {
            name: name.into(),
            steps: factors
                .into_iter()
                .map(crate::authn::factor::FactorStep::Required)
                .collect(),
            scope,
        }
    }

    /// Return the flat list of factor kinds for simple sequential methods.
    ///
    /// For methods using `AnyOf` steps, this returns the first choice of
    /// each `AnyOf` step; use `steps` directly for full fidelity.
    pub fn factors(&self) -> Vec<FactorKind> {
        self.steps
            .iter()
            .map(|step| match step {
                crate::authn::factor::FactorStep::Required(k) => k.clone(),
                crate::authn::factor::FactorStep::AnyOf(choices) => {
                    choices.first().cloned().unwrap_or(FactorKind::Password)
                }
            })
            .collect()
    }
}

// ── AuthnBackend convenience supertrait ───────────────────────────────────────

/// Convenience supertrait for types that implement both [`IdentityStore`]
/// and [`FactorStore`] with the same error type.
///
/// Most applications implement both traits on the same database-backed struct;
/// `AuthnService::from_backend(backend)` accepts any `B: AuthnBackend + Clone`
/// and avoids the universal `(b.clone(), b)` ceremony at every call site.
///
/// `IdentityStore` is itself an umbrella alias for the three-tier identity
/// surface (`IdentityLookup + IdentityAuthnLog + IdentityAdmin`), so
/// `AuthnBackend` resolves transitively to "all three identity tiers + the
/// factor store, sharing one `Error` type". Adopters who skip
/// [`IdentityAdmin`] (e.g. SCIM-provisioned deployments) construct the
/// service with `AuthnService::new(identity, factors)` directly instead
/// of the `from_backend` helper.
pub trait AuthnBackend: IdentityStore<Error = <Self as FactorStore>::Error> + FactorStore {}

impl<T> AuthnBackend for T where
    T: IdentityStore + FactorStore + IdentityStore<Error = <T as FactorStore>::Error>
{
}

#[cfg(test)]
mod noop_authn_log_tests;

#[cfg(test)]
mod store_tests;

#[cfg(test)]
mod password_history_capability_tests {
    //! The property that matters is a compile-time one: a store without
    //! password history cannot reach the password-change flow, because the
    //! flow is bounded on [`IdentityPasswordHistory`] and the trait has no
    //! default bodies to inherit.
    //!
    //! That cannot be asserted at runtime: a test that failed to compile
    //! would fail the build rather than the test. What is checked here is
    //! the thing that would silently undo it: a default body reappearing,
    //! which would make the bound satisfiable by any `IdentityAdmin` again
    //! and restore the panic this carve-out removed.

    /// Fails to compile if either method gains a default body, because a
    /// defaulted method would let this empty impl pass.
    #[test]
    fn trait_has_no_default_bodies() {
        let src = include_str!("store.rs");
        let start = src
            .find("pub trait IdentityPasswordHistory")
            .expect("trait must exist");
        let body = &src[start..];
        let end = body.find("\n}\n").expect("trait must be closed");
        let decl = &body[..end];

        assert!(
            !decl.contains('{') || decl.matches('{').count() == 1,
            "IdentityPasswordHistory gained a method body; the point of the \
             carve-out is that a store which cannot keep history fails to \
             compile rather than panicking mid password change"
        );
        assert!(
            !decl.contains("unimplemented!") && !decl.contains("todo!"),
            "a panicking default reappeared in IdentityPasswordHistory"
        );
        for m in ["fn record_password_hash", "fn password_history"] {
            assert!(decl.contains(m), "{m} must live on this trait");
        }
    }
}
