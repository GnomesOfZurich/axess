//! Core storage traits for authentication: `IdentityStore` and `FactorStore`.
//!
//! These replace the monolithic `AuthnBackend` trait. They use native `async fn`
//! (Rust 1.75+), no `async-trait`, and typed [`UserId`]/[`TenantId`] for identifiers.

use crate::authn::{
    factor::{FactorConfig, FactorKind, PasswordRules},
    ids::{TenantId, UserId},
    types::{AuthnScope, EntityState, LockoutPolicy, StatusDetail, Tenant, User},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

mod audit_query;
pub use audit_query::{AuditQuery, EventQueryFilter};

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

    /// The tenant `user_id` belongs to, or `Ok(None)` when no such user
    /// exists. Called on every request by the session validator's tenant
    /// cross-check, which needs nothing else about the user.
    ///
    /// The default loads the whole user through
    /// [`get_user`](Self::get_user). Override it with a query that selects
    /// only the tenant column when a user row is wide or a read crosses a
    /// network.
    fn get_user_tenant(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<Option<TenantId>, Self::Error>> + Send {
        async move { Ok(self.get_user(user_id).await?.map(|u| u.tenant_id)) }
    }

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

    /// Look up a tenant by its id, or `Ok(None)` when none exists.
    fn get_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<Tenant>, Self::Error>> + Send;

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

    /// Return the lockout policy for a tenant.
    ///
    /// Required, like the other policy methods below: a provided default
    /// would let a decorator that forgets to forward it switch the tenant's
    /// policy off without a compile error. A store with one policy for every
    /// tenant returns it whatever `tenant_id` is
    /// ([`LockoutPolicy::default`] is 5 attempts and a 15-minute lockout).
    fn lockout_policy_for_tenant(&self, tenant_id: &TenantId) -> LockoutPolicy;

    /// Return the password rules for a tenant (e.g., tenant A requires
    /// 16-character passwords, tenant B allows 12). A store with one set of
    /// rules returns it whatever `tenant_id` is; [`PasswordRules::default`]
    /// is the library's.
    fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<PasswordRules, Self::Error>> + Send;

    /// Return the IP access policy for a tenant, from your database or
    /// configuration. [`IpPolicy::default`](crate::authn::types::IpPolicy)
    /// (an empty policy) allows every address.
    fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<crate::authn::types::IpPolicy, Self::Error>> + Send;
}

mod authn_log;
pub use authn_log::{AuditOutcome, IdentityAuthnLog};

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
    /// check. There is no default body: a backend that cannot erase does
    /// not compile, instead of panicking the first time an admin honours an
    /// erasure request. The in-memory backend and the sqlite example show
    /// the set of rows to delete.
    fn delete_user(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Delete up to `limit` users that are still
    /// [`Candidate`](EntityState::Candidate) and were created before
    /// `before`, with the same erasure as [`delete_user`](Self::delete_user),
    /// and return the users deleted so the caller can audit each one. A user
    /// in any other state is never touched. An empty result means there was
    /// nothing to delete.
    ///
    /// The sweep behind
    /// [`purge_expired_candidates`](crate::authn::service::RequestAuthnService::purge_expired_candidates):
    /// an unverified signup holds its identifier only for a bounded time, and
    /// this reaps the ones nobody asks for again. No default body: a store
    /// that cannot list by age and state does not compile.
    fn delete_candidates_created_before(
        &self,
        before: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<User>, Self::Error>> + Send;
}

// ── IdentityStore (umbrella) ─────────────────────────────────────────────────

/// Umbrella alias for the all-three-tier identity store: the typical
/// production-backend shape. The blanket impl below makes any
/// `T: IdentityAdmin` an `IdentityStore`.
pub trait IdentityStore: IdentityAdmin {}
impl<T: IdentityAdmin> IdentityStore for T {}

// ── IdentityPasswordReset ────────────────────────────────────────────────────

/// Persistence for the out-of-band password-recovery flow.
///
/// Deliberately separate from [`IdentityAdmin`], and deliberately
/// without default bodies, because neither possible default is safe.
///
/// A default that panics would fail
/// [`RequestAuthnService::begin_password_reset`](crate::authn::service::RequestAuthnService::begin_password_reset)
/// on an unauthenticated route, and one that silently succeeds is worse:
/// recovery appears to work while no token is ever stored.
///
/// So the requirement is moved into the type system. A store that does
/// not implement this trait cannot call the reset flow, and the failure
/// is a compile error naming the two methods rather than a runtime
/// panic on an unauthenticated route.
pub trait IdentityPasswordReset: IdentityLookup {
    /// Add `(user_id, token_hash, expires_at)` to the user's live reset
    /// tokens, unless the user already holds `max_live` of them. Returns
    /// `Ok(true)` when the token was stored and `Ok(false)` when it was not,
    /// because the user's live tokens are full.
    ///
    /// A new token never invalidates an earlier live one: a third party who
    /// asks for a reset must not be able to kill the link in the owner's
    /// inbox. A token is live while `expires_at > now`; expired tokens of the
    /// user are removed here. Counting the live tokens, removing the expired
    /// ones and inserting are one atomic step (a transaction, a script), so
    /// two concurrent requests cannot both take the last slot. Storing a
    /// hash that is already held is `Ok(true)` and changes nothing.
    ///
    /// Store the **hash**, never the token: a database reader must not be
    /// able to complete a reset.
    fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
        max_live: usize,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;

    /// Compare the stored hashes for `user_id` with `token_hash` in **constant time**, deleting
    /// **every** token of the user on a match (using any one consumes them all, so a link
    /// that was mailed earlier cannot be used after the reset). Expired means `expires_at <= now`, the caller's clock reading.
    ///
    /// Return `Ok(false)` for absent, expired and mismatched alike (no token of the user is
    /// deleted then); the
    /// caller does not distinguish them and neither should the response.
    fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;

    /// [`verify_reset_token`](Self::verify_reset_token)'s constant-time
    /// comparison, leaving the row in place. The reset flow checks with this
    /// first and spends the token last, so a refused password keeps the link.
    fn check_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
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

mod noop;
pub use noop::NoopAuthnLog;

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

    /// Atomically store `config` at exactly `scope` only if no row of the
    /// same kind exists there yet. Returns `Ok(true)` when the row was
    /// inserted and `Ok(false)` when a row already existed (left
    /// untouched).
    ///
    /// Used for the first write of per-user mutable state (TOTP replay
    /// step, HOTP counter, failure counters) when the factor was
    /// inherited from the tenant or system scope. Of two concurrent
    /// first writes, exactly one must see `Ok(true)`; the other is a
    /// replay. Implementations MUST make this atomic (for SQL, an
    /// `INSERT ... ON CONFLICT DO NOTHING` checked via rows affected);
    /// a load-then-save would re-open the replay window.
    fn insert_factor_if_absent(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
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

    /// The user of `tenant_id` who holds a passkey with `credential_id`
    /// (the raw credential id bytes), or `Ok(None)` when no user of that
    /// tenant does.
    ///
    /// `finish_fido2_registration` calls this before it stores a passkey
    /// and refuses a credential id that another user of the tenant already
    /// holds, so one authenticator credential cannot be registered to two
    /// accounts. The lookup is by exact credential id within the tenant;
    /// the user's own holding is returned like any other and the caller
    /// compares.
    ///
    /// The default answers `Ok(None)`: a store that does not implement the
    /// lookup admits every credential id, and the cross-user check does not
    /// run. This keeps stores written against an earlier release building.
    /// The in-tree stores (the mock store and the SQLite example) answer. A
    /// store that keeps passkeys inside an opaque or sealed config row
    /// should keep an index of `(tenant_id, credential_id, user_id)` written
    /// together with the config, or it should leave the default in place and
    /// keep that check in the application.
    ///
    /// An `Err` is not read as "no holder": the registration fails.
    fn fido2_credential_holder(
        &self,
        tenant_id: &TenantId,
        credential_id: &[u8],
    ) -> impl std::future::Future<Output = Result<Option<UserId>, Self::Error>> + Send {
        let _ = (tenant_id, credential_id);
        async { Ok(None) }
    }

    /// Claim the passkey credential id `credential_id` for `user_id` within
    /// `tenant_id`, and say whether the claim holds: `Ok(true)` when the id
    /// is now (or already was) claimed by this user, `Ok(false)` when
    /// another user of the tenant holds it.
    ///
    /// `finish_fido2_registration` claims before it stores the passkey, so
    /// two accounts racing to register one credential id cannot both pass:
    /// the holder lookup and the per-user compare-and-swap write touch
    /// different rows, and only a claim the store makes atomically (a unique
    /// index on `(tenant_id, credential_id)`, written with a single
    /// conditional insert) closes the window between them. Claiming for the
    /// same user twice is `Ok(true)`.
    ///
    /// **The default is not atomic.** It answers from
    /// [`fido2_credential_holder`](Self::fido2_credential_holder) and writes
    /// nothing, so two registrations that both look before either stores
    /// still both succeed. Implement this method, with
    /// [`release_fido2_credential`](Self::release_fido2_credential), to get
    /// the guarantee. The in-tree stores (the mock store and the SQLite
    /// example) do.
    ///
    /// An `Err` is not read as a claim: the registration fails.
    fn claim_fido2_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async move {
            let holder = self
                .fido2_credential_holder(tenant_id, credential_id)
                .await?;
            Ok(holder.is_none_or(|holder| &holder == user_id))
        }
    }

    /// Release the claim `user_id` holds on `credential_id` in `tenant_id`,
    /// taken by [`claim_fido2_credential`](Self::claim_fido2_credential).
    ///
    /// Called when the passkey is deleted and when a registration that
    /// claimed the id did not store it, so the id can be registered again.
    /// Releasing a claim the user does not hold changes nothing. The default
    /// does nothing, matching the default claim, which writes nothing.
    fn release_fido2_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let _ = (tenant_id, user_id, credential_id);
        async { Ok(()) }
    }
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

    /// Whether the method can be run as defined: it has a step, and every
    /// step has a factor to offer (an `AnyOf` with no choices has none). A
    /// method that is not complete is skipped whole by a login; dropping
    /// only the empty step would let it pass with fewer steps than it
    /// requires.
    pub fn is_complete(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|step| step.primary().is_some())
    }

    /// Return the flat list of factor kinds for simple sequential methods.
    ///
    /// For methods using `AnyOf` steps, this returns the first choice of
    /// each `AnyOf` step, and nothing for an `AnyOf` with no choices; use
    /// `steps` directly for full fidelity.
    pub fn factors(&self) -> Vec<FactorKind> {
        // A step with no factor to offer (an empty `AnyOf`) contributes
        // nothing. It used to be reported as `Password`, a factor the method
        // never listed.
        self.steps
            .iter()
            .filter_map(|step| step.primary().cloned())
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
