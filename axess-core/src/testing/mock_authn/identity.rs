//! The in-memory identity store.

use super::{CallLog, MockFactorStore, MockStoreError, note};
use crate::authn::store::AuditOutcome;
use crate::authn::{
    event::AuthEvent,
    ids::{TenantId, UserId},
    types::{
        EntityState, LockoutPolicy, StatusDetail, Tenant, Throttle, ThrottleState, ThrottleSubject,
        User,
    },
};
use crate::locked::lock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq as _;

/// A user's failed-attempt count and the time of the last failure.
type FailedAttempts = (u32, chrono::DateTime<chrono::Utc>);

/// A reset token's hash and its expiry.
type ResetToken = (String, chrono::DateTime<chrono::Utc>);
// A user's live reset tokens.
type ResetTokens = Vec<ResetToken>;

/// In-memory [`IdentityStore`](crate::authn::IdentityStore) for unit tests.
///
/// Pre-load users and tenants using builder methods.
/// Tracks failed attempts and recorded events for assertion in tests.
#[derive(Clone)]
pub struct MockIdentityStore {
    /// user_id -> User
    users: Arc<Mutex<HashMap<String, User>>>,
    /// (tenant_id, identifier) -> user_id
    by_identifier: Arc<Mutex<HashMap<(String, String), String>>>,
    /// tenant identifier (slug) -> Tenant
    tenants: Arc<Mutex<HashMap<String, Tenant>>>,
    /// tenant id -> Tenant
    tenants_by_id: Arc<Mutex<HashMap<String, Tenant>>>,
    /// user_id -> (failed attempt count, time of the last failure)
    failed_attempts: Arc<Mutex<HashMap<String, FailedAttempts>>>,
    /// Throttle entries per key, as
    /// [`record_throttle_failure`](crate::authn::IdentityAuthnLog::record_throttle_failure)
    /// writes them. A record sweeps every stale entry, so the map holds only
    /// keys that still throttle.
    throttles: Arc<Mutex<HashMap<ThrottleSubject, ThrottleState>>>,
    /// Clock the last-failure time is read from. Share the service's
    /// [`MockClock`](axess_clock::testing::MockClock) with
    /// [`with_clock`](Self::with_clock) so a derived lockout expires on the
    /// service's time.
    clock: Arc<dyn axess_clock::Clock>,
    /// Append-only event log.
    events: Arc<Mutex<Vec<AuthEvent>>>,
    /// Default tenant returned by `default_tenant()`.
    default_tenant: Option<Tenant>,
    /// Lockout policy.
    lockout_policy: LockoutPolicy,
    /// Counter-outage test hook: when `true`, [`record_failed_attempt`](IdentityStore::record_failed_attempt)
    /// returns [`MockStoreError::NotFound`] without incrementing. Models a
    /// counter-store outage to assert the caller does not propagate it as
    /// `Err(Store)` (which would leak timing + bypass lockout).
    fail_record_failed_attempt: Arc<std::sync::atomic::AtomicBool>,
    /// Audit-outage test hook: when `true`, [`record_event`](IdentityAuthnLog::record_event)
    /// returns [`MockStoreError::NotFound`] without storing. Models an
    /// audit-store outage, which the service must surface as
    /// `Err(Store)` rather than proceeding unrecorded, and must surface
    /// identically for a known and an unknown identifier.
    fail_record_event: Arc<std::sync::atomic::AtomicBool>,
    /// When set, `record_event` reports `AuditOutcome::Shed` and stores
    /// nothing: a sink protecting its storage, not a broken one.
    shed_record_event: Arc<std::sync::atomic::AtomicBool>,
    /// When set, `record_event` never completes: an audit sink that hangs,
    /// for tests of what a flow has done by the time its caller gives up.
    hang_record_event: Arc<std::sync::atomic::AtomicBool>,
    /// When set, `store_reset_token` fails: a token store outage.
    fail_store_reset_token: Arc<std::sync::atomic::AtomicBool>,
    /// When set, `get_user` fails: a user-table outage, for tests of what a
    /// flow records when the lookup of a principal cannot be made.
    fail_get_user: Arc<std::sync::atomic::AtomicBool>,
    /// Password history per user: `user_id -> Vec<hash>`.
    password_history: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Active password reset tokens: `user_id -> (token_hash, expires_at)`.
    reset_tokens: Arc<Mutex<HashMap<String, ResetTokens>>>,
    /// Per-tenant password rules: `tenant_id -> PasswordRules`. Falls back
    /// to `PasswordRules::default()` for tenants without an override.
    password_rules: Arc<Mutex<HashMap<String, crate::authn::factor::PasswordRules>>>,
    /// tenant id -> IP policy, for
    /// [`IdentityLookup::ip_policy_for_tenant`](crate::authn::IdentityLookup::ip_policy_for_tenant).
    /// Absent means the trait default, which permits every address.
    ip_policies: Arc<Mutex<HashMap<String, crate::authn::types::IpPolicy>>>,
    /// Factor store whose rows for a user are erased along with the user by
    /// [`delete_user`](IdentityAdmin::delete_user); see
    /// [`with_factor_store`](Self::with_factor_store).
    linked_factors: Option<MockFactorStore>,
    /// Shared call record; see [`CallLog`].
    call_log: Option<CallLog>,
    /// user_id -> time of the last successful authentication, as written by
    /// [`record_last_login`](crate::authn::IdentityAuthnLog::record_last_login).
    last_logins: Arc<Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl Default for MockIdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MockIdentityStore {
    /// Create an empty mock identity store.
    pub fn new() -> Self {
        Self {
            users: Default::default(),
            by_identifier: Default::default(),
            tenants: Default::default(),
            tenants_by_id: Default::default(),
            failed_attempts: Default::default(),
            throttles: Default::default(),
            clock: Arc::new(axess_clock::SystemClock),
            events: Default::default(),
            default_tenant: None,
            lockout_policy: LockoutPolicy::default(),
            fail_record_failed_attempt: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fail_record_event: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shed_record_event: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hang_record_event: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fail_store_reset_token: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fail_get_user: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            password_history: Default::default(),
            reset_tokens: Default::default(),
            password_rules: Default::default(),
            ip_policies: Default::default(),
            linked_factors: None,
            call_log: None,
            last_logins: Default::default(),
        }
    }

    /// Record this store's lookups and event writes into `log`.
    pub fn with_call_log(mut self, log: &CallLog) -> Self {
        self.call_log = Some(log.clone());
        self
    }

    /// Link the [`MockFactorStore`] that holds this store's users' factors, so
    /// [`delete_user`](crate::authn::store::IdentityAdmin::delete_user) also
    /// erases the user's factor configs and auth methods, as the erasure
    /// contract requires. The identity and factor stores are separate objects
    /// in the mock, so without the link only identity-side data is erased.
    pub fn with_factor_store(mut self, factors: &MockFactorStore) -> Self {
        self.linked_factors = Some(factors.clone());
        self
    }

    /// Install per-tenant [`PasswordRules`](crate::authn::factor::PasswordRules)
    /// looked up by [`IdentityLookup::password_rules_for_tenant`](crate::authn::IdentityLookup::password_rules_for_tenant).
    pub fn with_password_rules(
        self,
        tenant_id: &TenantId,
        rules: crate::authn::factor::PasswordRules,
    ) -> Self {
        lock(&self.password_rules).insert(tenant_id.to_string(), rules);
        self
    }

    /// Install a per-tenant [`IpPolicy`](crate::authn::types::IpPolicy)
    /// looked up by [`IdentityLookup::ip_policy_for_tenant`](crate::authn::IdentityLookup::ip_policy_for_tenant).
    ///
    /// Without one the trait default applies, which permits every address:
    /// a login test that does not install a policy is not testing the gate,
    /// which is how the gate went untested while it could be skipped
    /// altogether by passing no address.
    pub fn with_ip_policy(
        self,
        tenant_id: &TenantId,
        policy: crate::authn::types::IpPolicy,
    ) -> Self {
        lock(&self.ip_policies).insert(tenant_id.to_string(), policy);
        self
    }

    /// Arm the counter-outage failure mode: subsequent `record_failed_attempt` calls
    /// return `Err(MockStoreError::NotFound)` without touching state.
    pub fn arm_record_failed_attempt_failure(&self) {
        self.fail_record_failed_attempt
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Disarm the counter-outage failure mode.
    pub fn disarm_record_failed_attempt_failure(&self) {
        self.fail_record_failed_attempt
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Arm the audit-outage failure mode: subsequent `record_event` calls
    /// return `Err(MockStoreError::NotFound)` without storing the event.
    pub fn arm_record_event_failure(&self) {
        self.fail_record_event
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Arm the token-store outage: subsequent `store_reset_token` calls fail.
    pub fn arm_store_reset_token_failure(&self) {
        self.fail_store_reset_token
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Arm the user-table outage: subsequent `get_user` calls fail with
    /// [`MockStoreError::Unavailable`] until
    /// [`disarm_get_user_failure`](Self::disarm_get_user_failure).
    pub fn arm_get_user_failure(&self) {
        self.fail_get_user
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// End the user-table outage armed by
    /// [`arm_get_user_failure`](Self::arm_get_user_failure).
    pub fn disarm_get_user_failure(&self) {
        self.fail_get_user
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Disarm the audit-outage failure mode.
    pub fn disarm_record_event_failure(&self) {
        self.fail_record_event
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Arm load-shedding: subsequent `record_event` calls store nothing
    /// and report [`AuditOutcome::Shed`].
    ///
    /// Distinct from
    /// [`arm_record_event_failure`](Self::arm_record_event_failure), and
    /// the distinction is the point: a shed event must not fail the flow,
    /// an outage must.
    pub fn arm_record_event_shedding(&self) {
        self.shed_record_event
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Disarm load-shedding.
    pub fn disarm_record_event_shedding(&self) {
        self.shed_record_event
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Arm a hanging audit sink: subsequent `record_event` calls never
    /// complete. For a test that times a flow out during its audit write and
    /// asks what the flow had done by then.
    pub fn arm_record_event_hang(&self) {
        self.hang_record_event
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Register a user (indexed by ID and by `(tenant_id, identifier)`).
    pub fn with_user(self, user: User) -> Self {
        lock(&self.by_identifier).insert(
            (user.tenant_id.to_string(), user.identifier.to_string()),
            user.id.to_string(),
        );
        lock(&self.users).insert(user.id.to_string(), user);
        self
    }

    /// The tenant of the registered user with this id, if any.
    pub(crate) fn tenant_of(&self, user_id: &UserId) -> Option<TenantId> {
        lock(&self.users)
            .get(user_id.to_string().as_str())
            .map(|user| user.tenant_id)
    }

    /// Register a tenant (indexed by ID and by identifier/slug).
    pub fn with_tenant(self, tenant: Tenant) -> Self {
        lock(&self.tenants_by_id).insert(tenant.id.to_string(), tenant.clone());
        lock(&self.tenants).insert(tenant.identifier.to_string(), tenant);
        self
    }

    /// Set the default tenant returned by `default_tenant()`.
    pub fn with_default_tenant(mut self, tenant: Tenant) -> Self {
        lock(&self.tenants_by_id).insert(tenant.id.to_string(), tenant.clone());
        lock(&self.tenants).insert(tenant.identifier.to_string(), tenant.clone());
        self.default_tenant = Some(tenant);
        self
    }

    /// Read the time of each recorded failure from `clock` instead of the
    /// system clock, so a lockout derived from the counter follows a test's
    /// mock clock.
    pub fn with_clock(mut self, clock: impl axess_clock::Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Override the lockout policy.
    pub fn with_lockout_policy(mut self, policy: LockoutPolicy) -> Self {
        self.lockout_policy = policy;
        self
    }

    /// Return a snapshot of all recorded events.
    pub fn events(&self) -> Vec<AuthEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Return the current failed attempt count for a user, looked up by
    /// the test label (e.g. `"u1"`); internally derives the same v5
    /// [`axess_identity::UserId`] that `axess_identity::testing::user(label)`
    /// produces and indexes the failed-attempts map by that.
    pub fn failed_attempts_for(&self, label: &str) -> u32 {
        let key = axess_identity::testing::user(label).to_string();
        lock(&self.failed_attempts).get(&key).map_or(0, |r| r.0)
    }

    /// When [`record_last_login`](crate::authn::IdentityAuthnLog::record_last_login)
    /// last ran for `user_id`, or `None` when it never did.
    pub fn last_login(&self, user_id: &UserId) -> Option<chrono::DateTime<chrono::Utc>> {
        lock(&self.last_logins)
            .get(user_id.to_string().as_str())
            .copied()
    }
}

impl crate::authn::store::IdentityLookup for MockIdentityStore {
    type Error = MockStoreError;

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, Self::Error> {
        note(&self.call_log, "find_user");
        let key = (tenant_id.to_string(), identifier.to_string());
        let user_id = lock(&self.by_identifier).get(&key).cloned();
        let user = user_id.and_then(|uid| lock(&self.users).get(uid.as_str()).cloned());
        Ok(user)
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        note(&self.call_log, "get_user");
        if self.fail_get_user.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MockStoreError::Unavailable);
        }
        Ok(lock(&self.users).get(user_id.to_string().as_str()).cloned())
    }

    async fn get_user_in_tenant(
        &self,
        user_id: &UserId,
        expected_tenant: &TenantId,
    ) -> Result<Option<User>, Self::Error> {
        note(&self.call_log, "get_user_in_tenant");
        Ok(lock(&self.users)
            .get(user_id.to_string().as_str())
            .filter(|u| &u.tenant_id == expected_tenant)
            .cloned())
    }

    async fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<Tenant>, Self::Error> {
        note(&self.call_log, "get_tenant");
        Ok(lock(&self.tenants_by_id)
            .get(tenant_id.to_string().as_str())
            .cloned())
    }

    async fn get_user_tenant(&self, user_id: &UserId) -> Result<Option<TenantId>, Self::Error> {
        note(&self.call_log, "get_user_tenant");
        Ok(lock(&self.users)
            .get(user_id.to_string().as_str())
            .map(|r| r.tenant_id))
    }

    async fn find_tenant(&self, identifier: &str) -> Result<Option<Tenant>, Self::Error> {
        note(&self.call_log, "find_tenant");
        Ok(lock(&self.tenants).get(identifier).cloned())
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        self.default_tenant
            .clone()
            .ok_or(MockStoreError::NoDefaultTenant)
    }

    async fn account_status(&self, user_id: &UserId) -> Result<EntityState, Self::Error> {
        note(&self.call_log, "account_status");
        Ok(lock(&self.users)
            .get(user_id.to_string().as_str())
            .map(|u| u.status.clone())
            .unwrap_or(EntityState::Guest))
    }

    fn lockout_policy_for_tenant(&self, _tenant_id: &TenantId) -> LockoutPolicy {
        self.lockout_policy.clone()
    }

    async fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<crate::authn::types::IpPolicy, Self::Error> {
        note(&self.call_log, "ip_policy_for_tenant");
        Ok(lock(&self.ip_policies)
            .get(tenant_id.to_string().as_str())
            .cloned()
            .unwrap_or_default())
    }

    async fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<crate::authn::factor::PasswordRules, Self::Error> {
        note(&self.call_log, "password_rules_for_tenant");
        Ok(lock(&self.password_rules)
            .get(tenant_id.to_string().as_str())
            .cloned()
            .unwrap_or_default())
    }
}

impl crate::authn::store::IdentityAuthnLog for MockIdentityStore {
    async fn record_event(&self, event: AuthEvent) -> Result<AuditOutcome, Self::Error> {
        note(&self.call_log, "record_event");
        if self
            .fail_record_event
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(MockStoreError::NotFound);
        }
        if self
            .shed_record_event
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(AuditOutcome::Shed);
        }
        if self
            .hang_record_event
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            std::future::pending::<()>().await;
        }
        self.events.lock().unwrap().push(event);
        Ok(AuditOutcome::Recorded)
    }

    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        if self
            .fail_record_failed_attempt
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(MockStoreError::NotFound);
        }
        note(&self.call_log, "record_failed_attempt");
        let now = self.clock.now();
        let mut attempts = lock(&self.failed_attempts);
        let entry = attempts.entry(user_id.to_string()).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        Ok(entry.0)
    }

    async fn reserve_attempt(
        &self,
        user_id: &UserId,
        policy: &crate::authn::types::LockoutPolicy,
    ) -> Result<Option<u32>, Self::Error> {
        if self
            .fail_record_failed_attempt
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(MockStoreError::NotFound);
        }
        note(&self.call_log, "reserve_attempt");
        let now = self.clock.now();
        let max = policy.effective_max_attempts();
        // Holding the map's lock makes the test and the increment one step.
        let mut attempts = lock(&self.failed_attempts);
        let entry = attempts.entry(user_id.to_string()).or_insert((0, now));
        let window = chrono::Duration::from_std(policy.attempt_window)
            .unwrap_or_else(|_| chrono::Duration::hours(1));
        // The window freshens a count below the limit only; at the limit the
        // count stays until a timed lockout has run out or the counter is
        // reset, so an indefinite lockout is not ended by the window.
        let at_limit = entry.0 >= max;
        let fresh = entry.0 == 0
            || (!at_limit && now - entry.1 > window)
            || (at_limit
                && policy
                    .derived_lockout(entry.0, Some(entry.1), now)
                    .is_none());
        if fresh {
            *entry = (1, now);
            return Ok(Some(1));
        }
        if entry.0 >= max {
            return Ok(None);
        }
        entry.0 += 1;
        entry.1 = now;
        Ok(Some(entry.0))
    }

    async fn release_attempt(&self, user_id: &UserId) -> Result<(), Self::Error> {
        note(&self.call_log, "release_attempt");
        let key = user_id.to_string();
        let mut attempts = lock(&self.failed_attempts);
        let spent = attempts.get_mut(key.as_str()).is_some_and(|entry| {
            entry.0 = entry.0.saturating_sub(1);
            entry.0 == 0
        });
        if spent {
            attempts.remove(key.as_str());
        }
        Ok(())
    }

    async fn failed_attempts(
        &self,
        user_id: &UserId,
    ) -> Result<(u32, Option<chrono::DateTime<chrono::Utc>>), Self::Error> {
        note(&self.call_log, "failed_attempts");
        Ok(lock(&self.failed_attempts)
            .get(user_id.to_string().as_str())
            .map(|r| (r.0, Some(r.1)))
            .unwrap_or((0, None)))
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        lock(&self.failed_attempts).remove(user_id.to_string().as_str());
        Ok(())
    }

    async fn throttle_state(
        &self,
        key: &ThrottleSubject,
    ) -> Result<Option<ThrottleState>, Self::Error> {
        note(&self.call_log, "throttle_state");
        Ok(lock(&self.throttles).get(key).copied())
    }

    async fn record_throttle_failure(
        &self,
        key: &ThrottleSubject,
        throttle: &Throttle,
    ) -> Result<(), Self::Error> {
        note(&self.call_log, "record_throttle_failure");
        let now = self.clock.now();
        // Holding the map's lock makes the read and the increment one step.
        let mut throttles = lock(&self.throttles);
        // Forget what no longer throttles, so the map holds only live keys.
        throttles.retain(|_, state| !throttle.is_stale(state, now));
        let entry = throttles.entry(*key).or_insert(ThrottleState {
            failures: 0,
            last_failure_at: now,
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_at = now;
        Ok(())
    }

    async fn clear_throttle(&self, key: &ThrottleSubject) -> Result<(), Self::Error> {
        note(&self.call_log, "clear_throttle");
        lock(&self.throttles).remove(key);
        Ok(())
    }

    async fn record_last_login(
        &self,
        user_id: &UserId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        note(&self.call_log, "record_last_login");
        lock(&self.last_logins).insert(user_id.to_string(), at);
        Ok(())
    }
}

impl crate::authn::store::IdentityAdmin for MockIdentityStore {
    async fn create_tenant(&self, tenant: Tenant) -> Result<(), Self::Error> {
        // Unique on both `id` and `identifier`, as the trait requires: a
        // second tenant under an existing slug would otherwise silently
        // replace the first in the slug index, where a real store refuses.
        let mut by_id = lock(&self.tenants_by_id);
        let mut by_slug = lock(&self.tenants);
        if by_id.contains_key(tenant.id.to_string().as_str())
            || by_slug.contains_key(tenant.identifier.to_string().as_str())
        {
            return Err(MockStoreError::AlreadyExists);
        }
        by_slug.insert(tenant.identifier.to_string(), tenant.clone());
        by_id.insert(tenant.id.to_string(), tenant);
        Ok(())
    }

    async fn create_user(&self, user: User) -> Result<(), Self::Error> {
        let key = (user.tenant_id.to_string(), user.identifier.to_string());
        // Unique on the user id as well as the identifier: a primary-key
        // collision replacing the stored row would let a test "create" a
        // user over an existing one, which a real store refuses.
        let mut by_identifier = lock(&self.by_identifier);
        let mut users = lock(&self.users);
        if by_identifier.contains_key(&key) || users.contains_key(&user.id.to_string()) {
            return Err(MockStoreError::AlreadyExists);
        }
        by_identifier.insert(key, user.id.to_string());
        users.insert(user.id.to_string(), user);
        Ok(())
    }

    async fn activate_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        let mut users = lock(&self.users);
        let entry = users
            .get_mut(user_id.to_string().as_str())
            .ok_or(MockStoreError::NotFound)?;
        entry.status = EntityState::Active;
        Ok(())
    }

    async fn suspend_user(
        &self,
        user_id: &UserId,
        detail: StatusDetail,
    ) -> Result<(), Self::Error> {
        let mut users = lock(&self.users);
        let entry = users
            .get_mut(user_id.to_string().as_str())
            .ok_or(MockStoreError::NotFound)?;
        entry.status = EntityState::Suspended(detail);
        Ok(())
    }

    /// Erase the user: the row, its identifier index entry, failed-attempt
    /// counter, password history and any pending reset token, and (when a
    /// factor store is linked) its factor configs and auth methods. A missing
    /// user is [`MockStoreError::NotFound`], and a second delete of the same
    /// user is therefore `NotFound` too.
    async fn delete_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        let key = user_id.to_string();
        let user = lock(&self.users)
            .remove(&key)
            .ok_or(MockStoreError::NotFound)?;
        lock(&self.by_identifier)
            .remove(&(user.tenant_id.to_string(), user.identifier.to_string()));
        lock(&self.failed_attempts).remove(&key);
        lock(&self.password_history).remove(&key);
        lock(&self.reset_tokens).remove(&key);
        if let Some(factors) = &self.linked_factors {
            factors.forget_user(&user.tenant_id, user_id);
        }
        Ok(())
    }

    /// The oldest candidates first, up to `limit`.
    async fn delete_candidates_created_before(
        &self,
        before: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> Result<Vec<crate::authn::types::User>, Self::Error> {
        let mut expired: Vec<crate::authn::types::User> = lock(&self.users)
            .values()
            .filter(|u| {
                matches!(u.status, crate::authn::types::EntityState::Candidate)
                    && u.created_at < before
            })
            .cloned()
            .collect();
        expired.sort_by_key(|u| u.created_at);
        expired.truncate(limit);
        for user in &expired {
            self.delete_user(&user.id).await?;
        }
        Ok(expired)
    }
}

impl crate::authn::store::IdentityPasswordReset for MockIdentityStore {
    async fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
        max_live: usize,
    ) -> Result<bool, Self::Error> {
        note(&self.call_log, "store_reset_token");
        if self
            .fail_store_reset_token
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(MockStoreError::NotFound);
        }
        let mut tokens = lock(&self.reset_tokens);
        let held = tokens.entry(user_id.to_string()).or_default();
        held.retain(|(_, expires)| *expires > now);
        if held.iter().any(|(hash, _)| hash == token_hash) {
            return Ok(true);
        }
        if held.len() >= max_live {
            return Ok(false);
        }
        held.push((token_hash.to_string(), expires_at));
        Ok(true)
    }

    async fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Self::Error> {
        // One atomic remove-if: of two concurrent verifications of the same
        // token exactly one may succeed (the token is single-use), and a
        // match consumes every token of the user. A mismatch or an expired
        // token leaves the stored rows alone.
        let mut tokens = lock(&self.reset_tokens);
        let key = user_id.to_string();
        let matches = tokens.get(key.as_str()).is_some_and(|held| {
            held.iter().any(|(stored_hash, expires_at)| {
                *expires_at > now && bool::from(stored_hash.as_bytes().ct_eq(token_hash.as_bytes()))
            })
        });
        if matches {
            tokens.remove(key.as_str());
        }
        Ok(matches)
    }

    async fn check_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Self::Error> {
        Ok(lock(&self.reset_tokens)
            .get(user_id.to_string().as_str())
            .is_some_and(|held| {
                held.iter().any(|(stored_hash, expires_at)| {
                    *expires_at > now
                        && bool::from(stored_hash.as_bytes().ct_eq(token_hash.as_bytes()))
                })
            }))
    }
}

impl crate::authn::store::IdentityPasswordHistory for MockIdentityStore {
    async fn record_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Self::Error> {
        note(&self.call_log, "record_password_hash");
        lock(&self.password_history)
            .entry(user_id.to_string())
            .or_default()
            .push(hash.to_string());
        Ok(())
    }

    async fn password_history(
        &self,
        user_id: &UserId,
        count: usize,
    ) -> Result<Vec<String>, Self::Error> {
        note(&self.call_log, "password_history");
        Ok(lock(&self.password_history)
            .get(user_id.to_string().as_str())
            .map(|hashes| hashes.iter().rev().take(count).cloned().collect())
            .unwrap_or_default())
    }
}
