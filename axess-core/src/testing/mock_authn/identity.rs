//! The in-memory identity store.

use super::{CallLog, MockFactorStore, MockStoreError, note};
use crate::authn::store::AuditOutcome;
use crate::authn::{
    event::AuthEvent,
    ids::{TenantId, UserId},
    types::{EntityState, LockoutPolicy, StatusDetail, Tenant, User},
};
use dashmap::DashMap;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq as _;

/// In-memory [`IdentityStore`](crate::authn::IdentityStore) for unit tests.
///
/// Pre-load users and tenants using builder methods.
/// Tracks failed attempts and recorded events for assertion in tests.
#[derive(Clone)]
pub struct MockIdentityStore {
    /// user_id -> User
    users: Arc<DashMap<String, User>>,
    /// (tenant_id, identifier) -> user_id
    by_identifier: Arc<DashMap<(String, String), String>>,
    /// tenant identifier (slug) -> Tenant
    tenants: Arc<DashMap<String, Tenant>>,
    /// tenant id -> Tenant
    tenants_by_id: Arc<DashMap<String, Tenant>>,
    /// user_id -> failed attempt count
    failed_attempts: Arc<DashMap<String, u32>>,
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
    /// Password history per user: `user_id -> Vec<hash>`.
    password_history: Arc<DashMap<String, Vec<String>>>,
    /// Active password reset tokens: `user_id -> (token_hash, expires_at)`.
    reset_tokens: Arc<DashMap<String, (String, chrono::DateTime<chrono::Utc>)>>,
    /// Per-tenant password rules: `tenant_id -> PasswordRules`. Falls back
    /// to `PasswordRules::default()` for tenants without an override.
    password_rules: Arc<DashMap<String, crate::authn::factor::PasswordRules>>,
    /// tenant id -> IP policy, for
    /// [`IdentityLookup::ip_policy_for_tenant`](crate::authn::IdentityLookup::ip_policy_for_tenant).
    /// Absent means the trait default, which permits every address.
    ip_policies: Arc<DashMap<String, crate::authn::types::IpPolicy>>,
    /// Factor store whose rows for a user are erased along with the user by
    /// [`delete_user`](IdentityAdmin::delete_user); see
    /// [`with_factor_store`](Self::with_factor_store).
    linked_factors: Option<MockFactorStore>,
    /// Shared call record; see [`CallLog`].
    call_log: Option<CallLog>,
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
            events: Default::default(),
            default_tenant: None,
            lockout_policy: LockoutPolicy::default(),
            fail_record_failed_attempt: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fail_record_event: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shed_record_event: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            password_history: Default::default(),
            reset_tokens: Default::default(),
            password_rules: Default::default(),
            ip_policies: Default::default(),
            linked_factors: None,
            call_log: None,
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
        self.password_rules.insert(tenant_id.to_string(), rules);
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
        self.ip_policies.insert(tenant_id.to_string(), policy);
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

    /// Register a user (indexed by ID and by `(tenant_id, identifier)`).
    pub fn with_user(self, user: User) -> Self {
        self.by_identifier.insert(
            (user.tenant_id.to_string(), user.identifier.to_string()),
            user.id.to_string(),
        );
        self.users.insert(user.id.to_string(), user);
        self
    }

    /// Register a tenant (indexed by ID and by identifier/slug).
    pub fn with_tenant(self, tenant: Tenant) -> Self {
        self.tenants_by_id
            .insert(tenant.id.to_string(), tenant.clone());
        self.tenants.insert(tenant.identifier.to_string(), tenant);
        self
    }

    /// Set the default tenant returned by `default_tenant()`.
    pub fn with_default_tenant(mut self, tenant: Tenant) -> Self {
        self.tenants_by_id
            .insert(tenant.id.to_string(), tenant.clone());
        self.tenants
            .insert(tenant.identifier.to_string(), tenant.clone());
        self.default_tenant = Some(tenant);
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
        self.failed_attempts.get(&key).map(|r| *r).unwrap_or(0)
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
        let user = self
            .by_identifier
            .get(&key)
            .and_then(|uid| self.users.get(uid.as_str()))
            .map(|r| r.clone());
        Ok(user)
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        Ok(self
            .users
            .get(user_id.to_string().as_str())
            .map(|r| r.clone()))
    }

    async fn find_tenant(&self, identifier: &str) -> Result<Option<Tenant>, Self::Error> {
        note(&self.call_log, "find_tenant");
        Ok(self.tenants.get(identifier).map(|r| r.clone()))
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        self.default_tenant
            .clone()
            .ok_or(MockStoreError::NoDefaultTenant)
    }

    async fn account_status(&self, user_id: &UserId) -> Result<EntityState, Self::Error> {
        note(&self.call_log, "account_status");
        Ok(self
            .users
            .get(user_id.to_string().as_str())
            .map(|u| u.status.clone())
            .unwrap_or(EntityState::Guest))
    }

    fn lockout_policy(&self) -> LockoutPolicy {
        self.lockout_policy.clone()
    }

    async fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<crate::authn::types::IpPolicy, Self::Error> {
        note(&self.call_log, "ip_policy_for_tenant");
        Ok(self
            .ip_policies
            .get(tenant_id.to_string().as_str())
            .map(|p| p.clone())
            .unwrap_or_default())
    }

    async fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<crate::authn::factor::PasswordRules, Self::Error> {
        Ok(self
            .password_rules
            .get(tenant_id.to_string().as_str())
            .map(|r| r.clone())
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
        let mut entry = self.failed_attempts.entry(user_id.to_string()).or_insert(0);
        *entry += 1;
        Ok(*entry)
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        self.failed_attempts.remove(user_id.to_string().as_str());
        Ok(())
    }
}

impl crate::authn::store::IdentityAdmin for MockIdentityStore {
    async fn create_tenant(&self, tenant: Tenant) -> Result<(), Self::Error> {
        // Unique on both `id` and `identifier`, as the trait requires: a
        // second tenant under an existing slug would otherwise silently
        // replace the first in the slug index, where a real store refuses.
        if self
            .tenants_by_id
            .contains_key(tenant.id.to_string().as_str())
            || self
                .tenants
                .contains_key(tenant.identifier.to_string().as_str())
        {
            return Err(MockStoreError::AlreadyExists);
        }
        self.tenants
            .insert(tenant.identifier.to_string(), tenant.clone());
        self.tenants_by_id.insert(tenant.id.to_string(), tenant);
        Ok(())
    }

    async fn create_user(&self, user: User) -> Result<(), Self::Error> {
        let key = (user.tenant_id.to_string(), user.identifier.to_string());
        // Unique on the user id as well as the identifier: a primary-key
        // collision replacing the stored row would let a test "create" a
        // user over an existing one, which a real store refuses.
        if self.by_identifier.contains_key(&key) || self.users.contains_key(&user.id.to_string()) {
            return Err(MockStoreError::AlreadyExists);
        }
        self.by_identifier.insert(key, user.id.to_string());
        self.users.insert(user.id.to_string(), user);
        Ok(())
    }

    async fn activate_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        let mut entry = self
            .users
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
        let mut entry = self
            .users
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
        let (_, user) = self.users.remove(&key).ok_or(MockStoreError::NotFound)?;
        self.by_identifier
            .remove(&(user.tenant_id.to_string(), user.identifier.to_string()));
        self.failed_attempts.remove(&key);
        self.password_history.remove(&key);
        self.reset_tokens.remove(&key);
        if let Some(factors) = &self.linked_factors {
            factors.forget_user(&user.tenant_id, user_id);
        }
        Ok(())
    }
}

impl crate::authn::store::IdentityPasswordReset for MockIdentityStore {
    async fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        self.reset_tokens
            .insert(user_id.to_string(), (token_hash.to_string(), expires_at));
        Ok(())
    }

    async fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Self::Error> {
        // One atomic remove-if: of two concurrent verifications of the same
        // token exactly one may succeed (the token is single-use). A
        // mismatch or an expired token leaves the stored row alone.
        Ok(self
            .reset_tokens
            .remove_if(
                user_id.to_string().as_str(),
                |_, (stored_hash, expires_at)| {
                    *expires_at > now
                        && bool::from(stored_hash.as_bytes().ct_eq(token_hash.as_bytes()))
                },
            )
            .is_some())
    }
}

impl crate::authn::store::IdentityPasswordHistory for MockIdentityStore {
    async fn record_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Self::Error> {
        self.password_history
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
        Ok(self
            .password_history
            .get(user_id.to_string().as_str())
            .map(|hashes| hashes.iter().rev().take(count).cloned().collect())
            .unwrap_or_default())
    }
}
