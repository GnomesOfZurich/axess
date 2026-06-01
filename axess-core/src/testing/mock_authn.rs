//! In-memory [`IdentityStore`](crate::authn::IdentityStore) and [`FactorStore`] for unit tests.
//!
//! Use the builder methods to pre-load users, tenants, and factor configs before
//! running tests. The mocks are fully thread-safe (`Arc<DashMap<…>>`).

use crate::authn::{
    event::AuthEvent,
    factor::{FactorConfig, FactorKind},
    ids::{TenantId, UserId},
    store::{AuthMethod, FactorStore},
    types::{AuthnScope, EntityState, LockoutPolicy, StatusDetail, Tenant, User},
};
use dashmap::DashMap;
use std::sync::{Arc, Mutex};

// ── MockStoreError ─────────────────────────────────────────────────────────────

/// Infallible-ish error for the in-memory mock stores.
#[derive(Debug, thiserror::Error)]
pub enum MockStoreError {
    /// Lookup target was not present in the in-memory map.
    #[error("entity not found")]
    NotFound,
    /// Insert collided with an existing entry under the same key.
    #[error("entity already exists")]
    AlreadyExists,
    /// A tenant lookup was made but no default tenant has been configured.
    #[error("no default tenant configured")]
    NoDefaultTenant,
    /// Caller tried to persist an auth method at [`AuthnScope::Global`], which is rejected.
    #[error("auth methods cannot be stored at global scope")]
    InvalidGlobalMethod,
}

// ── MockIdentityStore ─────────────────────────────────────────────────────────

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
    /// Password history per user: `user_id -> Vec<hash>`.
    password_history: Arc<DashMap<String, Vec<String>>>,
    /// Active password reset tokens: `user_id -> (token_hash, expires_at)`.
    reset_tokens: Arc<DashMap<String, (String, chrono::DateTime<chrono::Utc>)>>,
    /// Per-tenant password rules: `tenant_id -> PasswordRules`. Falls back
    /// to `PasswordRules::default()` for tenants without an override.
    password_rules: Arc<DashMap<String, crate::authn::factor::PasswordRules>>,
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
            password_history: Default::default(),
            reset_tokens: Default::default(),
            password_rules: Default::default(),
        }
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
        Ok(self.tenants.get(identifier).map(|r| r.clone()))
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        self.default_tenant
            .clone()
            .ok_or(MockStoreError::NoDefaultTenant)
    }

    async fn account_status(&self, user_id: &UserId) -> Result<EntityState, Self::Error> {
        Ok(self
            .users
            .get(user_id.to_string().as_str())
            .map(|u| u.status.clone())
            .unwrap_or(EntityState::Guest))
    }

    fn lockout_policy(&self) -> LockoutPolicy {
        self.lockout_policy.clone()
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
    async fn record_event(&self, event: AuthEvent) -> Result<(), Self::Error> {
        self.events.lock().unwrap().push(event);
        Ok(())
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
        if self
            .tenants_by_id
            .contains_key(tenant.id.to_string().as_str())
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
        if self.by_identifier.contains_key(&key) {
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
    ) -> Result<bool, Self::Error> {
        let key = user_id.to_string();
        let Some(entry) = self.reset_tokens.get(key.as_str()) else {
            return Ok(false);
        };
        let (stored_hash, expires_at) = entry.value().clone();
        drop(entry);
        if expires_at <= chrono::Utc::now() || stored_hash != token_hash {
            return Ok(false);
        }
        self.reset_tokens.remove(key.as_str());
        Ok(true)
    }
}

// ── MockFactorStore ───────────────────────────────────────────────────────────

/// In-memory [`FactorStore`] for unit tests.
///
/// Pre-load factor configs and auth methods using builder methods.
#[derive(Clone, Default)]
pub struct MockFactorStore {
    /// `scope_key::factor_kind_str` -> FactorConfig
    configs: Arc<DashMap<String, FactorConfig>>,
    /// `user_id -> Vec<AuthMethod>` (legacy test fixture keyed by user)
    methods: Arc<DashMap<String, Vec<AuthMethod>>>,
    /// `scope.key()` -> Vec<(method, enabled)>: storage for
    /// `save_method` / `remove_method` / `set_method_enabled`.
    scoped_methods: Arc<DashMap<String, Vec<(AuthMethod, bool)>>>,
    /// Number of upcoming `compare_and_save_factor` calls that must
    /// report a CAS loss regardless of stored state. Lets tests
    /// exercise the retry/reload path inside
    /// `persist_fail_with_update`.
    cas_failures_remaining: Arc<std::sync::atomic::AtomicUsize>,
}

impl MockFactorStore {
    /// Create an empty mock factor store.
    pub fn new() -> Self {
        Self::default()
    }

    fn config_key(scope: &AuthnScope, kind: &FactorKind) -> String {
        format!("{}::{}", scope.key(), kind.as_str())
    }

    /// Register a factor configuration for a given scope.
    pub fn with_factor(self, scope: AuthnScope, config: FactorConfig) -> Self {
        let key = Self::config_key(&scope, &config.kind());
        self.configs.insert(key, config);
        self
    }

    /// Register the available authentication methods for a user.
    pub fn with_method(self, user_id: &UserId, method: AuthMethod) -> Self {
        self.methods
            .entry(user_id.to_string())
            .or_default()
            .push(method);
        self
    }

    /// Arm the CAS-contention failure mode: the next `n` calls to
    /// [`crate::authn::store::FactorStore::compare_and_save_factor`]
    /// return `Ok(false)` regardless of whether the stored value matches
    /// `prior`. Lets tests drive the retry/reload path inside
    /// `persist_fail_with_update` without a real concurrent writer.
    pub fn arm_cas_failures(&self, n: usize) {
        self.cas_failures_remaining
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }
}

impl FactorStore for MockFactorStore {
    type Error = MockStoreError;

    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        let key = Self::config_key(scope, &kind);
        Ok(self.configs.get(&key).map(|r| r.clone()))
    }

    async fn save_factor(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<(), Self::Error> {
        let key = Self::config_key(scope, &config.kind());
        self.configs.insert(key, config);
        Ok(())
    }

    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        // Tests can pre-arm a sequence of CAS losses to drive the
        // retry/reload path without a real concurrent writer.
        let remaining = self
            .cas_failures_remaining
            .load(std::sync::atomic::Ordering::SeqCst);
        if remaining > 0 {
            self.cas_failures_remaining
                .store(remaining - 1, std::sync::atomic::Ordering::SeqCst);
            return Ok(false);
        }

        let key = Self::config_key(scope, &prior.kind());
        // FactorConfig has no PartialEq derive; compare via canonical JSON.
        // serde_json::to_value never fails for FactorConfig (no map-key shape
        // violations), so a None result here means "treat as mismatch."
        let prior_json = serde_json::to_value(prior).ok();
        if prior_json.is_none() {
            return Ok(false);
        }
        let mut swapped = false;
        let updated_for_swap = updated.clone();
        self.configs.entry(key).and_modify(|stored| {
            if serde_json::to_value(&*stored).ok() == prior_json {
                *stored = updated_for_swap.clone();
                swapped = true;
            }
        });
        Ok(swapped)
    }

    async fn available_methods(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        let mut out: Vec<AuthMethod> = self
            .methods
            .get(user_id.to_string().as_str())
            .map(|r| r.clone())
            .unwrap_or_default();

        // Scoped storage: user-scope first, then tenant-scope. Only
        // enabled rows are returned.
        let user_key = AuthnScope::User {
            user_id: *user_id,
            tenant_id: *tenant_id,
        }
        .key();
        if let Some(rows) = self.scoped_methods.get(&user_key) {
            out.extend(rows.iter().filter(|(_, en)| *en).map(|(m, _)| m.clone()));
        }

        let tenant_key = AuthnScope::Tenant(*tenant_id).key();
        if let Some(rows) = self.scoped_methods.get(&tenant_key) {
            out.extend(rows.iter().filter(|(_, en)| *en).map(|(m, _)| m.clone()));
        }

        Ok(out)
    }

    async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Self::Error> {
        if matches!(scope, AuthnScope::Global) {
            // Consistent with the example backend: auth methods are a
            // tenant-or-user-scoped concept.
            return Err(MockStoreError::InvalidGlobalMethod);
        }
        let key = scope.key();
        let mut entry = self.scoped_methods.entry(key).or_default();
        if let Some(existing) = entry.iter_mut().find(|(m, _)| m.name == method.name) {
            *existing = (method, true);
        } else {
            entry.push((method, true));
        }
        Ok(())
    }

    async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Self::Error> {
        if matches!(scope, AuthnScope::Global) {
            return Err(MockStoreError::InvalidGlobalMethod);
        }
        if let Some(mut entry) = self.scoped_methods.get_mut(&scope.key()) {
            entry.retain(|(m, _)| m.name.as_ref() != name);
        }
        Ok(())
    }

    async fn set_method_enabled(
        &self,
        scope: &AuthnScope,
        name: &str,
        enabled: bool,
    ) -> Result<bool, Self::Error> {
        if matches!(scope, AuthnScope::Global) {
            return Err(MockStoreError::InvalidGlobalMethod);
        }
        if let Some(mut entry) = self.scoped_methods.get_mut(&scope.key()) {
            for (m, en) in entry.iter_mut() {
                if m.name.as_ref() == name {
                    *en = enabled;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

// ── Pre-wired AuthnService fixture ──────────────────────────────────────────

/// Assemble a ready-to-login [`AuthnService`](crate::authn::service::AuthnService)
/// holding a single password-authenticated user under tenant `"t1"`.
///
/// Use this in tests whose subject is the surface around login (lockout,
/// session id rotation, custom-data limits) rather than the factor-chain
/// composition itself. The user id and identifier are taken separately so
/// tests can assert on both: `user_label` drives the deterministic UUID v5
/// via [`crate::testing::user_record`], while `identifier` is the
/// human-readable login string (e.g. an email).
///
/// ```ignore
/// use axess_core::testing::mock_authn::make_password_service;
/// let svc = make_password_service("u1", "alice@example.com", "hunter2");
/// // ... drive svc.begin_login("alice@example.com", "t1", &session, None) ...
/// ```
pub fn make_password_service(
    user_label: &str,
    identifier: &str,
    password: &str,
) -> crate::authn::service::AuthnService<MockIdentityStore, MockFactorStore> {
    use crate::authn::factor::{PasswordConfig, PasswordRules, ZeroizedString};
    use crate::authn::service::AuthnService;
    use crate::testing::{tenant_record, user_record};

    let mut user = user_record(user_label, "t1");
    user.identifier = identifier.into();
    user.display_name = identifier.into();
    let tenant = tenant_record("t1");
    let scope = AuthnScope::User {
        tenant_id: tenant.id,
        user_id: user.id,
    };

    let pw_config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(axess_factors::generate_password_hash(password)),
        rules: PasswordRules::default(),
    });

    let user_id = user.id;
    let identity = MockIdentityStore::new().with_tenant(tenant).with_user(user);
    let factors = MockFactorStore::new()
        .with_factor(scope.clone(), pw_config)
        .with_method(
            &user_id,
            AuthMethod::sequential("password", vec![FactorKind::Password], scope),
        );

    AuthnService::new(identity, factors)
}
