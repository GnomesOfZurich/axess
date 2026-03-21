//! In-memory [`IdentityStore`] and [`FactorStore`] for unit tests.
//!
//! Use the builder methods to pre-load users, tenants, and factor configs before
//! running tests. The mocks are fully thread-safe (`Arc<DashMap<…>>`).

use crate::authn::{
    event::AuthEvent,
    factor::{FactorConfig, FactorKind},
    store::{AuthMethod, FactorStore, IdentityStore},
    types::{AuthnScope, EntityState, LockoutPolicy, Tenant, User},
};
use dashmap::DashMap;
use std::sync::{Arc, Mutex};

// ── MockStoreError ─────────────────────────────────────────────────────────────

/// Infallible-ish error for the in-memory mock stores.
#[derive(Debug, thiserror::Error)]
pub enum MockStoreError {
    #[error("entity not found")]
    NotFound,
    #[error("no default tenant configured")]
    NoDefaultTenant,
}

// ── MockIdentityStore ─────────────────────────────────────────────────────────

/// In-memory [`IdentityStore`] for unit tests.
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
        }
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

    /// Return the current failed attempt count for a user.
    pub fn failed_attempts_for(&self, user_id: &str) -> u32 {
        self.failed_attempts.get(user_id).map(|r| *r).unwrap_or(0)
    }
}

impl IdentityStore for MockIdentityStore {
    type Error = MockStoreError;

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &str,
    ) -> Result<Option<User>, Self::Error> {
        let key = (tenant_id.to_string(), identifier.to_string());
        let user = self
            .by_identifier
            .get(&key)
            .and_then(|uid| self.users.get(uid.as_str()))
            .map(|r| r.clone());
        Ok(user)
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<User>, Self::Error> {
        Ok(self.users.get(user_id).map(|r| r.clone()))
    }

    async fn find_tenant(&self, identifier: &str) -> Result<Option<Tenant>, Self::Error> {
        Ok(self.tenants.get(identifier).map(|r| r.clone()))
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        self.default_tenant
            .clone()
            .ok_or(MockStoreError::NoDefaultTenant)
    }

    async fn account_status(&self, user_id: &str) -> Result<EntityState, Self::Error> {
        Ok(self
            .users
            .get(user_id)
            .map(|u| u.status.clone())
            .unwrap_or(EntityState::Guest))
    }

    async fn record_event(&self, event: AuthEvent) -> Result<(), Self::Error> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }

    async fn record_failed_attempt(&self, user_id: &str) -> Result<u32, Self::Error> {
        let mut entry = self.failed_attempts.entry(user_id.to_string()).or_insert(0);
        *entry += 1;
        Ok(*entry)
    }

    async fn reset_failed_attempts(&self, user_id: &str) -> Result<(), Self::Error> {
        self.failed_attempts.remove(user_id);
        Ok(())
    }

    fn lockout_policy(&self) -> LockoutPolicy {
        self.lockout_policy.clone()
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
    /// user_id -> Vec<AuthMethod>
    methods: Arc<DashMap<String, Vec<AuthMethod>>>,
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
    pub fn with_method(self, user_id: &str, method: AuthMethod) -> Self {
        self.methods
            .entry(user_id.to_string())
            .or_default()
            .push(method);
        self
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

    async fn available_methods(
        &self,
        user_id: &str,
        _tenant_id: &str,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        Ok(self
            .methods
            .get(user_id)
            .map(|r| r.clone())
            .unwrap_or_default())
    }
}
