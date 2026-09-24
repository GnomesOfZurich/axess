//! Ready-to-use in-memory authentication backend for prototyping and examples.
//!
//! `InMemoryBackend` provides a zero-configuration identity and factor store
//! that runs entirely in memory. Use it to get a working login flow in minutes
//! before committing to a database schema.
//!
//! # Example
//!
//! ```rust
//! use axess_core::session::storage::in_memory_backend::InMemoryBackend;
//!
//! let backend = InMemoryBackend::new()
//!     .with_default_tenant("default", "Default Tenant")
//!     .with_user_password("alice", "default", "Gnomes2+")
//!     .with_user_password("bob", "default", "s3cret!");
//! ```
//!
//! # Limitations
//!
//! - Data is lost on process restart; there is no persistence.
//! - Passwords are hashed with Argon2id at registration time (realistic latency).
//! - Not suitable for production; use `SqliteSessionStore`, `PostgresSessionStore`,
//!   or `ValkeySessionStore` for persistent deployments.

use crate::authn::store::AuditOutcome;
use crate::authn::{
    factor::{FactorConfig, FactorKind, PasswordConfig, PasswordRules, ZeroizedString},
    ids::{TenantId, UserId},
    store::{AuthMethod, FactorStore},
    types::{AuthnScope, EntityState, Tenant, User},
};
use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore, MockStoreError};
use std::sync::Arc;

/// In-memory authentication backend for prototyping and examples.
///
/// Wraps the thread-safe `MockIdentityStore` and `MockFactorStore` with a
/// higher-level API. Suitable for examples, demos, and integration tests.
///
/// See the [module documentation](self) for usage.
#[derive(Clone)]
pub struct InMemoryBackend {
    pub(crate) identity: MockIdentityStore,
    pub(crate) factors: MockFactorStore,
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryBackend {
    /// Create an empty backend with no users or tenants.
    pub fn new() -> Self {
        Self {
            identity: MockIdentityStore::new(),
            factors: MockFactorStore::new(),
        }
    }

    /// Register a default tenant with the given ID and display name.
    ///
    /// This tenant is returned by `default_tenant()` and used when the
    /// application is single-tenant.
    pub fn with_default_tenant(
        mut self,
        id: impl Into<Arc<str>>,
        name: impl Into<Arc<str>>,
    ) -> Self {
        let id_arc: Arc<str> = id.into();
        let name = name.into();
        let now = chrono::Utc::now();
        let tenant = Tenant {
            // Typed `TenantId` is a Uuid newtype; derive deterministically
            // from the human identifier so repeated calls produce the
            // same id (tests rely on this) without requiring the caller
            // to mint a UUID by hand.
            id: axess_identity::testing::tenant(&id_arc),
            identifier: id_arc,
            display_name: name,
            status: EntityState::Active,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        };
        self.identity = self.identity.with_default_tenant(tenant);
        self
    }

    /// Register a user with password authentication.
    ///
    /// Creates the user, hashes the password with Argon2id, and configures a
    /// `password` authentication method. The user is immediately `Active`.
    ///
    /// `tenant_id` must match a previously registered tenant (see
    /// [`with_default_tenant`](Self::with_default_tenant)).
    pub fn with_user_password(
        mut self,
        username: impl Into<Arc<str>>,
        tenant_id: impl Into<Arc<str>>,
        password: &str,
    ) -> Self {
        let username = username.into();
        let tenant_id_arc: Arc<str> = tenant_id.into();
        // Typed ids are Uuid newtypes derived deterministically from the
        // human identifiers so successive `with_user_password(...)` calls
        // for the same identifier resolve to the same row.
        let user_id = axess_identity::testing::user(&username);
        let tenant_id = axess_identity::testing::tenant(&tenant_id_arc);

        let now = chrono::Utc::now();
        let user = User {
            id: user_id,
            tenant_id,
            identifier: username.clone(),
            display_name: username.clone(),
            status: EntityState::Active,
            webauthn_id: None,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        };

        self.identity = self.identity.with_user(user);

        // Hash the password.
        let hash = axess_factors::generate_password_hash(password);
        let config = FactorConfig::Password(PasswordConfig {
            hash: ZeroizedString::new(hash),
            rules: PasswordRules::default(),
        });
        let scope = AuthnScope::User { user_id, tenant_id };
        self.factors = self.factors.with_factor(scope, config);

        // Register the password method.
        let method =
            AuthMethod::sequential("password", vec![FactorKind::Password], AuthnScope::System);
        self.factors = self.factors.with_method(&user_id, method);

        self
    }

    /// Return a reference to the underlying identity store (for advanced configuration).
    pub fn identity_store(&self) -> &MockIdentityStore {
        &self.identity
    }

    /// Return a reference to the underlying factor store (for advanced configuration).
    pub fn factor_store(&self) -> &MockFactorStore {
        &self.factors
    }
}

// ── Delegate identity tiers to inner MockIdentityStore ────────────────────────

impl crate::authn::store::IdentityLookup for InMemoryBackend {
    type Error = MockStoreError;

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, Self::Error> {
        self.identity.find_user(identifier, tenant_id).await
    }

    async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        self.identity.get_user(user_id).await
    }

    async fn find_tenant(&self, identifier: &str) -> Result<Option<Tenant>, Self::Error> {
        self.identity.find_tenant(identifier).await
    }

    async fn default_tenant(&self) -> Result<Tenant, Self::Error> {
        self.identity.default_tenant().await
    }

    async fn account_status(&self, user_id: &UserId) -> Result<EntityState, Self::Error> {
        self.identity.account_status(user_id).await
    }
}

impl crate::authn::store::IdentityAuthnLog for InMemoryBackend {
    async fn record_event(
        &self,
        event: crate::authn::event::AuthEvent,
    ) -> Result<AuditOutcome, Self::Error> {
        self.identity.record_event(event).await
    }

    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        self.identity.record_failed_attempt(user_id).await
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        self.identity.reset_failed_attempts(user_id).await
    }
}

impl crate::authn::store::IdentityAdmin for InMemoryBackend {
    async fn create_tenant(&self, tenant: Tenant) -> Result<(), Self::Error> {
        self.identity.create_tenant(tenant).await
    }

    async fn create_user(&self, user: User) -> Result<(), Self::Error> {
        self.identity.create_user(user).await
    }

    async fn activate_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        self.identity.activate_user(user_id).await
    }

    async fn suspend_user(
        &self,
        user_id: &UserId,
        detail: crate::authn::types::StatusDetail,
    ) -> Result<(), Self::Error> {
        self.identity.suspend_user(user_id, detail).await
    }
}

impl crate::authn::store::IdentityPasswordHistory for InMemoryBackend {
    async fn record_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Self::Error> {
        self.identity.record_password_hash(user_id, hash).await
    }

    async fn password_history(
        &self,
        user_id: &UserId,
        count: usize,
    ) -> Result<Vec<String>, Self::Error> {
        self.identity.password_history(user_id, count).await
    }
}

// ── Delegate FactorStore to inner MockFactorStore ──────────────────────────────

impl FactorStore for InMemoryBackend {
    type Error = MockStoreError;

    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<crate::authn::store::ResolvedFactor>, Self::Error> {
        self.factors.resolve_factor(scope, kind).await
    }

    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        self.factors.load_factor(scope, kind).await
    }

    async fn save_factor(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<(), Self::Error> {
        self.factors.save_factor(scope, config).await
    }

    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        self.factors
            .compare_and_save_factor(scope, prior, updated)
            .await
    }

    async fn available_methods(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        self.factors.available_methods(user_id, tenant_id).await
    }

    async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Self::Error> {
        self.factors.save_method(scope, method).await
    }

    async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Self::Error> {
        self.factors.remove_method(scope, name).await
    }

    async fn set_method_enabled(
        &self,
        scope: &AuthnScope,
        name: &str,
        enabled: bool,
    ) -> Result<bool, Self::Error> {
        self.factors.set_method_enabled(scope, name, enabled).await
    }
}

#[cfg(test)]
mod in_memory_backend_tests;

impl crate::authn::store::IdentityPasswordReset for InMemoryBackend {
    async fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        self.identity
            .store_reset_token(user_id, token_hash, expires_at)
            .await
    }

    async fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
    ) -> Result<bool, Self::Error> {
        self.identity.verify_reset_token(user_id, token_hash).await
    }
}
