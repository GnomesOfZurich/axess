//! Core storage traits for authentication — `IdentityStore` and `FactorStore`.
//!
//! These replace the monolithic `AuthnBackend` trait. They use native `async fn`
//! (Rust 1.75+), no `async-trait`, and `Arc<str>` for all IDs.

use crate::authn::{
    event::AuthEvent,
    factor::{FactorConfig, FactorKind},
    types::{AuthnScope, EntityState, LockoutPolicy, StatusDetail, Tenant, User},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── IdentityStore ─────────────────────────────────────────────────────────────

/// Minimal identity storage interface. The only required impl for authentication.
///
/// Uses [`Arc<str>`] for all IDs — no generics except the associated error type.
/// Implemented with native `async fn` (Rust 1.75+) — no `async-trait` macro.
pub trait IdentityStore: Send + Sync + Clone + 'static {
    /// Error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Look up a user by their login identifier within a tenant.
    fn find_user(
        &self,
        identifier: &str,
        tenant_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send;

    /// Look up a user by their opaque ID.
    fn get_user(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<User>, Self::Error>> + Send;

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
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<EntityState, Self::Error>> + Send;

    /// Record an authentication event (audit log).
    fn record_event(
        &self,
        event: AuthEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Increment the failed attempt counter for a user. Returns the new count.
    fn record_failed_attempt(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<u32, Self::Error>> + Send;

    /// Reset the failed attempt counter (call after successful authentication).
    fn reset_failed_attempts(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Return the lockout policy for this store. Default: 5 attempts, 15-minute lockout.
    fn lockout_policy(&self) -> LockoutPolicy {
        LockoutPolicy::default()
    }

    // ── Lifecycle management ──────────────────────────────────────────────────

    /// Create a new user. The user should typically be in [`EntityState::Candidate`]
    /// or [`EntityState::Pending`] state.
    ///
    /// Returns an error if a user with the same identifier already exists in the tenant.
    fn create_user(
        &self,
        user: User,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Transition a user to [`EntityState::Active`].
    ///
    /// Called after completing a signup workflow (e.g. email verification).
    fn activate_user(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Transition a user to [`EntityState::Suspended`] with the given reason.
    ///
    /// Existing authenticated sessions are not automatically invalidated —
    /// use middleware that checks [`account_status`](Self::account_status) on
    /// each request, or combine with [`SessionRegistry::invalidate_user`](crate::session::store::SessionRegistry::invalidate_user).
    fn suspend_user(
        &self,
        user_id: &str,
        detail: StatusDetail,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

// ── FactorStore ───────────────────────────────────────────────────────────────

/// Factor credential storage. Implement alongside [`IdentityStore`] (usually same DB struct).
///
/// Provides typed [`FactorConfig`] — no `HashMap<String, JsonValue>`.
pub trait FactorStore: Send + Sync + Clone + 'static {
    /// Error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the factor configuration for a given scope and kind.
    ///
    /// Scope resolution order: User > Tenant > Global.
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

    /// Return the ordered list of authentication methods available for a user.
    ///
    /// Each method has a name and an ordered list of factor kinds that must be
    /// verified in sequence.
    fn available_methods(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<AuthMethod>, Self::Error>> + Send;
}

// ── AuthMethod ────────────────────────────────────────────────────────────────

/// An authentication method: a named, ordered sequence of factor kinds.
///
/// For example, `"password+totp"` with `factors = [Password, Totp]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    /// Human-readable method name, e.g. `"password"`, `"password+totp"`.
    pub name: Arc<str>,
    /// Factor kinds in the order they must be verified.
    pub factors: Vec<FactorKind>,
    /// The scope at which this method is defined.
    pub scope: AuthnScope,
}

// ── AuthnBackend convenience supertrait ───────────────────────────────────────

/// Convenience supertrait for types that implement both [`IdentityStore`] and [`FactorStore`]
/// with the same error type.
///
/// Most applications implement both traits on the same database-backed struct.
pub trait AuthnBackend: IdentityStore<Error = <Self as FactorStore>::Error> + FactorStore {}

impl<T> AuthnBackend for T where
    T: IdentityStore + FactorStore + IdentityStore<Error = <T as FactorStore>::Error>
{
}
