//! Atomic tenant creation.
//!
//! A tenant cannot exist in a half-provisioned state: no factors, no
//! enabled auth method, or both. The single public entry point
//! [`create_tenant`] inserts the tenant row, materialises the chosen
//! [`FactorTemplate`] entries into tenant-scoped `factor_configs`, and
//! persists an [`AuthMethod`], all via the [`IdentityStore`] /
//! [`FactorStore`] trait methods. The caller bundles the inputs into a
//! [`TenantBootstrap`].
//!
//! If any step fails, the operation returns an error and the caller's
//! store is left in whatever partial state it reached. Backends that
//! care about atomicity should implement `create_tenant` / `create_user`
//! / `save_factor` / `save_method` inside a single transaction; the
//! trait doesn't impose this because not every backend supports
//! transactions (memory mocks in particular).
//!
//! ## Why this module owns the API shape
//!
//! 1. "Tenant with no factors" is unrepresentable: `TenantBootstrap`
//!    requires a non-empty `Vec<FactorTemplate>`.
//! 2. "Tenant with no enabled auth method" is unrepresentable: the
//!    default method is composed from the factors; applications that
//!    pass their own `AuthMethod` are still persisted via
//!    [`FactorStore::save_method`] which marks the row enabled.
//! 3. A single provisioning entry point keeps the invariants from
//!    being bypassed by calling factor- or method-save directly at
//!    tenant creation time.

use crate::authn::{
    factor::FactorTemplate,
    store::{AuthMethod, FactorStore, IdentityStore},
    types::{AuthnScope, Tenant},
};

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors raised during tenant provisioning.
#[derive(Debug)]
pub enum ProvisioningError<E: std::error::Error + Send + Sync + 'static> {
    /// No factor templates were supplied. A tenant must adopt at least
    /// one factor so its users have a way to authenticate.
    NoFactorsSpecified,
    /// Caller attempted to provision a tenant under the reserved
    /// system tenant id ([`TenantId::SYSTEM_STR`](crate::authn::ids::TenantId::SYSTEM_STR)).
    /// The system tenant is platform-operator scope and must not be
    /// claimable through self-service signup; allowing it would let
    /// any caller inherit "platform-global" privileges that join on
    /// the system-tenant id.
    ReservedTenantId,
    /// Wrapped backend error from the underlying stores.
    Store(E),
}

impl<E: std::error::Error + Send + Sync + 'static> std::fmt::Display for ProvisioningError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisioningError::NoFactorsSpecified => {
                f.write_str("tenant provisioning requires at least one factor template")
            }
            ProvisioningError::ReservedTenantId => {
                f.write_str("tenant id matches the reserved system-tenant UUID; refused")
            }
            ProvisioningError::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for ProvisioningError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProvisioningError::NoFactorsSpecified => None,
            ProvisioningError::ReservedTenantId => None,
            ProvisioningError::Store(e) => Some(e),
        }
    }
}

// ── TenantBootstrap ──────────────────────────────────────────────────────────

/// Everything needed to provision a tenant atomically.
///
/// Pass this to [`create_tenant`]. The caller is responsible for
/// attaching audit metadata (`created_by`) so the produced `users` /
/// `tenants` / `factor_configs` / `auth_methods` rows carry truthful
/// attribution.
///
/// For the simplest case, [`TenantBootstrap::minimal`] returns a
/// password-only bootstrap. Applications that ship a richer platform
/// default (password + TOTP, etc.) should wrap `minimal` with their own
/// constructor.
#[derive(Debug, Clone)]
pub struct TenantBootstrap {
    /// Tenant row to insert. Audit columns (`created_by`, `created_at`,
    /// etc.) should already be populated by the caller; axess does not
    /// override them.
    pub tenant: Tenant,
    /// Non-empty list of factor templates to adopt for this tenant.
    /// Each template's `default_config` is saved as a tenant-scoped row
    /// via [`FactorStore::save_factor`].
    pub factors: Vec<FactorTemplate>,
    /// Optional pre-composed auth method.
    ///
    /// - `None` → a sequential method named `default` is composed from
    ///   the factors in the order they appear. This is the common case.
    /// - `Some(method)` → persisted as-is. Use this for non-linear flows
    ///   (e.g. `FactorStep::AnyOf`) or custom method names.
    ///
    /// Either way the method is persisted via
    /// [`FactorStore::save_method`], which sets `enabled = true`: a
    /// provisioned tenant always ends up with one enabled method.
    pub method: Option<AuthMethod>,
}

impl TenantBootstrap {
    /// Minimal bootstrap: the password template from
    /// [`default_catalog`](crate::authn::factor::default_catalog) +
    /// `None` for the method (which makes `create_tenant` compose a
    /// sequential password-only method named `default`).
    ///
    /// Applications that want a richer platform default (password+TOTP,
    /// FIDO2-or-password, …) should write their own constructor rather
    /// than mutating the result of this one: the signature stays
    /// obvious and the default recipe stays discoverable.
    pub fn minimal(tenant: Tenant) -> Self {
        use crate::authn::factor::{FactorKind, default_catalog};
        let factors = default_catalog()
            .into_iter()
            .filter(|t| t.kind == FactorKind::Password)
            .collect();
        Self {
            tenant,
            factors,
            method: None,
        }
    }
}

// ── create_tenant ────────────────────────────────────────────────────────────

/// Atomically provision a new tenant.
///
/// Steps, in order:
///
/// 1. Validate `bootstrap.factors` is non-empty; otherwise return
///    [`ProvisioningError::NoFactorsSpecified`].
/// 2. Call [`IdentityAdmin::create_tenant`](crate::authn::IdentityAdmin::create_tenant) to insert the tenant row.
/// 3. For each factor template, call [`FactorStore::save_factor`] with
///    `AuthnScope::Tenant(tenant.id)` and the template's
///    `default_config`.
/// 4. Compose an `AuthMethod` from `bootstrap.method` (or default to a
///    sequential method named `default`) and persist it via
///    [`FactorStore::save_method`].
///
/// Returns the persisted tenant and the method that ended up in
/// storage so the caller can log / surface it.
///
/// # Atomicity
///
/// axess-core does not wrap the four store calls in a transaction;
/// individual backends should do so in their implementations if they
/// want all-or-nothing semantics. On failure between steps 2 and 4,
/// the tenant row exists but may have partial factor or no-method
/// state; the caller can retry or compensate as their lifecycle
/// requires.
///
/// # Example
///
/// ```no_run
/// # use axess_core::authn::{
/// #     provisioning::{TenantBootstrap, create_tenant},
/// #     types::{EntityState, Tenant},
/// #     ids::{TenantId, UserId},
/// # };
/// # use chrono::Utc;
/// # async fn demo<I, F>(identity: &I, factors: &F) -> Result<(), Box<dyn std::error::Error>>
/// # where I: axess_core::authn::store::IdentityStore,
/// #       F: axess_core::authn::store::FactorStore<Error = I::Error>,
/// # {
/// let now = Utc::now();
/// let tenant = Tenant {
///     id: axess_identity::testing::tenant("acme"),
///     identifier: "acme".into(),
///     display_name: "Acme Family Office".into(),
///     status: EntityState::Active,
///     created_by: UserId::system(),
///     created_at: now,
///     updated_by: UserId::system(),
///     updated_at: now,
/// };
/// let bootstrap = TenantBootstrap::minimal(tenant);
/// let (persisted, method) = create_tenant(identity, factors, bootstrap).await?;
/// assert_eq!(method.name.as_ref(), "default");
/// # let _ = persisted;
/// # Ok(())
/// # }
/// ```
pub async fn create_tenant<I, F>(
    identity: &I,
    factors: &F,
    bootstrap: TenantBootstrap,
) -> Result<(Tenant, AuthMethod), ProvisioningError<I::Error>>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    if bootstrap.factors.is_empty() {
        return Err(ProvisioningError::NoFactorsSpecified);
    }

    // Refuse self-service / runtime provisioning under the reserved
    // system tenant id. The system tenant must be installed exactly once at
    // platform setup, never again at runtime through this generic path.
    if bootstrap.tenant.id.is_system() {
        tracing::warn!(
            tenant_id = %bootstrap.tenant.id,
            identifier = %bootstrap.tenant.identifier,
            "provisioning refused; tenant id is reserved system UUID"
        );
        return Err(ProvisioningError::ReservedTenantId);
    }

    let scope = AuthnScope::Tenant(bootstrap.tenant.id);

    // 1. Insert the tenant row.
    identity
        .create_tenant(bootstrap.tenant.clone())
        .await
        .map_err(ProvisioningError::Store)?;

    // 2. Materialise factor configs.
    for template in &bootstrap.factors {
        factors
            .save_factor(&scope, template.default_config.clone())
            .await
            .map_err(ProvisioningError::Store)?;
    }

    // 3. Compose and persist the method.
    let method = bootstrap.method.unwrap_or_else(|| {
        AuthMethod::sequential(
            "default",
            bootstrap.factors.iter().map(|t| t.kind.clone()).collect(),
            scope.clone(),
        )
    });
    factors
        .save_method(&scope, method.clone())
        .await
        .map_err(ProvisioningError::Store)?;

    Ok((bootstrap.tenant, method))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::ids::{TenantId, UserId};
    use crate::authn::types::EntityState;
    use chrono::Utc;

    fn test_tenant() -> Tenant {
        let now = Utc::now();
        Tenant {
            id: axess_identity::testing::tenant("tenant-abc"),
            identifier: "acme".into(),
            display_name: "Acme Family Office".into(),
            status: EntityState::Active,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        }
    }

    #[test]
    fn minimal_bootstrap_has_one_factor_and_no_method() {
        let b = TenantBootstrap::minimal(test_tenant());
        assert_eq!(b.factors.len(), 1, "minimal = password only");
        assert!(b.method.is_none(), "method defaulted in create_tenant");
    }

    /// Display impl produces a distinct, non-default message per
    /// variant. Pins the `fmt -> Ok(Default::default())` body mutation
    /// (which would silently empty every error message that reaches a
    /// log line or response surface).
    #[test]
    fn provisioning_error_display_per_variant() {
        use std::io;
        let no_factors: ProvisioningError<io::Error> = ProvisioningError::NoFactorsSpecified;
        let reserved: ProvisioningError<io::Error> = ProvisioningError::ReservedTenantId;
        let store_err: ProvisioningError<io::Error> =
            ProvisioningError::Store(io::Error::other("underlying-boom"));

        assert!(
            no_factors.to_string().contains("at least one factor"),
            "NoFactorsSpecified message must mention factors"
        );
        assert!(
            reserved.to_string().contains("system-tenant"),
            "ReservedTenantId message must mention system-tenant"
        );
        let store_msg = store_err.to_string();
        assert!(
            store_msg.contains("store error") && store_msg.contains("underlying-boom"),
            "Store(_) message must surface the wrapped error (got: {store_msg})"
        );
    }

    /// `source()` returns `Some` only for the `Store(_)` variant
    /// (which wraps an underlying backend error). Pins both
    /// `source -> None` (would hide the chain so callers can't walk to
    /// the root cause) and `source -> Some(...)` body replacements
    /// (would advertise a phantom source for variants that have none).
    #[test]
    fn provisioning_error_source_only_for_store_variant() {
        use std::error::Error as _;
        use std::io;
        let no_factors: ProvisioningError<io::Error> = ProvisioningError::NoFactorsSpecified;
        let reserved: ProvisioningError<io::Error> = ProvisioningError::ReservedTenantId;
        let store_err: ProvisioningError<io::Error> =
            ProvisioningError::Store(io::Error::other("underlying"));

        assert!(
            no_factors.source().is_none(),
            "NoFactorsSpecified must not have a source"
        );
        assert!(
            reserved.source().is_none(),
            "ReservedTenantId must not have a source"
        );
        assert!(
            store_err.source().is_some(),
            "Store(_) must expose the wrapped backend error as source"
        );
    }

    /// Regression: provisioning under the reserved system tenant
    /// id must be refused, even when factors are valid and the rest of the
    /// bootstrap is well-formed.
    #[tokio::test]
    async fn create_tenant_refuses_reserved_system_tenant_id() {
        use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore};
        let now = Utc::now();
        let system_tenant = Tenant {
            id: TenantId::system(),
            identifier: "attacker-claim".into(),
            display_name: "Spoofed System".into(),
            status: EntityState::Active,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        };
        let bootstrap = TenantBootstrap::minimal(system_tenant);
        let identity = MockIdentityStore::new();
        let factors = MockFactorStore::new();
        let res = create_tenant(&identity, &factors, bootstrap).await;
        assert!(matches!(res, Err(ProvisioningError::ReservedTenantId)));
    }
}
