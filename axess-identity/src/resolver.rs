//! `PrincipalResolver` trait + `CliResolver` impl.
//!
//! The trait shape is the workload-identity roadmap pattern: one
//! async method, one return type, multiple impls. Adopters select the
//! impl appropriate to their context (CLI bootstrap for workers;
//! session extraction provided in axess-core for HTTP handlers);
//! downstream code consumes the resulting [`Principal`] uniformly.
//!
//! Two impls land here:
//!
//! - `CliResolver`: workload identity from CLI / env data, the
//!   only resolution mode available before federated identity work
//!   lights up. The builder shape avoids the long argument list of
//!   a direct constructor; every field is required by the time
//!   `build()` is called so the resulting resolver is always
//!   complete.
//! - [`MockResolver`](crate::testing::MockResolver): testing aid; lives
//!   in [`crate::testing`].
//!
//! Session-aware resolution stays in axess-core (`SessionResolver`,
//! depends on `AuthSession`).

use std::collections::BTreeMap;

use crate::TenantId;

use crate::{IdentityError, Issuer, Principal, TrustDomain, WorkloadId, WorkloadPrincipal};

/// Async resolver that produces a [`Principal`] from a context-specific
/// identity source. See module-level docs for the dispatch model.
pub trait PrincipalResolver: Send + Sync {
    /// Resolve the principal. Implementations may hit the network
    /// (future `JwtSvidResolver`), read a session
    /// (axess-core's `SessionResolver`), or simply return a value
    /// built at construction (`CliResolver`, [`MockResolver`](crate::testing::MockResolver)).
    fn resolve(&self)
    -> impl std::future::Future<Output = Result<Principal, IdentityError>> + Send;
}

/// CLI / environment-sourced workload-identity resolver.
///
/// The operator supplies trust domain, service name, tenant slug, and
/// the typed [`TenantId`] (matching `tenants.id` in the adopter's
/// store; adopters with a slug↔UUID registry resolve it once at
/// startup before constructing the resolver). Holds the resolved
/// principal as a frozen value; every call to [`resolve`](Self::resolve)
/// returns the same `Principal::Workload`.
///
/// Future swap-in for JWT-SVID / mTLS / SPIRE happens at the resolver
/// boundary; adopter code that depends on [`PrincipalResolver`] does
/// not change.
#[derive(Debug, Clone)]
pub struct CliResolver {
    workload: WorkloadPrincipal,
}

impl CliResolver {
    /// Begin a builder for a [`CliResolver`]. All fields are required
    /// by [`build`](CliResolverBuilder::build).
    pub fn builder() -> CliResolverBuilder {
        CliResolverBuilder::default()
    }

    /// Borrow the resolved workload principal without re-running
    /// `resolve`. Useful for adopter code that needs the typed
    /// principal at sync call sites (e.g. building log spans).
    pub fn workload(&self) -> &WorkloadPrincipal {
        &self.workload
    }

    /// Build a [`Principal::Human`] from the same principal data
    /// (CLI-supplied tenant) instead of [`Principal::Workload`].
    /// Useful only in narrow adapter contexts; most adopters want
    /// the default `Workload` shape from [`resolve`](Self::resolve).
    pub fn as_workload_principal(&self) -> &WorkloadPrincipal {
        &self.workload
    }
}

impl PrincipalResolver for CliResolver {
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        Ok(Principal::Workload(self.workload.clone()))
    }
}

/// Builder for [`CliResolver`]. Every field except `attributes` is
/// required; `build()` returns `Err` if any are missing.
#[derive(Debug, Default, Clone)]
pub struct CliResolverBuilder {
    trust_domain: Option<TrustDomain>,
    service_name: Option<String>,
    tenant_id: Option<TenantId>,
    tenant_slug: Option<String>,
    attributes: BTreeMap<String, serde_json::Value>,
}

impl CliResolverBuilder {
    /// Set the trust domain. Required.
    pub fn trust_domain(mut self, value: TrustDomain) -> Self {
        self.trust_domain = Some(value);
        self
    }

    /// Set the service name. Required.
    pub fn service_name(mut self, value: impl Into<String>) -> Self {
        self.service_name = Some(value.into());
        self
    }

    /// Set the typed tenant identifier. Required.
    pub fn tenant_id(mut self, value: TenantId) -> Self {
        self.tenant_id = Some(value);
        self
    }

    /// Set the human-readable tenant slug. Required.
    pub fn tenant_slug(mut self, value: impl Into<String>) -> Self {
        self.tenant_slug = Some(value.into());
        self
    }

    /// Set arbitrary key-value attributes. Optional; defaults to empty.
    pub fn attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Build the resolver. Validates that every required field is set
    /// and that the resulting [`WorkloadId`] is a valid SPIFFE URI.
    pub fn build(self) -> Result<CliResolver, IdentityError> {
        let trust_domain = self
            .trust_domain
            .ok_or_else(|| IdentityError::InvalidComponent("trust_domain not set".to_string()))?;
        let service_name = self
            .service_name
            .ok_or_else(|| IdentityError::InvalidComponent("service_name not set".to_string()))?;
        let tenant_id = self
            .tenant_id
            .ok_or_else(|| IdentityError::InvalidComponent("tenant_id not set".to_string()))?;
        let tenant_slug = self
            .tenant_slug
            .ok_or_else(|| IdentityError::InvalidComponent("tenant_slug not set".to_string()))?;
        let workload_id = WorkloadId::build(&trust_domain, &service_name, &tenant_slug)?;
        let workload = WorkloadPrincipal {
            workload_id,
            trust_domain,
            issuer: Issuer::Cli,
            tenant_id,
            tenant_slug,
            service_name,
            attributes: self.attributes,
        };
        Ok(CliResolver { workload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tenant() -> TenantId {
        TenantId::from_bytes([9u8; 16])
    }

    #[tokio::test]
    async fn cli_resolver_builds_workload_principal() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let resolver = CliResolver::builder()
            .trust_domain(trust.clone())
            .service_name("compute-worker")
            .tenant_id(sample_tenant())
            .tenant_slug("ekekrantz")
            .build()
            .unwrap();
        let principal = resolver.resolve().await.unwrap();
        match principal {
            Principal::Workload(w) => {
                assert_eq!(
                    w.workload_id.as_str(),
                    "spiffe://gnomes.local/compute-worker/ekekrantz"
                );
                assert_eq!(w.trust_domain, trust);
                assert_eq!(w.issuer, Issuer::Cli);
                assert_eq!(w.tenant_id, sample_tenant());
                assert_eq!(w.tenant_slug, "ekekrantz");
                assert_eq!(w.service_name, "compute-worker");
                assert!(w.attributes.is_empty());
            }
            Principal::Human(_) => panic!("expected Workload principal"),
        }
    }

    #[tokio::test]
    async fn cli_resolver_resolve_is_idempotent() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let resolver = CliResolver::builder()
            .trust_domain(trust)
            .service_name("feed-worker")
            .tenant_id(sample_tenant())
            .tenant_slug("ekekrantz")
            .build()
            .unwrap();
        let a = resolver.resolve().await.unwrap();
        let b = resolver.resolve().await.unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn cli_resolver_builder_rejects_missing_trust_domain() {
        let err = CliResolver::builder()
            .service_name("compute-worker")
            .tenant_id(sample_tenant())
            .tenant_slug("ekekrantz")
            .build()
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidComponent(_)));
    }

    #[test]
    fn cli_resolver_builder_rejects_missing_service_name() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let err = CliResolver::builder()
            .trust_domain(trust)
            .tenant_id(sample_tenant())
            .tenant_slug("ekekrantz")
            .build()
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidComponent(_)));
    }

    #[test]
    fn cli_resolver_builder_rejects_missing_tenant_id() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let err = CliResolver::builder()
            .trust_domain(trust)
            .service_name("compute-worker")
            .tenant_slug("ekekrantz")
            .build()
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidComponent(_)));
    }

    #[test]
    fn cli_resolver_builder_rejects_missing_tenant_slug() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let err = CliResolver::builder()
            .trust_domain(trust)
            .service_name("compute-worker")
            .tenant_id(sample_tenant())
            .build()
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidComponent(_)));
    }

    #[test]
    fn cli_resolver_builder_rejects_invalid_service_name() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let err = CliResolver::builder()
            .trust_domain(trust)
            .service_name("compute worker")
            .tenant_id(sample_tenant())
            .tenant_slug("ekekrantz")
            .build()
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidComponent(_)));
    }

    #[tokio::test]
    async fn cli_resolver_carries_attributes() {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let resolver = CliResolver::builder()
            .trust_domain(trust)
            .service_name("compute-worker")
            .tenant_id(sample_tenant())
            .tenant_slug("ekekrantz")
            .attribute("worker_pid", serde_json::json!(12345))
            .attribute("hostname", serde_json::json!("worker-1.local"))
            .build()
            .unwrap();
        let workload = resolver.workload();
        assert_eq!(workload.attributes.len(), 2);
        assert_eq!(workload.attributes["worker_pid"], serde_json::json!(12345));
    }
}
