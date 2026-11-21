//! A workload principal from a JWT SVID the agent validated.
//!
//! [`JwtSvidResolver`](https://docs.rs/axess-factors/latest/axess_factors/jwt/svid/struct.JwtSvidResolver.html)
//! verifies a token in the process, against a key set. This resolver asks
//! the agent instead, through `ValidateJWTSVID`: the agent holds the
//! bundles and makes the cryptographic check, and the process holds no key
//! set at all. What follows the check is the same as there: the trust
//! domain is pinned, the SPIFFE path has the platform's shape, and the
//! tenant is the registry's answer for the slug the path names.

use std::collections::BTreeMap;
use std::sync::Arc;

use axess_identity::{
    IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain, WorkloadPrincipal,
};
use zeroize::Zeroizing;

use super::client::SpireClient;
use super::transport::TARGET;

/// Maps a SPIFFE tenant slug to the tenant registered for it.
type TenantLookup = Arc<dyn Fn(&str) -> Option<TenantId> + Send + Sync>;

/// Resolves a [`Principal::Workload`] from a JWT SVID by having the SPIRE
/// agent validate it.
///
/// Built per request, as the other resolvers are. The agent checks the
/// token's signature, its audience and its expiry; the resolver then pins
/// the trust domain, reads `spiffe://<trust_domain>/<service>/<tenant_slug>`
/// out of the SPIFFE ID, and takes the tenant from `tenant_lookup`. A token
/// that carries a `tid` claim must name the tenant the lookup answered.
///
/// Every refusal by the agent, and an agent that cannot be reached, is
/// [`IdentityError::NotAuthenticated`]: the caller learns that it was
/// refused, and the cause is logged at `debug` on `axess::workload::spire`.
///
/// ```no_run
/// use axess_core::workload::spire::{AgentJwtSvidResolver, Endpoint, SpireClient};
/// use axess_identity::{PrincipalResolver, TenantId, TrustDomain};
///
/// # async fn run(token: String, tenants: std::collections::HashMap<String, TenantId>)
/// # -> Result<(), Box<dyn std::error::Error>> {
/// let trust_domain = TrustDomain::new("prod.example.com")?;
/// let client = SpireClient::builder(Endpoint::from_env()?, trust_domain.clone()).build();
///
/// let resolver = AgentJwtSvidResolver::new(
///     client,
///     "https://api.example.com",
///     trust_domain,
///     token,
///     move |slug| tenants.get(slug).copied(),
/// );
/// let principal = resolver.resolve().await?;
/// # let _ = principal;
/// # Ok(())
/// # }
/// ```
pub struct AgentJwtSvidResolver {
    client: SpireClient,
    audience: String,
    expected_trust_domain: TrustDomain,
    token: Zeroizing<String>,
    tenant_lookup: TenantLookup,
}

impl AgentJwtSvidResolver {
    /// A resolver for `token`, presented to this service as `audience`, by
    /// a workload that must belong to `expected_trust_domain`.
    /// `tenant_lookup` maps the tenant slug of the SPIFFE path to the
    /// tenant registered for it, and answers `None` for a slug it does not
    /// know.
    pub fn new(
        client: SpireClient,
        audience: impl Into<String>,
        expected_trust_domain: TrustDomain,
        token: impl Into<String>,
        tenant_lookup: impl Fn(&str) -> Option<TenantId> + Send + Sync + 'static,
    ) -> Self {
        Self {
            client,
            audience: audience.into(),
            expected_trust_domain,
            token: Zeroizing::new(token.into()),
            tenant_lookup: Arc::new(tenant_lookup),
        }
    }
}

impl PrincipalResolver for AgentJwtSvidResolver {
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        let validated = self
            .client
            .validate_jwt_svid(&self.audience, &self.token)
            .await
            .map_err(|error| {
                tracing::debug!(
                    target: TARGET,
                    error = %error,
                    "AgentJwtSvidResolver: the agent did not validate the token",
                );
                IdentityError::NotAuthenticated
            })?;

        if *validated.trust_domain() != self.expected_trust_domain {
            tracing::warn!(
                target: TARGET,
                expected = %self.expected_trust_domain,
                presented = %validated.trust_domain(),
                "AgentJwtSvidResolver: trust domain mismatch",
            );
            return Err(IdentityError::InvalidSpiffeId(format!(
                "trust domain mismatch: expected {expected}, presented {presented}",
                expected = self.expected_trust_domain,
                presented = validated.trust_domain(),
            )));
        }

        // The platform's shape, read where the in-process SVID resolvers
        // read it.
        let parts = validated.spiffe_id().components()?;
        let (service_name, tenant_slug) = (parts.service.to_owned(), parts.tenant_slug.to_owned());
        let Some(tenant_id) = (self.tenant_lookup)(&tenant_slug) else {
            tracing::warn!(
                target: TARGET,
                "AgentJwtSvidResolver: tenant slug is not in the registry",
            );
            return Err(IdentityError::NotAuthenticated);
        };
        // A `tid` claim is the issuer's statement of the tenant; where the
        // token makes one, it has to agree with the registry.
        if let Some(claimed) = validated.claims().get("tid") {
            let agrees = claimed
                .as_str()
                .and_then(|tid| tid.parse::<TenantId>().ok())
                .is_some_and(|tid| tid == tenant_id);
            if !agrees {
                tracing::warn!(
                    target: TARGET,
                    "AgentJwtSvidResolver: tid claim disagrees with the SPIFFE tenant slug",
                );
                return Err(IdentityError::NotAuthenticated);
            }
        }

        Ok(Principal::Workload(WorkloadPrincipal {
            workload_id: validated.spiffe_id().clone(),
            trust_domain: validated.trust_domain().clone(),
            issuer: Issuer::JwtSvid,
            tenant_id,
            tenant_slug,
            service_name,
            attributes: BTreeMap::new(),
        }))
    }
}

#[cfg(all(test, unix))]
mod tests;
