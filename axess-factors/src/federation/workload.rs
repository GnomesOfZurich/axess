//! Generic workload-identity resolver.
//!
//! Verifies a bearer JWT against a configured
//! [`super::super::jwt::verifier::JwtVerifier`] and dispatches the
//! verified claims through a caller-supplied claim-mapping closure to
//! produce a [`WorkloadMapping`]. The resolver then wraps the mapped
//! identity in a [`axess_identity::Principal::Workload`] with the
//! caller-supplied [`axess_identity::Issuer`] and the pinned trust
//! domain.
//!
//! Use this for **every** JWT-bearer workload identity flow; GitHub
//! Actions OIDC, Kubernetes service-account projected tokens, GitLab CI
//! OIDC, CircleCI / Buildkite OIDC, Okta / Azure AD / Auth0, axess's
//! own `LocalIdP`, internal token formats, etc. Different IdPs put the
//! identity in different claims (`sub`, `azp`, `client_id`, a custom
//! `service`, …); rather than baking one convention into axess, the
//! adopter supplies a small claim type + mapping closure per issuer.
//! The resolver handles JWT verification + trust-domain pinning +
//! `Principal` construction; the closure handles
//! claim → identity-components.
//!
//! # SPIFFE-spec adapter
//!
//! [`JwtSvidResolver`](super::super::jwt::svid::JwtSvidResolver) is the
//! one exception: it implements the SPIFFE JWT-SVID *spec* (mandatory
//! `spiffe://` URI format in `sub`, trust-domain extracted from the
//! URI, etc.), not just a claim shape. Use it when the IdP advertises
//! SPIFFE compliance.
//!
//! # Recipes for common issuers
//!
//! See the `axess-example-workload-identity` crate for ready-made
//! claim parsers + mappers for GitHub Actions and Kubernetes
//! service-account tokens. Adopters copy the recipe that matches their
//! IdP into their own code and wire it up against the resolver here.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use axess_identity::{
    IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain, WorkloadId,
    WorkloadPrincipal,
};
use serde::de::DeserializeOwned;

use crate::jwt::verifier::{JtiReplayStore, JwtVerifier, NoReplay, VerifiedClaims};

/// Output of the caller-supplied claim-mapping closure.
///
/// The closure builds these from the verified JWT claims; the resolver
/// wraps them into a [`Principal::Workload`] after pinning the trust
/// domain.
#[derive(Debug, Clone)]
pub struct WorkloadMapping {
    /// Synthesized SPIFFE-shape identifier. The resolver checks that
    /// its trust domain matches the resolver's `expected_trust_domain`
    /// before accepting the token.
    pub workload_id: WorkloadId,
    /// Service name component (second SPIFFE path segment).
    pub service_name: String,
    /// Tenant slug component (third SPIFFE path segment). Used to
    /// derive the typed [`TenantId`] in adopter middleware.
    pub tenant_slug: String,
    /// Provider-specific attributes preserved on the resulting
    /// [`WorkloadPrincipal::attributes`]; useful for Cedar policies
    /// conditioning on issuer-specific metadata (org, environment,
    /// scope set, …).
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Generic workload-identity resolver.
///
/// Construction is per-request. The wrapped [`JwtVerifier`] is the
/// long-lived shared instance configured at process startup with the
/// IdP's JWKS handle, expected `iss`, and expected `aud`.
///
/// ```ignore
/// // Startup wiring:
/// let verifier = Arc::new(
///     JwtVerifier::new(okta_jwks_handle)
///         .with_issuer("https://gnomes.okta.com")
///         .with_audience("axess-platform"),
/// );
/// let trust_domain = TrustDomain::new("okta.gnomes.local").unwrap();
///
/// // Per-request: adopter middleware peeks at the token to look up
/// // tenant_id, then constructs the resolver with a claim mapper that
/// // pulls the workload identity from the `sub` claim.
/// let resolver = WorkloadResolver::new(
///     verifier.clone(),
///     trust_domain.clone(),
///     tenant_id,
///     Issuer::OAuth, // or Issuer::custom("github_actions").unwrap(), etc.
///     token,
///     |claims| {
///         let sub = claims.sub.as_deref().ok_or_else(|| {
///             IdentityError::InvalidComponent("missing sub claim".into())
///         })?;
///         // …adopter parses sub into (service, tenant_slug)…
///         let workload_id = WorkloadId::build(&trust_domain, service, tenant_slug)?;
///         Ok(WorkloadMapping {
///             workload_id,
///             service_name: service.to_string(),
///             tenant_slug: tenant_slug.to_string(),
///             attributes: BTreeMap::new(),
///         })
///     },
/// );
/// let principal = resolver.resolve().await?;
/// ```
pub struct WorkloadResolver<C, F, R = NoReplay>
where
    C: DeserializeOwned + Send + Sync + 'static,
    F: Fn(&VerifiedClaims<C>) -> Result<WorkloadMapping, IdentityError> + Send + Sync,
    R: JtiReplayStore,
{
    verifier: Arc<JwtVerifier<R>>,
    expected_trust_domain: TrustDomain,
    tenant_id: TenantId,
    issuer: Issuer,
    token: String,
    claim_mapper: F,
    _marker: PhantomData<fn() -> C>,
}

impl<C, F, R> WorkloadResolver<C, F, R>
where
    C: DeserializeOwned + Send + Sync + 'static,
    F: Fn(&VerifiedClaims<C>) -> Result<WorkloadMapping, IdentityError> + Send + Sync,
    R: JtiReplayStore,
{
    /// Construct a resolver. JWT-level validation (signature, `iss`,
    /// `aud`, `exp`, `nbf`, algorithm allowlist) is delegated to the
    /// wrapped [`JwtVerifier`]. The claim-mapping closure is invoked
    /// on successful verification. The `issuer` parameter is recorded
    /// verbatim on the resulting [`WorkloadPrincipal`] for audit
    /// attribution; use [`Issuer::OAuth`] for generic JWT-bearer flows
    /// or [`Issuer::Custom`] with a stable short label
    /// (e.g. `"github_actions"`, `"kubernetes"`) when audit logs need
    /// finer granularity.
    pub fn new(
        verifier: Arc<JwtVerifier<R>>,
        expected_trust_domain: TrustDomain,
        tenant_id: TenantId,
        issuer: Issuer,
        token: impl Into<String>,
        claim_mapper: F,
    ) -> Self {
        Self {
            verifier,
            expected_trust_domain,
            tenant_id,
            issuer,
            token: token.into(),
            claim_mapper,
            _marker: PhantomData,
        }
    }
}

impl<C, F, R> PrincipalResolver for WorkloadResolver<C, F, R>
where
    C: DeserializeOwned + Send + Sync + 'static,
    F: Fn(&VerifiedClaims<C>) -> Result<WorkloadMapping, IdentityError> + Send + Sync,
    R: JtiReplayStore + 'static,
{
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        let claims = self.verifier.verify::<C>(&self.token).await.map_err(|e| {
            tracing::debug!(error = %e, "WorkloadResolver: JWT verification failed");
            IdentityError::NotAuthenticated
        })?;

        let mapped = (self.claim_mapper)(&claims)?;

        // Trust-domain pinning; defense in depth against a confused
        // deputy where the JWKS happens to be shared across trust
        // domains. Mirrors the JwtSvidResolver + MtlsResolver pattern.
        let token_trust_domain = extract_trust_domain(&mapped.workload_id)?;
        if token_trust_domain != self.expected_trust_domain {
            tracing::warn!(
                expected = %self.expected_trust_domain,
                presented = %token_trust_domain,
                "WorkloadResolver: trust domain mismatch",
            );
            return Err(IdentityError::InvalidSpiffeId(format!(
                "trust domain mismatch: expected {expected}, presented {presented}",
                expected = self.expected_trust_domain,
                presented = token_trust_domain,
            )));
        }

        Ok(Principal::Workload(WorkloadPrincipal {
            workload_id: mapped.workload_id,
            trust_domain: token_trust_domain,
            issuer: self.issuer.clone(),
            tenant_id: self.tenant_id,
            tenant_slug: mapped.tenant_slug,
            service_name: mapped.service_name,
            attributes: mapped.attributes,
        }))
    }
}

/// Pull the trust domain off a parsed [`WorkloadId`].
///
/// The SPIFFE-ID format is `spiffe://<trust_domain>/<path>`; the
/// trust domain is the host component. Used by the trust-domain
/// pinning check after the claim mapper has produced its `WorkloadId`.
fn extract_trust_domain(id: &WorkloadId) -> Result<TrustDomain, IdentityError> {
    let raw = id.as_str();
    let after = raw
        .strip_prefix("spiffe://")
        .ok_or_else(|| IdentityError::InvalidSpiffeId(format!("missing scheme: {raw}")))?;
    let td_str = after
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            IdentityError::InvalidSpiffeId(format!("SPIFFE URI missing trust domain: {raw}"))
        })?;
    TrustDomain::new(td_str)
}

#[cfg(test)]
mod tests;
