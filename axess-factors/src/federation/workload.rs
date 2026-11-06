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
//! The resolver handles JWT verification + `Principal` construction; the
//! closure handles claim → identity-components (service name, tenant slug,
//! attributes).
//!
//! The resolver builds the [`WorkloadId`] itself, from its own expected trust
//! domain and the mapped service and tenant slug, and derives the
//! [`TenantId`] from the verified claims' slug through the lookup it was
//! given, refusing a slug the lookup does not know. The mapper cannot choose
//! the trust domain or the tenant. The separation between issuers is still
//! the verifier's `iss` and `aud` pins.
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

use crate::jwt::verifier::{
    JtiReplayStore, JwtVerifier, NoReplay, VerifiedClaims, verifier_is_pinned,
};

/// The adopter's registry: a tenant slug to its typed id, `None` when unknown.
type TenantLookup = Arc<dyn Fn(&str) -> Option<TenantId> + Send + Sync>;

/// Output of the caller-supplied claim-mapping closure.
///
/// The closure builds these from the verified JWT claims; the resolver
/// builds the [`WorkloadId`] from them under its own trust domain, looks the
/// tenant up from the slug, and wraps the result into a
/// [`Principal::Workload`].
#[derive(Debug, Clone)]
pub struct WorkloadMapping {
    /// Service name component (second SPIFFE path segment).
    pub service_name: String,
    /// Tenant slug component (third SPIFFE path segment). The resolver's
    /// tenant lookup turns it into the typed [`TenantId`]; a slug the lookup
    /// does not know refuses the token.
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
/// // Per request: the tenant registry (a cached slug → TenantId map) is the
/// // lookup, and a claim mapper pulls the workload identity from `sub`.
/// let resolver = WorkloadResolver::new(
///     verifier.clone(),
///     trust_domain.clone(),
///     move |slug: &str| tenants.get(slug).copied(),
///     Issuer::OAuth, // or Issuer::custom("github_actions").unwrap(), etc.
///     token,
///     |claims| {
///         let sub = claims.sub.as_deref().ok_or_else(|| {
///             IdentityError::InvalidComponent("missing sub claim".into())
///         })?;
///         // …adopter parses sub into (service, tenant_slug)…
///         Ok(WorkloadMapping {
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
    tenant_lookup: TenantLookup,
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
    /// wrapped [`JwtVerifier`], which must pin both an issuer and an
    /// audience: resolving through a verifier that pins either of them
    /// loosely answers `NotAuthenticated`, as
    /// [`JwtSvidResolver`](crate::jwt::svid::JwtSvidResolver) does. The claim-mapping closure is invoked
    /// on successful verification. The `issuer` parameter is recorded
    /// verbatim on the resulting [`WorkloadPrincipal`] for audit
    /// attribution; use [`Issuer::OAuth`] for generic JWT-bearer flows
    /// or [`Issuer::Custom`] with a stable short label
    /// (e.g. `"github_actions"`, `"kubernetes"`) when audit logs need
    /// finer granularity.
    ///
    /// `tenant_lookup` maps the mapped `tenant_slug` to the typed
    /// [`TenantId`] (typically a cached `HashMap<String, TenantId>`); the
    /// resolver calls it on the slug of the *verified* claims and refuses
    /// the token with [`IdentityError::NotAuthenticated`] when it answers
    /// `None`. `expected_trust_domain` is the domain of the resulting
    /// [`WorkloadId`], which the resolver builds itself.
    pub fn new(
        verifier: Arc<JwtVerifier<R>>,
        expected_trust_domain: TrustDomain,
        tenant_lookup: impl Fn(&str) -> Option<TenantId> + Send + Sync + 'static,
        issuer: Issuer,
        token: impl Into<String>,
        claim_mapper: F,
    ) -> Self {
        Self {
            verifier,
            expected_trust_domain,
            tenant_lookup: Arc::new(tenant_lookup),
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
        // A workload token is only meaningful for the audience it names, and
        // a shared issuer makes `aud` the only separation between services,
        // so a verifier that pins neither is refused before the token is read.
        if !verifier_is_pinned(&self.verifier, "WorkloadResolver") {
            return Err(IdentityError::NotAuthenticated);
        }
        let claims = self.verifier.verify::<C>(&self.token).await.map_err(|e| {
            tracing::debug!(error = %e, "WorkloadResolver: JWT verification failed");
            IdentityError::NotAuthenticated
        })?;

        let mapped = (self.claim_mapper)(&claims)?;

        // The tenant is the registry's answer for the verified claims' own
        // slug, never a value the caller supplied before the token was read.
        let Some(tenant_id) = (self.tenant_lookup)(&mapped.tenant_slug) else {
            tracing::warn!("WorkloadResolver: tenant slug is not in the registry");
            return Err(IdentityError::NotAuthenticated);
        };

        // The id is built here, under the resolver's own trust domain, from
        // the mapped service and slug: the mapper cannot name another domain.
        let workload_id = WorkloadId::build(
            &self.expected_trust_domain,
            &mapped.service_name,
            &mapped.tenant_slug,
        )?;

        Ok(Principal::Workload(WorkloadPrincipal {
            workload_id,
            trust_domain: self.expected_trust_domain.clone(),
            issuer: self.issuer.clone(),
            tenant_id,
            tenant_slug: mapped.tenant_slug,
            service_name: mapped.service_name,
            attributes: mapped.attributes,
        }))
    }
}

#[cfg(test)]
mod tests;
