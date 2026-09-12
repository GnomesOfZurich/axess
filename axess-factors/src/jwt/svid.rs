//! SPIFFE JWT-SVID resolver.
//!
//! Implements [`PrincipalResolver`] over a bearer JWT-SVID per the
//! [SPIFFE JWT-SVID spec](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
//! Returns [`Principal::Workload`] when the token verifies, the
//! SPIFFE ID in the `sub` claim parses, and the trust domain matches
//! the pinned expectation.
//!
//! # Where the token comes from
//!
//! The resolver holds the token at construction. Per-request use:
//! adopter middleware extracts the bearer token from the
//! `Authorization: Bearer …` header (or similar), constructs a
//! fresh [`JwtSvidResolver`] with the shared
//! [`super::verifier::JwtVerifier`] handle and pinned
//! [`TrustDomain`], and calls `resolve().await` once per request.
//! The verifier itself is `Clone` (cheap: `Arc`-backed JWKS, no
//! per-request state) so a process-wide singleton is the expected
//! shape.
//!
//! # SPIFFE path shape
//!
//! The first cut requires the platform shape
//! `spiffe://<trust_domain>/<service>/<tenant_slug>` so the
//! resolver can return a typed `(service_name, tenant_slug)` pair on
//! the [`WorkloadPrincipal`]. Adopters that use a deeper SPIFFE path
//! (`spiffe://td/region/svc/tenant`) need a different resolver shape
//! today; the trait is open to additional impls. This one is the
//! Gnomes-platform-aligned one.
//!
//! # Tenant id source
//!
//! The SPIFFE path carries the tenant *slug*; the
//! [`WorkloadPrincipal`] also requires a typed [`TenantId`] (UUID-
//! backed). The JWT must carry a custom `tid` claim with the
//! UUID-string value. Production IdPs that issue JWT-SVIDs for the
//! Gnomes platform set this claim from the same registry the
//! `CliResolver` consults at startup; the two paths produce
//! byte-identical principals for the same `(service, tenant)` pair.

use std::collections::BTreeMap;
use std::sync::Arc;

use axess_identity::{
    IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain, WorkloadId,
    WorkloadPrincipal,
};
use serde::Deserialize;

use super::verifier::{JtiReplayStore, JwtVerifier, NoReplay};

/// Custom-claim shape the resolver deserialises from the JWT.
/// `tid` carries the typed tenant identifier (UUID string).
#[derive(Debug, Deserialize)]
struct SvidCustomClaims {
    /// Tenant identifier: UUID string in standard hyphenated form.
    tid: TenantId,
}

/// Resolver that verifies a SPIFFE JWT-SVID and returns the
/// corresponding [`Principal::Workload`].
///
/// Construction is per-request; the wrapped [`JwtVerifier`] is the
/// long-lived shared instance.
///
/// ```ignore
/// // At process startup:
/// let verifier = Arc::new(
///     JwtVerifier::new(jwks_handle)
///         .with_issuer("https://idp.example.com")
///         .with_audience("axess-platform"),
/// );
/// let trust_domain = TrustDomain::new("gnomes.local")?;
///
/// // Per request:
/// let token = bearer_token_from_headers(&headers)?;
/// let resolver = JwtSvidResolver::new(
///     verifier.clone(),
///     trust_domain.clone(),
///     token,
/// );
/// let principal = resolver.resolve().await?;
/// ```
pub struct JwtSvidResolver<R: JtiReplayStore = NoReplay> {
    verifier: Arc<JwtVerifier<R>>,
    expected_trust_domain: TrustDomain,
    token: String,
}

impl<R: JtiReplayStore> JwtSvidResolver<R> {
    /// Construct a resolver. The token must include `sub` carrying a
    /// SPIFFE-ID and a custom `tid` claim with the tenant UUID. All
    /// JWT-level validation (signature, `iss`, `aud`, `exp`, `nbf`,
    /// allowed algorithms) is delegated to the wrapped
    /// [`JwtVerifier`].
    pub fn new(
        verifier: Arc<JwtVerifier<R>>,
        expected_trust_domain: TrustDomain,
        token: impl Into<String>,
    ) -> Self {
        Self {
            verifier,
            expected_trust_domain,
            token: token.into(),
        }
    }
}

impl<R: JtiReplayStore + 'static> PrincipalResolver for JwtSvidResolver<R> {
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        // 1. JWT signature + standard claims (iss, aud, exp, nbf,
        //    allowed algorithm allowlist, replay-store check if
        //    configured). Failure is mapped to NotAuthenticated; the
        //    underlying JwtError detail is logged for operators but
        //    not surfaced to callers; the trait surface is
        //    intentionally opaque about which check rejected the
        //    token, mirroring the Authn user-enumeration discipline.
        let claims = self
            .verifier
            .verify::<SvidCustomClaims>(&self.token)
            .await
            .map_err(|e| {
                tracing::debug!(error = %e, "JwtSvidResolver: JWT verification failed");
                IdentityError::NotAuthenticated
            })?;

        // 2. Parse the SPIFFE ID out of `sub`. Missing `sub` or
        //    malformed SPIFFE URI reject as NotAuthenticated; the
        //    token validated cryptographically but isn't a SPIFFE
        //    JWT-SVID.
        let sub = claims.sub.ok_or_else(|| {
            tracing::debug!("JwtSvidResolver: token missing `sub` claim");
            IdentityError::NotAuthenticated
        })?;
        let workload_id = WorkloadId::parse(&sub)?;

        // 3. Decompose the SPIFFE URI into (trust_domain, service,
        //    tenant_slug) using the platform shape. WorkloadId::parse
        //    already validated structure; the split here cannot fail
        //    on a parsed value but each step still returns Result so
        //    a future loosening of the parse rules surfaces here
        //    rather than panicking.
        let (token_trust_domain, service, tenant_slug) = decompose_platform_spiffe(&workload_id)?;

        // 4. Pin the trust domain. JWT-SVIDs from a different trust
        //    domain are rejected even when the JWKS happened to
        //    accept them; defense in depth against a cross-trust-
        //    domain confused-deputy where a victim service trusts the
        //    same JWKS as the attacker's trust domain.
        if token_trust_domain != self.expected_trust_domain {
            tracing::warn!(
                expected = %self.expected_trust_domain,
                presented = %token_trust_domain,
                "JwtSvidResolver: trust domain mismatch",
            );
            return Err(IdentityError::InvalidSpiffeId(format!(
                "trust domain mismatch: expected {expected}, presented {presented}",
                expected = self.expected_trust_domain,
                presented = token_trust_domain,
            )));
        }

        Ok(Principal::Workload(WorkloadPrincipal {
            workload_id,
            trust_domain: token_trust_domain,
            issuer: Issuer::JwtSvid,
            tenant_id: claims.custom.tid,
            tenant_slug,
            service_name: service,
            attributes: BTreeMap::new(),
        }))
    }
}

/// Split a parsed [`WorkloadId`] into its
/// `(trust_domain, service, tenant_slug)` components per the platform
/// shape `spiffe://<trust_domain>/<service>/<tenant_slug>`. Returns
/// [`IdentityError::InvalidSpiffeId`] if the SPIFFE path doesn't
/// match the platform shape.
fn decompose_platform_spiffe(
    id: &WorkloadId,
) -> Result<(TrustDomain, String, String), IdentityError> {
    let raw = id.as_str();
    let after = raw
        .strip_prefix("spiffe://")
        .ok_or_else(|| IdentityError::InvalidSpiffeId(format!("missing scheme: {raw}")))?;
    let (td_str, rest) = after.split_once('/').ok_or_else(|| {
        IdentityError::InvalidSpiffeId(format!(
            "SPIFFE path missing service/tenant components: {raw}"
        ))
    })?;
    let mut parts = rest.split('/');
    let service = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        IdentityError::InvalidSpiffeId(format!("SPIFFE path missing service component: {raw}"))
    })?;
    let tenant_slug = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        IdentityError::InvalidSpiffeId(format!("SPIFFE path missing tenant component: {raw}"))
    })?;
    if parts.next().is_some() {
        return Err(IdentityError::InvalidSpiffeId(format!(
            "SPIFFE path has unexpected extra components beyond service/tenant: {raw}"
        )));
    }
    let td = TrustDomain::new(td_str)?;
    Ok((td, service.to_string(), tenant_slug.to_string()))
}

#[cfg(test)]
mod tests;
