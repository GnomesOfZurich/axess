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
//! today; the trait is open to additional impls. This one reads the
//! two-segment shape.
//!
//! # Tenant id source
//!
//! The SPIFFE path carries the tenant *slug*; the
//! [`WorkloadPrincipal`] also requires a typed [`TenantId`] (UUID-
//! backed). The JWT must carry a custom `tid` claim with the
//! UUID-string value. An IdP that sets this claim from the same
//! tenant registry the `CliResolver` consults at startup makes the two
//! paths produce byte-identical principals for the same
//! `(service, tenant)` pair.

use std::collections::BTreeMap;
use std::sync::Arc;

use axess_identity::{
    IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain, WorkloadId,
    WorkloadPrincipal,
};
use jsonwebtoken::Algorithm;
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
/// let trust_domain = TrustDomain::new("example.org")?;
///
/// // Per request:
/// let token = bearer_token_from_headers(&headers)?;
/// let resolver = JwtSvidResolver::new(
///     verifier.clone(),
///     trust_domain.clone(),
///     token,
/// )
/// // The slug in `sub` and the `tid` claim are cross-checked against your
/// // tenant registry; `without_tenant_cross_check()` is the named waiver.
/// .with_tenant_lookup(|slug| tenants.id_of(slug));
/// let principal = resolver.resolve().await?;
/// ```
pub struct JwtSvidResolver<R: JtiReplayStore = NoReplay> {
    verifier: Arc<JwtVerifier<R>>,
    expected_trust_domain: TrustDomain,
    token: String,
    tenant_lookup: Option<TenantLookup>,
    cross_check_waived: bool,
}

/// Maps a SPIFFE tenant slug to the typed tenant the deployment registered
/// for it; `None` when the slug is unknown.
type TenantLookup = Arc<dyn Fn(&str) -> Option<TenantId> + Send + Sync>;

impl<R: JtiReplayStore> JwtSvidResolver<R> {
    /// Construct a resolver. The token must include `sub` carrying a
    /// SPIFFE-ID and a custom `tid` claim with the tenant UUID. All
    /// JWT-level validation (signature, `iss`, `aud`, `exp`, `nbf`,
    /// allowed algorithms) is delegated to the wrapped
    /// [`JwtVerifier`].
    ///
    /// The slug in `sub` and the `tid` claim are checked against each other,
    /// and the check needs a registry: set it with
    /// [`with_tenant_lookup`](Self::with_tenant_lookup), or waive the check by
    /// name with
    /// [`without_tenant_cross_check`](Self::without_tenant_cross_check). A
    /// resolver with neither refuses every token, as the verifier refuses
    /// one it cannot pin.
    pub fn new(
        verifier: Arc<JwtVerifier<R>>,
        expected_trust_domain: TrustDomain,
        token: impl Into<String>,
    ) -> Self {
        Self {
            verifier,
            expected_trust_domain,
            token: token.into(),
            tenant_lookup: None,
            cross_check_waived: false,
        }
    }

    /// Cross-check the `tid` claim against the SPIFFE tenant slug. The slug
    /// in `sub` and the UUID in `tid` are two statements about one tenant,
    /// both written by the IdP; without a registry nothing ties them
    /// together, so an IdP bug or a loosely templated claim could put one
    /// tenant's UUID under another's slug. With a lookup, the token is
    /// refused when the slug is unknown or maps to a different tenant than
    /// `tid`. A resolver needs this, or
    /// [`without_tenant_cross_check`](Self::without_tenant_cross_check).
    pub fn with_tenant_lookup(
        mut self,
        lookup: impl Fn(&str) -> Option<TenantId> + Send + Sync + 'static,
    ) -> Self {
        self.tenant_lookup = Some(Arc::new(lookup));
        self
    }

    /// Resolve without cross-checking the SPIFFE tenant slug against the
    /// `tid` claim. A waiver by name, in line with the verifier's
    /// `allow_any_*` waivers: the resolved principal then carries a slug and
    /// an id that two claims of one token asserted, with nothing tying them to
    /// the same tenant, so a policy that reads one and data scoping that reads
    /// the other can split. Use it only where the issuer is the sole writer of
    /// both claims and you trust its templating. A
    /// [`with_tenant_lookup`](Self::with_tenant_lookup) set as well still
    /// applies.
    #[must_use]
    pub fn without_tenant_cross_check(mut self) -> Self {
        self.cross_check_waived = true;
        self
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
        // 0. A JWT-SVID is only meaningful for the audience it names, and
        //    a shared issuer makes `aud` the only separation between
        //    services. A verifier that pins neither would accept a token
        //    minted for anyone, so it is refused before any token is read.
        if !pinned_for_svids(&self.verifier) {
            return Err(IdentityError::NotAuthenticated);
        }
        // The JWT-SVID standard (section 2.1) names the algorithms an SVID
        // may be signed with, and a validator rejects a token with any
        // other, whatever the verifier's own allowlist admits: the verifier
        // takes only those of its algorithms the standard names. The
        // header is read once, by the verifier, after the token's length:
        // every step from the header on costs in proportion to the token.
        // Without a `kid` the token is tried against each key of the trust
        // domain's set (section 2.2 makes `kid` optional).
        let claims = self
            .verifier
            .verify_for_svid::<SvidCustomClaims>(&self.token, &JWT_SVID_ALGORITHMS)
            .await
            .map_err(|e| {
                tracing::debug!(error = %e, "JwtSvidResolver: JWT verification failed");
                IdentityError::NotAuthenticated
            })?;

        // 2. Parse the SPIFFE ID out of `sub`. A missing `sub` rejects as
        //    NotAuthenticated; a `sub` that is not a SPIFFE URI rejects as
        //    InvalidSpiffeId. Either way the token validated
        //    cryptographically but is not a SPIFFE JWT-SVID.
        let sub = claims.sub.ok_or_else(|| {
            tracing::debug!("JwtSvidResolver: token missing `sub` claim");
            IdentityError::NotAuthenticated
        })?;
        let workload_id = WorkloadId::parse(&sub)?;

        // 3. Decompose the SPIFFE URI into (trust_domain, service,
        //    tenant_slug) using the platform shape. WorkloadId::parse
        //    validated it as a SPIFFE ID; one of another shape (no
        //    path, one segment, more than two) is refused here.
        let parts = workload_id.components()?;
        let (token_trust_domain, service, tenant_slug) = (
            parts.trust_domain,
            parts.service.to_owned(),
            parts.tenant_slug.to_owned(),
        );

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

        // 5. The slug and the `tid` claim must name the same tenant. With no
        //    registry to ask, only a named waiver lets the token through.
        if self.tenant_lookup.is_none() && !self.cross_check_waived {
            tracing::warn!(
                slug = %crate::log_text::log_safe(&tenant_slug, SPIFFE_ID_LOG_BYTES),
                "JwtSvidResolver: no tenant lookup to cross-check the tid claim against the \
                 SPIFFE tenant slug, and no without_tenant_cross_check() waiver; refusing",
            );
            return Err(IdentityError::NotAuthenticated);
        }
        if let Some(lookup) = &self.tenant_lookup {
            match lookup(&tenant_slug) {
                Some(registered) if registered == claims.custom.tid => {}
                other => {
                    tracing::warn!(
                        slug = %crate::log_text::log_safe(&tenant_slug, SPIFFE_ID_LOG_BYTES),
                        known = other.is_some(),
                        "JwtSvidResolver: tid claim disagrees with the SPIFFE tenant slug",
                    );
                    return Err(IdentityError::NotAuthenticated);
                }
            }
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

/// The most bytes of a part of a SPIFFE identifier that a log line quotes.
const SPIFFE_ID_LOG_BYTES: usize = 128;

/// The signature algorithms a JWT-SVID may carry: RSASSA-PKCS1-v1_5, ECDSA
/// and RSASSA-PSS (JWT-SVID standard, section 2.1). The standard lists
/// `ES512` as well; the JOSE library has no such algorithm, so a token
/// signed with it is refused where its header is read.
const JWT_SVID_ALGORITHMS: [Algorithm; 8] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// Whether `verifier` is fit to verify JWT-SVIDs: it pins `aud`, and it
/// pins `iss` or waives it by name.
///
/// The audience is the only separation between the services of one trust
/// domain, so it is always pinned. The issuer need not be: the JWT-SVID
/// standard defines `sub`, `aud` and `exp` and no `iss`, so an SVID may
/// carry none, and what names its signer is the key set of the trust domain
/// in its `sub`, which the resolver pins. A verifier built on a trust
/// domain's own keys states that with `allow_any_issuer`.
fn pinned_for_svids<R: JtiReplayStore>(verifier: &JwtVerifier<R>) -> bool {
    let issuer_settled = verifier.has_issuer() || verifier.allows_any_issuer();
    if verifier.has_audience() && issuer_settled {
        return true;
    }
    tracing::error!(
        has_issuer = verifier.has_issuer(),
        issuer_waived = verifier.allows_any_issuer(),
        has_audience = verifier.has_audience(),
        "JwtSvidResolver: the verifier must pin `aud`, and pin `iss` or waive it by name; refusing"
    );
    false
}

#[cfg(test)]
mod tests;
