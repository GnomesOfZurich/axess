//! SPIFFE X509-SVID resolver over rustls peer-cert chain.
//!
//! Implements [`PrincipalResolver`] over the leaf client certificate
//! presented during the mTLS handshake. Returns [`Principal::Workload`]
//! when the certificate's `Subject Alternative Name` contains a SPIFFE
//! URI (`spiffe://<trust_domain>/...`) and the trust domain matches the
//! pinned expectation.
//!
//! # Wiring expectations
//!
//! axess does not terminate TLS; adopters do, in front of axess. The
//! standard pattern under tokio-rustls is:
//!
//! 1. Configure the rustls `ServerConfig` to request (or require) a
//!    client certificate.
//! 2. After the TLS handshake, read
//!    `ServerConnection::peer_certificates()` to get the presented
//!    chain.
//! 3. Insert a [`PeerCertChain`] into every Axum request's extensions
//!    via adopter-side middleware. The chain is request-scoped; axess
//!    does not own its lifetime.
//! 4. Per request, build an [`MtlsResolver`] (peer cert + expected
//!    trust domain + caller-resolved [`TenantId`]) and call
//!    `resolve().await`.
//!
//! axess provides the request-extension type and the SPIFFE-ID parse;
//! the rustls plumbing stays in the adopter so axess remains
//! transport-agnostic.
//!
//! # SPIFFE path shape
//!
//! Mirrors `axess_core::authn::jwt::svid::JwtSvidResolver`'s platform
//! shape `spiffe://<trust_domain>/<service>/<tenant_slug>`. The cert's
//! SAN URI must parse against this shape; deeper paths (e.g.
//! `spiffe://td/region/svc/tenant`) are rejected today and would need
//! a different resolver impl.
//!
//! # TenantId source
//!
//! Unlike the JWT-SVID flow (where a custom `tid` claim carries the
//! typed [`TenantId`] UUID), an X509-SVID has no JWT claims. The
//! adopter middleware does the `tenant_slug → TenantId` lookup against
//! its own registry before constructing the resolver, typically via a
//! cached `HashMap<String, TenantId>` populated at startup. The
//! resolver itself is intentionally registry-agnostic; baking a tenant
//! registry trait into axess would couple this module to adopter data
//! shapes.
//!
//! See `axess_core::authn::jwt::svid::JwtSvidResolver` for the JWT-SVID
//! cousin (federation feature in axess-core).

use std::collections::BTreeMap;
use std::sync::Arc;

use axess_identity::{
    IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain, WorkloadId,
    WorkloadPrincipal,
};
use rustls_pki_types::CertificateDer;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

/// Per-request wrapper around the rustls peer-certificate chain.
///
/// Inserted by adopter middleware after the mTLS handshake completes.
/// `Arc` so the wrapper is cheap to clone into request extensions and
/// across resolver constructions.
#[derive(Clone, Debug)]
pub struct PeerCertChain {
    chain: Arc<[CertificateDer<'static>]>,
}

impl PeerCertChain {
    /// Wrap a peer-cert chain (leaf first, as presented by the client).
    /// Cloning is cheap; the inner storage is `Arc<[..]>`.
    pub fn new(chain: Vec<CertificateDer<'static>>) -> Self {
        Self {
            chain: Arc::from(chain.into_boxed_slice()),
        }
    }

    /// Borrow the chain as a slice (leaf first).
    pub fn as_slice(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// Borrow the leaf (client) certificate. `None` only if the chain
    /// is empty; the wiring middleware should reject the request
    /// before this gets called with an empty chain.
    pub fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.chain.first()
    }
}

/// Errors specific to the mTLS resolver layer.
///
/// Distinct from [`IdentityError`] so callers wiring the middleware can
/// log structured detail. The trait surface (`PrincipalResolver::resolve`)
/// still returns [`IdentityError`]; these are flattened to
/// [`IdentityError::NotAuthenticated`] or
/// [`IdentityError::InvalidSpiffeId`] before crossing the trait boundary,
/// mirroring the JWT-SVID resolver's user-enumeration discipline.
#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    /// The peer-cert chain in the request extension was empty.
    /// Adopter middleware should have rejected the request earlier;
    /// this is a defense-in-depth path.
    #[error("peer certificate chain is empty")]
    EmptyChain,
    /// The leaf certificate failed DER parsing.
    #[error("failed to parse peer certificate: {0}")]
    CertParse(String),
    /// The leaf certificate has no `Subject Alternative Name`
    /// extension. Not a SPIFFE X509-SVID.
    #[error("certificate has no Subject Alternative Name extension")]
    NoSan,
    /// The SAN had no `URI` entry starting with `spiffe://`.
    #[error("certificate SAN has no SPIFFE URI entry")]
    NoSpiffeUri,
    /// SPIFFE-ID validation failed (malformed URI, trust-domain
    /// mismatch, unexpected path shape).
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// SPIFFE-ID components extracted from a peer certificate before
/// resolver construction. Returned by [`peek_spiffe`] so adopter
/// middleware can look up the typed [`TenantId`] from `tenant_slug`
/// (against its own registry) before building the resolver.
#[derive(Debug, Clone)]
pub struct SpiffeIdComponents {
    /// Parsed SPIFFE-ID: `spiffe://<trust_domain>/<service>/<tenant_slug>`.
    pub workload_id: WorkloadId,
    /// Trust domain from the SPIFFE-ID. Adopter middleware compares
    /// against the expected trust domain before constructing the
    /// resolver to fail fast on cross-domain certs.
    pub trust_domain: TrustDomain,
    /// Service name (second SPIFFE path segment).
    pub service_name: String,
    /// Tenant slug (third SPIFFE path segment). Adopter middleware
    /// uses this as the lookup key for the typed [`TenantId`].
    pub tenant_slug: String,
}

/// Extract and parse the SPIFFE-ID out of a peer certificate without
/// constructing a full [`MtlsResolver`]. Use this in adopter
/// middleware to drive the `tenant_slug → TenantId` lookup before
/// resolver construction.
///
/// Returns [`MtlsError::NoSan`] / [`MtlsError::NoSpiffeUri`] when the
/// cert is not a SPIFFE X509-SVID.
pub fn peek_spiffe(peer_cert: &CertificateDer<'_>) -> Result<SpiffeIdComponents, MtlsError> {
    let (_, cert) = X509Certificate::from_der(peer_cert.as_ref())
        .map_err(|e| MtlsError::CertParse(e.to_string()))?;

    let san_ext = cert
        .subject_alternative_name()
        .map_err(|e| MtlsError::CertParse(e.to_string()))?
        .ok_or(MtlsError::NoSan)?;

    // Per SPIFFE X509-SVID spec §3: the SVID identifier MUST appear in
    // the URI SAN. Walk the URIs and take the first that starts with
    // `spiffe://`. Multiple SPIFFE URIs in one cert is not part of the
    // SVID spec; if it ever surfaces in practice, take the first one
    // (deterministic).
    let spiffe_uri = san_ext
        .value
        .general_names
        .iter()
        .find_map(|name| match name {
            GeneralName::URI(uri) if uri.starts_with("spiffe://") => Some(*uri),
            _ => None,
        })
        .ok_or(MtlsError::NoSpiffeUri)?;

    let workload_id = WorkloadId::parse(spiffe_uri).map_err(MtlsError::Identity)?;
    let (trust_domain, service_name, tenant_slug) =
        decompose_platform_spiffe(&workload_id).map_err(MtlsError::Identity)?;

    Ok(SpiffeIdComponents {
        workload_id,
        trust_domain,
        service_name,
        tenant_slug,
    })
}

/// Resolver that produces [`Principal::Workload`] from a SPIFFE
/// X509-SVID in a peer certificate.
///
/// Construction is per-request; the wrapped `peer_cert` is the leaf
/// from the rustls peer-cert chain.
pub struct MtlsResolver {
    expected_trust_domain: TrustDomain,
    peer_cert: CertificateDer<'static>,
    tenant_id: TenantId,
}

impl MtlsResolver {
    /// Construct a resolver. The caller has already used [`peek_spiffe`]
    /// to look up the typed [`TenantId`] from the cert's `tenant_slug`.
    /// `expected_trust_domain` is the trust domain axess will accept;
    /// certs from any other trust domain are rejected on `resolve`.
    pub fn new(
        peer_cert: CertificateDer<'static>,
        expected_trust_domain: TrustDomain,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            expected_trust_domain,
            peer_cert,
            tenant_id,
        }
    }
}

impl PrincipalResolver for MtlsResolver {
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        // Re-parse the cert here (cheap) so the resolve path is the
        // single source of truth for the principal; the
        // `peek_spiffe` step in adopter middleware feeds the tenant
        // lookup but the cryptographic claim flows through here.
        let comps = peek_spiffe(&self.peer_cert).map_err(|e| match e {
            MtlsError::Identity(id) => id,
            other => {
                tracing::debug!(error = %other, "MtlsResolver: peer cert rejected");
                IdentityError::NotAuthenticated
            }
        })?;

        if comps.trust_domain != self.expected_trust_domain {
            tracing::warn!(
                expected = %self.expected_trust_domain,
                presented = %comps.trust_domain,
                "MtlsResolver: trust domain mismatch",
            );
            return Err(IdentityError::InvalidSpiffeId(format!(
                "trust domain mismatch: expected {expected}, presented {presented}",
                expected = self.expected_trust_domain,
                presented = comps.trust_domain,
            )));
        }

        Ok(Principal::Workload(WorkloadPrincipal {
            workload_id: comps.workload_id,
            trust_domain: comps.trust_domain,
            issuer: Issuer::Mtls,
            tenant_id: self.tenant_id,
            tenant_slug: comps.tenant_slug,
            service_name: comps.service_name,
            attributes: BTreeMap::new(),
        }))
    }
}

/// Split a parsed [`WorkloadId`] into its
/// `(trust_domain, service, tenant_slug)` components per the platform
/// shape `spiffe://<trust_domain>/<service>/<tenant_slug>`. Returns
/// [`IdentityError::InvalidSpiffeId`] if the SPIFFE path doesn't
/// match the platform shape.
///
/// Duplicated structure from
/// `axess_core::authn::jwt::svid::decompose_platform_spiffe`. Kept
/// private here to avoid coupling the mTLS path to the
/// `oauth`/`jwt-svid` feature gate. The two helpers should stay in
/// lock-step on shape changes.
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
