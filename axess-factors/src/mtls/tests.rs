//! tests for the mTLS SPIFFE X509-SVID resolver.
//!
//! Cert generation uses `rcgen` (dev-dep) so each test owns the SAN
//! content driving the assertion. Production cert trust is the
//! adopter's TLS terminator's job; these tests exercise the
//! parse-and-decompose contract only.

use super::*;
use rcgen::{CertificateParams, KeyPair, SanType};

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([7u8; 16])
}

fn cert_with_san_uri(uri: &str) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CertificateParams::new");
    params.subject_alt_names = vec![SanType::URI(uri.try_into().expect("Ia5String"))];
    let signing_key = KeyPair::generate().expect("KeyPair::generate");
    let cert = params.self_signed(&signing_key).expect("self_signed");
    cert.der().clone()
}

fn cert_with_no_san() -> CertificateDer<'static> {
    let params = CertificateParams::new(Vec::<String>::new()).expect("CertificateParams::new");
    let signing_key = KeyPair::generate().expect("KeyPair::generate");
    let cert = params.self_signed(&signing_key).expect("self_signed");
    cert.der().clone()
}

fn cert_with_dns_san_only() -> CertificateDer<'static> {
    let params =
        CertificateParams::new(vec!["host.example".to_string()]).expect("CertificateParams::new");
    let signing_key = KeyPair::generate().expect("KeyPair::generate");
    let cert = params.self_signed(&signing_key).expect("self_signed");
    cert.der().clone()
}

#[test]
fn peek_spiffe_extracts_platform_shape() {
    let cert = cert_with_san_uri("spiffe://gnomes.local/compute-worker/ekekrantz");
    let comps = peek_spiffe(&cert).expect("must extract SPIFFE components");
    assert_eq!(
        comps.workload_id.as_str(),
        "spiffe://gnomes.local/compute-worker/ekekrantz"
    );
    assert_eq!(comps.trust_domain.as_str(), "gnomes.local");
    assert_eq!(comps.service_name, "compute-worker");
    assert_eq!(comps.tenant_slug, "ekekrantz");
}

#[test]
fn peek_spiffe_rejects_cert_without_san() {
    let cert = cert_with_no_san();
    let err = peek_spiffe(&cert).expect_err("cert without SAN must reject");
    assert!(
        matches!(err, MtlsError::NoSan),
        "expected NoSan, got {err:?}"
    );
}

#[test]
fn peek_spiffe_rejects_san_without_spiffe_uri() {
    let cert = cert_with_dns_san_only();
    let err = peek_spiffe(&cert).expect_err("SAN with no SPIFFE URI must reject");
    assert!(
        matches!(err, MtlsError::NoSpiffeUri),
        "expected NoSpiffeUri, got {err:?}"
    );
}

#[test]
fn peek_spiffe_rejects_uri_san_without_spiffe_scheme() {
    let cert = cert_with_san_uri("https://example.com/compute-worker/ekekrantz");
    let err = peek_spiffe(&cert).expect_err("URI SAN without spiffe:// scheme must reject");
    assert!(
        matches!(err, MtlsError::NoSpiffeUri),
        "expected NoSpiffeUri, got {err:?}"
    );
}

#[test]
fn peek_spiffe_rejects_malformed_spiffe_uri() {
    // Starts with "spiffe://" so the SPIFFE-URI filter accepts it, but
    // the trust domain is invalid (empty path component).
    let cert = cert_with_san_uri("spiffe://");
    let err = peek_spiffe(&cert).expect_err("malformed SPIFFE URI must reject");
    assert!(
        matches!(err, MtlsError::Identity(IdentityError::InvalidSpiffeId(_))),
        "expected Identity(InvalidSpiffeId), got {err:?}"
    );
}

#[test]
fn peek_spiffe_rejects_extra_path_segments() {
    let cert = cert_with_san_uri("spiffe://gnomes.local/region/compute-worker/ekekrantz");
    let err = peek_spiffe(&cert).expect_err("3-segment path must reject under platform shape");
    assert!(
        matches!(err, MtlsError::Identity(IdentityError::InvalidSpiffeId(_))),
        "expected Identity(InvalidSpiffeId), got {err:?}"
    );
}

#[tokio::test]
async fn mtls_resolver_returns_workload_principal_on_match() {
    let cert = cert_with_san_uri("spiffe://gnomes.local/compute-worker/ekekrantz");
    let resolver = MtlsResolver::new(
        cert,
        TrustDomain::new("gnomes.local").unwrap(),
        sample_tenant(),
    );
    let principal = resolver.resolve().await.expect("must resolve");
    match principal {
        Principal::Workload(w) => {
            assert_eq!(
                w.workload_id.as_str(),
                "spiffe://gnomes.local/compute-worker/ekekrantz"
            );
            assert_eq!(w.trust_domain.as_str(), "gnomes.local");
            assert_eq!(w.issuer, Issuer::Mtls);
            assert_eq!(w.tenant_id, sample_tenant());
            assert_eq!(w.tenant_slug, "ekekrantz");
            assert_eq!(w.service_name, "compute-worker");
            assert!(w.attributes.is_empty());
        }
        Principal::Human(_) => panic!("expected Workload, got Human"),
    }
}

#[tokio::test]
async fn mtls_resolver_rejects_trust_domain_mismatch() {
    // Cert presents `attacker.example`; resolver pins `gnomes.local`.
    let cert = cert_with_san_uri("spiffe://attacker.example/compute-worker/ekekrantz");
    let resolver = MtlsResolver::new(
        cert,
        TrustDomain::new("gnomes.local").unwrap(),
        sample_tenant(),
    );
    let err = resolver
        .resolve()
        .await
        .expect_err("trust-domain mismatch must reject");
    assert!(
        matches!(err, IdentityError::InvalidSpiffeId(_)),
        "expected InvalidSpiffeId, got {err:?}"
    );
}

#[tokio::test]
async fn mtls_resolver_rejects_non_spiffe_cert() {
    let cert = cert_with_dns_san_only();
    let resolver = MtlsResolver::new(
        cert,
        TrustDomain::new("gnomes.local").unwrap(),
        sample_tenant(),
    );
    let err = resolver
        .resolve()
        .await
        .expect_err("DNS-only SAN must reject");
    // peek_spiffe returns MtlsError::NoSpiffeUri, which flattens to
    // NotAuthenticated through the trait surface.
    assert!(
        matches!(err, IdentityError::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
}

#[test]
fn peer_cert_chain_leaf_returns_first_cert() {
    let cert = cert_with_san_uri("spiffe://gnomes.local/compute-worker/ekekrantz");
    let chain = PeerCertChain::new(vec![cert.clone()]);
    assert_eq!(chain.leaf().map(|c| c.as_ref()), Some(cert.as_ref()));
    assert_eq!(chain.as_slice().len(), 1);
}

#[test]
fn peer_cert_chain_leaf_is_none_for_empty_chain() {
    let chain = PeerCertChain::new(Vec::new());
    assert!(chain.leaf().is_none());
    assert!(chain.as_slice().is_empty());
}

#[test]
fn issuer_mtls_wire_string_is_stable() {
    assert_eq!(Issuer::Mtls.as_str(), "mtls");
}
