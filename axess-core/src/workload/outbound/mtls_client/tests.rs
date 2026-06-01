//!  Phase 4: tests for the outbound mTLS client.
//!
//! Cert generation uses `rcgen` (dev-dep) so each test owns its
//! cert/key material. End-to-end TLS handshake testing is out of
//! scope: that's rustls's own test surface; here we exercise the
//! construction API + error cases.

use super::*;
use rcgen::{CertificateParams, KeyPair};

/// Install a `CryptoProvider` exactly once for the whole test run.
/// Without it, [`rustls::ClientConfig::builder`] panics. Using
/// `aws_lc_rs` here matches axess-core's `oauth` feature path; tests
/// don't drive the handshake so the choice is cosmetic.
fn install_default_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn self_signed_pem() -> (String, String) {
    let params = CertificateParams::new(vec!["axess-test.example".to_string()])
        .expect("CertificateParams::new");
    let key_pair = KeyPair::generate().expect("KeyPair::generate");
    let cert = params.self_signed(&key_pair).expect("self_signed");
    (cert.pem(), key_pair.serialize_pem())
}

#[test]
fn new_from_pem_parses_valid_pair() {
    let (cert_pem, key_pem) = self_signed_pem();
    let client = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("must parse a valid self-signed cert + key");
    assert_eq!(client.cert_chain().len(), 1);
}

#[test]
fn new_from_pem_rejects_empty_cert_chain() {
    let (_cert_pem, key_pem) = self_signed_pem();
    let err = OutboundMtlsClient::new_from_pem(b"", key_pem.as_bytes())
        .expect_err("empty cert PEM must reject");
    assert!(
        matches!(err, MtlsClientError::CertParse(_)),
        "expected CertParse, got {err:?}"
    );
}

#[test]
fn new_from_pem_rejects_missing_key() {
    let (cert_pem, _key_pem) = self_signed_pem();
    let err = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), b"")
        .expect_err("empty key PEM must reject");
    assert!(
        matches!(err, MtlsClientError::KeyParse(_)),
        "expected KeyParse, got {err:?}"
    );
}

#[test]
fn new_from_pem_rejects_wrong_block_type_for_cert() {
    // A PRIVATE KEY block where the caller swapped cert + key by
    // mistake. `CertificateDer::pem_slice_iter` filters by section
    // type, so this yields zero items and surfaces as CertParse.
    let (_cert_pem, key_pem) = self_signed_pem();
    let err = OutboundMtlsClient::new_from_pem(key_pem.as_bytes(), key_pem.as_bytes())
        .expect_err("PRIVATE KEY in cert slot must reject");
    assert!(
        matches!(err, MtlsClientError::CertParse(_)),
        "expected CertParse, got {err:?}"
    );
}

#[test]
fn with_server_roots_pem_populates_root_store() {
    let (cert_pem, key_pem) = self_signed_pem();
    let client = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("parse client material");

    // The same cert serves as a root in tests; adopters would supply
    // the IdP / counterparty CA bundle here.
    let client = client
        .with_server_roots_pem(cert_pem.as_bytes())
        .expect("roots PEM must parse");
    assert!(client.server_roots().is_some(), "roots must be set");
}

#[test]
fn with_server_roots_pem_rejects_empty_bundle() {
    let (cert_pem, key_pem) = self_signed_pem();
    let client = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("parse client material");
    let err = client
        .with_server_roots_pem(b"")
        .expect_err("empty roots PEM must reject");
    assert!(
        matches!(err, MtlsClientError::RootsParse(_)),
        "expected RootsParse, got {err:?}"
    );
}

#[test]
fn rustls_client_config_requires_server_roots() {
    install_default_provider();
    let (cert_pem, key_pem) = self_signed_pem();
    let client = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("parse client material");

    let err = client
        .rustls_client_config()
        .expect_err("missing server roots must reject");
    assert!(
        matches!(err, MtlsClientError::ClientConfig(_)),
        "expected ClientConfig, got {err:?}"
    );
}

#[test]
fn rustls_client_config_builds_with_cert_chain_and_roots() {
    install_default_provider();
    let (cert_pem, key_pem) = self_signed_pem();
    let client = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("parse client material")
        .with_server_roots_pem(cert_pem.as_bytes())
        .expect("roots parse");

    drop(
        client
            .rustls_client_config()
            .expect("ClientConfig must build with valid material + roots"),
    );
    // `ClientConfig` exposes very little for direct inspection; the
    // fact that `with_client_auth_cert` accepted the pair is the
    // contract we care about here (key matches cert, signature
    // algorithm is supported by the installed CryptoProvider).
}

#[test]
fn new_from_der_round_trips_pem_input() {
    let (cert_pem, key_pem) = self_signed_pem();
    let pem_built = OutboundMtlsClient::new_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("parse from pem");

    // Re-build from the DER bytes the PEM-parse extracted.
    let cert_chain_der: Vec<CertificateDer<'static>> = pem_built.cert_chain().to_vec();
    let key_der = pem_built.private_key().clone_key();

    let der_built = OutboundMtlsClient::new_from_der(cert_chain_der, key_der)
        .expect("new_from_der accepts the same material");
    assert_eq!(der_built.cert_chain().len(), 1);
}

#[test]
fn new_from_der_rejects_empty_chain() {
    let (_cert_pem, key_pem) = self_signed_pem();
    let pem_built =
        OutboundMtlsClient::new_from_pem(_cert_pem.as_bytes(), key_pem.as_bytes()).expect("parse");
    let key_der = pem_built.private_key().clone_key();

    let err = OutboundMtlsClient::new_from_der(Vec::new(), key_der)
        .expect_err("empty DER cert chain must reject");
    assert!(
        matches!(err, MtlsClientError::CertParse(_)),
        "expected CertParse, got {err:?}"
    );
}
