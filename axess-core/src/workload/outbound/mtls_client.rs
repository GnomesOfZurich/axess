//!  Phase 4: outbound mTLS client.
//!
//! Constructs a [`rustls::ClientConfig`] that presents axess's own
//! X509 client certificate during the TLS handshake. Used when axess
//! calls a 3rd-party mTLS-protected endpoint (FAPI 2.0 / PSD2 SCA
//! token endpoints, bank swap-data repositories, FIX-over-TLS
//! gateways, private backplane traffic between gnomes services).
//!
//! # Scope
//!
//! This module only constructs the `ClientConfig`; adopters plug it
//! into their HTTP client (`reqwest::Client::builder().use_preconfigured_tls(cfg)`),
//! their direct `tokio-rustls` stack, or any other rustls consumer.
//! axess does not own the connection lifecycle.
//!
//! # Cipher provider
//!
//! axess does not install a `CryptoProvider` itself; that's an
//! application-level decision (see [`docs/production/security-posture.md`]). Adopters
//! call `rustls::crypto::aws_lc_rs::default_provider().install_default()`
//! (or the `ring` variant) once at process startup, *before*
//! constructing the [`OutboundMtlsClient`]. Skipping this step makes
//! the `ClientConfig` builder panic with a clear message.
//!
//! [`docs/production/security-posture.md`]: https://github.com/GnomesOfZurich/axess/blob/main/docs/production/security-posture.md

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// Errors surfaced by [`OutboundMtlsClient`].
#[derive(Debug, thiserror::Error)]
pub enum MtlsClientError {
    /// Client-certificate PEM / DER could not be parsed (malformed,
    /// wrong type, empty input).
    #[error("client certificate decode failed: {0}")]
    CertParse(String),
    /// Private-key PEM / DER could not be parsed.
    #[error("private key decode failed: {0}")]
    KeyParse(String),
    /// Server-roots PEM did not yield any usable certificates.
    #[error("server root certificate decode failed: {0}")]
    RootsParse(String),
    /// rustls rejected the `(cert_chain, private_key)` pair when
    /// building the `ClientConfig`: typically the key doesn't match
    /// the cert's public key, or the chosen `CryptoProvider`
    /// doesn't support the cert's signature algorithm.
    #[error("rustls ClientConfig construction failed: {0}")]
    ClientConfig(String),
}

/// Outbound mTLS client wrapper.
///
/// Carries the parsed cert chain + private key plus an optional
/// server-roots store. Convert to an `Arc<ClientConfig>` via
/// [`rustls_client_config`](Self::rustls_client_config) at the point
/// where the HTTPS client is being assembled.
///
/// The PEM bytes are consumed at construction time (parsed into typed
/// rustls types) so the original byte buffers can be zeroed by the
/// caller after `new_from_pem` returns.
pub struct OutboundMtlsClient {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    server_roots: Option<RootCertStore>,
}

impl std::fmt::Debug for OutboundMtlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the private key; a heap-dump containing the
        // formatted struct would otherwise leak the raw key material.
        f.debug_struct("OutboundMtlsClient")
            .field("cert_chain_len", &self.cert_chain.len())
            .field("private_key", &"<redacted>")
            .field("server_roots_present", &self.server_roots.is_some())
            .finish()
    }
}

impl OutboundMtlsClient {
    /// Construct from PEM-encoded client cert chain + private key.
    ///
    /// `cert_chain_pem` may contain multiple `BEGIN CERTIFICATE`
    /// blocks (leaf first, intermediates following). `private_key_pem`
    /// is the matching private key: PKCS#1 RSA, PKCS#8 (any
    /// algorithm), or SEC1 EC, all detected automatically by
    /// `rustls-pki-types`.
    pub fn new_from_pem(
        cert_chain_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<Self, MtlsClientError> {
        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_chain_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| MtlsClientError::CertParse(e.to_string()))?;

        if cert_chain.is_empty() {
            return Err(MtlsClientError::CertParse(
                "no PEM `CERTIFICATE` block found".to_string(),
            ));
        }

        let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
            .map_err(|e| MtlsClientError::KeyParse(e.to_string()))?;

        Ok(Self {
            cert_chain,
            private_key,
            server_roots: None,
        })
    }

    /// Construct from DER-encoded inputs. The cert chain is leaf-first;
    /// the private key is in whatever DER format `PrivateKeyDer`
    /// accepts (PKCS#1 / PKCS#8 / SEC1: caller selects the variant).
    pub fn new_from_der(
        cert_chain_der: Vec<CertificateDer<'static>>,
        private_key_der: PrivateKeyDer<'static>,
    ) -> Result<Self, MtlsClientError> {
        if cert_chain_der.is_empty() {
            return Err(MtlsClientError::CertParse(
                "empty cert chain provided".to_string(),
            ));
        }
        Ok(Self {
            cert_chain: cert_chain_der,
            private_key: private_key_der,
            server_roots: None,
        })
    }

    /// Pin a custom server-roots store. Useful when the 3rd-party API
    /// uses a private CA, typical for bank APIs that issue their own
    /// transport-layer root.
    ///
    /// Unset (the default) means the resulting `ClientConfig` will
    /// reject every server (rustls requires explicit trust roots).
    /// Adopters using system roots typically configure them via the
    /// HTTP client's TLS-options layer (e.g.
    /// `reqwest::ClientBuilder::tls_built_in_root_certs`) rather than
    /// pinning them here.
    pub fn with_server_roots(mut self, roots: RootCertStore) -> Self {
        self.server_roots = Some(roots);
        self
    }

    /// Pin a custom server-roots store from a PEM bundle.
    /// Convenience wrapper over
    /// [`with_server_roots`](Self::with_server_roots).
    pub fn with_server_roots_pem(self, roots_pem: &[u8]) -> Result<Self, MtlsClientError> {
        let mut store = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(roots_pem) {
            let cert = cert.map_err(|e| MtlsClientError::RootsParse(e.to_string()))?;
            store
                .add(cert)
                .map_err(|e| MtlsClientError::RootsParse(e.to_string()))?;
        }
        if store.is_empty() {
            return Err(MtlsClientError::RootsParse(
                "no `CERTIFICATE` blocks found in roots PEM".to_string(),
            ));
        }
        Ok(self.with_server_roots(store))
    }

    /// Borrow the parsed client-certificate chain (leaf first).
    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    /// Borrow the parsed private key. The returned reference can be
    /// passed by clone into rustls construction sites that don't take
    /// `&self` access patterns.
    pub fn private_key(&self) -> &PrivateKeyDer<'static> {
        &self.private_key
    }

    /// Borrow the configured server-roots store, if any.
    pub fn server_roots(&self) -> Option<&RootCertStore> {
        self.server_roots.as_ref()
    }

    /// Build an `Arc<ClientConfig>` ready to plug into an HTTPS client.
    ///
    /// **Requires** a `CryptoProvider` to be installed on the current
    /// thread via [`rustls::crypto::CryptoProvider::install_default`]
    /// *before* this call (e.g. in `main` before any axess code runs).
    /// Adopters that skip this will get a panic from rustls; the
    /// panic message points at the install_default step.
    ///
    /// Server roots must have been configured via
    /// [`with_server_roots`](Self::with_server_roots) or
    /// [`with_server_roots_pem`](Self::with_server_roots_pem); the
    /// resulting `ClientConfig` rejects every server otherwise.
    pub fn rustls_client_config(&self) -> Result<Arc<ClientConfig>, MtlsClientError> {
        let roots = self.server_roots.clone().ok_or_else(|| {
            MtlsClientError::ClientConfig(
                "no server-roots store configured; call with_server_roots or \
                 with_server_roots_pem before building the ClientConfig"
                    .to_string(),
            )
        })?;

        let cert_chain = self.cert_chain.clone();
        let private_key = self.private_key.clone_key();

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| MtlsClientError::ClientConfig(e.to_string()))?;
        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests;
