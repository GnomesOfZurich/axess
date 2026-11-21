//! rustls configured from what the agent serves.
//!
//! Three pieces, each usable alone and all following the agent as it
//! rotates:
//!
//! - [`SvidCertResolver`] presents the current X.509 SVID, as a client or as
//!   a server. It reads the source at every handshake, so a rotation needs
//!   no new configuration.
//! - [`SpiffeClientCertVerifier`] and [`SpiffeServerCertVerifier`] verify a
//!   peer's X.509 SVID against the bundle of the trust domain its SPIFFE ID
//!   names, read from the source at every handshake, and only for the trust
//!   domains the deployment admits. A federated trust domain's bundle being
//!   served by the agent does not admit it.
//! - [`ClockTimeProvider`] gives rustls the client's injected clock, so a
//!   certificate's validity is judged by the same clock as everything else.
//!
//! A SPIFFE peer is identified by the SPIFFE ID in its certificate, not by
//! a DNS name: [`SpiffeServerCertVerifier`] does not compare the server's
//! certificate with the name that was dialled. It verifies the chain, and
//! that the identity is one the caller admits.
//!
//! A resumed TLS session is not verified again: rustls restores the peer's
//! certificate from the session and asks no verifier. A session resumed
//! after the peer's SVID expired, or after its authority left the bundle,
//! would be accepted on the strength of a check made before. The
//! configurations [`X509Source`] builds therefore resume nothing, and every
//! connection is a full handshake against the bundles of that moment. A
//! configuration built by hand around these pieces has to do the same: on a
//! client, the `resumption` field set to rustls's disabled resumption; on a
//! server, the `session_storage` field set to rustls's `NoServerSessionStorage`,
//! `send_tls13_tickets` set to zero, and no ticketer.
//!
//! The pieces need a `CryptoProvider`, as every rustls configuration does;
//! [`installed_provider`] reads the one the process installed.

use std::sync::{Arc, Mutex, PoisonError};

use axess_clock::Clock;
use axess_clock::Timestamp;
use axess_identity::{TrustDomain, WorkloadId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{
    ClientHello, NoServerSessionStorage, ParsedCertificate, ResolvesServerCert,
    WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::time_provider::TimeProvider;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore,
    ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use super::bundle::X509Bundle;
use super::error::SpireError;
use super::source::{X509BundleProvider, X509Source};
use super::svid::{X509Svid, read_leaf};
use super::transport::TARGET;
use crate::workload::outbound::mtls_client::{MtlsClientError, OutboundMtlsClient};

/// The `CryptoProvider` the process installed as its default (rustls's
/// `install_default`, called once at process start), or an error saying
/// none was.
pub fn installed_provider() -> Result<Arc<CryptoProvider>, SpireError> {
    CryptoProvider::get_default().cloned().ok_or_else(|| {
        SpireError::Tls(
            "no rustls CryptoProvider is installed; install one at process start".to_owned(),
        )
    })
}

/// The injected [`Clock`] as rustls's source of time.
#[derive(Clone)]
pub struct ClockTimeProvider {
    clock: Arc<dyn Clock>,
}

impl ClockTimeProvider {
    /// A time provider reading `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl std::fmt::Debug for ClockTimeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockTimeProvider").finish_non_exhaustive()
    }
}

impl TimeProvider for ClockTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        let seconds = u64::try_from(self.clock.now().unix_seconds()).ok()?;
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            seconds,
        )))
    }
}

impl X509Bundle {
    /// The authorities that have not expired at `now`, as a rustls root
    /// store. rustls does not read a root's own validity, so an authority
    /// past its `notAfter` is left out here; a bundle with none left is
    /// refused with [`SpireError::AuthoritiesExpired`] and never becomes an
    /// empty store that some other error would have to explain.
    pub fn root_store(&self, now: Timestamp) -> Result<RootCertStore, SpireError> {
        let mut store = RootCertStore::empty();
        for authority in self.valid_at(now) {
            store.add(authority.clone()).map_err(|error| {
                SpireError::Tls(format!(
                    "an authority of {} is not usable as a trust anchor: {error}",
                    self.trust_domain()
                ))
            })?;
        }
        if store.is_empty() {
            return Err(SpireError::AuthoritiesExpired(self.trust_domain().clone()));
        }
        Ok(store)
    }
}

/// Load `pkcs8` as the TLS stack will, and compare the public key it
/// derives with the leaf's `SubjectPublicKeyInfo`. `Ok(true)` when they are
/// the same, `Ok(false)` when the provider derives none; bytes that load as
/// no key, and a key that is another certificate's, are refused.
///
/// The provider is the one the process installed, which is the one that
/// will sign with the key; before any is installed, the one this crate's
/// rustls is built with.
pub(crate) fn derived_key_is(pkcs8: &[u8], leaf_public_key: &[u8]) -> Result<bool, SpireError> {
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));
    let loaded = provider
        .key_provider
        .load_private_key(key)
        .map_err(|error| {
            SpireError::Refused(format!(
                "the SVID is refused: its private key is not usable ({error})"
            ))
        })?;
    match loaded.public_key() {
        Some(derived) if derived.as_ref() == leaf_public_key => Ok(true),
        Some(_) => Err(SpireError::Refused(
            "the SVID is refused: the private key is not the leaf certificate's".to_owned(),
        )),
        None => Ok(false),
    }
}

impl X509Svid {
    /// The SVID as the client certificate of an [`OutboundMtlsClient`], for
    /// a downstream that is verified the way a web server is, by its DNS
    /// name. Pin the server's roots on the result before building its
    /// configuration: roots of the caller's choosing, and not a trust
    /// domain's bundle, which the Workload API has a workload use to
    /// authenticate X.509 SVIDs and nothing else. For a peer that is an
    /// X.509 SVID, use [`X509Source::rustls_client_config`].
    pub fn outbound_mtls_client(&self) -> Result<OutboundMtlsClient, MtlsClientError> {
        OutboundMtlsClient::new_from_der(
            self.cert_chain().to_vec(),
            PrivateKeyDer::Pkcs8(self.private_key()),
        )
    }
}

/// Presents the source's current X.509 SVID in a TLS handshake, as a client
/// certificate or as a server certificate.
///
/// The source is read at every handshake. While it holds no valid SVID (the
/// first has not arrived, or the last expired with no replacement) no
/// certificate is presented, and a peer that requires one refuses the
/// handshake.
pub struct SvidCertResolver {
    source: X509Source,
    provider: Arc<CryptoProvider>,
    /// What the provider made of the SVID last read, kept until the source
    /// holds another.
    made: Mutex<Option<Made>>,
}

/// What a provider made of one SVID.
struct Made {
    /// The SVID it was made of.
    svid: Arc<X509Svid>,
    /// The certificate and its signing key, or `None` when the provider
    /// could load no key.
    key: Option<Arc<CertifiedKey>>,
}

impl SvidCertResolver {
    /// A resolver presenting the SVID of `source`, signing with `provider`.
    pub fn new(source: X509Source, provider: Arc<CryptoProvider>) -> Self {
        Self {
            source,
            provider,
            made: Mutex::new(None),
        }
    }

    fn current(&self) -> Option<Arc<CertifiedKey>> {
        let svid = self.source.svid().ok()?;
        let mut made = self.made.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = made.as_ref()
            && Arc::ptr_eq(&held.svid, &svid)
        {
            return held.key.clone();
        }
        // An SVID is admitted only with a key the process's provider loads
        // as the certificate's. This resolver's provider may be another one;
        // what it cannot load is reported once for the SVID, and nothing is
        // presented until the source holds the next.
        let key = match CertifiedKey::from_der(
            svid.cert_chain().to_vec(),
            PrivateKeyDer::Pkcs8(svid.private_key()),
            &self.provider,
        ) {
            Ok(key) => Some(Arc::new(key)),
            Err(error) => {
                tracing::error!(
                    target: TARGET,
                    spiffe_id = %svid.spiffe_id(),
                    error = %error,
                    "the X.509 SVID cannot be presented: this provider does not load its key",
                );
                None
            }
        };
        *made = Some(Made {
            svid,
            key: key.clone(),
        });
        key
    }
}

impl std::fmt::Debug for SvidCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvidCertResolver")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl ResolvesClientCert for SvidCertResolver {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.current()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for SvidCertResolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current()
    }
}

/// Which peers a verifier admits, and the bundles it checks them against.
struct PeerPolicy {
    bundles: Arc<dyn X509BundleProvider>,
    provider: Arc<CryptoProvider>,
    admitted: Vec<TrustDomain>,
    peer_id: Option<WorkloadId>,
}

impl PeerPolicy {
    /// The roots to verify `end_entity` against: the bundle of the trust
    /// domain its SPIFFE ID names, when the peer is one this policy admits.
    fn roots_for(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<RootCertStore, rustls::Error> {
        let refuse = |why: &str| {
            tracing::debug!(target: TARGET, reason = why, "peer X.509 SVID refused");
            rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        };
        let facts =
            read_leaf(end_entity).map_err(|_| refuse("the certificate is not an X.509 SVID"))?;
        let spiffe_id = WorkloadId::parse(&facts.spiffe_id)
            .map_err(|_| refuse("the URI name is not a SPIFFE ID"))?;
        let trust_domain = spiffe_id.trust_domain();
        if !self.admitted.contains(&trust_domain) {
            return Err(refuse("the trust domain is not admitted"));
        }
        if self
            .peer_id
            .as_ref()
            .is_some_and(|wanted| *wanted != spiffe_id)
        {
            return Err(refuse("the SPIFFE ID is not the peer expected"));
        }
        // A source whose bundle set is stale, or whose SVID has expired,
        // answers an error here, and the handshake fails saying so.
        let bundles = self.bundles.x509_bundles().map_err(|error| {
            rustls::Error::General(format!("no X.509 bundles to verify the peer with: {error}"))
        })?;
        let Some(bundle) = bundles.get(&trust_domain) else {
            tracing::debug!(
                target: TARGET,
                reason = "the agent serves no bundle for the trust domain",
                "peer X.509 SVID refused",
            );
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        };
        // The time is the one rustls judges the peer's chain by: the
        // configuration's time provider, the client's clock. An authority
        // that has expired by it is no trust anchor.
        let now = i64::try_from(now.as_secs())
            .ok()
            .and_then(Timestamp::from_unix_seconds)
            .ok_or_else(|| rustls::Error::General("the time is out of range".to_owned()))?;
        bundle
            .root_store(now)
            .map_err(|error| rustls::Error::General(error.to_string()))
    }

    fn verify_tls12(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Verifies a server's X.509 SVID: the chain against the bundle of the
/// trust domain its SPIFFE ID names, and the identity against what the
/// caller admits.
///
/// The name the client dialled is not compared with the certificate. A
/// resumed session does not reach this verifier; the module's notes say
/// what a configuration built by hand has to turn off.
pub struct SpiffeServerCertVerifier {
    policy: PeerPolicy,
}

impl SpiffeServerCertVerifier {
    /// A verifier admitting servers of the `admitted` trust domains, each
    /// checked against its own bundle from `bundles`. With no trust domain
    /// admitted it refuses every server.
    pub fn new(
        bundles: Arc<dyn X509BundleProvider>,
        provider: Arc<CryptoProvider>,
        admitted: impl IntoIterator<Item = TrustDomain>,
    ) -> Self {
        Self {
            policy: PeerPolicy {
                bundles,
                provider,
                admitted: admitted.into_iter().collect(),
                peer_id: None,
            },
        }
    }

    /// Admit only the server with this SPIFFE ID, whose trust domain must
    /// be one of those admitted.
    #[must_use]
    pub fn with_peer_id(mut self, spiffe_id: WorkloadId) -> Self {
        self.policy.peer_id = Some(spiffe_id);
        self
    }
}

impl std::fmt::Debug for SpiffeServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeServerCertVerifier")
            .field("admitted", &self.policy.admitted)
            .field("peer_id", &self.policy.peer_id)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let roots = self.policy.roots_for(end_entity, now)?;
        let certificate = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &certificate,
            &roots,
            intermediates,
            now,
            self.policy.provider.signature_verification_algorithms.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.policy.verify_tls12(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.policy.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.policy.schemes()
    }
}

/// Verifies a client's X.509 SVID for a TLS server: the chain against the
/// bundle of the trust domain its SPIFFE ID names, and the trust domain
/// against those the deployment admits. A client certificate is required.
///
/// This is the per-trust-domain root store the `mtls` feature's
/// `MtlsResolver` relies on its terminator to have: a certificate that names
/// one trust domain and chains to another's authorities is refused here,
/// whichever bundles are served. A resumed session does not reach this
/// verifier; the module's notes say what a configuration built by hand has
/// to turn off.
pub struct SpiffeClientCertVerifier {
    policy: PeerPolicy,
}

impl SpiffeClientCertVerifier {
    /// A verifier admitting clients of the `admitted` trust domains, each
    /// checked against its own bundle from `bundles`. With no trust domain
    /// admitted it refuses every client.
    pub fn new(
        bundles: Arc<dyn X509BundleProvider>,
        provider: Arc<CryptoProvider>,
        admitted: impl IntoIterator<Item = TrustDomain>,
    ) -> Self {
        Self {
            policy: PeerPolicy {
                bundles,
                provider,
                admitted: admitted.into_iter().collect(),
                peer_id: None,
            },
        }
    }
}

impl std::fmt::Debug for SpiffeClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientCertVerifier")
            .field("admitted", &self.policy.admitted)
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No hints: the bundles change under a running server, and a client
        // of a SPIFFE deployment holds one SVID to present.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let roots = self.policy.roots_for(end_entity, now)?;
        let chain = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            self.policy.provider.clone(),
        )
        .build()
        .map_err(|error| rustls::Error::General(error.to_string()))?;
        chain.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.policy.verify_tls12(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.policy.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.policy.schemes()
    }
}

impl X509Source {
    /// A rustls client configuration that presents the source's current
    /// SVID and admits servers of the `admitted` trust domains, each
    /// verified against its own bundle as the source holds it at the
    /// handshake. Certificate validity is judged by the client's clock.
    ///
    /// Built once: a rotated SVID and a changed bundle are picked up by the
    /// handshakes that follow. Sessions are not resumed, so every
    /// connection is one of those handshakes.
    pub fn rustls_client_config(
        &self,
        provider: Arc<CryptoProvider>,
        admitted: impl IntoIterator<Item = TrustDomain>,
    ) -> Result<ClientConfig, SpireError> {
        let verifier =
            SpiffeServerCertVerifier::new(Arc::new(self.clone()), provider.clone(), admitted);
        self.rustls_client_config_with(provider, verifier)
    }

    /// As [`rustls_client_config`](Self::rustls_client_config), with a
    /// verifier of the caller's making: one that admits a single SPIFFE ID
    /// ([`SpiffeServerCertVerifier::with_peer_id`]), or one built on another
    /// source of bundles.
    pub fn rustls_client_config_with(
        &self,
        provider: Arc<CryptoProvider>,
        verifier: SpiffeServerCertVerifier,
    ) -> Result<ClientConfig, SpireError> {
        let time = Arc::new(ClockTimeProvider::new(self.clock()));
        let resolver = SvidCertResolver::new(self.clone(), provider.clone());
        let mut config = ClientConfig::builder_with_details(provider, time)
            .with_safe_default_protocol_versions()
            .map_err(|error| SpireError::Tls(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_cert_resolver(Arc::new(resolver));
        // A resumed session skips the verifier: see the module's notes.
        config.resumption = Resumption::disabled();
        Ok(config)
    }

    /// A rustls server configuration that presents the source's current
    /// SVID and requires a client certificate of one of the `admitted`
    /// trust domains, verified against that trust domain's bundle as the
    /// source holds it at the handshake. Certificate validity is judged by
    /// the client's clock. Sessions are not resumed and no session ticket
    /// is sent, so every connection is one of those handshakes.
    pub fn rustls_server_config(
        &self,
        provider: Arc<CryptoProvider>,
        admitted: impl IntoIterator<Item = TrustDomain>,
    ) -> Result<ServerConfig, SpireError> {
        let time = Arc::new(ClockTimeProvider::new(self.clock()));
        let verifier =
            SpiffeClientCertVerifier::new(Arc::new(self.clone()), provider.clone(), admitted);
        let resolver = SvidCertResolver::new(self.clone(), provider.clone());
        let mut config = ServerConfig::builder_with_details(provider, time)
            .with_safe_default_protocol_versions()
            .map_err(|error| SpireError::Tls(error.to_string()))?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_cert_resolver(Arc::new(resolver));
        // A resumed session skips the verifier: see the module's notes.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(config)
    }
}

#[cfg(all(test, unix))]
mod tests;
