#![cfg(feature = "oidc")]
//! A client the policy built keeps the policy whatever settings the caller
//! adds to it: the settings on offer are named (timeouts, a `User-Agent`, a
//! trusted root certificate, a client certificate), and none of them can
//! route a name past the connect-time address screen. That a caller cannot
//! pin a name to an address of its own is a compile-time property, shown on
//! `ClientSettings`; this file shows that the settings on offer leave the
//! screen in place, and that a root named in the settings is trusted.

use axess_factors::egress::EgressPolicy;
use std::net::TcpListener;
use std::time::Duration;

/// A self-signed client certificate and key, as PEM.
fn client_identity() -> openidconnect::reqwest::Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["client.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}\n{}", cert.pem(), key.serialize_pem());
    openidconnect::reqwest::Identity::from_pem(pem.as_bytes()).unwrap()
}

/// A self-signed certificate for `localhost`, as the root a client is told
/// to trust, with the certificate and its key as a TLS server presents them.
fn private_root() -> (
    openidconnect::reqwest::Certificate,
    tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    Vec<u8>,
) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let root = openidconnect::reqwest::Certificate::from_der(cert.der()).unwrap();
    (root, cert.der().clone(), key.serialize_der())
}

/// Serve `body` as the answer to every request on a loopback port, over TLS
/// under `certificate`. Returns the port. A client that does not trust the
/// certificate never gets past the handshake.
async fn serve_over_tls(
    certificate: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    key: Vec<u8>,
    body: impl Fn(u16) -> String + Send + 'static,
) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .expect("server certificate");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = body(port);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, body) = (acceptor.clone(), body.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut request = [0u8; 2048];
                if tls.read(&mut request).await.is_err() {
                    return;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                if tls.write_all(response.as_bytes()).await.is_ok() {
                    tls.shutdown().await.ok();
                }
            });
        }
    });
    port
}

/// Every message in an error's chain, outermost first.
fn messages(err: &dyn std::error::Error) -> Vec<String> {
    let mut out = vec![err.to_string()];
    let mut next = err.source();
    while let Some(e) = next {
        out.push(e.to_string());
        next = e.source();
    }
    out
}

/// With every setting the surface offers in place, a name that resolves to
/// loopback is still refused at connect time, by the name of the range.
#[tokio::test]
async fn every_setting_on_offer_leaves_the_resolver_screen_in_place() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = EgressPolicy::screened()
        .build_client(|settings| {
            settings
                .timeout(Duration::from_secs(3))
                .connect_timeout(Duration::from_secs(2))
                .user_agent("egress-test/1.0")
                .root_certificate(private_root().0)
                .client_certificate(client_identity())
        })
        .unwrap();

    let err = client
        .inner()
        .get(format!("http://localhost:{port}/"))
        .send()
        .await
        .expect_err("a screened client reached a loopback name");

    let chain = messages(&err);
    assert!(
        chain.iter().any(|m| m.contains("loopback")),
        "the refusal does not name the range: {chain:?}"
    );
    assert!(
        listener.accept().is_err(),
        "the screened client connected to loopback"
    );
}

/// The client carries the policy it was built under.
#[test]
fn a_screened_client_reports_its_policy() {
    let client = EgressPolicy::unscreened()
        .build_client(|settings| settings.timeout(Duration::from_secs(1)))
        .unwrap();

    assert_eq!(client.policy(), EgressPolicy::unscreened());
}

/// An identity provider whose certificate chains to a private root is
/// reached by a client that names the root in its settings, and by no
/// other: the discovery document arrives through the first and the second
/// fails the handshake. The root widens whom the client believes; the
/// policy it was built under is unchanged.
#[tokio::test]
async fn a_private_root_named_in_the_settings_is_trusted_and_only_then() {
    use axess_factors::oidc::{DiscoveryDocument, OidcError};
    let (root, certificate, key) = private_root();
    let port = serve_over_tls(certificate, key, |port| {
        axess_testing::oauth_wiremock::oauth_discovery_document(&format!(
            "https://localhost:{port}"
        ))
        .to_string()
    })
    .await;
    let issuer = format!("https://localhost:{port}");
    let trusting = EgressPolicy::unscreened()
        .build_client(|settings| {
            settings
                .timeout(Duration::from_secs(5))
                .root_certificate(root)
        })
        .unwrap();
    let plain = EgressPolicy::unscreened()
        .build_client(|settings| settings.timeout(Duration::from_secs(5)))
        .unwrap();

    let document = DiscoveryDocument::fetch(&issuer, &trusting)
        .await
        .expect("the client was told to trust this root");
    assert_eq!(document.issuer, issuer);
    assert_eq!(trusting.policy(), EgressPolicy::unscreened());

    let refused = DiscoveryDocument::fetch(&issuer, &plain)
        .await
        .expect_err("a certificate from an unknown root was trusted");
    assert!(
        matches!(refused, OidcError::DiscoveryFetch(_)),
        "{refused:?}"
    );
}
