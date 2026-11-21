//! rustls configured from the agent: real handshakes, in memory, between a
//! client and a server that each took their certificate and their trust
//! bundles from a fake agent.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::KeyProvider;
use rustls::{ClientConnection, HandshakeKind, ServerConnection};

use super::*;
use crate::metrics::WorkloadCredentialKind;
use crate::testing::spire_agent::{FakeSpireAgent, WorkloadApiMethod};
use crate::workload::spire::test_support::{Day, Minted, TestCa, World, served, uri, within};
use crate::workload::spire::{SpireClientBuilder, SvidSelector};

const BILLING: &str = "spiffe://example.org/billing/acme";
const API: &str = "spiffe://example.org/api/acme";
const PARTNER: &str = "spiffe://partner.test/reports/acme";
const HOUR: i64 = 3600;

/// A maximum bundle age no test reaches: for the tests that jump the clock
/// by a day at once, where the bundles that came with an SVID would
/// otherwise go stale on the way.
const NEVER_STALE: Duration = Duration::from_secs(7 * 24 * 3600);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn trust_domain(name: &str) -> TrustDomain {
    TrustDomain::new(name).expect("a trust domain")
}

fn id(text: &str) -> WorkloadId {
    WorkloadId::parse(text).expect("a SPIFFE ID")
}

/// Run a TLS handshake between the two configurations, in memory. `Ok` is
/// the SPIFFE IDs each side saw of the other: `(server's, client's)`.
fn handshake(client: &ClientConfig, server: &ServerConfig) -> Result<(String, String), String> {
    let (client, server) = connect(client, server)?;
    let seen = |chain: Option<&[CertificateDer<'_>]>| {
        let leaf = chain
            .and_then(|chain| chain.first())
            .ok_or("no peer certificate")?;
        read_leaf(leaf)
            .map(|facts| facts.spiffe_id)
            .map_err(|error| error.to_string())
    };
    Ok((
        seen(client.peer_certificates())?,
        seen(server.peer_certificates())?,
    ))
}

/// Run a TLS handshake between the two configurations, in memory, and give
/// both ends once it is complete. An error says which end refused.
fn connect(
    client: &ClientConfig,
    server: &ServerConfig,
) -> Result<(ClientConnection, ServerConnection), String> {
    let name = ServerName::try_from("workload.invalid").map_err(|error| error.to_string())?;
    let mut client =
        ClientConnection::new(Arc::new(client.clone()), name).map_err(|error| error.to_string())?;
    let mut server =
        ServerConnection::new(Arc::new(server.clone())).map_err(|error| error.to_string())?;
    let mut wire = Vec::new();
    for _ in 0..16 {
        wire.clear();
        while client.wants_write() {
            client
                .write_tls(&mut wire)
                .map_err(|error| error.to_string())?;
        }
        let mut unread = wire.as_slice();
        while !unread.is_empty() {
            server
                .read_tls(&mut unread)
                .map_err(|error| error.to_string())?;
            server
                .process_new_packets()
                .map_err(|error| format!("server: {error}"))?;
        }
        wire.clear();
        while server.wants_write() {
            server
                .write_tls(&mut wire)
                .map_err(|error| error.to_string())?;
        }
        let mut unread = wire.as_slice();
        while !unread.is_empty() {
            client
                .read_tls(&mut unread)
                .map_err(|error| error.to_string())?;
            client
                .process_new_packets()
                .map_err(|error| format!("client: {error}"))?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    Err("the handshake did not complete".to_owned())
}

/// A trust domain with its authority, its agent and the world they run in.
struct Domain {
    world: World,
    agent: FakeSpireAgent,
    ca: TestCa,
    name: &'static str,
}

impl Domain {
    fn new(name: &'static str) -> Self {
        Self::with_authority(name, TestCa::new(name))
    }

    /// A trust domain whose authority is `ca`.
    fn with_authority(name: &'static str, ca: TestCa) -> Self {
        let world = World::new();
        let agent = world.agent();
        Self {
            world,
            agent,
            ca,
            name,
        }
    }

    /// A client builder for the SVID of `spiffe_id`, whose bundles never go
    /// stale.
    fn builder(&self, spiffe_id: &str) -> SpireClientBuilder {
        self.world
            .builder(self.name)
            .with_max_bundle_age(NEVER_STALE)
            .with_svid_selector(SvidSelector::SpiffeId(id(spiffe_id)))
    }

    /// Serve `svids` from this domain's authority, with `federated` as the
    /// bundles of other trust domains.
    fn serve(&self, svids: &[&Minted], federated: &[(&str, &TestCa)]) {
        let bundle = self.ca.bundle_der();
        let svids: Vec<_> = svids.iter().map(|svid| served(svid, &bundle)).collect();
        let bundles: Vec<(&str, Vec<u8>)> = federated
            .iter()
            .map(|(name, ca)| (*name, ca.bundle_der()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = bundles
            .iter()
            .map(|(name, bundle)| (*name, bundle.as_slice()))
            .collect();
        self.agent.set_x509_svids(&svids, &borrowed);
    }

    /// A source of the SVID for `spiffe_id`, ready.
    async fn source(&self, spiffe_id: &str) -> X509Source {
        let source = self
            .builder(spiffe_id)
            .build()
            .watch_x509()
            .expect("inside a runtime");
        within(source.ready()).await;
        source
    }
}

/// A server configuration built by hand around the pieces, resuming no
/// session, as the module's notes require.
fn server_config_of(
    time: &World,
    verifier: SpiffeClientCertVerifier,
    resolver: SvidCertResolver,
) -> ServerConfig {
    let mut config = ServerConfig::builder_with_details(
        provider(),
        Arc::new(ClockTimeProvider::new(Arc::new(time.clock.clone()))),
    )
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_client_cert_verifier(Arc::new(verifier))
    .with_cert_resolver(Arc::new(resolver));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config
}

#[tokio::test(start_paused = true)]
async fn two_workloads_of_one_trust_domain_authenticate_each_other() {
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(2));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];

    let client_config = client
        .rustls_client_config(provider(), own.clone())
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), own)
        .expect("a server configuration");
    assert_eq!(
        handshake(&client_config, &server_config),
        Ok((API.to_owned(), BILLING.to_owned()))
    );
}

#[tokio::test(start_paused = true)]
async fn a_federated_trust_domain_is_verified_once_it_is_admitted() {
    let home = Domain::new("example.org");
    let partner = Domain::new("partner.test");
    let api = home.ca.svid(API, Day(1), Day(2));
    let reports = partner.ca.svid(PARTNER, Day(1), Day(2));
    // Each agent serves its own bundle and the other domain's as federated.
    home.serve(&[&api], &[("spiffe://partner.test", &partner.ca)]);
    partner.serve(&[&reports], &[("example.org", &home.ca)]);
    let server = home.source(API).await;
    let client = partner.source(PARTNER).await;
    let client_config = client
        .rustls_client_config(provider(), [trust_domain("example.org")])
        .expect("a client configuration");

    // The partner's bundle is served to the server, and that alone admits
    // nobody.
    let own_only = server
        .rustls_server_config(provider(), [trust_domain("example.org")])
        .expect("a server configuration");
    let refused = handshake(&client_config, &own_only).expect_err("not admitted");
    assert!(refused.starts_with("server: "), "{refused}");

    let with_partner = server
        .rustls_server_config(
            provider(),
            [trust_domain("example.org"), trust_domain("partner.test")],
        )
        .expect("a server configuration");
    assert_eq!(
        handshake(&client_config, &with_partner),
        Ok((API.to_owned(), PARTNER.to_owned()))
    );

    // A client that does not admit the server's trust domain refuses it.
    let narrow = client
        .rustls_client_config(provider(), [trust_domain("partner.test")])
        .expect("a client configuration");
    let refused = handshake(&narrow, &with_partner).expect_err("not admitted");
    assert!(refused.starts_with("client: "), "{refused}");
}

#[tokio::test(start_paused = true)]
async fn a_certificate_is_verified_against_the_bundle_of_the_trust_domain_it_names() {
    let home = Domain::new("example.org");
    let partner = Domain::new("partner.test");
    let api = home.ca.svid(API, Day(1), Day(2));
    home.serve(&[&api], &[("spiffe://partner.test", &partner.ca)]);
    let server = home.source(API).await;
    let server_config = server
        .rustls_server_config(
            provider(),
            [trust_domain("example.org"), trust_domain("partner.test")],
        )
        .expect("a server configuration");

    // The partner's authority signs a certificate for a name in
    // example.org, and a workload presents it. Both trust domains are
    // admitted and both bundles are held, and it is still refused: a name
    // in example.org is checked against example.org's authorities alone.
    let forged = partner.ca.svid(BILLING, Day(1), Day(2));
    let impostor = Domain::new("example.org");
    // The impostor holds example.org's real bundle, so it accepts the
    // server; what it presents is the forgery.
    impostor
        .agent
        .set_x509_svids(&[served(&forged, &home.ca.bundle_der())], &[]);
    let client = impostor.source(BILLING).await;
    let client_config = client
        .rustls_client_config(provider(), [trust_domain("example.org")])
        .expect("a client configuration");
    let refused = handshake(&client_config, &server_config).expect_err("a forged name");
    assert!(refused.starts_with("server: "), "{refused}");
}

#[tokio::test(start_paused = true)]
async fn a_rotated_svid_is_presented_by_the_configuration_built_before_it() {
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(3));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];
    let client_config = client
        .rustls_client_config(provider(), own.clone())
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), own)
        .expect("a server configuration");
    assert!(handshake(&client_config, &server_config).is_ok());
    let before = client.svid().expect("the first SVID");

    // The agent rotates the client's SVID ahead of its expiry, and the first
    // certificate then expires: the configuration built at the start
    // presents the new one.
    let renewed = domain.ca.svid(BILLING, Day(2), Day(3));
    domain.serve(&[&renewed, &api], &[]);
    let generation = client.generation();
    within(client.updated(generation)).await;
    domain.world.clock.advance_secs(24 * HOUR);
    let after = client.svid().expect("the rotated SVID");
    assert_ne!(before.leaf(), after.leaf());
    assert!(before.not_after() <= axess_clock::Clock::now(&domain.world.clock));
    assert_eq!(
        handshake(&client_config, &server_config),
        Ok((API.to_owned(), BILLING.to_owned()))
    );
}

#[tokio::test(start_paused = true)]
async fn a_changed_bundle_is_what_the_next_handshake_is_verified_against() {
    let home = Domain::new("example.org");
    let billing = home.ca.svid(BILLING, Day(1), Day(2));
    let api = home.ca.svid(API, Day(1), Day(2));
    home.serve(&[&billing, &api], &[]);
    let client = home.source(BILLING).await;
    let own = [trust_domain("example.org")];
    let client_config = client
        .rustls_client_config(provider(), own.clone())
        .expect("a client configuration");

    // The server takes its bundles from a bundle source of their own.
    home.agent
        .set_x509_bundles(&[("example.org", home.ca.bundle_der().as_slice())]);
    let bundles = home
        .world
        .client("example.org")
        .watch_x509_bundles()
        .expect("inside a runtime");
    within(bundles.ready()).await;
    let server = home.source(API).await;
    let verifier = SpiffeClientCertVerifier::new(Arc::new(bundles.clone()), provider(), own);
    let server_config = server_config_of(
        &home.world,
        verifier,
        SvidCertResolver::new(server, provider()),
    );
    assert!(handshake(&client_config, &server_config).is_ok());

    // The trust domain's authority is replaced. The client's certificate,
    // signed by the old one, no longer verifies.
    let replacement = TestCa::new("example.org, replaced");
    home.agent
        .set_x509_bundles(&[("example.org", replacement.bundle_der().as_slice())]);
    within(bundles.updated(1)).await;
    let refused = handshake(&client_config, &server_config).expect_err("an old authority");
    assert!(refused.starts_with("server: "), "{refused}");
}

#[tokio::test(start_paused = true)]
async fn no_session_is_resumed() {
    // A resumed session is verified by nobody. The two tests around this
    // one would pass on a resumed session's stored certificate if the
    // configurations resumed; this one says that they do not.
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(2));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];
    let client_config = client
        .rustls_client_config(provider(), own.clone())
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), own)
        .expect("a server configuration");

    for _ in 0..3 {
        let (client_end, server_end) =
            connect(&client_config, &server_config).expect("a handshake");
        assert_ne!(client_end.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_ne!(server_end.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(client_end.handshake_kind().is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn an_authority_that_has_expired_verifies_no_peer() {
    // The authority's own certificate runs out a day before the SVIDs it
    // signed do.
    let retiring = TestCa::expiring("example.org authority", Day(2));
    let domain = Domain::with_authority("example.org", retiring);
    let billing = domain.ca.svid(BILLING, Day(1), Day(3));
    let api = domain.ca.svid(API, Day(1), Day(3));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];
    let client_config = client
        .rustls_client_config(provider(), own.clone())
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), own)
        .expect("a server configuration");
    assert!(handshake(&client_config, &server_config).is_ok());

    // One second past the authority's `notAfter`. Both SVIDs are valid for
    // another day, and neither end has a trust anchor left.
    domain.world.clock.advance_secs(24 * HOUR + 1);
    assert!(client.svid().is_ok() && server.svid().is_ok());
    let refused = handshake(&client_config, &server_config).expect_err("an expired authority");
    assert!(
        refused.contains("every authority in the X.509 bundle of example.org has expired"),
        "{refused}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_retired_authority_left_in_the_bundle_stops_verifying_at_its_expiry() {
    // A rotation of the trust domain's authority: the bundle lists the old
    // one, which runs out at the start of the second of January, and the
    // new one.
    let old = TestCa::expiring("example.org authority, old", Day(2));
    let domain = Domain::new("example.org");
    let both = [old.bundle_der(), domain.ca.bundle_der()].concat();
    let late = old.svid(BILLING, Day(1), Day(3));
    let renewed = domain
        .ca
        .svid("spiffe://example.org/reports/acme", Day(1), Day(3));
    let api = domain.ca.svid(API, Day(1), Day(3));
    domain.agent.set_x509_svids(
        &[
            served(&late, &both),
            served(&renewed, &both),
            served(&api, &both),
        ],
        &[],
    );
    let own = [trust_domain("example.org")];
    let config_of = |source: &X509Source| {
        source
            .rustls_client_config(provider(), own.clone())
            .expect("a client configuration")
    };
    let signed_by_old = config_of(&domain.source(BILLING).await);
    let signed_by_new = config_of(&domain.source("spiffe://example.org/reports/acme").await);
    let server_config = domain
        .source(API)
        .await
        .rustls_server_config(provider(), own.clone())
        .expect("a server configuration");

    // While the old authority is valid, a certificate it signed verifies.
    assert!(handshake(&signed_by_old, &server_config).is_ok());
    assert!(handshake(&signed_by_new, &server_config).is_ok());

    // Past its `notAfter` it is still in the bundle and is no anchor: the
    // certificate it signed is refused, though that certificate is valid
    // for another day. The new authority's is accepted.
    domain.world.clock.advance_secs(24 * HOUR + 1);
    let refused = handshake(&signed_by_old, &server_config).expect_err("a retired authority");
    assert!(refused.starts_with("server: "), "{refused}");
    assert!(handshake(&signed_by_new, &server_config).is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_stale_bundle_source_refuses_every_peer_and_says_why() {
    let home = Domain::new("example.org");
    let billing = home.ca.svid(BILLING, Day(1), Day(2));
    let api = home.ca.svid(API, Day(1), Day(2));
    home.serve(&[&billing, &api], &[]);
    home.agent
        .set_x509_bundles(&[("example.org", home.ca.bundle_der().as_slice())]);
    let client = home.source(BILLING).await;
    let server = home.source(API).await;
    let own = [trust_domain("example.org")];
    let client_config = client
        .rustls_client_config(provider(), own.clone())
        .expect("a client configuration");

    // The server verifies its clients against a bundle source with a
    // maximum bundle age of ten minutes.
    let bundles = home
        .world
        .builder("example.org")
        .with_max_bundle_age(Duration::from_secs(600))
        .build()
        .watch_x509_bundles()
        .expect("inside a runtime");
    within(bundles.ready()).await;
    let verifier = SpiffeClientCertVerifier::new(Arc::new(bundles.clone()), provider(), own);
    let server_config = server_config_of(
        &home.world,
        verifier,
        SvidCertResolver::new(server, provider()),
    );
    assert!(handshake(&client_config, &server_config).is_ok());

    // The agent goes away; ten minutes later nothing has confirmed the set.
    drop(home.agent);
    home.world.clock.advance_secs(600);
    let refused = handshake(&client_config, &server_config).expect_err("stale bundles");
    assert!(refused.starts_with("server: "), "{refused}");
    assert!(
        refused.contains("the X.509 bundle set is stale"),
        "{refused}"
    );
}

/// A key provider that loads no key, as a provider for other key types
/// than the SVID's would.
#[derive(Debug)]
struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(
        &self,
        _: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Err(rustls::Error::General("no key is loaded here".to_owned()))
    }
}

#[tokio::test(start_paused = true)]
async fn a_resolver_whose_provider_does_not_load_the_key_presents_nothing() {
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(2));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];
    let keyless = Arc::new(CryptoProvider {
        key_provider: &NoKeys,
        ..rustls::crypto::aws_lc_rs::default_provider()
    });

    let resolver = SvidCertResolver::new(client.clone(), keyless.clone());
    assert!(ResolvesClientCert::has_certs(&resolver));
    // Asked twice: the answer for one SVID is made once and kept.
    assert!(ResolvesClientCert::resolve(&resolver, &[], &[]).is_none());
    assert!(ResolvesClientCert::resolve(&resolver, &[], &[]).is_none());
    assert!(format!("{resolver:?}").contains("SvidCertResolver"));

    // A client configured with it has no certificate to show a server that
    // requires one.
    let client_config = client
        .rustls_client_config(keyless, own.clone())
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), own)
        .expect("a server configuration");
    let refused = handshake(&client_config, &server_config).expect_err("no certificate");
    assert!(refused.starts_with("server: "), "{refused}");
}

#[tokio::test(start_paused = true)]
async fn an_expired_svid_is_not_presented() {
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(4));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];
    // The client verifies servers against a set it keeps, so that what it
    // can still verify does not depend on its own SVID.
    let kept = client.bundles().expect("the bundles");
    let verifier = SpiffeServerCertVerifier::new(Arc::new(kept), provider(), own.clone());
    let client_config = client
        .rustls_client_config_with(provider(), verifier)
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), own)
        .expect("a server configuration");
    assert!(handshake(&client_config, &server_config).is_ok());

    // The agent goes away and the client's SVID runs out.
    domain
        .agent
        .refuse(WorkloadApiMethod::FetchX509Svid, 14, "agent is restarting");
    domain.world.clock.advance_secs(24 * HOUR);
    assert_eq!(
        client.svid().err(),
        Some(SpireError::Expired(WorkloadCredentialKind::X509Svid))
    );
    // The client has nothing to present, and the server requires a
    // certificate.
    let refused = handshake(&client_config, &server_config).expect_err("no certificate");
    assert!(refused.starts_with("server: "), "{refused}");
}

#[tokio::test(start_paused = true)]
async fn a_client_can_admit_one_server_by_its_spiffe_id() {
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(2));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let own = [trust_domain("example.org")];
    let server_config = server
        .rustls_server_config(provider(), own.clone())
        .expect("a server configuration");
    let expecting = |peer: &str| {
        let verifier =
            SpiffeServerCertVerifier::new(Arc::new(client.clone()), provider(), own.clone())
                .with_peer_id(id(peer));
        client
            .rustls_client_config_with(provider(), verifier)
            .expect("a client configuration")
    };

    assert!(handshake(&expecting(API), &server_config).is_ok());
    let refused = handshake(
        &expecting("spiffe://example.org/other/acme"),
        &server_config,
    )
    .expect_err("another server");
    assert!(refused.starts_with("client: "), "{refused}");
}

#[tokio::test(start_paused = true)]
async fn a_verifier_that_admits_no_trust_domain_refuses_everyone() {
    let domain = Domain::new("example.org");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    let api = domain.ca.svid(API, Day(1), Day(2));
    domain.serve(&[&billing, &api], &[]);
    let client = domain.source(BILLING).await;
    let server = domain.source(API).await;
    let client_config = client
        .rustls_client_config(provider(), [trust_domain("example.org")])
        .expect("a client configuration");
    let server_config = server
        .rustls_server_config(provider(), [])
        .expect("a server configuration");
    assert!(handshake(&client_config, &server_config).is_err());
}

#[tokio::test(start_paused = true)]
async fn a_certificate_that_is_not_an_svid_is_refused() {
    let domain = Domain::new("example.org");
    let api = domain.ca.svid(API, Day(1), Day(2));
    domain.serve(&[&api], &[]);
    let source = domain.source(API).await;
    let own = [trust_domain("example.org")];
    let verifier = SpiffeServerCertVerifier::new(Arc::new(source.clone()), provider(), own);
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_767_225_660));
    let name = ServerName::try_from("workload.invalid").expect("a name");

    let svid = source.svid().expect("the SVID");
    assert!(
        verifier
            .verify_server_cert(svid.leaf(), &[], &name, &[], now)
            .is_ok()
    );
    // A certificate of the same authority whose SPIFFE ID has no path names
    // the trust domain, not a workload: no leaf to authenticate a peer by.
    let domain_only = domain.ca.leaf(
        vec![uri("spiffe://example.org")],
        rcgen::IsCa::NoCa,
        Day(1),
        Day(2),
        "spiffe://example.org",
    );
    assert!(
        verifier
            .verify_server_cert(
                &CertificateDer::from(domain_only.cert_der),
                &[],
                &name,
                &[],
                now
            )
            .is_err()
    );
    // The authority's own certificate chains to itself and names nobody.
    let authority = CertificateDer::from(domain.ca.bundle_der());
    assert!(
        verifier
            .verify_server_cert(&authority, &[], &name, &[], now)
            .is_err()
    );
    // After the certificate's validity, by the time the caller passes.
    let later = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_767_225_600 + 86_401));
    assert!(
        verifier
            .verify_server_cert(svid.leaf(), &[], &name, &[], later)
            .is_err()
    );
    assert!(!verifier.supported_verify_schemes().is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_svid_becomes_an_outbound_mtls_client() {
    let domain = Domain::new("example.org");
    let partner = TestCa::new("partner authority");
    let billing = domain.ca.svid(BILLING, Day(1), Day(2));
    domain.serve(&[&billing], &[("partner.test", &partner)]);
    let source = domain.source(BILLING).await;
    let context = source.context().expect("the context");

    let client = context
        .svid()
        .outbound_mtls_client()
        .expect("a client certificate");
    assert_eq!(client.cert_chain(), context.svid().cert_chain());
    assert!(client.server_roots().is_none());

    let now = domain.world.clock.now();
    let roots = context
        .bundles()
        .get(&trust_domain("example.org"))
        .expect("the own bundle")
        .root_store(now)
        .expect("a root store");
    assert_eq!(roots.len(), 1);
}

#[test]
fn a_root_store_holds_the_authorities_that_are_valid() {
    let old = TestCa::expiring("example.org authority, old", Day(2));
    let current = TestCa::new("example.org authority");
    let bundle = X509Bundle::new(
        trust_domain("example.org"),
        vec![
            CertificateDer::from(old.bundle_der()),
            CertificateDer::from(current.bundle_der()),
        ],
    )
    .expect("two certificates");
    let clock = crate::testing::MockClock::at_reference();
    assert_eq!(bundle.root_store(clock.now()).expect("both").len(), 2);
    clock.advance_secs(24 * HOUR + 1);
    assert_eq!(bundle.root_store(clock.now()).expect("one").len(), 1);

    let retired = X509Bundle::new(
        trust_domain("example.org"),
        vec![CertificateDer::from(old.bundle_der())],
    )
    .expect("a certificate");
    assert_eq!(
        retired.root_store(clock.now()).err(),
        Some(SpireError::AuthoritiesExpired(trust_domain("example.org")))
    );
}

#[test]
fn rustls_reads_the_injected_clock() {
    let clock = crate::testing::MockClock::at_reference();
    let time = ClockTimeProvider::new(Arc::new(clock.clone()));
    assert_eq!(
        time.current_time(),
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            1_767_225_600
        )))
    );
    clock.advance_secs(90);
    assert_eq!(
        time.current_time(),
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            1_767_225_690
        )))
    );
    assert!(format!("{time:?}").contains("ClockTimeProvider"));
}
