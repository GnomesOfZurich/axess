//! The Workload API client against a running SPIRE agent.
//!
//! The suite needs an agent that issues the test process two identities,
//! `spiffe://<trust domain>/axess-live/steady` (with an X.509 SVID lifetime
//! of two minutes, so that a rotation comes about a minute in) and
//! `spiffe://<trust domain>/axess-live/withdrawn`, and somebody who deletes
//! a registration entry when a test asks for it: the test prints
//! `spire-live: delete the entry of <SPIFFE ID>` and waits. No test changes
//! anything on the server.
//!
//! `scripts/spire-live.sh` is that somebody. It starts a server and an
//! agent of its own, registers the two entries for the uid it runs as,
//! runs the suite and deletes each entry a test asks for:
//!
//! ```text
//! ./scripts/spire-live.sh /path/to/spire/bin
//! ```
//!
//! Against an agent that is already running, with the two entries
//! registered and a person to delete them:
//!
//! ```text
//! SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock \
//!     SPIFFE_TRUST_DOMAIN=example.org ./scripts/check-live-stores.sh spire
//! ```
//!
//! Every test is ignored unless asked for, since it needs the agent. The
//! last one ends the identity of the process, so the gate runs it by
//! itself after the others.
//!
//! No test reads the machine's clock. The agent's host stamps what the
//! tests check, so each test's world runs on that host's time, read from
//! what it signs (the `iat` of a JWT SVID minted as the test starts) and
//! carried forward by a stopwatch.

#![cfg(all(unix, feature = "spire", feature = "outbound-mtls", feature = "jwt"))]

/// The tests sit in a module of the suite's name, so that a run of the
/// other live suites leaves them out by name (`--skip spire_live::`).
mod spire_live {
    use axess_clock::testing::Shift;
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axess_clock::testing::MockClock;
    use axess_core::workload::spire::{
        Endpoint, GrpcCode, SpireClient, SpireError, SvidSelector, WorkloadApiEvent,
        WorkloadApiListener, WorkloadCredentialKind, X509Source,
    };
    use axess_factors::jwt::verifier::JwtVerifier;
    use axess_identity::{TrustDomain, WorkloadId};
    use axess_testing::stopwatch::Stopwatch;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

    /// Who the JWT SVIDs of the suite are for.
    const AUDIENCE: &str = "https://api.axess-live.test";
    /// An audience no token of the suite names.
    const ANOTHER_AUDIENCE: &str = "https://billing.axess-live.test";
    /// The identity no test asks to have deleted before the last one.
    const STEADY: &str = "steady";
    /// The identity whose entry is deleted while `STEADY` remains.
    const WITHDRAWN: &str = "withdrawn";

    /// How long the agent may take to answer a first call.
    const ANSWER: Duration = Duration::from_secs(60);
    /// How long a rotation may take: the entry's SVIDs live two minutes
    /// and the agent replaces one at half its lifetime.
    const ROTATION: Duration = Duration::from_secs(240);
    /// How long a deleted entry may take to reach the workload: the server
    /// and the agent each reload on an interval of a few seconds.
    const WITHDRAWAL: Duration = Duration::from_secs(180);

    fn trust_domain() -> TrustDomain {
        let name = std::env::var("SPIFFE_TRUST_DOMAIN")
            .expect("set SPIFFE_TRUST_DOMAIN to the agent's trust domain, e.g. example.org");
        TrustDomain::new(&name).expect("SPIFFE_TRUST_DOMAIN is a trust domain")
    }

    fn identity(name: &str) -> WorkloadId {
        let trust_domain = trust_domain();
        WorkloadId::parse(&format!(
            "spiffe://{}/axess-live/{name}",
            trust_domain.as_str()
        ))
        .expect("a SPIFFE ID")
    }

    /// What the watchers of one client reported.
    #[derive(Default)]
    struct Seen {
        failures: Mutex<Vec<SpireError>>,
        withdrawn: Mutex<Vec<WorkloadCredentialKind>>,
    }

    impl Seen {
        fn failures(&self) -> Vec<SpireError> {
            self.failures.lock().expect("the failures").clone()
        }

        fn withdrawn(&self) -> Vec<WorkloadCredentialKind> {
            self.withdrawn.lock().expect("the withdrawals").clone()
        }
    }

    impl WorkloadApiListener for Seen {
        fn on_event(&self, event: &WorkloadApiEvent<'_>) {
            match event {
                WorkloadApiEvent::RefreshFailed { error, .. } => self
                    .failures
                    .lock()
                    .expect("the failures")
                    .push((*error).clone()),
                WorkloadApiEvent::Withdrawn { kind, .. } => {
                    self.withdrawn.lock().expect("the withdrawals").push(*kind)
                }
                _ => {}
            }
        }
    }

    /// `step`, or a panic that names it when it takes longer than `limit`.
    async fn within<T>(limit: Duration, what: &str, step: impl Future<Output = T>) -> T {
        match tokio::time::timeout(limit, step).await {
            Ok(value) => value,
            Err(_) => panic!("{what}: nothing within {limit:?}"),
        }
    }

    /// One test's client, what its watchers report, and the clock all of
    /// it runs on.
    struct World {
        client: SpireClient,
        seen: Arc<Seen>,
        clock: MockClock,
    }

    /// The world of the test `test`: a client for the identity `name`, on
    /// the agent the environment names.
    ///
    /// The clock is the agent's host's: the `iat` of a JWT SVID the agent
    /// has minted for this call, carried forward by a stopwatch ten times a
    /// second. The audience of that token names the test and the process,
    /// so the agent mints one and does not answer from its cache with an
    /// older `iat`. The stamp is whole seconds, so the clock runs up to a
    /// second and the call's own time behind the host's, well inside the
    /// ten seconds by which a SPIRE server backdates a certificate.
    async fn world_for(test: &str, name: &str) -> World {
        let endpoint = Endpoint::from_env().expect(
            "set SPIFFE_ENDPOINT_SOCKET to the agent's socket, e.g. unix:///run/spire/sockets/agent.sock",
        );
        let clock = MockClock::at_reference();
        let seen = Arc::new(Seen::default());
        let client = SpireClient::builder(endpoint, trust_domain())
            .with_clock(Arc::new(clock.clone()))
            .with_svid_selector(SvidSelector::SpiffeId(identity(name)))
            .with_listener(seen.clone())
            .build();

        let audience = format!(
            "https://clock.axess-live.test/{}/{test}",
            std::process::id()
        );
        let stamp = within(ANSWER, "the token the clock is read from", async {
            client.fetch_jwt_svid([audience]).await
        })
        .await
        .expect("a JWT SVID to read the agent's time from")
        .issued_at();
        assert!(
            stamp > MockClock::reference_time(),
            "the agent's token carries an `iat`"
        );
        let since = Stopwatch::start();
        clock.set(stamp);
        tokio::spawn({
            let clock = clock.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    clock.set(
                        stamp.plus(axess_clock::SignedDuration::try_from(since.elapsed()).unwrap()),
                    );
                }
            }
        });
        World {
            client,
            seen,
            clock,
        }
    }

    /// Ask whoever runs the suite to delete the entry of `spiffe_id`.
    fn ask_for_deletion(spiffe_id: &WorkloadId) {
        eprintln!("spire-live: delete the entry of {spiffe_id}");
    }

    /// Wait until `source` refuses its SVID, and return the refusal.
    async fn refusal(source: &X509Source) -> SpireError {
        within(WITHDRAWAL, "the withdrawal", async {
            loop {
                match source.svid() {
                    Ok(_) => tokio::time::sleep(Duration::from_millis(250)).await,
                    Err(error) => return error,
                }
            }
        })
        .await
    }

    /// Run a TLS handshake between the two configurations, in memory.
    /// `Ok` is the leaf each side was shown: `(the server's, the client's)`.
    fn handshake(client: ClientConfig, server: ServerConfig) -> Result<(Vec<u8>, Vec<u8>), String> {
        let name = ServerName::try_from("workload.invalid").map_err(|error| error.to_string())?;
        let mut client =
            ClientConnection::new(Arc::new(client), name).map_err(|error| error.to_string())?;
        let mut server =
            ServerConnection::new(Arc::new(server)).map_err(|error| error.to_string())?;
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
                let leaf = |chain: Option<&[rustls::pki_types::CertificateDer<'_>]>| {
                    chain
                        .and_then(|chain| chain.first())
                        .map(|leaf| leaf.as_ref().to_vec())
                        .ok_or("no peer certificate")
                };
                return Ok((
                    leaf(client.peer_certificates())?,
                    leaf(server.peer_certificates())?,
                ));
            }
        }
        Err("the handshake did not complete".to_owned())
    }

    /// A mutual TLS handshake between two ends that both took their
    /// certificate and their bundles from `source`: each end is shown the
    /// source's current leaf and verifies it against the agent's bundle.
    fn handshake_with_itself(source: &X509Source) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client = source
            .rustls_client_config(provider.clone(), [trust_domain()])
            .expect("a client configuration");
        let server = source
            .rustls_server_config(provider, [trust_domain()])
            .expect("a server configuration");
        let (servers, clients) = handshake(client, server).expect("a handshake");
        let leaf = source.svid().expect("an SVID").leaf().as_ref().to_vec();
        assert_eq!(servers, leaf, "the client was shown the SVID's leaf");
        assert_eq!(clients, leaf, "the server was shown the SVID's leaf");
    }

    #[tokio::test]
    #[ignore = "needs a SPIRE agent: SPIFFE_ENDPOINT_SOCKET and SPIFFE_TRUST_DOMAIN"]
    async fn an_x509_svid_arrives_with_the_bundle_that_verifies_it() {
        let World { client, .. } = world_for(
            "an_x509_svid_arrives_with_the_bundle_that_verifies_it",
            STEADY,
        )
        .await;
        let own = trust_domain();

        let context = within(ANSWER, "the X.509 context", client.fetch_x509_context())
            .await
            .expect("the agent's X.509 context");
        assert_eq!(context.svid().spiffe_id(), &identity(STEADY));
        assert_eq!(context.svid().trust_domain(), &own);
        assert!(context.svid().not_before() < context.svid().not_after());
        let with_svid = context
            .bundles()
            .get(&own)
            .expect("the bundle of the workload's trust domain comes with its SVID");
        assert!(!with_svid.authorities().is_empty());

        // The bundles asked for on their own are the same authorities.
        let bundles = within(ANSWER, "the X.509 bundles", client.fetch_x509_bundles())
            .await
            .expect("the agent's X.509 bundles");
        let alone = bundles.get(&own).expect("the trust domain's bundle");
        assert_eq!(alone.authorities(), with_svid.authorities());

        // The SVID verifies against the bundle in a real handshake.
        let source = client.watch_x509().expect("a source");
        within(ANSWER, "the source's first SVID", source.ready()).await;
        handshake_with_itself(&source);
    }

    #[tokio::test]
    #[ignore = "needs a SPIRE agent: SPIFFE_ENDPOINT_SOCKET and SPIFFE_TRUST_DOMAIN"]
    async fn a_jwt_svid_is_validated_by_the_agent_and_against_its_bundle() {
        let World { client, clock, .. } = world_for(
            "a_jwt_svid_is_validated_by_the_agent_and_against_its_bundle",
            STEADY,
        )
        .await;
        let own = trust_domain();

        let svid = within(ANSWER, "the JWT SVID", client.fetch_jwt_svid([AUDIENCE]))
            .await
            .expect("a JWT SVID");
        assert_eq!(svid.spiffe_id(), &identity(STEADY));
        assert_eq!(svid.audience(), [AUDIENCE]);
        assert!(svid.issued_at() < svid.expires_at());

        // The agent validates it for its audience and for no other.
        let validated = within(
            ANSWER,
            "the validation",
            client.validate_jwt_svid(AUDIENCE, svid.token()),
        )
        .await
        .expect("the agent validates its own token");
        assert_eq!(validated.spiffe_id(), &identity(STEADY));
        assert_eq!(validated.trust_domain(), &own);
        let refused = within(
            ANSWER,
            "the refusal",
            client.validate_jwt_svid(ANOTHER_AUDIENCE, svid.token()),
        )
        .await
        .expect_err("a token for another audience");
        assert!(
            matches!(refused, SpireError::Status { .. }),
            "the agent refuses with a status: {refused}"
        );

        // The same token verifies against the keys of the agent's JWT
        // bundle, without the agent.
        let bundles = client.watch_jwt_bundles().expect("a bundle source");
        within(ANSWER, "the JWT bundles", bundles.ready()).await;
        let verifier = JwtVerifier::new(bundles.key_set(&own))
            .with_clock(Arc::new(clock.clone()))
            .allow_any_issuer()
            .with_audience(AUDIENCE);
        let claims = verifier
            .verify::<serde_json::Value>(svid.token())
            .await
            .expect("the token verifies against the bundle");
        assert_eq!(
            claims.sub.as_deref(),
            Some(identity(STEADY).to_string().as_str())
        );
        let elsewhere = JwtVerifier::new(bundles.key_set(&own))
            .with_clock(Arc::new(clock.clone()))
            .allow_any_issuer()
            .with_audience(ANOTHER_AUDIENCE);
        assert!(
            elsewhere
                .verify::<serde_json::Value>(svid.token())
                .await
                .is_err(),
            "a token for another audience is refused"
        );
    }

    #[tokio::test]
    #[ignore = "needs a SPIRE agent: SPIFFE_ENDPOINT_SOCKET and SPIFFE_TRUST_DOMAIN"]
    async fn a_rotation_of_the_x509_svid_is_followed() {
        let World { client, seen, .. } =
            world_for("a_rotation_of_the_x509_svid_is_followed", STEADY).await;
        let source = client.watch_x509().expect("a source");
        within(ANSWER, "the source's first SVID", source.ready()).await;
        let first = source.svid().expect("the first SVID");

        let next = within(ROTATION, "the rotation", async {
            let mut generation = source.generation();
            loop {
                generation = source.updated(generation).await;
                let now = source.svid().expect("an SVID after a change");
                if now.leaf() != first.leaf() {
                    return now;
                }
            }
        })
        .await;

        assert_eq!(next.spiffe_id(), first.spiffe_id());
        assert!(
            next.not_after() > first.not_after(),
            "the SVID that replaced the first one lasts longer"
        );
        // The source was never without an SVID on the way, and the new one
        // verifies against the bundle as the first did.
        assert!(seen.withdrawn().is_empty());
        handshake_with_itself(&source);
    }

    #[tokio::test]
    #[ignore = "needs a SPIRE agent: SPIFFE_ENDPOINT_SOCKET and SPIFFE_TRUST_DOMAIN"]
    async fn a_deleted_entry_is_withdrawn_while_another_identity_remains() {
        let World { client, seen, .. } = world_for(
            "a_deleted_entry_is_withdrawn_while_another_identity_remains",
            WITHDRAWN,
        )
        .await;
        let source = client.watch_x509().expect("a source");
        within(ANSWER, "the source's first SVID", source.ready()).await;
        let served = source.svid().expect("the SVID before its entry is deleted");
        assert_eq!(served.spiffe_id(), &identity(WITHDRAWN));

        ask_for_deletion(&identity(WITHDRAWN));
        let refusal = refusal(&source).await;

        // The agent goes on answering with the process's other identity:
        // an answer without the selected one is what withdraws it.
        assert_eq!(
            refusal,
            SpireError::Withdrawn(WorkloadCredentialKind::X509Svid)
        );
        assert_eq!(seen.withdrawn(), [WorkloadCredentialKind::X509Svid]);
        assert!(
            seen.failures()
                .iter()
                .any(|error| matches!(error, SpireError::NotIssued(_))),
            "the answer no longer held the identity: {:?}",
            seen.failures()
        );
    }

    #[tokio::test]
    #[ignore = "needs a SPIRE agent: SPIFFE_ENDPOINT_SOCKET and SPIFFE_TRUST_DOMAIN; run by itself, last"]
    async fn the_last_entry_deleted_is_refused_by_the_agent_and_withdrawn() {
        let World { client, seen, .. } = world_for(
            "the_last_entry_deleted_is_refused_by_the_agent_and_withdrawn",
            STEADY,
        )
        .await;
        let source = client.watch_x509().expect("a source");
        within(ANSWER, "the source's first SVID", source.ready()).await;
        let served = source.svid().expect("the SVID before its entry is deleted");
        assert_eq!(served.spiffe_id(), &identity(STEADY));

        ask_for_deletion(&identity(STEADY));
        let refusal = refusal(&source).await;

        // With no entry left the agent refuses the workload by status, and
        // the client, which has no withdrawal grace, stops serving at once.
        assert_eq!(
            refusal,
            SpireError::Withdrawn(WorkloadCredentialKind::X509Svid)
        );
        assert_eq!(seen.withdrawn(), [WorkloadCredentialKind::X509Svid]);
        let denied = |error: &SpireError| {
            matches!(
                error,
                SpireError::Status {
                    code: GrpcCode::PermissionDenied,
                    ..
                }
            )
        };
        assert!(
            seen.failures().iter().any(denied),
            "the agent answered PERMISSION_DENIED: {:?}",
            seen.failures()
        );
        let token = within(ANSWER, "the JWT SVID", client.fetch_jwt_svid([AUDIENCE]))
            .await
            .expect_err("no JWT SVID for a workload with no entry");
        assert!(denied(&token), "the agent refuses the token too: {token}");
    }
}
