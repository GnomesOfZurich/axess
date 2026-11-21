//! One call each, against the fake agent: what the client asks, what it
//! returns, and what it refuses.

use std::time::Duration;

use serde_json::json;

use super::*;
use crate::testing::spire_agent::{FakeJwtSvid, FakeSpireAgent, WorkloadApiMethod};
use crate::workload::spire::GrpcCode;
use crate::workload::spire::test_support::{
    Day, REFERENCE, TestCa, World, jwt_svid, served, within,
};
use crate::workload::spire::wire::put_bytes;

const ID: &str = "spiffe://example.org/billing/acme";

fn trust_domain(name: &str) -> TrustDomain {
    TrustDomain::new(name).expect("a trust domain")
}

const OTHER_ID: &str = "spiffe://example.org/reports/acme";

fn jwt(spiffe_id: &str, token: &str) -> FakeJwtSvid {
    hinted(spiffe_id, token, "")
}

fn hinted(spiffe_id: &str, token: &str, hint: &str) -> FakeJwtSvid {
    FakeJwtSvid {
        spiffe_id: spiffe_id.to_owned(),
        token: token.to_owned(),
        hint: hint.to_owned(),
    }
}

fn id(text: &str) -> WorkloadId {
    WorkloadId::parse(text).expect("a SPIFFE ID")
}

/// What a server on the world's socket was sent by each call, in order:
/// the request path and the value of the `workload.spiffe.io` metadata.
/// Every call is answered UNIMPLEMENTED.
fn requests_as_sent(world: &World) -> std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> {
    let listener = tokio::net::UnixListener::bind(world.socket()).expect("the socket");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((io, _)) = listener.accept().await {
            let Ok(mut connection) = h2::server::handshake(io).await else {
                continue;
            };
            let record = record.clone();
            tokio::spawn(async move {
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let metadata = request
                        .headers()
                        .get("workload.spiffe.io")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("absent")
                        .to_owned();
                    record
                        .lock()
                        .expect("the record's lock")
                        .push((request.uri().path().to_owned(), metadata));
                    // The request message is read to its end before the
                    // answer, as a gRPC server does.
                    let mut body = request.into_body();
                    while let Some(Ok(chunk)) = body.data().await {
                        drop(body.flow_control().release_capacity(chunk.len()));
                    }
                    let response = axum::http::Response::builder()
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "12")
                        .body(())
                        .expect("a response");
                    // A client that has gone away makes this fail; the
                    // request is recorded either way.
                    drop(respond.send_response(response, true));
                }
            });
        }
    });
    seen
}

#[tokio::test(start_paused = true)]
async fn the_client_sends_the_names_the_workload_api_defines() {
    // The method paths of `workloadapi.proto` (SPIFFE Workload API standard,
    // sections 3, 5.2 and 6.2) and the metadata key of the Workload Endpoint
    // standard, section 3, written out here and compared with what arrives
    // on the wire.
    let world = World::new();
    let seen = requests_as_sent(&world);
    let client = world.client("example.org");

    let unimplemented = |outcome: Option<SpireError>| {
        assert!(
            matches!(
                outcome,
                Some(SpireError::Status {
                    code: GrpcCode::Unimplemented,
                    ..
                })
            ),
            "{outcome:?}"
        );
    };
    unimplemented(within(client.fetch_x509_context()).await.err());
    unimplemented(within(client.fetch_x509_bundles()).await.err());
    unimplemented(within(client.fetch_jwt_svid(["api"])).await.err());
    unimplemented(within(client.fetch_jwt_bundles()).await.err());
    unimplemented(within(client.validate_jwt_svid("api", "h.p.s")).await.err());

    let seen = seen.lock().expect("the record's lock").clone();
    let sent: Vec<(&str, &str)> = seen
        .iter()
        .map(|(path, metadata)| (path.as_str(), metadata.as_str()))
        .collect();
    assert_eq!(
        sent,
        [
            ("/SpiffeWorkloadAPI/FetchX509SVID", "true"),
            ("/SpiffeWorkloadAPI/FetchX509Bundles", "true"),
            ("/SpiffeWorkloadAPI/FetchJWTSVID", "true"),
            ("/SpiffeWorkloadAPI/FetchJWTBundles", "true"),
            ("/SpiffeWorkloadAPI/ValidateJWTSVID", "true"),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn an_agent_on_loopback_tcp_is_reached() {
    let world = World::new();
    let agent = FakeSpireAgent::start_tcp().expect("a loopback port");
    agent.set_jwt_bundles(&[("example.org", br#"{"keys":[]}"#.as_slice())]);
    let address = agent
        .endpoint()
        .tcp_address()
        .expect("the agent listens on TCP");
    assert!(address.ip().is_loopback());

    // By the default constructor, which admits a loopback address.
    let endpoint = Endpoint::tcp_loopback(address).expect("a loopback address");
    assert_eq!(endpoint, agent.endpoint());
    let client = world.builder_at(endpoint, "example.org").build();
    let bundles = within(client.fetch_jwt_bundles())
        .await
        .expect("JWT bundles");
    assert_eq!(bundles.len(), 1);

    // By the named opt-in, which admits any address.
    let opted_in = world
        .builder_at(Endpoint::tcp_clear_text(address), "example.org")
        .build();
    assert!(within(opted_in.fetch_jwt_bundles()).await.is_ok());

    // And kept current over it.
    let source = client.watch_jwt_bundles().expect("inside a runtime");
    within(source.ready()).await;
    agent.set_jwt_bundles(&[(
        "example.org",
        br#"{"keys":[{"kty":"EC","kid":"next"}]}"#.as_slice(),
    )]);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(agent.calls(WorkloadApiMethod::FetchJwtBundles), 3);
}

#[tokio::test(start_paused = true)]
async fn the_x509_context_is_the_svid_and_every_bundle() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    agent.set_x509_svids(
        &[served(&minted, &ca.bundle_der())],
        &[("spiffe://partner.test", partner.bundle_der().as_slice())],
    );
    let client = world.client("example.org");

    let context = within(client.fetch_x509_context())
        .await
        .expect("the agent's SVID");
    assert_eq!(context.svid().spiffe_id().as_str(), ID);
    assert_eq!(context.svid().leaf().as_ref(), minted.cert_der.as_slice());
    assert_eq!(context.bundles().len(), 2);
    let federated = context
        .bundles()
        .get(&trust_domain("partner.test"))
        .expect("the federated bundle");
    assert_eq!(
        federated.authorities()[0].as_ref(),
        partner.bundle_der().as_slice()
    );
    // The fake refuses a call without the security metadata, as an agent
    // does: an answer is proof the client sent it.
    assert_eq!(agent.calls(WorkloadApiMethod::FetchX509Svid), 1);

    let svid = within(client.fetch_x509_svid()).await.expect("the SVID");
    assert_eq!(svid.spiffe_id().as_str(), ID);
    assert_eq!(client.trust_domain().as_str(), "example.org");
    assert_eq!(client.endpoint(), &agent.endpoint());
}

#[tokio::test(start_paused = true)]
async fn a_call_without_the_security_metadata_would_be_refused() {
    // The control for the test above: the fake does check the metadata. A
    // request written by hand, with everything but that header, is answered
    // INVALID_ARGUMENT (3).
    let world = World::new();
    let agent = world.agent();
    agent.set_jwt_bundles(&[("example.org", br#"{"keys":[]}"#.as_slice())]);

    let io = tokio::net::UnixStream::connect(world.socket())
        .await
        .expect("the agent's socket");
    let (sender, connection) = within(h2::client::handshake(io))
        .await
        .expect("an HTTP/2 connection");
    let driver = tokio::spawn(connection);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("http://localhost/SpiffeWorkloadAPI/FetchJWTBundles")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("a request");
    let mut sender = within(sender.ready()).await.expect("a ready connection");
    let (response, mut body) = sender.send_request(request, false).expect("a stream");
    body.send_data(crate::workload::spire::wire::frame(&[]), true)
        .expect("the request message");
    let response = within(response).await.expect("an answer");
    assert_eq!(
        response
            .headers()
            .get("grpc-status")
            .and_then(|status| status.to_str().ok()),
        Some("3")
    );
    driver.abort();

    // The client's own call, on the same agent, is answered.
    assert!(
        within(world.client("example.org").fetch_jwt_bundles())
            .await
            .is_ok()
    );
    assert_eq!(agent.calls(WorkloadApiMethod::FetchJwtBundles), 2);
}

#[tokio::test(start_paused = true)]
async fn an_svid_for_another_trust_domain_is_refused() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("other authority");
    let minted = ca.svid("spiffe://other.test/billing/acme", Day(1), Day(2));
    agent.set_x509_svids(&[served(&minted, &ca.bundle_der())], &[]);

    let outcome = within(world.client("example.org").fetch_x509_svid()).await;
    assert_eq!(
        outcome.err(),
        Some(SpireError::TrustDomainMismatch {
            expected: trust_domain("example.org"),
            presented: "other.test".to_owned(),
        })
    );
}

#[tokio::test(start_paused = true)]
async fn an_agent_with_no_identity_for_the_workload_says_so() {
    let world = World::new();
    let agent = world.agent();
    let outcome = within(world.client("example.org").fetch_x509_svid()).await;
    assert_eq!(
        outcome.err(),
        Some(SpireError::Status {
            code: GrpcCode::PermissionDenied,
            message: "no identity issued".to_owned(),
        })
    );
    assert_eq!(agent.calls(WorkloadApiMethod::FetchX509Svid), 1);
}

#[tokio::test(start_paused = true)]
async fn an_agent_that_is_not_there_is_a_connection_error() {
    let world = World::new();
    let outcome = within(world.client("example.org").fetch_x509_bundles()).await;
    assert!(
        matches!(outcome, Err(SpireError::Connect(_))),
        "{outcome:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn an_agent_that_never_answers_is_a_timeout() {
    let world = World::new();
    // A listener that accepts and says nothing.
    let listener = tokio::net::UnixListener::bind(world.socket()).expect("the socket");
    let client = world
        .builder("example.org")
        .with_call_timeout(Duration::from_secs(3))
        .build();
    let outcome = within(client.fetch_jwt_bundles()).await;
    assert_eq!(
        outcome.err(),
        Some(SpireError::Timeout(Duration::from_secs(3)))
    );
    drop(listener);
}

#[tokio::test(start_paused = true)]
async fn bundles_are_fetched_by_trust_domain() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    agent.set_x509_bundles(&[
        ("example.org", ca.bundle_der().as_slice()),
        ("spiffe://partner.test", partner.bundle_der().as_slice()),
    ]);
    agent.set_jwt_bundles(&[
        (
            "example.org",
            br#"{"keys":[{"kty":"EC","kid":"own"}]}"#.as_slice(),
        ),
        (
            "partner.test",
            br#"{"keys":[{"kty":"EC","kid":"theirs","use":"jwt-svid"}]}"#.as_slice(),
        ),
    ]);
    let client = world.client("example.org");

    let x509 = within(client.fetch_x509_bundles())
        .await
        .expect("X.509 bundles");
    assert_eq!(x509.len(), 2);
    assert_eq!(
        x509.get(&trust_domain("partner.test"))
            .expect("the partner's")
            .authorities()[0]
            .as_ref(),
        partner.bundle_der().as_slice()
    );

    let jwt = within(client.fetch_jwt_bundles())
        .await
        .expect("JWT bundles");
    assert_eq!(jwt.len(), 2);
    let theirs = jwt
        .get(&trust_domain("partner.test"))
        .expect("the partner's");
    assert_eq!(theirs.key_ids(), ["theirs"]);
    assert_eq!(
        theirs.jwks(),
        &json!({ "keys": [{ "kty": "EC", "kid": "theirs" }] })
    );
}

#[tokio::test(start_paused = true)]
async fn a_jwt_svid_is_fetched_for_the_audience_named() {
    let world = World::new();
    let agent = world.agent();
    let token = jwt_svid(ID, &["api", "audit"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &token)]);
    let client = world.client("example.org");

    let svid = within(client.fetch_jwt_svid(["api", "audit"]))
        .await
        .expect("a JWT SVID");
    assert_eq!(svid.token(), token);
    assert_eq!(svid.spiffe_id().as_str(), ID);
    assert_eq!(svid.audience(), ["api", "audit"]);
    assert_eq!(agent.jwt_audiences(), [["api", "audit"]]);
}

#[tokio::test(start_paused = true)]
async fn the_selector_decides_whose_jwt_svid_is_fetched() {
    let world = World::new();
    let agent = world.agent();
    let main = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    let reports = jwt_svid(OTHER_ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[
        hinted(ID, &main, "main"),
        hinted(OTHER_ID, &reports, "reports"),
    ]);
    let selecting = |selector: SvidSelector| {
        world
            .builder("example.org")
            .with_svid_selector(selector)
            .build()
    };

    // By SPIFFE ID: the request names the identity.
    let by_id = selecting(SvidSelector::SpiffeId(id(OTHER_ID)));
    let svid = within(by_id.fetch_jwt_svid(["api"]))
        .await
        .expect("the named identity's SVID");
    assert_eq!(svid.token(), reports);
    assert_eq!(svid.spiffe_id().as_str(), OTHER_ID);
    assert_eq!(agent.jwt_subjects(), [OTHER_ID]);

    // By hint: every identity is asked for, and the hinted one is taken.
    let by_hint = selecting(SvidSelector::Hint("reports".to_owned()));
    let svid = within(by_hint.fetch_jwt_svid(["api"]))
        .await
        .expect("the hinted identity's SVID");
    assert_eq!(svid.token(), reports);
    assert_eq!(svid.hint(), "reports");

    // By default: the agent's first.
    let svid = within(world.client("example.org").fetch_jwt_svid(["api"]))
        .await
        .expect("the first identity's SVID");
    assert_eq!(svid.token(), main);
    assert_eq!(agent.jwt_subjects(), [OTHER_ID, "", ""]);
}

#[tokio::test(start_paused = true)]
async fn a_jwt_svid_of_an_identity_the_selector_does_not_name_is_never_returned() {
    let world = World::new();
    let agent = world.agent();
    let main = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[hinted(ID, &main, "main")]);
    let selecting = |selector: SvidSelector| {
        world
            .builder("example.org")
            .with_svid_selector(selector)
            .build()
    };
    let by_id = selecting(SvidSelector::SpiffeId(id(OTHER_ID)));
    let by_hint = selecting(SvidSelector::Hint("reports".to_owned()));

    // The agent has no such identity, and says so to the request that
    // names it.
    let unissued = within(by_id.fetch_jwt_svid(["api"])).await;
    assert_eq!(
        unissued.err(),
        Some(SpireError::Status {
            code: GrpcCode::PermissionDenied,
            message: "no identity issued".to_owned(),
        })
    );
    // No SVID of the answer carries the hint.
    let unhinted = within(by_hint.fetch_jwt_svid(["api"])).await;
    assert_eq!(
        unhinted.err(),
        Some(SpireError::NotIssued("the hint reports".to_owned()))
    );

    // An agent that ignores the name and answers with another identity's
    // token: the client checks the answer itself.
    let mut entry = Vec::new();
    put_bytes(&mut entry, 1, ID.as_bytes());
    put_bytes(&mut entry, 2, main.as_bytes());
    let mut answer = Vec::new();
    put_bytes(&mut answer, 1, &entry);
    agent.answer_with_message(WorkloadApiMethod::FetchJwtSvid, &answer);
    let substituted = within(by_id.fetch_jwt_svid(["api"])).await;
    assert_eq!(
        substituted.err(),
        Some(SpireError::NotIssued(OTHER_ID.to_owned()))
    );
}

#[tokio::test(start_paused = true)]
async fn a_jwt_svid_without_an_audience_is_not_asked_for() {
    let world = World::new();
    let agent = world.agent();
    let client = world.client("example.org");
    let none = within(client.fetch_jwt_svid(Vec::<String>::new())).await;
    assert!(matches!(none, Err(SpireError::Request(_))), "{none:?}");
    let empty = within(client.fetch_jwt_svid([""])).await;
    assert!(matches!(empty, Err(SpireError::Request(_))), "{empty:?}");
    assert_eq!(agent.calls(WorkloadApiMethod::FetchJwtSvid), 0);
}

#[tokio::test(start_paused = true)]
async fn the_agent_validates_a_jwt_svid() {
    let world = World::new();
    let agent = world.agent();
    let client = world.client("example.org");

    // An agent that does not offer the method.
    let unoffered = within(client.validate_jwt_svid("api", "h.p.s")).await;
    assert!(
        matches!(
            unoffered,
            Err(SpireError::Status {
                code: GrpcCode::Unimplemented,
                ..
            })
        ),
        "{unoffered:?}"
    );

    let claims = json!({ "sub": ID, "aud": ["api"], "exp": REFERENCE + 300, "tid": "t" });
    agent.accept_validations(ID, claims.as_object().expect("an object"));
    let validated = within(client.validate_jwt_svid("api", "h.p.s"))
        .await
        .expect("a validated token");
    assert_eq!(validated.spiffe_id().as_str(), ID);
    assert_eq!(validated.trust_domain().as_str(), "example.org");
    assert_eq!(
        serde_json::Value::Object(validated.claims().clone()),
        claims
    );
    assert_eq!(
        agent.validations().last(),
        Some(&("api".to_owned(), "h.p.s".to_owned()))
    );

    agent.refuse(WorkloadApiMethod::ValidateJwtSvid, 3, "token has expired");
    let refused = within(client.validate_jwt_svid("api", "h.p.s")).await;
    assert_eq!(
        refused.err(),
        Some(SpireError::Status {
            code: GrpcCode::InvalidArgument,
            message: "token has expired".to_owned(),
        })
    );

    let no_audience = within(client.validate_jwt_svid("", "h.p.s")).await;
    assert!(
        matches!(no_audience, Err(SpireError::Request(_))),
        "{no_audience:?}"
    );
    // Both fields of the request are mandatory: a call with no token is not
    // made.
    let calls = agent.calls(WorkloadApiMethod::ValidateJwtSvid);
    let no_token = within(client.validate_jwt_svid("api", "")).await;
    assert!(
        matches!(no_token, Err(SpireError::Request(_))),
        "{no_token:?}"
    );
    assert_eq!(agent.calls(WorkloadApiMethod::ValidateJwtSvid), calls);

    // And both fields of the answer: one with no claims is discarded.
    agent.accept_validations(ID, &serde_json::Map::new());
    let no_claims = within(client.validate_jwt_svid("api", "h.p.s")).await;
    assert_eq!(
        no_claims.err(),
        Some(SpireError::Refused(
            "the validation answer holds no claims".to_owned()
        ))
    );
}

#[tokio::test(start_paused = true)]
async fn a_response_that_does_not_decode_is_refused_with_bounded_escaped_text() {
    let world = World::new();
    let agent = world.agent();
    let client = world.client("example.org");
    let bounded = |error: &SpireError| {
        let text = error.to_string();
        assert!(
            !text.contains('\n') && !text.contains('\r') && !text.contains('\u{1b}'),
            "{text:?}"
        );
        assert!(text.len() < 400, "the text is {} bytes", text.len());
        text
    };

    // Bytes that are no protobuf message at all.
    agent.answer_with_message(WorkloadApiMethod::FetchX509Svid, &[0xFF; 64]);
    let garbage = within(client.fetch_x509_svid()).await.expect_err("garbage");
    assert!(matches!(garbage, SpireError::Malformed(_)), "{garbage:?}");
    bounded(&garbage);

    // A message whose SVID names itself with a forged log line, at length.
    let mut svid = Vec::new();
    let hostile = format!(
        "spiffe://example.org/a\n\u{1b}[2JFORGED {}",
        "x".repeat(100_000)
    );
    put_bytes(&mut svid, 1, hostile.as_bytes());
    let mut message = Vec::new();
    put_bytes(&mut message, 1, &svid);
    agent.answer_with_message(WorkloadApiMethod::FetchX509Svid, &message);
    let forged = within(client.fetch_x509_svid())
        .await
        .expect_err("a forged id");
    assert!(matches!(forged, SpireError::Refused(_)), "{forged:?}");
    let text = bounded(&forged);
    assert!(text.contains("\\n") && text.contains("\\u{1b}"), "{text:?}");

    // A status message with the same.
    agent.refuse(
        WorkloadApiMethod::FetchX509Svid,
        13,
        &format!("boom\r\n\u{1b}[31mFORGED {}", "y".repeat(5_000)),
    );
    let status = within(client.fetch_x509_svid())
        .await
        .expect_err("a status");
    assert!(
        matches!(
            status,
            SpireError::Status {
                code: GrpcCode::Internal,
                ..
            }
        ),
        "{status:?}"
    );
    let text = bounded(&status);
    assert!(text.contains("boom\\r\\n\\u{1b}[31mFORGED"), "{text:?}");
}

#[tokio::test(start_paused = true)]
async fn a_broken_frame_is_refused() {
    let world = World::new();
    let agent = world.agent();
    let client = world.client("example.org");

    // A frame marked compressed, which the client never asked for.
    agent.answer_with_body(WorkloadApiMethod::FetchJwtBundles, &[1, 0, 0, 0, 1, 0]);
    let compressed = within(client.fetch_jwt_bundles())
        .await
        .expect_err("compressed");
    assert!(
        matches!(&compressed, SpireError::Malformed(text) if text.contains("compressed")),
        "{compressed:?}"
    );

    // A frame that claims four gigabytes: refused from its prefix.
    agent.answer_with_body(
        WorkloadApiMethod::FetchJwtBundles,
        &[0, 0xFF, 0xFF, 0xFF, 0xFF],
    );
    let huge = within(client.fetch_jwt_bundles())
        .await
        .expect_err("too large");
    assert!(
        matches!(&huge, SpireError::Malformed(text) if text.contains("over the limit")),
        "{huge:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_message_over_the_configured_limit_is_refused() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    agent.set_x509_bundles(&[("example.org", ca.bundle_der().as_slice())]);
    let client = world
        .builder("example.org")
        .with_max_message_bytes(64)
        .build();
    let outcome = within(client.fetch_x509_bundles()).await;
    assert!(
        matches!(&outcome, Err(SpireError::Malformed(text)) if text.contains("over the limit of 64")),
        "{outcome:?}"
    );
}

#[test]
fn a_watcher_started_outside_a_runtime_is_refused() {
    let client = SpireClient::builder(
        Endpoint::unix("/nonexistent/agent.sock").expect("an absolute path"),
        trust_domain("example.org"),
    )
    .with_clock(Arc::new(crate::testing::MockClock::at_reference()))
    .build();
    let refused = Some(SpireError::NoRuntime);
    assert_eq!(client.watch_x509().err(), refused);
    assert_eq!(client.watch_x509_bundles().err(), refused);
    assert_eq!(client.watch_jwt_bundles().err(), refused);
    assert_eq!(client.watch_jwt_svid(["api"]).err(), refused);
}
