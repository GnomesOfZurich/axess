//! The X.509 source: one stream, the safety net beside it, and what is
//! kept when an answer is refused.

use axess_clock::Clock;
use axess_clock::Timestamp;

use super::{HOUR, ID, MINUTE, NEVER_STALE, OTHER_ID, idle, trust_domain};
use crate::metrics::WorkloadCredentialKind;
use crate::testing::spire_agent::{FakeSpireAgent, FakeX509Svid, WorkloadApiMethod};
use crate::workload::spire::test_support::{
    Day, Minted, REFERENCE, TestCa, World, served, settled, within,
};
use crate::workload::spire::wire::put_bytes;
use crate::workload::spire::{SpireError, SvidSelector, X509Source};

const METHOD: WorkloadApiMethod = WorkloadApiMethod::FetchX509Svid;

/// The leaf the source serves now.
fn leaf(source: &X509Source) -> Vec<u8> {
    source
        .svid()
        .expect("a current SVID")
        .leaf()
        .as_ref()
        .to_vec()
}

fn serve(agent: &FakeSpireAgent, ca: &TestCa, minted: &Minted) {
    agent.set_x509_svids(&[served(minted, &ca.bundle_der())], &[]);
}

/// A source on the world's agent whose bundles never go stale.
fn watch(world: &World) -> X509Source {
    world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .build()
        .watch_x509()
        .expect("inside a runtime")
}

#[tokio::test(start_paused = true)]
async fn the_first_answer_fills_the_source() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);

    let source = world
        .client("example.org")
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;

    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(source.generation(), 1);
    assert!(source.is_watching());
    let context = source.context().expect("the context");
    assert_eq!(context.svid().spiffe_id().as_str(), ID);
    assert!(
        source
            .bundles()
            .expect("the bundles")
            .get(&trust_domain("example.org"))
            .is_some()
    );
    assert_eq!(source.confirmed_at(), Some(world.clock.now()));
    assert_eq!(
        world.metrics.count("workload_credential_rotated:x509_svid"),
        1
    );
    assert_eq!(world.recorder.lines(), ["rotated:x509_svid"]);
}

#[tokio::test(start_paused = true)]
async fn a_read_before_the_first_answer_says_there_is_nothing_yet() {
    let world = World::new();
    let source = world
        .client("example.org")
        .watch_x509()
        .expect("inside a runtime");
    let nothing = Some(SpireError::NotYetFetched(WorkloadCredentialKind::X509Svid));
    assert_eq!(source.svid().err(), nothing);
    assert_eq!(source.bundles().err(), nothing);
    assert_eq!(source.confirmed_at(), None);
    assert_eq!(source.generation(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_rotation_the_agent_pushes_replaces_the_svid() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    serve(&agent, &ca, &second);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
    // One stream carried both answers.
    assert_eq!(agent.calls(METHOD), 1);
    assert_eq!(
        world.metrics.count("workload_credential_rotated:x509_svid"),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn an_agent_that_rotates_at_half_the_lifetime_is_never_asked_twice() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    // Each SVID is valid for two days and replaced by the agent after one,
    // at half its lifetime. The safety net of each is at a day and a half.
    let first = ca.svid(ID, Day(1), Day(3));
    let second = ca.svid(ID, Day(2), Day(4));
    let third = ca.svid(ID, Day(3), Day(5));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    for (rotation, next) in [(1, &second), (2, &third)] {
        world.clock.advance_secs(24 * HOUR);
        idle(120).await;
        assert_eq!(
            agent.calls(METHOD),
            1,
            "half the lifetime is not the safety net's point"
        );
        serve(&agent, &ca, next);
        assert_eq!(within(source.updated(rotation)).await, rotation + 1);
    }
    world.clock.advance_secs(12 * HOUR);
    idle(120).await;
    assert_eq!(leaf(&source), third.cert_der);
    assert_eq!(agent.calls(METHOD), 1, "one stream, from start to end");
    assert_eq!(agent.open_calls(METHOD), 1);
    assert_eq!(world.recorder.count("failed"), 0);
}

#[tokio::test(start_paused = true)]
async fn the_svid_is_replaced_before_its_expiry_when_the_stream_has_stalled() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    // Valid for a day: the safety net is at 18:00.
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    // The agent rotates, and the open stream is never told.
    agent.hold_updates(true);
    serve(&agent, &ca, &second);
    world.clock.advance_secs(17 * HOUR);
    idle(120).await;
    assert_eq!(leaf(&source), first.cert_der, "not due before 18:00");
    assert_eq!(agent.calls(METHOD), 1);

    // Past 18:00 the watcher stops waiting and asks on a second request.
    // That one brings what the open stream never delivered, and takes over.
    world.clock.advance_secs(2 * HOUR);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
    assert_eq!(agent.calls(METHOD), 2);
    settled(|| agent.open_calls(METHOD) == 1).await;
    let first_expiry = Timestamp::from_unix_seconds(REFERENCE + 24 * HOUR).expect("in range");
    assert!(world.clock.now() < first_expiry);
    assert_eq!(world.recorder.count("failed"), 0);
}

#[tokio::test(start_paused = true)]
async fn an_agent_with_nothing_newer_is_asked_beside_the_open_stream_at_a_slowing_pace() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    world.clock.advance_secs(19 * HOUR);
    idle(300).await;
    // Five minutes past the safety net's point: asked again, a longer wait
    // each time (thirty seconds at most), and never in a loop.
    let calls = agent.calls(METHOD);
    assert!((8..=30).contains(&calls), "{calls} calls in five minutes");
    assert_eq!(source.generation(), 1, "the same SVID is no rotation");
    assert_eq!(world.recorder.count("failed"), 0, "and no failure");
    assert_eq!(leaf(&source), first.cert_der);
    // Every ask was a request of its own and is closed; the stream that was
    // open before them is open still.
    settled(|| agent.open_calls(METHOD) == 1).await;

    serve(&agent, &ca, &second);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
}

#[tokio::test(start_paused = true)]
async fn an_ask_that_fails_leaves_the_open_stream_open() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    // New calls are refused; the stream that is open is told nothing.
    agent.hold_updates(true);
    agent.refuse(METHOD, 14, "agent is restarting");
    world.clock.advance_secs(19 * HOUR);
    world
        .recorder
        .at_least(2, "failed:x509_svid:serving=true")
        .await;
    assert_eq!(leaf(&source), first.cert_der);
    // The asks failed beside the stream, which was not closed for them.
    settled(|| agent.open_calls(METHOD) == 1).await;
    assert!(agent.calls(METHOD) >= 3);
}

#[tokio::test(start_paused = true)]
async fn a_failed_refresh_keeps_serving_the_valid_svid_and_is_reported() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    agent.refuse(METHOD, 14, "agent is restarting");
    world
        .recorder
        .at_least(3, "failed:x509_svid:serving=true")
        .await;
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(source.generation(), 1);
    assert!(
        world
            .metrics
            .count("workload_credential_refresh_failed:x509_svid")
            >= 3
    );
    assert!(
        world
            .recorder
            .errors()
            .iter()
            .all(|error| error == "workload API answered UNAVAILABLE: agent is restarting"),
        "{:?}",
        world.recorder.errors()
    );

    serve(&agent, &ca, &second);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
}

#[tokio::test(start_paused = true)]
async fn the_failures_in_a_row_do_not_count_the_asks_that_brought_nothing_newer() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    // A run of asks that each bring the SVID the source holds.
    world.clock.advance_secs(19 * HOUR);
    idle(120).await;
    assert!(agent.calls(METHOD) >= 6);
    assert_eq!(world.recorder.count("failed"), 0);

    // Then the agent goes away. The first failure is the first.
    agent.refuse(METHOD, 14, "agent is restarting");
    world.recorder.at_least(3, "failed:x509_svid").await;
    let failures: Vec<String> = world
        .recorder
        .lines()
        .into_iter()
        .filter(|line| line.starts_with("failed"))
        .take(3)
        .collect();
    assert_eq!(
        failures,
        [
            "failed:x509_svid:serving=true:run=1",
            "failed:x509_svid:serving=true:run=2",
            "failed:x509_svid:serving=true:run=3",
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn an_expired_svid_is_never_served() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;
    agent.refuse(METHOD, 14, "agent is restarting");
    world.recorder.at_least(1, "failed:x509_svid").await;

    // One second before the expiry it is served.
    world.clock.advance_secs(24 * HOUR - 1);
    assert_eq!(leaf(&source), first.cert_der);

    // At the expiry the read itself refuses, before the watcher has looked.
    world.clock.advance_secs(1);
    let expired = Some(SpireError::Expired(WorkloadCredentialKind::X509Svid));
    assert_eq!(source.svid().err(), expired);
    assert_eq!(source.context().err(), expired);
    assert_eq!(source.bundles().err(), expired);

    // The watcher reports it, once, and keeps trying.
    world.recorder.at_least(1, "expired:x509_svid").await;
    world
        .recorder
        .at_least(1, "failed:x509_svid:serving=false")
        .await;
    idle(120).await;
    assert_eq!(
        world.metrics.count("workload_credential_expired:x509_svid"),
        1
    );
    assert_eq!(world.recorder.count("expired"), 1);
    assert_eq!(source.svid().err(), expired);

    // A new SVID ends the outage.
    let renewed = ca.svid(ID, Day(2), Day(3));
    serve(&agent, &ca, &renewed);
    let generation = source.generation();
    within(source.updated(generation)).await;
    assert_eq!(leaf(&source), renewed.cert_der);
}

#[tokio::test(start_paused = true)]
async fn the_bundles_of_an_x509_source_go_stale_while_its_svid_is_still_served() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    // The default maximum bundle age: one hour.
    let source = world
        .client("example.org")
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;

    drop(agent);
    world.recorder.at_least(1, "failed:x509_svid").await;
    world.clock.advance_secs(HOUR - 1);
    assert!(source.bundles().is_ok(), "confirmed less than an hour ago");

    // An hour after the agent last confirmed them, the read itself refuses
    // the bundles. The SVID has most of its day left and is served.
    world.clock.advance_secs(1);
    let stale = Some(SpireError::Stale(WorkloadCredentialKind::X509Bundles));
    assert_eq!(source.bundles().err(), stale);
    assert_eq!(source.context().err(), stale);
    assert_eq!(leaf(&source), first.cert_der);
    world.recorder.at_least(1, "expired:x509_bundles").await;
    idle(120).await;
    assert_eq!(world.recorder.count("expired"), 1, "reported once");
    assert_eq!(
        world
            .metrics
            .count("workload_credential_expired:x509_bundles"),
        1
    );
    assert_eq!(source.generation(), 1, "the SVID did not change");

    // The agent returns with the same answer: that confirms the bundles.
    let agent = world.agent();
    serve(&agent, &ca, &first);
    settled(|| source.bundles().is_ok()).await;
    assert_eq!(source.confirmed_at(), Some(world.clock.now()));
    assert_eq!(source.generation(), 1);
}

#[tokio::test(start_paused = true)]
async fn an_x509_source_has_its_bundles_confirmed_beside_the_stream() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    // The default maximum bundle age: one hour, confirmed at 45 minutes.
    let source = world
        .client("example.org")
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;

    world.clock.advance_secs(44 * MINUTE);
    idle(120).await;
    assert_eq!(agent.calls(METHOD), 1, "not due before 45 minutes");

    // At 46 minutes, and 46 minutes after each confirmation: one request
    // beside the stream, which the agent answers with what the source holds.
    for (round, step) in [(1, 2 * MINUTE), (2, 46 * MINUTE), (3, 46 * MINUTE)] {
        world.clock.advance_secs(step);
        let now = world.clock.now();
        settled(|| source.confirmed_at() == Some(now)).await;
        assert!(source.bundles().is_ok());
        assert_eq!(agent.calls(METHOD), 1 + round);
    }
    // More than two hours on, nothing went stale and nothing was replaced.
    settled(|| agent.open_calls(METHOD) == 1).await;
    assert_eq!(source.generation(), 1);
    assert_eq!(world.recorder.count("expired"), 0);
    assert_eq!(world.recorder.count("failed"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_drops_resumes() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    agent.drop_connections();
    world
        .recorder
        .at_least(1, "failed:x509_svid:serving=true")
        .await;
    assert!(
        world.recorder.errors()[0].starts_with("workload API transport failed"),
        "{:?}",
        world.recorder.errors()
    );
    assert_eq!(leaf(&source), first.cert_der);

    // The watcher comes back on its own; what the agent holds by then is
    // what it gets.
    serve(&agent, &ca, &second);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
    assert!(agent.calls(METHOD) >= 2);
}

#[tokio::test(start_paused = true)]
async fn a_reconnect_that_brings_the_same_svid_is_not_a_rotation() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    agent.drop_connections();
    world.recorder.at_least(1, "failed:x509_svid").await;
    idle(120).await;
    assert_eq!(agent.calls(METHOD), 2);
    assert_eq!(agent.open_calls(METHOD), 1, "the new stream is kept");
    assert_eq!(source.generation(), 1);
    assert_eq!(world.metrics.count("workload_credential_rotated"), 1);
    assert_eq!(world.recorder.count("failed"), 1, "one drop, one failure");
}

#[tokio::test(start_paused = true)]
async fn an_agent_that_is_down_at_start_is_retried_until_it_answers() {
    let world = World::new();
    let source = watch(&world);

    world
        .recorder
        .at_least(3, "failed:x509_svid:serving=false")
        .await;
    assert!(
        world
            .recorder
            .errors()
            .iter()
            .all(|error| error.starts_with("workload API connection failed")),
        "{:?}",
        world.recorder.errors()
    );
    assert_eq!(
        source.svid().err(),
        Some(SpireError::NotYetFetched(WorkloadCredentialKind::X509Svid))
    );

    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    within(source.ready()).await;
    assert_eq!(leaf(&source), first.cert_der);
}

#[tokio::test(start_paused = true)]
async fn an_svid_for_the_wrong_trust_domain_is_refused_and_the_held_one_kept() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let other = TestCa::new("other authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    let foreign = other.svid("spiffe://other.test/billing/acme", Day(1), Day(3));
    serve(&agent, &other, &foreign);
    world
        .recorder
        .at_least(1, "failed:x509_svid:serving=true")
        .await;
    assert_eq!(
        world.recorder.errors()[0],
        "trust domain mismatch: expected example.org, the agent issued for other.test"
    );
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(source.generation(), 1);
    assert!(
        source
            .bundles()
            .expect("the bundles")
            .get(&trust_domain("other.test"))
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn an_svid_whose_key_is_another_certificates_is_refused_and_the_held_one_kept() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    // The next SVID arrives with the key of some other certificate: a
    // workload that took it could present nothing.
    let second = ca.svid(ID, Day(1), Day(3));
    let stranger = ca.svid(ID, Day(1), Day(3));
    let mismatched = FakeX509Svid {
        private_key_der: stranger.key_der,
        ..served(&second, &ca.bundle_der())
    };
    agent.set_x509_svids(&[mismatched], &[]);
    world
        .recorder
        .at_least(1, "failed:x509_svid:serving=true")
        .await;
    assert!(
        world.recorder.errors()[0].contains("the private key is not the leaf certificate's"),
        "{:?}",
        world.recorder.errors()
    );
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(source.generation(), 1);

    serve(&agent, &ca, &second);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
}

#[tokio::test(start_paused = true)]
async fn a_malformed_response_is_refused_with_bounded_escaped_text() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    // An SVID that names itself with a forged log line, a megabyte long.
    let mut svid = Vec::new();
    let hostile = format!(
        "spiffe://example.org/a\r\n\u{1b}[2J{}",
        "x".repeat(1_000_000)
    );
    put_bytes(&mut svid, 1, hostile.as_bytes());
    let mut message = Vec::new();
    put_bytes(&mut message, 1, &svid);
    agent.answer_with_message(METHOD, &message);
    world.recorder.at_least(1, "failed:x509_svid").await;

    // Bytes that are no message at all.
    agent.answer_with_message(METHOD, &[0xFF; 32]);
    world.recorder.at_least(4, "failed:x509_svid").await;

    let errors = world.recorder.errors();
    assert!(
        errors[0].starts_with("workload API credential refused: the SVID's SPIFFE ID is not valid"),
        "{:?}",
        errors[0]
    );
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("workload API response refused")),
        "{errors:?}"
    );
    for error in &errors {
        assert!(
            !error.contains('\n') && !error.contains('\r') && !error.contains('\u{1b}'),
            "{error:?}"
        );
        assert!(error.len() < 400, "an error of {} bytes", error.len());
    }
    assert!(errors[0].contains("\\r\\n\\u{1b}[2J"), "{:?}", errors[0]);
    // What was held is still served.
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(source.generation(), 1);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_last_handle_stops_the_watcher() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    let clone = source.clone();
    within(source.ready()).await;

    drop(source);
    assert!(clone.is_watching(), "a clone keeps the watcher");
    agent.drop_connections();
    world.recorder.at_least(1, "failed:x509_svid").await;
    idle(120).await;
    let calls = agent.calls(METHOD);
    assert!(calls >= 2, "the watcher reconnected");

    drop(clone);
    settled(|| agent.open_calls(METHOD) == 0).await;
    idle(600).await;
    assert_eq!(agent.calls(METHOD), calls);
    assert_eq!(world.recorder.count("failed"), 1);
}

#[tokio::test(start_paused = true)]
async fn the_recheck_percent_moves_the_point_of_the_safety_net() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &first);
    let client = world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_recheck_percent(90)
        .build();
    let source = client.watch_x509().expect("inside a runtime");
    within(source.ready()).await;
    agent.hold_updates(true);
    serve(&agent, &ca, &second);

    world.clock.advance_secs(21 * HOUR);
    idle(120).await;
    assert_eq!(leaf(&source), first.cert_der, "ninety percent is 21:36");
    world.clock.advance_secs(HOUR);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), second.cert_der);
}

#[tokio::test(start_paused = true)]
async fn a_rotation_of_an_svid_the_selector_did_not_choose_is_taken() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let main = ca.svid(ID, Day(1), Day(3));
    let before = ca.svid(OTHER_ID, Day(1), Day(2));
    let after = ca.svid(OTHER_ID, Day(1), Day(3));
    let bundle = ca.bundle_der();
    agent.set_x509_svids(&[served(&main, &bundle), served(&before, &bundle)], &[]);
    let source = watch(&world);
    within(source.ready()).await;

    // Only the SVID the selector did not choose changes.
    agent.set_x509_svids(&[served(&main, &bundle), served(&after, &bundle)], &[]);
    assert_eq!(within(source.updated(1)).await, 2);
    let context = source.context().expect("the context");
    assert_eq!(context.svid().leaf().as_ref(), main.cert_der.as_slice());
    assert_eq!(
        context.svids()[1].leaf().as_ref(),
        after.cert_der.as_slice()
    );
    assert_eq!(
        world.metrics.count("workload_credential_rotated:x509_svid"),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn a_hint_that_moves_moves_the_svid_a_hint_selector_serves() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let billing = ca.svid(ID, Day(1), Day(3));
    let reports = ca.svid(OTHER_ID, Day(1), Day(3));
    let bundle = ca.bundle_der();
    let hinted = |minted: &Minted, hint: &str| FakeX509Svid {
        hint: hint.to_owned(),
        ..served(minted, &bundle)
    };
    agent.set_x509_svids(
        &[hinted(&billing, "internal"), hinted(&reports, "external")],
        &[],
    );
    let source = world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_svid_selector(SvidSelector::Hint("internal".to_owned()))
        .build()
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;
    assert_eq!(leaf(&source), billing.cert_der);

    // The operator moves the hint. No certificate changes, no order
    // changes, no bundle changes: the selection does.
    agent.set_x509_svids(
        &[hinted(&billing, "external"), hinted(&reports, "internal")],
        &[],
    );
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(leaf(&source), reports.cert_der);
    assert_eq!(
        source.svid().expect("the SVID").spiffe_id().as_str(),
        OTHER_ID
    );
}

#[tokio::test(start_paused = true)]
async fn an_svid_that_expires_while_held_is_left_out_of_the_next_read() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    // The selected SVID is valid for four days, so its safety net is three
    // days away; the other expires after one.
    let main = ca.svid(ID, Day(1), Day(5));
    let short = ca.svid(OTHER_ID, Day(1), Day(2));
    let bundle = ca.bundle_der();
    agent.set_x509_svids(&[served(&main, &bundle), served(&short, &bundle)], &[]);
    let source = watch(&world);
    within(source.ready()).await;
    assert_eq!(source.context().expect("the context").svids().len(), 2);

    // The watcher has nothing to do yet; the read itself leaves it out.
    world.clock.advance_secs(24 * HOUR);
    let context = source.context().expect("the context");
    assert_eq!(context.svids().len(), 1);
    assert_eq!(context.svid().leaf().as_ref(), main.cert_der.as_slice());
    assert_eq!(leaf(&source), main.cert_der);
    assert_eq!(source.generation(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_partners_bundle_that_does_not_read_is_reported_and_the_rest_taken() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    let main = ca.svid(ID, Day(1), Day(2));
    agent.set_x509_svids(
        &[served(&main, &ca.bundle_der())],
        &[
            ("spiffe://partner.test", b"not a certificate".as_slice()),
            ("spiffe://other.test", partner.bundle_der().as_slice()),
        ],
    );
    agent.set_x509_bundles(&[
        ("example.org", ca.bundle_der().as_slice()),
        ("spiffe://Not_A_Domain", partner.bundle_der().as_slice()),
    ]);
    let client = world.client("example.org");
    let x509 = client.watch_x509().expect("inside a runtime");
    let bundles = client.watch_x509_bundles().expect("inside a runtime");
    within(x509.ready()).await;
    within(bundles.ready()).await;

    assert_eq!(
        leaf(&x509),
        main.cert_der,
        "the workload's own SVID is taken"
    );
    let held = x509.bundles().expect("the bundles");
    assert!(held.get(&trust_domain("other.test")).is_some());
    assert!(held.get(&trust_domain("partner.test")).is_none());
    assert_eq!(held.skipped()[0].key(), "spiffe://partner.test");
    assert_eq!(bundles.bundles().expect("the set").len(), 1);

    world.recorder.at_least(1, "skipped:x509_svid").await;
    world.recorder.at_least(1, "skipped:x509_bundles").await;
    assert_eq!(
        world
            .recorder
            .count("skipped:x509_svid:spiffe://partner.test"),
        1
    );
    assert_eq!(
        world
            .recorder
            .count("skipped:x509_bundles:spiffe://Not_A_Domain"),
        1
    );
    assert_eq!(world.metrics.count("workload_bundle_skipped"), 2);
    assert_eq!(world.recorder.count("failed"), 0);
}

/// Workload API standard, section 5.2.1: when the server redacts every SVID,
/// by answering `PERMISSION_DENIED`, the client ceases to use them.
#[tokio::test(start_paused = true)]
async fn an_svid_the_agent_withdraws_is_no_longer_served() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    // The registration entry is removed: the agent ends the stream with
    // PERMISSION_DENIED (7), and answers every new call the same.
    agent.refuse(METHOD, 7, "no identity issued");
    world.recorder.at_least(1, "withdrawn:x509_svid").await;
    let withdrawn = Some(SpireError::Withdrawn(WorkloadCredentialKind::X509Svid));
    assert_eq!(source.svid().err(), withdrawn);
    assert_eq!(source.bundles().err(), withdrawn);
    assert_eq!(source.context().err(), withdrawn);
    assert_eq!(source.generation(), 2, "the loss is a change");
    world
        .recorder
        .at_least(2, "failed:x509_svid:serving=false")
        .await;
    assert_eq!(world.recorder.count("withdrawn"), 1, "reported once");
    assert_eq!(
        world.metrics.count("workload_credential_expired:x509_svid"),
        1
    );

    // The entry is back: the watcher was asking all along.
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &second);
    assert_eq!(within(source.updated(2)).await, 3);
    assert_eq!(leaf(&source), second.cert_der);
}

/// The same for one identity among several: an answer that no longer holds
/// the identity the client selects redacts it, whatever else it holds.
#[tokio::test(start_paused = true)]
async fn the_selected_svid_is_no_longer_served_once_the_agent_leaves_it_out() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let main = ca.svid(ID, Day(1), Day(2));
    let reports = ca.svid(OTHER_ID, Day(1), Day(2));
    let bundle = ca.bundle_der();
    agent.set_x509_svids(&[served(&main, &bundle), served(&reports, &bundle)], &[]);
    let selected = axess_identity::WorkloadId::parse(OTHER_ID).expect("a SPIFFE ID");
    let source = world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_svid_selector(SvidSelector::SpiffeId(selected))
        .build()
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;
    assert_eq!(leaf(&source), reports.cert_der);

    agent.set_x509_svids(&[served(&main, &bundle)], &[]);
    world.recorder.at_least(1, "withdrawn:x509_svid").await;
    assert_eq!(
        source.svid().err(),
        Some(SpireError::Withdrawn(WorkloadCredentialKind::X509Svid))
    );
    assert_eq!(
        world.recorder.errors()[0],
        format!("workload API issued no SVID for the selected identity: {OTHER_ID}")
    );
}

/// Workload Endpoint standard, section 6: `INVALID_ARGUMENT` is an error in
/// the client and `UNIMPLEMENTED` a method the server does not have; both
/// are reported and not retried.
#[tokio::test(start_paused = true)]
async fn a_status_that_is_not_retried_ends_the_asking() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch(&world);
    within(source.ready()).await;

    agent.refuse(METHOD, 3, "security header missing from request");
    world.recorder.at_least(1, "stopped:x509_svid").await;
    assert_eq!(
        world.recorder.errors(),
        ["workload API answered INVALID_ARGUMENT: security header missing from request"]
    );
    // What the source holds is served until it runs out, and nothing is
    // asked again, whatever the agent would answer by now.
    let second = ca.svid(ID, Day(1), Day(3));
    serve(&agent, &ca, &second);
    idle(600).await;
    assert_eq!(agent.calls(METHOD), 1);
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(source.generation(), 1);
    assert_eq!(world.recorder.count("failed"), 0);
    assert_eq!(world.recorder.count("stopped"), 1);
    world.clock.advance_secs(24 * HOUR);
    assert_eq!(
        source.svid().err(),
        Some(SpireError::Expired(WorkloadCredentialKind::X509Svid))
    );
}

#[tokio::test(start_paused = true)]
async fn a_method_the_agent_does_not_offer_is_asked_for_once() {
    let world = World::new();
    let agent = world.agent();
    agent.refuse(METHOD, 12, "not offered here");
    let source = watch(&world);
    world.recorder.at_least(1, "stopped:x509_svid").await;
    idle(600).await;
    assert_eq!(agent.calls(METHOD), 1);
    // A reader is told why there is nothing, and not that it is on its way.
    assert_eq!(
        source.svid().err(),
        Some(SpireError::Status {
            code: crate::workload::spire::GrpcCode::Unimplemented,
            message: "not offered here".to_owned(),
        })
    );
    assert!(source.is_watching());
}

/// Workload API standard, section 4.2: when the connection is terminated the
/// client establishes a new one at once. The back-off paces what follows a
/// failed attempt, not the return to a stream that was working.
#[tokio::test(start_paused = true)]
async fn a_stream_that_is_cut_is_opened_again_at_once() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    // Every wait of the back-off is five minutes or more, and the clock is
    // checked once an hour, so that no check falls between the two cuts
    // below: one immediate reconnection is allowed for each check.
    let ten_minutes = std::time::Duration::from_secs(600);
    let source = world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_check_interval(std::time::Duration::from_secs(3600))
        .with_backoff(crate::workload::spire::BackoffPolicy::new(
            ten_minutes,
            ten_minutes,
        ))
        .build()
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;

    agent.drop_connections();
    let reopened = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while agent.calls(METHOD) < 2 || agent.open_calls(METHOD) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(reopened.is_ok(), "the stream is opened again with no wait");
    assert_eq!(world.recorder.count("failed"), 1);
    assert_eq!(leaf(&source), first.cert_der);

    // Cut again before the next check: this time the back-off paces it.
    agent.drop_connections();
    world.recorder.at_least(2, "failed:x509_svid").await;
    idle(2).await;
    assert_eq!(
        agent.calls(METHOD),
        2,
        "no loop on an agent that cuts every stream"
    );
}

/// A source with a withdrawal grace of ten minutes, whose bundles never go
/// stale.
fn watch_with_grace(world: &World) -> X509Source {
    world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_withdrawal_grace(std::time::Duration::from_secs(600))
        .build()
        .watch_x509()
        .expect("inside a runtime")
}

/// The one choice an operator has: with a withdrawal grace, an SVID the
/// agent withdraws with `PERMISSION_DENIED` is served until the grace ends,
/// the source says that it is, and then it is withdrawn.
#[tokio::test(start_paused = true)]
async fn a_withdrawal_grace_serves_the_svid_until_it_lapses() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch_with_grace(&world);
    within(source.ready()).await;

    agent.refuse(METHOD, 7, "no identity issued");
    world.recorder.at_least(1, "deferred:x509_svid").await;
    world
        .recorder
        .at_least(3, "failed:x509_svid:serving=true")
        .await;
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(world.recorder.count("deferred"), 1, "reported once");
    assert_eq!(world.recorder.count("withdrawn"), 0);
    assert_eq!(
        world
            .metrics
            .count("workload_credential_withdrawal_deferred:x509_svid"),
        1
    );

    // One second before the grace ends it is served; at its end the read
    // itself refuses, before the watcher has looked.
    world.clock.advance_secs(599);
    assert_eq!(leaf(&source), first.cert_der);
    world.clock.advance_secs(1);
    let withdrawn = Some(SpireError::Withdrawn(WorkloadCredentialKind::X509Svid));
    assert_eq!(source.svid().err(), withdrawn);
    world.recorder.at_least(1, "withdrawn:x509_svid").await;
    idle(60).await;
    assert_eq!(source.svid().err(), withdrawn);
    assert_eq!(world.recorder.count("withdrawn"), 1);
    assert_eq!(world.recorder.count("deferred"), 1);
}

#[tokio::test(start_paused = true)]
async fn a_withdrawal_grace_never_outlives_the_certificate() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    // A grace of two days, on an SVID that is valid for one.
    let source = world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_withdrawal_grace(std::time::Duration::from_secs(48 * 3600))
        .build()
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;

    agent.refuse(METHOD, 7, "no identity issued");
    world.recorder.at_least(1, "deferred:x509_svid").await;
    world.clock.advance_secs(24 * HOUR - 1);
    assert_eq!(leaf(&source), first.cert_der);
    world.clock.advance_secs(1);
    assert_eq!(
        source.svid().err(),
        Some(SpireError::Expired(WorkloadCredentialKind::X509Svid))
    );
    world.recorder.at_least(1, "expired:x509_svid").await;
}

/// The grace covers `PERMISSION_DENIED` alone. An answer that holds SVIDs
/// and not the selected one is the agent's positive statement, and it is
/// honoured at once.
#[tokio::test(start_paused = true)]
async fn an_answer_without_the_selected_identity_is_honoured_whatever_the_grace() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let main = ca.svid(ID, Day(1), Day(2));
    let reports = ca.svid(OTHER_ID, Day(1), Day(2));
    let bundle = ca.bundle_der();
    agent.set_x509_svids(&[served(&main, &bundle), served(&reports, &bundle)], &[]);
    let selected = axess_identity::WorkloadId::parse(OTHER_ID).expect("a SPIFFE ID");
    let source = world
        .builder("example.org")
        .with_max_bundle_age(NEVER_STALE)
        .with_withdrawal_grace(std::time::Duration::from_secs(600))
        .with_svid_selector(SvidSelector::SpiffeId(selected))
        .build()
        .watch_x509()
        .expect("inside a runtime");
    within(source.ready()).await;

    agent.set_x509_svids(&[served(&main, &bundle)], &[]);
    world.recorder.at_least(1, "withdrawn:x509_svid").await;
    assert_eq!(
        source.svid().err(),
        Some(SpireError::Withdrawn(WorkloadCredentialKind::X509Svid))
    );
    assert_eq!(world.recorder.count("deferred"), 0);
}

/// An agent that answers `PERMISSION_DENIED` for a moment and then issues
/// the identity again: the grace is over, and nothing is withdrawn when the
/// time it would have ended comes.
#[tokio::test(start_paused = true)]
async fn an_identity_that_returns_inside_the_grace_is_served_on() {
    let world = World::new();
    let agent = world.agent();
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    serve(&agent, &ca, &first);
    let source = watch_with_grace(&world);
    within(source.ready()).await;

    agent.refuse(METHOD, 7, "no identity issued");
    world.recorder.at_least(1, "deferred:x509_svid").await;

    // A minute on, the agent has its entries again and sends the same SVID.
    world.clock.advance_secs(MINUTE);
    serve(&agent, &ca, &first);
    let returned = world.clock.now();
    settled(|| source.confirmed_at() == Some(returned)).await;

    // Past the time the grace would have ended.
    world.clock.advance_secs(10 * MINUTE);
    idle(60).await;
    assert_eq!(leaf(&source), first.cert_der);
    assert_eq!(world.recorder.count("withdrawn"), 0);
    assert_eq!(source.generation(), 1);

    // And a later withdrawal starts a grace of its own.
    agent.refuse(METHOD, 7, "no identity issued");
    world.recorder.at_least(2, "deferred:x509_svid").await;
}
