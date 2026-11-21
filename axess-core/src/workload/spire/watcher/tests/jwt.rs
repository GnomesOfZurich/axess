//! The JWT SVID source: asked for, asked again, tied to the expiry, and
//! never serving the token of an identity its client was not built for.

use std::time::Duration;

use super::{ID, OTHER_ID, idle};
use crate::metrics::WorkloadCredentialKind;
use crate::testing::spire_agent::{FakeJwtSvid, WorkloadApiMethod};
use crate::workload::spire::test_support::{REFERENCE, World, jwt_svid, settled, within};
use crate::workload::spire::wire::put_bytes;
use crate::workload::spire::{BackoffPolicy, JwtSvidSource, SpireError, SvidSelector};

const METHOD: WorkloadApiMethod = WorkloadApiMethod::FetchJwtSvid;

fn jwt(spiffe_id: &str, token: &str, hint: &str) -> FakeJwtSvid {
    FakeJwtSvid {
        spiffe_id: spiffe_id.to_owned(),
        token: token.to_owned(),
        hint: hint.to_owned(),
    }
}

fn token(source: &JwtSvidSource) -> String {
    source.token().expect("a current token").to_string()
}

fn id(text: &str) -> axess_identity::WorkloadId {
    axess_identity::WorkloadId::parse(text).expect("a SPIFFE ID")
}

#[tokio::test(start_paused = true)]
async fn a_jwt_svid_is_fetched_again_at_its_refresh_point() {
    let world = World::new();
    let agent = world.agent();
    // Valid for five minutes: the refresh point is at two and a half.
    let first = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    let second = jwt_svid(ID, &["api"], REFERENCE + 150, REFERENCE + 450);
    agent.set_jwt_svids(&[jwt(ID, &first, "")]);
    let source = world
        .client("example.org")
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    within(source.ready()).await;
    assert_eq!(token(&source), first);
    assert_eq!(source.svid().expect("the SVID").spiffe_id().as_str(), ID);

    // The agent has a newer one; nothing tells the client.
    agent.set_jwt_svids(&[jwt(ID, &second, "")]);
    world.clock.advance_secs(149);
    idle(60).await;
    assert_eq!(token(&source), first, "not due yet");
    assert_eq!(agent.calls(METHOD), 1);

    world.clock.advance_secs(2);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(token(&source), second);
    assert_eq!(agent.jwt_audiences(), [["api"], ["api"]]);
    assert_eq!(
        world.metrics.count("workload_credential_rotated:jwt_svid"),
        2
    );
    assert!(source.is_watching());
}

#[tokio::test(start_paused = true)]
async fn the_jwt_refresh_percent_moves_the_refresh_point() {
    let world = World::new();
    let agent = world.agent();
    let first = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    let second = jwt_svid(ID, &["api"], REFERENCE + 240, REFERENCE + 540);
    agent.set_jwt_svids(&[jwt(ID, &first, "")]);
    let source = world
        .builder("example.org")
        .with_jwt_refresh_percent(80)
        .build()
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    within(source.ready()).await;

    agent.set_jwt_svids(&[jwt(ID, &second, "")]);
    world.clock.advance_secs(239);
    idle(60).await;
    assert_eq!(token(&source), first, "eighty percent is four minutes");
    world.clock.advance_secs(2);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(token(&source), second);
}

#[tokio::test(start_paused = true)]
async fn an_expired_jwt_svid_is_never_served() {
    let world = World::new();
    let agent = world.agent();
    let first = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &first, "")]);
    let source = world
        .client("example.org")
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    within(source.ready()).await;

    agent.refuse(METHOD, 14, "agent is restarting");
    world.clock.advance_secs(299);
    world
        .recorder
        .at_least(1, "failed:jwt_svid:serving=true")
        .await;
    assert_eq!(token(&source), first, "valid for one more second");

    world.clock.advance_secs(1);
    let expired = Some(SpireError::Expired(WorkloadCredentialKind::JwtSvid));
    assert_eq!(source.token().err(), expired);
    world.recorder.at_least(1, "expired:jwt_svid").await;
    assert_eq!(source.svid().err(), expired);
    assert_eq!(
        world.metrics.count("workload_credential_expired:jwt_svid"),
        1
    );

    let renewed = jwt_svid(ID, &["api"], REFERENCE + 300, REFERENCE + 600);
    agent.set_jwt_svids(&[jwt(ID, &renewed, "")]);
    let generation = source.generation();
    within(source.updated(generation)).await;
    assert_eq!(token(&source), renewed);
}

#[tokio::test(start_paused = true)]
async fn a_token_that_runs_out_inside_an_ask_again_wait_is_replaced_at_once() {
    let world = World::new();
    let agent = world.agent();
    let first = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &first, "")]);
    // Every wait of the back-off is between five and ten minutes: longer
    // than the token has left when it is first asked for again.
    let ten_minutes = Duration::from_secs(600);
    let source = world
        .builder("example.org")
        .with_backoff(BackoffPolicy::new(ten_minutes, ten_minutes))
        .build()
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    within(source.ready()).await;

    // Past the refresh point the agent still answers with the token it has
    // cached, so the watcher waits before it asks again.
    world.clock.advance_secs(151);
    settled(|| agent.calls(METHOD) == 2).await;
    idle(2).await;
    assert_eq!(source.generation(), 1);

    // The token runs out inside that wait. The agent has a new one by then.
    let second = jwt_svid(ID, &["api"], REFERENCE + 300, REFERENCE + 600);
    agent.set_jwt_svids(&[jwt(ID, &second, "")]);
    world.clock.advance_secs(149);
    // Ten seconds of the runtime's time: the wait under way has five
    // minutes or more left.
    let replaced = tokio::time::timeout(Duration::from_secs(10), async {
        while source.token().is_err() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        replaced.is_ok(),
        "the expiry starts an ask; the wait is not sat out"
    );
    assert_eq!(token(&source), second);
    assert_eq!(agent.calls(METHOD), 3);
    assert_eq!(world.recorder.count("expired:jwt_svid"), 1);
    assert_eq!(world.recorder.count("failed"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_token_whose_validity_runs_backwards_is_refused() {
    let world = World::new();
    let agent = world.agent();
    // An `iat` in milliseconds lies far after the `exp` in seconds.
    let backwards = jwt_svid(ID, &["api"], (REFERENCE + 10) * 1000, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &backwards, "")]);
    let source = world
        .client("example.org")
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    world
        .recorder
        .at_least(2, "failed:jwt_svid:serving=false")
        .await;
    assert_eq!(
        world.recorder.errors()[0],
        "workload API credential refused: the JWT SVID was issued after it expires"
    );
    assert_eq!(
        source.svid().err(),
        Some(SpireError::NotYetFetched(WorkloadCredentialKind::JwtSvid))
    );

    let good = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &good, "")]);
    within(source.ready()).await;
    assert_eq!(token(&source), good);
}

#[tokio::test(start_paused = true)]
async fn a_jwt_source_that_can_never_succeed_is_refused_before_it_starts() {
    let world = World::new();
    let agent = world.agent();
    let client = world.client("example.org");

    let none = client.watch_jwt_svid(Vec::<String>::new());
    assert!(matches!(none, Err(SpireError::Request(_))), "{none:?}");
    let empty = client.watch_jwt_svid(["api", ""]);
    assert!(matches!(empty, Err(SpireError::Request(_))), "{empty:?}");

    // A selector for an identity of another trust domain than the client's.
    let foreign = world
        .builder("example.org")
        .with_svid_selector(SvidSelector::SpiffeId(id(
            "spiffe://other.test/billing/acme",
        )))
        .build();
    let mismatch = Some(SpireError::TrustDomainMismatch {
        expected: super::trust_domain("example.org"),
        presented: "other.test".to_owned(),
    });
    assert_eq!(foreign.watch_jwt_svid(["api"]).err(), mismatch);
    assert_eq!(foreign.watch_x509().err(), mismatch);
    assert_eq!(
        within(foreign.fetch_jwt_svid(["api"])).await.err(),
        mismatch
    );
    assert_eq!(within(foreign.fetch_x509_svid()).await.err(), mismatch);

    // Nothing was started, nothing was asked, nothing is reported.
    idle(30).await;
    assert_eq!(agent.calls(METHOD), 0);
    assert_eq!(agent.calls(WorkloadApiMethod::FetchX509Svid), 0);
    assert!(world.recorder.lines().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_jwt_source_follows_the_identity_its_client_selects() {
    let world = World::new();
    let agent = world.agent();
    let main = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    let reports = jwt_svid(OTHER_ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &main, "main"), jwt(OTHER_ID, &reports, "reports")]);
    let watch = |selector: Option<SvidSelector>| {
        let builder = world.builder("example.org");
        let builder = match selector {
            Some(selector) => builder.with_svid_selector(selector),
            None => builder,
        };
        builder
            .build()
            .watch_jwt_svid(["api"])
            .expect("an audience, inside a runtime")
    };

    // By SPIFFE ID: the request names the identity, and the answer is its.
    let by_id = watch(Some(SvidSelector::SpiffeId(id(OTHER_ID))));
    within(by_id.ready()).await;
    assert_eq!(token(&by_id), reports);
    assert_eq!(by_id.svid().expect("the SVID").hint(), "reports");

    // By hint: every identity is asked for, and the hinted one is taken.
    let by_hint = watch(Some(SvidSelector::Hint("reports".to_owned())));
    within(by_hint.ready()).await;
    assert_eq!(token(&by_hint), reports);

    // By default: the agent's first.
    let first = watch(None);
    within(first.ready()).await;
    assert_eq!(token(&first), main);

    assert_eq!(agent.jwt_subjects(), [OTHER_ID, "", ""]);

    // At the refresh point each asks again for the identity it is for.
    let renewed_main = jwt_svid(ID, &["api"], REFERENCE + 150, REFERENCE + 450);
    let renewed_reports = jwt_svid(OTHER_ID, &["api"], REFERENCE + 150, REFERENCE + 450);
    agent.set_jwt_svids(&[
        jwt(ID, &renewed_main, "main"),
        jwt(OTHER_ID, &renewed_reports, "reports"),
    ]);
    world.clock.advance_secs(151);
    within(by_id.updated(1)).await;
    within(by_hint.updated(1)).await;
    within(first.updated(1)).await;
    assert_eq!(token(&by_id), renewed_reports);
    assert_eq!(token(&by_hint), renewed_reports);
    assert_eq!(token(&first), renewed_main);
}

#[tokio::test(start_paused = true)]
async fn a_jwt_source_never_serves_the_token_of_another_identity() {
    let world = World::new();
    let agent = world.agent();
    let main = jwt_svid(ID, &["api"], REFERENCE, REFERENCE + 300);
    let reports = jwt_svid(OTHER_ID, &["api"], REFERENCE, REFERENCE + 300);
    agent.set_jwt_svids(&[jwt(ID, &main, "main"), jwt(OTHER_ID, &reports, "reports")]);
    let by_hint = world
        .builder("example.org")
        .with_svid_selector(SvidSelector::Hint("reports".to_owned()))
        .build()
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    let by_id = world
        .builder("example.org")
        .with_svid_selector(SvidSelector::SpiffeId(id(OTHER_ID)))
        .build()
        .watch_jwt_svid(["api"])
        .expect("an audience, inside a runtime");
    within(by_hint.ready()).await;
    within(by_id.ready()).await;

    // The selected identity is withdrawn. The agent goes on answering, with
    // the other identity's token alone, whatever the request named: an
    // answer written by hand, as an agent that ignores the name would.
    let renewed_main = jwt_svid(ID, &["api"], REFERENCE + 150, REFERENCE + 450);
    let mut entry = Vec::new();
    put_bytes(&mut entry, 1, ID.as_bytes());
    put_bytes(&mut entry, 2, renewed_main.as_bytes());
    put_bytes(&mut entry, 3, b"main");
    let mut answer = Vec::new();
    put_bytes(&mut answer, 1, &entry);
    agent.answer_with_message(METHOD, &answer);
    world.clock.advance_secs(151);
    // An answer with SVIDs and none for the selected identity is the agent
    // no longer issuing it: each source stops serving its token at once,
    // with most of the token's life left.
    world.recorder.at_least(2, "withdrawn:jwt_svid").await;
    let withdrawn = Some(SpireError::Withdrawn(WorkloadCredentialKind::JwtSvid));
    assert_eq!(by_hint.token().err(), withdrawn);
    assert_eq!(by_id.token().err(), withdrawn);
    world
        .recorder
        .at_least(2, "failed:jwt_svid:serving=false")
        .await;
    let errors = world.recorder.errors();
    for selected in ["the hint reports", "spiffe://example.org/reports/acme"] {
        let text = format!("workload API issued no SVID for the selected identity: {selected}");
        assert!(errors.contains(&text), "{errors:?}");
    }
    idle(60).await;
    assert_eq!(by_hint.token().err(), withdrawn);
    assert_eq!(by_id.token().err(), withdrawn);
    assert_eq!(world.recorder.count("withdrawn"), 2, "each reported once");
    assert_eq!(
        world.metrics.count("workload_credential_rotated:jwt_svid"),
        2,
        "the other identity's token was never taken"
    );

    // The agent issues the identity again: both sources serve its token.
    let reissued = jwt_svid(OTHER_ID, &["api"], REFERENCE + 151, REFERENCE + 451);
    agent.set_jwt_svids(&[jwt(OTHER_ID, &reissued, "reports")]);
    settled(|| by_hint.token().is_ok() && by_id.token().is_ok()).await;
    assert_eq!(token(&by_hint), reissued);
    assert_eq!(token(&by_id), reissued);
}
