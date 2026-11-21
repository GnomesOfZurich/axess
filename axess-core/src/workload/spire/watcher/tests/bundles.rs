//! The bundle sources: updates, federation, the check beside the stream,
//! staleness, and the answers that never replace a good set.

use axess_clock::Clock;

use super::{MINUTE, idle, trust_domain};
use crate::metrics::WorkloadCredentialKind;
use crate::testing::spire_agent::WorkloadApiMethod;
use crate::workload::spire::test_support::{TestCa, World, settled, within};
use crate::workload::spire::{SpireError, X509BundleSource};

const METHOD: WorkloadApiMethod = WorkloadApiMethod::FetchX509Bundles;

/// The authorities the source serves for example.org, DER.
fn authorities(source: &X509BundleSource) -> Vec<Vec<u8>> {
    source
        .bundles()
        .expect("a bundle set")
        .get(&trust_domain("example.org"))
        .expect("the own bundle")
        .authorities()
        .iter()
        .map(|authority| authority.as_ref().to_vec())
        .collect()
}

#[tokio::test(start_paused = true)]
async fn a_bundle_update_reaches_the_bundle_source() {
    let world = World::new();
    let agent = world.agent();
    let old = TestCa::new("example.org authority");
    let new = TestCa::new("example.org authority, rotated");
    agent.set_x509_bundles(&[("example.org", old.bundle_der().as_slice())]);
    let source = world
        .client("example.org")
        .watch_x509_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;
    assert_eq!(authorities(&source), [old.bundle_der()]);
    assert_eq!(source.confirmed_at(), Some(world.clock.now()));

    // During a rotation the bundle holds both authorities, then the new one.
    let both = [old.bundle_der(), new.bundle_der()].concat();
    agent.set_x509_bundles(&[("example.org", both.as_slice())]);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(authorities(&source), [old.bundle_der(), new.bundle_der()]);

    agent.set_x509_bundles(&[("example.org", new.bundle_der().as_slice())]);
    assert_eq!(within(source.updated(2)).await, 3);
    assert_eq!(authorities(&source), [new.bundle_der()]);
    assert_eq!(
        world
            .metrics
            .count("workload_credential_rotated:x509_bundles"),
        3
    );
    assert_eq!(agent.calls(METHOD), 1);
    assert!(source.is_watching());
}

#[tokio::test(start_paused = true)]
async fn federated_bundles_come_and_go_with_their_trust_domains() {
    let world = World::new();
    let agent = world.agent();
    let own = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    agent.set_x509_bundles(&[("example.org", own.bundle_der().as_slice())]);
    agent.set_jwt_bundles(&[(
        "example.org",
        br#"{"keys":[{"kty":"EC","kid":"own"}]}"#.as_slice(),
    )]);
    let client = world.client("example.org");
    let x509 = client.watch_x509_bundles().expect("inside a runtime");
    let jwt = client.watch_jwt_bundles().expect("inside a runtime");
    within(x509.ready()).await;
    within(jwt.ready()).await;
    let partner_domain = trust_domain("partner.test");
    assert!(
        x509.bundles()
            .expect("a set")
            .get(&partner_domain)
            .is_none()
    );
    assert!(jwt.bundles().expect("a set").get(&partner_domain).is_none());

    // The operator federates with the partner.
    agent.set_x509_bundles(&[
        ("example.org", own.bundle_der().as_slice()),
        ("spiffe://partner.test", partner.bundle_der().as_slice()),
    ]);
    agent.set_jwt_bundles(&[
        (
            "example.org",
            br#"{"keys":[{"kty":"EC","kid":"own"}]}"#.as_slice(),
        ),
        (
            "spiffe://partner.test",
            br#"{"keys":[{"kty":"EC","kid":"theirs"}]}"#.as_slice(),
        ),
    ]);
    within(x509.updated(1)).await;
    within(jwt.updated(1)).await;
    let x509_set = x509.bundles().expect("a set");
    assert_eq!(x509_set.len(), 2);
    assert_eq!(
        x509_set
            .get(&partner_domain)
            .expect("the partner's")
            .authorities()[0]
            .as_ref(),
        partner.bundle_der().as_slice()
    );
    let jwt_set = jwt.bundles().expect("a set");
    assert_eq!(
        jwt_set
            .get(&partner_domain)
            .expect("the partner's")
            .key_ids(),
        ["theirs"]
    );
    assert_eq!(
        world
            .metrics
            .count("workload_credential_rotated:jwt_bundles"),
        2
    );

    // And ends the federation.
    agent.set_x509_bundles(&[("example.org", own.bundle_der().as_slice())]);
    within(x509.updated(2)).await;
    assert!(
        x509.bundles()
            .expect("a set")
            .get(&partner_domain)
            .is_none()
    );
    assert!(jwt.is_watching());
}

#[tokio::test(start_paused = true)]
async fn a_bundle_set_the_agent_has_stopped_confirming_goes_stale() {
    let world = World::new();
    let agent = world.agent();
    let own = TestCa::new("example.org authority");
    agent.set_x509_bundles(&[("example.org", own.bundle_der().as_slice())]);
    // The default maximum bundle age: one hour.
    let source = world
        .client("example.org")
        .watch_x509_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;

    drop(agent);
    world
        .recorder
        .at_least(2, "failed:x509_bundles:serving=true")
        .await;
    world.clock.advance_secs(60 * MINUTE - 1);
    assert_eq!(source.bundles().expect("the last set").len(), 1);
    assert_eq!(world.recorder.count("expired"), 0);

    // An hour after the agent last sent the set, the read itself refuses
    // it, before the watcher has looked.
    world.clock.advance_secs(1);
    let stale = SpireError::Stale(WorkloadCredentialKind::X509Bundles);
    assert_eq!(source.bundles().err().as_ref(), Some(&stale));
    world.recorder.at_least(1, "expired:x509_bundles").await;
    world
        .recorder
        .at_least(1, "failed:x509_bundles:serving=false")
        .await;
    idle(120).await;
    assert_eq!(world.recorder.count("expired"), 1, "reported once");
    assert_eq!(
        world
            .metrics
            .count("workload_credential_expired:x509_bundles"),
        1
    );
    assert_eq!(source.generation(), 2, "the loss is a change");
    assert_eq!(source.bundles().err().as_ref(), Some(&stale));
    assert_eq!(
        stale.to_string(),
        "the X.509 bundle set is stale: the agent has not confirmed it within the maximum bundle age"
    );

    // The agent returns with the set it had: served again, from now.
    let agent = world.agent();
    agent.set_x509_bundles(&[("example.org", own.bundle_der().as_slice())]);
    assert_eq!(within(source.updated(2)).await, 3);
    assert_eq!(authorities(&source), [own.bundle_der()]);
    assert_eq!(source.confirmed_at(), Some(world.clock.now()));
}

#[tokio::test(start_paused = true)]
async fn a_bundle_stream_that_has_stalled_is_found_out_by_a_second_request() {
    let world = World::new();
    let agent = world.agent();
    let old = TestCa::new("example.org authority");
    let new = TestCa::new("example.org authority, rotated");
    agent.set_x509_bundles(&[("example.org", old.bundle_der().as_slice())]);
    let source = world
        .client("example.org")
        .watch_x509_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;

    // The agent withdraws the old authority, and the open stream is never
    // told.
    agent.hold_updates(true);
    agent.set_x509_bundles(&[("example.org", new.bundle_der().as_slice())]);
    world.clock.advance_secs(44 * MINUTE);
    idle(120).await;
    assert_eq!(authorities(&source), [old.bundle_der()]);
    assert_eq!(agent.calls(METHOD), 1, "not due before 45 minutes");

    // Three quarters into the maximum bundle age the watcher asks on a
    // second request, which brings the set the stream never delivered.
    world.clock.advance_secs(2 * MINUTE);
    assert_eq!(within(source.updated(1)).await, 2);
    assert_eq!(authorities(&source), [new.bundle_der()]);
    assert_eq!(agent.calls(METHOD), 2);
    settled(|| agent.open_calls(METHOD) == 1).await;
    assert_eq!(world.recorder.count("failed"), 0);
    assert_eq!(world.recorder.count("expired"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_bundle_set_is_confirmed_beside_its_stream_and_never_goes_stale() {
    let world = World::new();
    let agent = world.agent();
    let own = TestCa::new("example.org authority");
    agent.set_x509_bundles(&[("example.org", own.bundle_der().as_slice())]);
    agent.set_jwt_bundles(&[(
        "example.org",
        br#"{"keys":[{"kty":"EC","kid":"own"}]}"#.as_slice(),
    )]);
    let client = world.client("example.org");
    let x509 = client.watch_x509_bundles().expect("inside a runtime");
    let jwt = client.watch_jwt_bundles().expect("inside a runtime");
    within(x509.ready()).await;
    within(jwt.ready()).await;

    // Four hours, in steps of 46 minutes: each step is past the point at
    // which the set is confirmed, and short of the age at which it is stale.
    for round in 1..=5 {
        world.clock.advance_secs(46 * MINUTE);
        let now = world.clock.now();
        settled(|| x509.confirmed_at() == Some(now) && jwt.confirmed_at() == Some(now)).await;
        assert!(x509.bundles().is_ok() && jwt.bundles().is_ok());
        assert_eq!(agent.calls(METHOD), 1 + round);
        assert_eq!(agent.calls(WorkloadApiMethod::FetchJwtBundles), 1 + round);
    }
    settled(|| agent.open_calls(METHOD) == 1).await;
    settled(|| agent.open_calls(WorkloadApiMethod::FetchJwtBundles) == 1).await;
    assert_eq!(x509.generation(), 1, "the same set is no change");
    assert_eq!(jwt.generation(), 1);
    assert_eq!(world.recorder.count("expired"), 0);
    assert_eq!(world.recorder.count("failed"), 0);
}

#[tokio::test(start_paused = true)]
async fn the_maximum_bundle_age_is_a_setting() {
    let world = World::new();
    let agent = world.agent();
    let own = TestCa::new("example.org authority");
    agent.set_x509_bundles(&[("example.org", own.bundle_der().as_slice())]);
    let source = world
        .builder("example.org")
        .with_max_bundle_age(std::time::Duration::from_secs(10 * 60))
        .build()
        .watch_x509_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;

    drop(agent);
    world.recorder.at_least(1, "failed:x509_bundles").await;
    world.clock.advance_secs(10 * MINUTE - 1);
    assert!(source.bundles().is_ok());
    world.clock.advance_secs(1);
    assert_eq!(
        source.bundles().err(),
        Some(SpireError::Stale(WorkloadCredentialKind::X509Bundles))
    );
}

#[tokio::test(start_paused = true)]
async fn an_answer_without_the_workloads_own_trust_domain_never_replaces_a_good_set() {
    let world = World::new();
    let agent = world.agent();
    let own = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    agent.set_x509_bundles(&[
        ("example.org", own.bundle_der().as_slice()),
        ("partner.test", partner.bundle_der().as_slice()),
    ]);
    agent.set_jwt_bundles(&[(
        "example.org",
        br#"{"keys":[{"kty":"EC","kid":"own"}]}"#.as_slice(),
    )]);
    let client = world.client("example.org");
    let x509 = client.watch_x509_bundles().expect("inside a runtime");
    let jwt = client.watch_jwt_bundles().expect("inside a runtime");
    within(x509.ready()).await;
    within(jwt.ready()).await;

    // An empty answer: a message with no entry at all.
    agent.answer_with_message(METHOD, &[]);
    agent.answer_with_message(WorkloadApiMethod::FetchJwtBundles, &[]);
    world
        .recorder
        .at_least(1, "failed:x509_bundles:serving=true")
        .await;
    world
        .recorder
        .at_least(1, "failed:jwt_bundles:serving=true")
        .await;
    let errors = world.recorder.errors();
    assert!(
        errors
            .iter()
            .any(|error| error.ends_with("the answer holds no X.509 bundle for example.org")),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.ends_with("the answer holds no JWT bundle for example.org")),
        "{errors:?}"
    );

    // An answer with a partner's bundle and not the workload's own.
    agent.set_x509_bundles(&[("partner.test", partner.bundle_der().as_slice())]);
    world
        .recorder
        .at_least(3, "failed:x509_bundles:serving=true")
        .await;

    // Neither was a rotation: both sources serve what they held.
    assert_eq!(x509.bundles().expect("the held set").len(), 2);
    assert_eq!(authorities(&x509), [own.bundle_der()]);
    assert_eq!(x509.generation(), 1);
    assert_eq!(
        jwt.bundles()
            .expect("the held set")
            .get(&trust_domain("example.org"))
            .expect("the own bundle")
            .key_ids(),
        ["own"]
    );
    assert_eq!(jwt.generation(), 1);
    assert_eq!(world.metrics.count("workload_credential_rotated"), 2);
}
