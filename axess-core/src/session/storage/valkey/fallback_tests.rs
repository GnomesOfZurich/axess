//! A two-key script that does not run is said once: the store's rotation
//! warns on its first sequenced run and logs the later ones at debug, so a
//! deployment whose steady state is the sequenced form gets one line, not one
//! per request. The helpers here also give the registry's tests a server
//! that refuses scripts.

use super::internal::FallbackNotice;
use super::registry_tests::{client_denied, connect};
use super::store::ValkeySessionStore;
use crate::authn::ids::UserId;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CycleOutcome, SessionStore};
use axess_rng::SystemRng;
use axess_testing::mock_tracing::TracingCapture;
use fred::prelude::*;
use std::time::Duration;
use tracing::Level;

/// The events logged about a sequenced run, at `level`.
fn noted(capture: &TracingCapture, level: Level) -> usize {
    capture
        .events()
        .iter()
        .filter(|e| e.level == level && e.message.contains("sequenced form used"))
        .count()
}

/// The first note is a warning that says how to restore the script; the
/// later ones are debug lines.
#[test]
fn a_fallback_is_warned_once_then_logged_at_debug() {
    let capture = TracingCapture::install();
    let notice = FallbackNotice::default();
    for _ in 0..3 {
        notice.note(
            "session cycle",
            "the two keys hash to different cluster slots",
        );
    }
    assert_eq!(noted(&capture, Level::WARN), 1);
    assert_eq!(noted(&capture, Level::DEBUG), 2);
    assert!(capture.contains_at_level(Level::WARN, "hash-tag prefix"));
}

/// The warnings axess logged, whatever they said.
fn axess_warnings(capture: &TracingCapture) -> usize {
    capture
        .events()
        .iter()
        .filter(|e| e.level == Level::WARN && e.target.starts_with("axess"))
        .count()
}

/// Runs `body` with an admin client and the client of a Valkey user that may
/// not run scripts, then removes that user whether `body` passed or
/// panicked (its guard, `AclUser`), so a failing test leaves no user
/// behind on the shared server. The body runs on the test's own thread, so
/// a capture the test installed sees its events.
pub(super) async fn with_scripting_refused<F, Fut>(body: F)
where
    F: FnOnce(Client, Client) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let admin = connect().await;
    let name = format!(
        "noscript{}",
        UserId::new(&SystemRng).to_string().replace('-', "")
    );
    let (user, restricted) = client_denied(&admin, &name, "-@scripting").await;
    body(admin.clone(), restricted).await;
    user.remove(&admin).await;
}

/// The sequenced runs of `step` the capture saw, at any level.
pub(super) fn sequenced_runs(capture: &TracingCapture, step: &str) -> usize {
    let step = format!("step={step}");
    capture
        .events()
        .iter()
        .filter(|e| e.message.contains("sequenced form used") && e.message.contains(&step))
        .count()
}

/// Rotations on a server that refuses scripts each rotate, and the store
/// warns once for all of them.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_rotations_without_scripting_warn_once() {
    let capture = TracingCapture::install();
    let sweep = crate::testing::valkey_sweep::on_node("fb");
    let prefix = sweep.prefix().to_owned();
    with_scripting_refused(|_, restricted| async move {
        let store =
            ValkeySessionStore::new(restricted, crate::testing::test_key(3)).with_prefix(prefix);
        for _ in 0..3 {
            let (old, new) = (SessionId::new(&SystemRng), SessionId::new(&SystemRng));
            store
                .save(
                    &SessionKey::of(&old),
                    &SessionData::default(),
                    Duration::from_secs(60),
                )
                .await
                .expect("a save");
            let outcome = store
                .cycle(
                    &SessionKey::of(&old),
                    &SessionKey::of(&new),
                    &SessionData::default(),
                    Duration::from_secs(60),
                    true,
                )
                .await;
            assert_eq!(outcome.expect("a rotation"), CycleOutcome::Rotated);
        }
    })
    .await;

    assert_eq!(sequenced_runs(&capture, "session cycle"), 3);
    assert_eq!(axess_warnings(&capture), 1, "{:#?}", capture.events());
}
