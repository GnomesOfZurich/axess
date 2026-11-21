//! The unready inner service answers as it says: pending or failed when
//! asked, an error when called, and one count of the questions across its
//! clones.

use axess_testing::readiness::{NotReady, Unready, poll_ready_once};
use std::task::Poll;
use tower_service::Service;

#[test]
fn a_pending_service_is_pending_every_time_it_is_asked() {
    let mut service = Unready::<u8>::pending();
    for asked in 1..=3 {
        assert!(poll_ready_once::<_, ()>(&mut service).is_pending());
        assert_eq!(service.polls(), asked);
    }
}

#[test]
fn a_failing_service_fails_every_time_it_is_asked() {
    let mut service = Unready::<u8>::failing();
    for asked in 1..=3 {
        assert_eq!(
            poll_ready_once::<_, ()>(&mut service),
            Poll::Ready(Err(NotReady::Failed))
        );
        assert_eq!(service.polls(), asked);
    }
}

#[test]
fn the_count_is_shared_by_clones() {
    let original = Unready::<u8>::pending();
    let mut clone = original.clone();
    assert_eq!(original.polls(), 0);
    assert!(poll_ready_once::<_, ()>(&mut clone).is_pending());
    assert_eq!(original.polls(), 1);
}

#[tokio::test]
async fn a_call_answers_that_the_service_was_not_ready() {
    for mut service in [Unready::<u8>::pending(), Unready::<u8>::failing()] {
        assert_eq!(service.call("request").await, Err(NotReady::Called));
        assert_eq!(service.polls(), 0, "a call asks nothing");
    }
}

#[test]
fn the_errors_say_what_happened() {
    assert_eq!(
        NotReady::Failed.to_string(),
        "the inner service failed to become ready"
    );
    assert_eq!(
        NotReady::Called.to_string(),
        "the inner service was called before it was ready"
    );
}
