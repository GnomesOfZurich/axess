//! Routing of revocation messages to watchers, without a server: the
//! dispatcher's handlers are plain methods, so the routing is checked by
//! calling them.

use super::*;
use std::sync::atomic::Ordering::SeqCst;

fn channels(n: usize) -> [String; 2] {
    [
        format!("p:revoked-user:u{n}"),
        format!("p:revoked-session:s{n}"),
    ]
}

fn wakeups(hold: &Hold) -> usize {
    hold.slot.wakeups.load(SeqCst)
}

/// A thousand revocations for other users and sessions wake none of a
/// thousand watchers.
#[test]
fn revocations_for_other_channels_wake_no_watcher() {
    let shared = SharedSubscriber::new();
    let holds: Vec<Hold> = (0..1000).map(|n| shared.register(channels(n))).collect();
    for n in 1000..2000 {
        let [user, session] = channels(n);
        shared.dispatch_message(&user);
        shared.dispatch_message(&session);
    }
    assert!(holds.iter().all(|h| wakeups(h) == 0));
    assert_eq!(shared.watcher_count(), 1000);
}

/// A message wakes exactly the watchers of its channel, and a user-level
/// message reaches every session of that user.
#[tokio::test]
async fn a_revocation_wakes_only_the_watchers_of_its_channel() {
    let shared = SharedSubscriber::new();
    let a = shared.register(["p:revoked-user:alice".into(), "p:revoked-session:a1".into()]);
    let b = shared.register(["p:revoked-user:alice".into(), "p:revoked-session:a2".into()]);
    let c = shared.register(["p:revoked-user:bob".into(), "p:revoked-session:b1".into()]);

    shared.dispatch_message("p:revoked-session:a1");
    assert_eq!((wakeups(&a), wakeups(&b), wakeups(&c)), (1, 0, 0));
    assert_eq!(a.slot.next().await, Event::Revoked);

    shared.dispatch_message("p:revoked-user:alice");
    assert_eq!((wakeups(&a), wakeups(&b), wakeups(&c)), (2, 1, 0));
    assert_eq!(b.slot.next().await, Event::Revoked);
}

/// Dropped messages flag every watcher once for a recheck, although each
/// sits under two channels.
#[tokio::test]
async fn a_lag_flags_every_watcher_once_for_a_recheck() {
    let shared = SharedSubscriber::new();
    let holds: Vec<Hold> = (0..50).map(|n| shared.register(channels(n))).collect();
    shared.dispatch_lag();
    assert!(holds.iter().all(|h| wakeups(h) == 1));
    for hold in &holds {
        assert_eq!(hold.slot.next().await, Event::Recheck);
    }
}

/// A notification sent before the watcher waits is not lost.
#[tokio::test]
async fn a_notification_before_the_wait_is_kept() {
    let shared = SharedSubscriber::new();
    let hold = shared.register(channels(1));
    shared.dispatch_message(&channels(1)[1]);
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), hold.slot.next())
        .await
        .expect("the stored wake-up is delivered");
    assert_eq!(event, Event::Revoked);
}

/// Dropping a hold removes its slot from every route.
#[test]
fn dropping_a_hold_removes_its_routes() {
    let shared = SharedSubscriber::new();
    let keep = shared.register(channels(1));
    let gone = shared.register(channels(1));
    drop(gone);
    assert_eq!(shared.watcher_count(), 1);
    assert_eq!(
        shared.lock().routes.values().map(Vec::len).sum::<usize>(),
        2
    );
    drop(keep);
    assert!(shared.lock().routes.is_empty());
}
