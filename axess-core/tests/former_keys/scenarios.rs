//! Each scenario on a world the caller built: the memory tests and the live
//! Valkey test run the same ones.

use axess_core::authn::service::Actor;
use axess_core::federation::sid_map::SidKey;

use crate::world::{Browser, ISSUER, SUBJECT, World, alice};

/// The rotations a handler can make: a completed step-up, the service's
/// `rotate_session`, and a bare `regenerate`.
pub const ROTATIONS: [(&str, &str); 3] = [
    ("/step-up", "Authenticated"),
    ("/rotate", "rotated"),
    ("/regenerate", "regenerated"),
];

fn sid_key(sid: &str) -> SidKey {
    (ISSUER.to_owned(), sid.to_owned())
}

/// An OAuth login, a rotation by `path`, then a back-channel logout naming
/// the login's `sid` (`by_sid`) or its subject alone: the provider is told
/// the session ended, and it has. The ending is reported by the key the
/// login registered.
pub async fn backchannel_after(w: &World, (path, answer): (&str, &str), by_sid: bool) {
    let mut b = Browser::default();
    let registered = w.oauth_login(&mut b, "idp-1").await;
    assert_eq!(w.get(&mut b, path).await, answer, "{path}");
    let current = w.key(&mut b).await;
    assert_ne!(current, registered, "{path} rotated the key");
    assert_eq!(
        w.held().await,
        vec![current],
        "{path}: held under its new key"
    );

    let status = if by_sid {
        w.backchannel_logout(None, Some("idp-1")).await
    } else {
        w.backchannel_logout(Some(SUBJECT), None).await
    };

    assert_eq!(status, 200, "{path}, by sid {by_sid}");
    assert!(
        w.held().await.is_empty(),
        "{path}, by sid {by_sid}: the registry holds nothing for the session"
    );
    assert_eq!(
        w.reported.keys(),
        vec![registered],
        "{path}, by sid {by_sid}: reported once, by the key the login registered"
    );
    assert_eq!(w.unmatched(), 0, "{path}, by sid {by_sid}");
    assert_eq!(
        w.get(&mut b, "/whoami").await,
        "guest",
        "{path}, by sid {by_sid}: the next request with the cookie is a guest"
    );
}

/// An OAuth login and a step-up, then the front-channel logout of the
/// login's `sid` from the session's own browser: the session ends.
pub async fn frontchannel_after_a_step_up(w: &World) {
    let mut b = Browser::default();
    let registered = w.oauth_login(&mut b, "idp-1").await;
    assert_eq!(w.get(&mut b, "/step-up").await, "Authenticated");
    assert_ne!(w.key(&mut b).await, registered);

    w.frontchannel_logout(&mut b, "idp-1").await;

    assert!(w.held().await.is_empty(), "the session is ended");
    assert!(
        w.sid.get(&sid_key("idp-1"), None).await.unwrap().is_none(),
        "the mapping is removed"
    );
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// The same, sent from another session's browser: nothing is ended.
pub async fn frontchannel_from_another_session(w: &World) {
    let (mut mine, mut other) = (Browser::default(), Browser::default());
    w.oauth_login(&mut mine, "idp-1").await;
    w.oauth_login(&mut other, "idp-2").await;
    assert_eq!(w.get(&mut mine, "/step-up").await, "Authenticated");
    let current = w.key(&mut mine).await;

    w.frontchannel_logout(&mut other, "idp-1").await;

    assert!(
        w.held().await.contains(&current),
        "another session's request ends nothing"
    );
    assert!(
        w.sid.get(&sid_key("idp-1"), None).await.unwrap().is_some(),
        "the mapping stays"
    );
    assert_eq!(w.get(&mut mine, "/whoami").await, "user");
    assert_eq!(w.get(&mut other, "/whoami").await, "user");
}

/// An OAuth login with no `sid`, which only the subject records reach, and
/// a rotation; then another login, whose upkeep sweeps the subject records:
/// the rotated session's record stays, so a logout by `sub` still ends it.
pub async fn the_sweep_keeps_a_rotated_session(w: &World) {
    let (mut b, mut later) = (Browser::default(), Browser::default());
    let registered = w.oauth_login(&mut b, "-").await;
    assert_eq!(w.get(&mut b, "/step-up").await, "Authenticated");
    let later_key = w.oauth_login(&mut later, "-").await;

    let subjects = w.sid.subject_sessions(ISSUER, SUBJECT, None).await.unwrap();
    assert!(
        subjects.contains(&(alice(), registered)),
        "the sweep kept the rotated session's record: {subjects:?}"
    );

    assert_eq!(w.backchannel_logout(Some(SUBJECT), None).await, 200);
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
    let mut reported = w.reported.keys();
    reported.sort();
    let mut expected = vec![registered, later_key];
    expected.sort();
    assert_eq!(reported, expected, "both sessions of the subject ended");
}

/// An OAuth login with no `sid` whose session is ended by a kick, then
/// another login: its upkeep's sweep forgets the ended session's subject
/// record.
pub async fn the_sweep_forgets_an_ended_session(w: &World) {
    let (mut b, mut later) = (Browser::default(), Browser::default());
    let registered = w.oauth_login(&mut b, "-").await;
    w.authn
        .invalidate_session(&alice(), &registered, Actor::System)
        .await
        .expect("the kick");
    let later_key = w.oauth_login(&mut later, "-").await;

    assert_eq!(
        w.sid.subject_sessions(ISSUER, SUBJECT, None).await.unwrap(),
        vec![(alice(), later_key)],
        "only the live session's record is left"
    );
}

/// `active_sessions` is read, the session rotates, and the listed key is
/// kicked: the session ends, its row goes, and the audit row names the key
/// it was under when it ended.
pub async fn a_kick_after_a_rotation(w: &World) {
    let mut b = Browser::default();
    w.oauth_login(&mut b, "idp-1").await;
    let listed = w.authn.active_sessions(&alice()).await.expect("listed");
    assert_eq!(w.get(&mut b, "/step-up").await, "Authenticated");
    let current = w.key(&mut b).await;
    assert_ne!(vec![current], listed);
    let rows = w.invalidation_rows().len();

    w.authn
        .invalidate_session(&alice(), &listed[0], Actor::Admin(&crate::world::admin()))
        .await
        .expect("a kick of a listed key ends the session");

    assert!(w.held().await.is_empty(), "the session is ended");
    assert!(!w.row(&current).await, "its row is deleted");
    let after = w.invalidation_rows();
    assert_eq!(after.len(), rows + 1, "one row");
    assert_eq!(
        after.last(),
        Some(&Some(current)),
        "the row names the key the session was under when it ended"
    );
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// An OAuth login whose session a kick ended, and a back-channel logout
/// for it, by `sid` or by `sub`: nothing is reported, no row is written,
/// the records go, and the token counts as one that ended nothing.
pub async fn a_logout_for_a_session_that_is_gone(w: &World, by_sid: bool) {
    let mut b = Browser::default();
    let registered = w.oauth_login(&mut b, "idp-1").await;
    w.authn
        .invalidate_session(&alice(), &registered, Actor::System)
        .await
        .expect("the kick");
    let rows = w.invalidation_rows().len();

    let status = if by_sid {
        w.backchannel_logout(None, Some("idp-1")).await
    } else {
        w.backchannel_logout(Some(SUBJECT), None).await
    };

    assert_eq!(status, 200, "by sid {by_sid}");
    assert!(
        w.reported.keys().is_empty(),
        "by sid {by_sid}: no ending is reported"
    );
    assert_eq!(
        w.invalidation_rows().len(),
        rows,
        "by sid {by_sid}: no row is written"
    );
    assert!(
        w.sid.get(&sid_key("idp-1"), None).await.unwrap().is_none(),
        "by sid {by_sid}: the mapping is removed"
    );
    assert!(
        w.sid
            .subject_sessions(ISSUER, SUBJECT, None)
            .await
            .unwrap()
            .is_empty(),
        "by sid {by_sid}: the subject record is removed"
    );
    assert_eq!(w.unmatched(), 1, "by sid {by_sid}: counted as unmatched");
}
