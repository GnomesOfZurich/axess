//! Every flow that names a session to a door, driven through the world's
//! application in one run: what each door must have seen is returned beside
//! it.

use axess_core::authn::service::Actor;
use axess_core::session::SessionKey;
use axess_factors::key_proof::testing::SoftwareKey;

use crate::doors::RecordingStore;
use crate::world::{Browser, MAX_AGE, World};

/// The sessions each door must have been handed, by key.
#[derive(Default)]
pub struct Expected {
    /// Every session a cookie named that reached the store.
    pub stored: Vec<SessionKey>,
    /// Every session that was signed in, which the registry holds.
    pub registered: Vec<SessionKey>,
    /// The sessions an OAuth login recorded in the sid store.
    pub mapped: Vec<SessionKey>,
    /// The sessions the layer ended and told its sink of.
    pub ended: Vec<SessionKey>,
    /// The sessions a back-channel logout ended.
    pub logged_out: Vec<SessionKey>,
    /// The sessions an audit row of the service names.
    pub audited: Vec<SessionKey>,
    /// A session a log line names by its prefix.
    pub logged: Vec<SessionKey>,
    /// Sessions the layer's sink was told of under one of two keys: the
    /// one a failed rotation loaded and the one it rotated to.
    pub ended_either: Vec<[SessionKey; 2]>,
    /// The flows' outcomes that were not as expected. The test fails on
    /// them after the doors are searched, so a door that was handed a
    /// session id fails the test for that first, whatever it changed.
    pub mismatches: Vec<String>,
}

macro_rules! check {
    ($seen:ident, $cond:expr $(, $why:expr)? $(,)?) => {
        if !$cond {
            $seen
                .mismatches
                .push(format!("line {}: {} {}", line!(), stringify!($cond), stringify!($($why)?)));
        }
    };
}

macro_rules! check_eq {
    ($seen:ident, $left:expr, $right:expr $(, $why:expr)? $(,)?) => {{
        let (left, right) = ($left, $right);
        if left != right {
            $seen.mismatches.push(format!(
                "line {}: {left:?} where {right:?} was expected",
                line!()
            ));
        }
    }};
}

macro_rules! check_ne {
    ($seen:ident, $left:expr, $right:expr $(, $why:expr)? $(,)?) => {{
        let (left, right) = ($left, $right);
        if left == right {
            $seen.mismatches.push(format!(
                "line {}: {left:?} was not to be {right:?}",
                line!()
            ));
        }
    }};
}

/// Run every flow. `store` is the world's session store, told to fail its
/// cycles for the one flow whose rotation fails.
pub async fn run<S>(w: &World, store: &RecordingStore<S>) -> Expected {
    let mut seen = Expected::default();
    let alice = axess_core::testing::fixtures::uid("u1");
    let bob = axess_core::testing::fixtures::uid("u2");
    let admin = axess_core::testing::fixtures::uid("admin");

    // A guest request that stores a session.
    let mut main = Browser::default();
    check_eq!(seen, w.get(&mut main, "/guest").await, "guest");
    seen.stored.push(main.key());

    // A login with a second factor, and a request.
    check_eq!(seen, w.get(&mut main, "/login").await, "Authenticated");
    check_eq!(seen, w.get(&mut main, "/whoami").await, "user");
    let signed_in = main.key();
    seen.stored.push(signed_in);
    seen.registered.push(signed_in);
    seen.audited.push(signed_in);

    // A step-up, then a rotation the application asks for.
    w.get(&mut main, "/step-up").await;
    check_eq!(
        seen,
        w.get(&mut main, "/whoami").await,
        "user",
        "the step-up finished"
    );
    check_eq!(seen, w.get(&mut main, "/regenerate").await, "regenerated");
    check_eq!(seen, w.get(&mut main, "/whoami").await, "user");
    seen.stored.push(main.key());
    seen.registered.push(main.key());

    // The service's rotation, on a browser of its own: the handler asks for
    // it and the layer moves the registry entry, so the session survives
    // under its new key.
    w.next_code();
    let mut rotating = Browser::default();
    check_eq!(seen, w.get(&mut rotating, "/login").await, "Authenticated");
    check_eq!(seen, w.get(&mut rotating, "/rotate").await, "rotated");
    check_eq!(seen, w.get(&mut rotating, "/whoami").await, "user");
    seen.stored.push(rotating.key());
    seen.registered.push(rotating.key());

    // A second browser signs in; the first cuts its other sessions off.
    w.next_code();
    let mut other = Browser::default();
    check_eq!(seen, w.get(&mut other, "/login").await, "Authenticated");
    let cut = other.key();
    seen.registered.push(cut);
    check_eq!(seen, w.get(&mut main, "/cut-off").await, "cut off");
    check_eq!(seen, w.get(&mut main, "/whoami").await, "user");
    check_eq!(
        seen,
        w.get(&mut other, "/whoami").await,
        "guest",
        "the cut-off ended it"
    );

    // An OAuth login that writes the sid store, ended by a back-channel
    // logout.
    let mut federated = Browser::default();
    check_eq!(
        seen,
        w.get(&mut federated, "/oauth/idp-session-1").await,
        "in"
    );
    let by_backchannel = federated.key();
    seen.mapped.push(by_backchannel);
    seen.logged_out.push(by_backchannel);
    check_eq!(seen, w.backchannel_logout("idp-session-1").await, 200);
    check_eq!(seen, w.get(&mut federated, "/whoami").await, "guest");

    // Another, ended by a front-channel logout on its own browser.
    let mut framed = Browser::default();
    check_eq!(seen, w.get(&mut framed, "/oauth/idp-session-2").await, "in");
    seen.mapped.push(framed.key());
    w.get(
        &mut framed,
        &format!(
            "/frontchannel?iss={}&sid=idp-session-2",
            crate::world::ISSUER
        ),
    )
    .await;
    check_eq!(seen, w.get(&mut framed, "/whoami").await, "guest");

    // A key registration and a request the key proves.
    w.next_code();
    let mut keyed = Browser::default();
    check_eq!(seen, w.get(&mut keyed, "/login").await, "Authenticated");
    check_eq!(seen, w.get(&mut keyed, "/whoami").await, "user");
    w.register(&mut keyed, &SoftwareKey::from_seed([7; 32]))
        .await;
    check_eq!(
        seen,
        w.get(&mut keyed, "/bound").await,
        "true",
        "a bound request"
    );
    seen.stored.push(keyed.key());

    // An administrator's kick: refused first for a session that is not the
    // named user's, which the refusal's log line names by its prefix.
    let kicked = keyed.key();
    check!(
        seen,
        w.authn
            .invalidate_session(&bob, &kicked, Actor::Admin(&admin))
            .await
            .is_err()
    );
    seen.logged.push(kicked);
    w.authn
        .invalidate_session(&alice, &kicked, Actor::Admin(&admin))
        .await
        .expect("the kick");
    check_eq!(seen, w.get(&mut keyed, "/whoami").await, "guest");

    // A login whose rotation fails in the store: the layer ends the session
    // and tells its sink, under the key it was loaded by or the one it was
    // rotating to.
    w.next_code();
    let mut failing = Browser::default();
    check_eq!(seen, w.get(&mut failing, "/guest").await, "guest");
    let loaded = failing.key();
    store.fail_cycles(true);
    w.get(&mut failing, "/login").await;
    store.fail_cycles(false);
    let rotated = failing.key();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    check_ne!(seen, rotated, loaded, "the cookie carries the rotated id");
    seen.ended_either.push([loaded, rotated]);
    check_eq!(seen, w.get(&mut failing, "/whoami").await, "guest");

    // A logout.
    w.next_code();
    let mut leaving = Browser::default();
    check_eq!(seen, w.get(&mut leaving, "/login").await, "Authenticated");
    check_eq!(seen, w.get(&mut leaving, "/logout").await, "out");
    check_eq!(seen, w.get(&mut leaving, "/whoami").await, "guest");

    // The age cap ends the first browser's session on its next request.
    let capped = main.key();
    w.clock.advance_secs(MAX_AGE.as_secs() as i64 + 60);
    check_eq!(seen, w.get(&mut main, "/whoami").await, "guest");
    seen.ended.push(capped);
    seen
}
