//! A registry member and the channel of one session's revocation are named
//! by the session's key: nothing the registry writes or publishes holds a
//! value a cookie could carry, and a member that is not a key is never read
//! as one.

use super::internal::{ValkeyStoreError, user_keys};
use super::layout_tests::names_under;
use super::registry::ValkeySessionRegistry;
use super::registry_tests::connect;
use crate::authn::ids::UserId;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, SessionRegistry};
use axess_rng::SystemRng;
use axess_testing::mock_tracing::TracingCapture;
use fred::prelude::*;
use std::time::Duration;
use tracing::Level;

/// A registry built by its constructor under a prefix of its own.
async fn registry_under(prefix: &str) -> ValkeySessionRegistry {
    ValkeySessionRegistry::with_options(connect().await, prefix, Duration::from_secs(60))
        .await
        .expect("a registry")
}

/// The members of a sorted set, in order.
async fn members(client: &Client, set: &str) -> Vec<String> {
    client
        .zrange(set, 0_i64, -1_i64, None, false, None, false)
        .await
        .expect("ZRANGE")
}

/// `text` holds none of the forms of `id`: its hyphenated text, its 32
/// hexadecimal digits, or its 16 bytes.
fn holds_no_form_of(text: &str, id: &SessionId) -> bool {
    let hyphenated = id.to_string();
    !text.contains(&hyphenated)
        && !text.contains(&hyphenated.replace('-', ""))
        && !text.as_bytes().windows(16).any(|w| w == id.as_bytes())
}

/// A session is registered and revoked under its key: the two sets hold the
/// key's 64 characters, the revocation is published on the channel named by
/// the key, and no member, key name or channel holds the id in any form.
/// The registry's log lines name it by the key's first eight characters.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_session_is_held_and_revoked_under_its_key_alone() {
    let sweep = crate::testing::valkey_sweep::on_node("members");
    let prefix = sweep.prefix().to_owned();
    let registry = registry_under(&prefix).await;
    let (user, id) = (UserId::new(&SystemRng), SessionId::new(&SystemRng));
    let key = SessionKey::of(&id);

    let listener = connect().await;
    let mut published = listener.message_rx();
    listener
        .psubscribe(format!("{prefix}:revoked-session:*"))
        .await
        .expect("PSUBSCRIBE");

    let capture = TracingCapture::install();
    registry.register(&user, &key).await.expect("register");
    let client = connect().await;
    let keys = user_keys(&prefix, &user).expect("one slot");
    let mut written = Vec::new();
    for set in [&keys.registry, &keys.registered_at] {
        let held = members(&client, set).await;
        assert_eq!(held, vec![key.to_string()], "{set} holds the key's text");
        written.extend(held);
    }
    written.extend(names_under(&client, &prefix).await);

    registry
        .invalidate_session(&user, &key)
        .await
        .expect("invalidate");
    let message = tokio::time::timeout(Duration::from_secs(5), published.recv())
        .await
        .expect("published in time")
        .expect("a message");
    let channel = String::from(&*message.channel);
    assert_eq!(channel, format!("{prefix}:revoked-session:{key}"));
    written.push(channel);

    let kept = SessionKey::of(&SessionId::new(&SystemRng));
    registry.register(&user, &kept).await.expect("register");
    registry.register(&user, &key).await.expect("register");
    let CutOff::KeptOne(ended) = registry
        .invalidate_other_sessions(&user, &kept)
        .await
        .expect("the cut-off")
    else {
        panic!("the kept session is held");
    };
    assert_eq!(ended, vec![key]);

    for text in &written {
        assert!(holds_no_form_of(text, &id), "{text} holds the session id");
    }
    let lines: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|event| event.message.contains("valkey registry"))
        .collect();
    assert_eq!(
        lines.len(),
        5,
        "a register, its removal, two registers, the cut-off: {lines:?}"
    );
    for line in &lines {
        assert!(!line.message.contains(&key.to_string()), "{line}");
        assert!(!line.message.contains(&kept.to_string()), "{line}");
        assert!(holds_no_form_of(&line.message, &id), "{line}");
    }
    let prefix_of = |k: &SessionKey| k.prefix().to_string();
    for (line, named) in lines.iter().zip([key, key, kept, key, kept]) {
        assert!(line.message.contains(&prefix_of(&named)), "{line}");
    }
    listener.quit().await.expect("quit");
}

/// The text an earlier release wrote as a member: a session id.
fn planted_member() -> String {
    SessionId::new(&SystemRng).to_string()
}

/// A member that is not a key fails the listing, which lists nothing: a
/// shorter list would let the session limit count fewer sessions than the
/// registry holds. The error names no member.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_member_that_is_not_a_key_fails_the_listing() {
    let sweep = crate::testing::valkey_sweep::on_node("members");
    let prefix = sweep.prefix().to_owned();
    let registry = registry_under(&prefix).await;
    let user = UserId::new(&SystemRng);
    let session = SessionKey::of(&SessionId::new(&SystemRng));
    registry.register(&user, &session).await.expect("register");
    assert_eq!(
        registry.active_sessions(&user).await.unwrap(),
        vec![session]
    );

    let client = connect().await;
    let keys = user_keys(&prefix, &user).expect("one slot");
    let planted = planted_member();
    let score: Option<f64> = client
        .zscore(&keys.registry, session.to_string())
        .await
        .expect("ZSCORE");
    let score = score.expect("the session's score");
    client
        .zadd::<(), _, _>(
            &keys.registry,
            None,
            None,
            false,
            false,
            (score, planted.as_str()),
        )
        .await
        .expect("plant a member");

    let listed = registry.active_sessions(&user).await;
    let Err(ValkeyStoreError::Connection(error)) = &listed else {
        panic!("a member that is not a key fails the listing: {listed:?}");
    };
    let text = error.to_string();
    assert!(
        text.contains("a registry member is not a session key"),
        "{text}"
    );
    assert!(
        !text.contains(&planted),
        "the error names the member: {text}"
    );
}

/// The cut-off removes a member that is not a key with the rest, returns the
/// keys of the other sessions it ended, and says at `warn` that it met one,
/// without its text.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_cut_off_removes_a_member_that_is_not_a_key_and_warns() {
    let sweep = crate::testing::valkey_sweep::on_node("members");
    let prefix = sweep.prefix().to_owned();
    let registry = registry_under(&prefix).await;
    let user = UserId::new(&SystemRng);
    let [kept, other] = [(); 2].map(|()| SessionKey::of(&SessionId::new(&SystemRng)));
    registry.register(&user, &kept).await.expect("register");
    registry.register(&user, &other).await.expect("register");

    let client = connect().await;
    let keys = user_keys(&prefix, &user).expect("one slot");
    let planted = planted_member();
    let score: Option<f64> = client
        .zscore(&keys.registry, kept.to_string())
        .await
        .expect("ZSCORE");
    client
        .zadd::<(), _, _>(
            &keys.registry,
            None,
            None,
            false,
            false,
            (score.expect("the kept score"), planted.as_str()),
        )
        .await
        .expect("plant a member");

    let capture = TracingCapture::install();
    let CutOff::KeptOne(ended) = registry
        .invalidate_other_sessions(&user, &kept)
        .await
        .expect("the cut-off")
    else {
        panic!("the kept session is held");
    };
    assert_eq!(
        ended,
        vec![other],
        "the keys of the other sessions it ended"
    );
    assert_eq!(
        members(&client, &keys.registry).await,
        vec![kept.to_string()],
        "the planted member is removed with the rest"
    );
    assert!(
        capture.contains_at_level(Level::WARN, "not a session key"),
        "{:?}",
        capture.events()
    );
    assert!(
        !capture.contains(&planted),
        "the member's text is logged: {:?}",
        capture.events()
    );
}
