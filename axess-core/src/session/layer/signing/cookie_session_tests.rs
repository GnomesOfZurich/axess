//! The session a cookie names: its key is the key of its id, a signed
//! cookie reads back as the same session, and its `Debug` shows eight
//! characters of the key and nothing of the id.

use super::*;
use axess_rng::testing::MockRng;

#[test]
fn a_minted_session_holds_the_key_of_its_id() {
    let session = CookieSession::mint(&MockRng::new(11));
    assert_eq!(session.id, SessionId::new(&MockRng::new(11)));
    assert_eq!(*session.key(), SessionKey::of(&session.id));
}

#[test]
fn two_minted_sessions_differ_in_id_and_key() {
    let rng = MockRng::new(12);
    let (one, other) = (CookieSession::mint(&rng), CookieSession::mint(&rng));
    assert_ne!(one.id, other.id);
    assert_ne!(one.key(), other.key());
}

#[test]
fn a_signed_cookie_reads_back_as_the_same_session() {
    let ring = SigningKeyRing::from_master(&[0x5A; 32]);
    let session = CookieSession::mint(&MockRng::new(13));
    let verified = ring
        .decode_cookie(&ring.sign_cookie(&session))
        .expect("a cookie this ring signed verifies");
    assert_eq!(verified.session.id, session.id);
    assert_eq!(verified.session.key(), session.key());
    assert_eq!(*verified.session.key(), SessionKey::of(&session.id));
    assert!(!verified.verified_by_previous);
}

/// The key a decoded cookie carries is the key of the id in that cookie,
/// not of another value the decoder had at hand (the encoded text, the
/// signature).
#[test]
fn a_decoded_cookie_holds_the_key_of_the_id_it_carries() {
    let key = [0xA5; 32];
    let id = SessionId::from_bytes([0xC3; 16]);
    let cookie = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(id.as_bytes()),
        sign_bytes(id.as_bytes(), &key)
    );
    let session = decode_cookie_with_key(&cookie, &key).expect("the cookie verifies");
    assert_eq!(session.id, id);
    assert_eq!(
        session.key().to_string(),
        SessionKey::of(&SessionId::from_bytes([0xC3; 16])).to_string()
    );
}

#[test]
fn debug_shows_the_log_form_of_the_key_and_not_the_id() {
    let session = CookieSession::of_id(SessionId::from_bytes([7; 16]));
    let printed = format!("{session:?}");
    assert_eq!(printed, "CookieSession(SessionKey(01068096...))");
    let verified = VerifiedCookie {
        session,
        verified_by_previous: false,
    };
    for printed in [printed, format!("{verified:?}"), format!("{verified:#?}")] {
        assert!(!printed.contains(&session.id.to_string()));
        assert!(!printed.contains("07070707"));
        assert!(!printed.contains(&session.key().to_string()));
    }
}
