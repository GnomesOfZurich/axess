//! The registration a credential was granted through is authenticated with
//! its envelopes: a row moved under another registration does not open, and
//! a row sealed before the registration was bound opens as granted through
//! none, which a session never uses.

use super::*;
use crate::delegated::error::DelegatedError;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use crate::delegated::stored::{DelegatedProvider, GrantRegistration, StoredDelegationSession};
use axess_clock::Timestamp;
use url::Url;
use wiremock::MockServer;

fn tenant() -> TenantId {
    TenantId::from_bytes([1u8; 16])
}

fn user() -> UserId {
    UserId::from_bytes([2u8; 16])
}

/// A `mail` registration whose token endpoint is `server`'s.
fn mail(server: &MockServer, client_id: &str) -> DelegatedProvider {
    DelegatedProvider::new(
        "mail",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(&format!("{}/token", server.uri())).unwrap(),
        client_id,
        "secret",
        Url::parse("https://example.org/callback").unwrap(),
    )
}

/// A credential granted through `registration`, fresh until 2030.
fn granted_through(registration: Option<GrantRegistration>) -> StoredDelegation {
    StoredDelegation {
        provider: "mail".to_string(),
        registration,
        access_token: ZeroizedString::from("at-plaintext"),
        refresh_token: Some(ZeroizedString::from("rt-plaintext")),
        expires_at: Some(Timestamp::from_utc(2030, 1, 1, 0, 0, 0).unwrap()),
        scopes: vec!["mail.read".to_string()],
        token_type: "Bearer".to_string(),
    }
}

type Store = EncryptedDelegatedCredentialStore<MemoryDelegatedCredentialStore, MemoryKeyProvider>;

fn store() -> Store {
    let keys = MemoryKeyProvider::new("k1", test_key(31)).expect("valid key");
    EncryptedDelegatedCredentialStore::new(MemoryDelegatedCredentialStore::new(), keys)
}

async fn raw(store: &Store) -> StoredDelegation {
    store
        .inner()
        .load(&tenant(), &user(), "mail")
        .await
        .expect("inner load")
        .expect("present")
}

/// The access token a session built with `provider` gets from `store`, on a
/// clock before the credential's expiry.
async fn token_from(store: Store, provider: DelegatedProvider) -> Result<String, DelegatedError> {
    let clock = axess_clock::testing::MockClock::at_reference();
    StoredDelegationSession::new(Arc::new(provider), Arc::new(store), tenant(), user())
        .expect("the default client builds")
        .with_clock(Arc::new(clock))
        .get_access_token()
        .await
}

/// A sealed row whose clear registration is rewritten, to another
/// registration of the same name or to none, fails to open: the envelopes
/// were sealed for the registration the credential was granted through. The
/// row as it was sealed opens, with that registration.
#[tokio::test]
async fn a_row_moved_under_another_registration_fails_to_open() {
    let server = MockServer::start().await;
    let own = GrantRegistration::of(&mail(&server, "acme-client"));
    let other = GrantRegistration::of(&mail(&server, "beta-client"));
    let store = store();
    store
        .save(&tenant(), &user(), granted_through(Some(own.clone())))
        .await
        .expect("save");
    let sealed = raw(&store).await;

    for moved in [Some(other), None] {
        store
            .inner()
            .save(
                &tenant(),
                &user(),
                StoredDelegation {
                    registration: moved.clone(),
                    ..sealed.clone()
                },
            )
            .await
            .expect("inner save");
        let opened = store.load(&tenant(), &user(), "mail").await;
        assert!(
            opened.as_ref().is_err_and(|e| e.contains("decrypt")),
            "a row moved under {moved:?} opened: {opened:?}"
        );
    }

    store
        .inner()
        .save(&tenant(), &user(), sealed)
        .await
        .expect("inner save");
    let opened = store
        .load(&tenant(), &user(), "mail")
        .await
        .expect("the row as sealed")
        .expect("present");
    assert_eq!(opened.registration, Some(own));
}

/// A row sealed in the format before the registration was bound (`v3`)
/// opens with its tokens and expiry but as granted through no registration,
/// whatever registration is written beside it; a session refuses it and
/// sends nothing. The same credential sealed now is used.
#[tokio::test]
async fn a_row_sealed_before_the_registration_was_bound_is_not_used() {
    let server = MockServer::start().await;
    let own = GrantRegistration::of(&mail(&server, "acme-client"));
    let current = CurrentKey {
        key_id: Arc::from("k1"),
        key: Arc::new(EncryptionKey::from_bytes(test_key(31))),
    };
    let plain = granted_through(Some(own.clone()));
    let v3 = |field: &[u8], text: &str| {
        let aad = build_aad_v3(
            "mail",
            &tenant(),
            &user(),
            field,
            &plain.scopes,
            &plain.token_type,
            plain.expires_at,
        );
        let sealed = encrypt_envelope(&current, &axess_rng::SystemRng, text, &aad).unwrap();
        ZeroizedString::from(sealed.replacen("v4.", "v3.", 1))
    };
    let before = StoredDelegation {
        access_token: v3(FIELD_ACCESS, "at-plaintext"),
        refresh_token: Some(v3(FIELD_REFRESH, "rt-plaintext")),
        ..plain.clone()
    };

    let legacy = store();
    legacy
        .inner()
        .save(&tenant(), &user(), before)
        .await
        .expect("inner save");
    let opened = legacy
        .load(&tenant(), &user(), "mail")
        .await
        .expect("a v3 row opens")
        .expect("present");
    assert_eq!(&*opened.access_token, "at-plaintext");
    assert_eq!(opened.expires_at, plain.expires_at, "its expiry is bound");
    assert_eq!(opened.registration, None, "its registration is not");
    let refused = token_from(legacy, mail(&server, "acme-client")).await;
    assert!(
        matches!(&refused, Err(DelegatedError::RegistrationMismatch { provider }) if provider == "mail"),
        "{refused:?}"
    );

    let now = store();
    now.save(&tenant(), &user(), plain).await.expect("save");
    let token = token_from(now, mail(&server, "acme-client"))
        .await
        .expect("sealed with its registration");
    assert_eq!(token, "at-plaintext");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "nothing is sent: one row is refused, the other fresh"
    );
}
