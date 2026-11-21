//! A grant completes only against the registration it began with, the code
//! exchange follows no redirect, and a stored credential is used only with
//! the registration it was granted through.

use super::*;
use crate::delegated::error::DelegatedError;
use axess_clock::Clock as _;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use axess_identity::{TenantId, UserId};
use axess_rng::testing::MockRng;
use serde_json::json;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn registration(name: &str, client_id: &str, token_endpoint: &str) -> DelegatedProvider {
    DelegatedProvider::new(
        name,
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(token_endpoint).unwrap(),
        client_id,
        "secret",
        Url::parse("https://example.org/callback").unwrap(),
    )
}

/// A token endpoint that answers every POST with a token and must receive
/// exactly `requests` of them by the time it is dropped.
async fn token_server(requests: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access",
            "token_type": "Bearer",
        })))
        .expect(requests)
        .mount(&server)
        .await;
    server
}

/// One tenant's registration, another tenant's of the same name, a shared
/// one of that name, and one that differs from the first by its client id
/// alone: a grant begun with the first completes only against the first,
/// and none of the others is sent anything.
#[tokio::test]
async fn a_grant_completes_only_against_the_registration_it_began_with() {
    let own = token_server(1).await;
    let other_tenant = token_server(0).await;
    let shared = token_server(0).await;
    let own_token = format!("{}/token", own.uri());
    let began = registration("mail", "acme-client", &own_token);
    let others = [
        registration(
            "mail",
            "beta-client",
            &format!("{}/token", other_tenant.uri()),
        ),
        registration("mail", "shared-client", &format!("{}/token", shared.uri())),
        registration("mail", "beta-client", &own_token),
    ];
    let (_, ctx) = begin_grant(&began, &[], &MockRng::new(1)).expect("begin_grant");
    let http = grant_client(|settings| settings).expect("client");
    let clock = MockClock::at_reference();

    for another in &others {
        let err = complete_grant(another, &ctx, "code", &ctx.state, &http, &clock)
            .await
            .expect_err("another registration of the same name was sent the code");
        assert!(
            matches!(&err, DelegatedError::RegistrationMismatch { provider } if provider == "mail"),
            "{err}"
        );
    }
    complete_grant(&began, &ctx, "code", &ctx.state, &http, &clock)
        .await
        .expect("the registration the grant began with");
}

/// The exchange carries the code, the verifier and the client credentials.
/// A token endpoint that answers with a redirect to another host is not
/// followed there: the other host receives nothing.
#[tokio::test]
async fn a_redirecting_token_endpoint_sends_the_code_exchange_nowhere_else() {
    let elsewhere = token_server(0).await;
    let location = format!("{}/token", elsewhere.uri());
    let first = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", location.as_str()))
        .expect(1)
        .mount(&first)
        .await;
    let provider = registration("mail", "client", &format!("{}/token", first.uri()));
    let (_, ctx) = begin_grant(&provider, &[], &MockRng::new(1)).expect("begin_grant");
    let http = grant_client(|settings| settings).expect("client");

    let err = complete_grant(
        &provider,
        &ctx,
        "code",
        &ctx.state,
        &http,
        &MockClock::at_reference(),
    )
    .await
    .expect_err("a redirect is an answer, not a token");

    assert!(
        matches!(&err, DelegatedError::TokenEndpoint { status: 307, .. }),
        "{err}"
    );
}

#[test]
fn a_registration_differs_when_any_of_its_five_values_does_and_not_by_its_secret() {
    let token = "https://idp.example/token";
    let base = GrantRegistration::of(&registration("mail", "client", token));

    let mut rotated_secret = registration("mail", "client", token);
    rotated_secret.client_secret = "rotated".into();
    assert_eq!(base, GrantRegistration::of(&rotated_secret));

    let mut other_authorize = registration("mail", "client", token);
    other_authorize.authorization_endpoint = Url::parse("https://idp.example/other").unwrap();
    let mut other_redirect = registration("mail", "client", token);
    other_redirect.redirect_uri = Url::parse("https://example.org/other").unwrap();
    for other in [
        registration("post", "client", token),
        registration("mail", "client-2", token),
        registration("mail", "client", "https://idp.example/token-2"),
        other_authorize,
        other_redirect,
    ] {
        assert_ne!(base, GrantRegistration::of(&other), "{other:?}");
    }

    // Each value is preceded by its length: a character moved from one
    // value to the next is another registration.
    assert_ne!(
        GrantRegistration::of(&registration("ab", "c", token)).fingerprint,
        GrantRegistration::of(&registration("a", "bc", token)).fingerprint,
    );
}

/// A token endpoint that answers every POST with an access token that
/// expires on arrival and a refresh token, so a stored credential is due a
/// refresh as soon as it is saved.
async fn expiring_token_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 0,
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;
    server
}

async fn requests(server: &MockServer) -> usize {
    server.received_requests().await.expect("requests").len()
}

fn owner() -> (TenantId, UserId) {
    (TenantId::from_bytes([1; 16]), UserId::from_bytes([2; 16]))
}

/// A credential granted through acme's `mail` registration, the one the
/// session is given or another, from a store that holds it as `stored`.
async fn token_for(
    stored: StoredDelegation,
    provider: DelegatedProvider,
    clock: &MockClock,
) -> Result<String, DelegatedError> {
    let (tenant, user) = owner();
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    store.save(&tenant, &user, stored).await.expect("save");
    StoredDelegationSession::new(Arc::new(provider), store, tenant, user)
        .expect("the default client builds")
        .with_clock(Arc::new(clock.clone()))
        .get_access_token()
        .await
}

/// The grant records the registration it was completed against, and the
/// credential is then used with that registration only. A session built
/// with another tenant's `mail` or a shared `mail` is refused by name,
/// whether the access token is due a refresh or still fresh, and neither of
/// those registrations' token endpoints is sent anything. The registration
/// the grant went through refreshes it.
#[tokio::test]
async fn a_stored_credential_is_used_only_with_the_registration_it_was_granted_through() {
    let acme = expiring_token_server().await;
    let other_tenant = expiring_token_server().await;
    let shared = expiring_token_server().await;
    let acme_token = format!("{}/token", acme.uri());
    let began = || registration("mail", "acme-client", &acme_token);
    let others = || {
        [
            registration(
                "mail",
                "beta-client",
                &format!("{}/token", other_tenant.uri()),
            ),
            registration("mail", "shared-client", &format!("{}/token", shared.uri())),
            registration("mail", "beta-client", &acme_token),
        ]
    };
    let clock = MockClock::at_reference();
    let (_, ctx) = begin_grant(&began(), &[], &MockRng::new(1)).expect("begin_grant");
    let http = grant_client(|settings| settings).expect("client");
    let granted = complete_grant(&began(), &ctx, "code", &ctx.state, &http, &clock)
        .await
        .expect("the grant completes");
    assert_eq!(
        granted.registration,
        Some(GrantRegistration::of(&began())),
        "the credential carries the registration it was granted through"
    );
    assert_eq!(requests(&acme).await, 1, "the code exchange");
    let fresh = StoredDelegation {
        expires_at: Some(clock.now().plus(axess_clock::SignedDuration::hours(1))),
        ..granted.clone()
    };

    for (index, another) in others().into_iter().enumerate() {
        for row in [granted.clone(), fresh.clone()] {
            let refused = token_for(row, registration_like(&another), &clock).await;
            assert!(
                matches!(&refused, Err(DelegatedError::RegistrationMismatch { provider }) if provider == "mail"),
                "registration {index}: {refused:?}"
            );
        }
    }
    assert_eq!(requests(&other_tenant).await, 0, "another tenant's mail");
    assert_eq!(requests(&shared).await, 0, "the shared mail");
    assert_eq!(
        requests(&acme).await,
        1,
        "nothing sent with another client id"
    );

    let refreshed = token_for(granted, began(), &clock)
        .await
        .expect("the registration the grant went through");
    assert_eq!(refreshed, "access");
    assert_eq!(
        requests(&acme).await,
        2,
        "the code exchange and one refresh"
    );
}

/// A credential stored with no registration (by a release before the
/// registration was recorded) is never used: not refreshed, and not handed
/// out while fresh. The session does not guess which registration it came
/// from; the user grants again.
#[tokio::test]
async fn a_credential_stored_without_a_registration_is_never_used() {
    let acme = expiring_token_server().await;
    let acme_token = format!("{}/token", acme.uri());
    let clock = MockClock::at_reference();
    let unbound = StoredDelegation {
        provider: "mail".to_string(),
        registration: None,
        access_token: "access".into(),
        refresh_token: Some("refresh".into()),
        expires_at: Some(clock.now()),
        scopes: vec![],
        token_type: "Bearer".to_string(),
    };
    let fresh = StoredDelegation {
        expires_at: Some(clock.now().plus(axess_clock::SignedDuration::hours(1))),
        ..unbound.clone()
    };

    for row in [unbound, fresh] {
        let refused = token_for(
            row,
            registration("mail", "acme-client", &acme_token),
            &clock,
        )
        .await;
        assert!(
            matches!(&refused, Err(DelegatedError::RegistrationMismatch { provider }) if provider == "mail"),
            "{refused:?}"
        );
    }
    assert_eq!(
        requests(&acme).await,
        0,
        "the refresh token is sent nowhere"
    );
}

/// A second value of the same registration: `DelegatedProvider` is not
/// `Clone`, and each session takes its own.
fn registration_like(provider: &DelegatedProvider) -> DelegatedProvider {
    DelegatedProvider::new(
        provider.name.clone(),
        provider.authorization_endpoint.clone(),
        provider.token_endpoint.clone(),
        provider.client_id.clone(),
        "secret",
        provider.redirect_uri.clone(),
    )
}
