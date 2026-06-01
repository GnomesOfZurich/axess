#![cfg(all(feature = "testing", feature = "fido2"))]
//! FIDO2 integration smoke tests: `MockFido2Provider` failure
//! semantics, missing-provider returns `NoFlow`, and `DefaultFido2Provider`
//! stores ceremony state in the session on begin.

mod common;

use axess_core::{
    authn::service::AuthnService,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use axess_factors::fido2::{DefaultFido2Provider, Fido2Provider, MockFido2Provider};
use common::{test_tenant, test_user};
use url::Url;
use webauthn_rs::prelude::*;

/// MockFido2Provider returns CredentialNotFound for all ceremony operations.
/// This verifies the service handles mock errors gracefully.
#[test]
fn mock_provider_returns_errors_for_all_ceremonies() {
    let mock = MockFido2Provider::new();

    // start_registration should fail
    let reg = mock.start_registration(uuid::Uuid::new_v4(), "alice", "Alice", None);
    assert!(reg.is_err());

    // start_authentication with empty credentials; should fail
    let auth = mock.start_authentication(&[]);
    assert!(auth.is_err());

    // start_discoverable_authentication; should fail
    let disc = mock.start_discoverable_authentication();
    assert!(disc.is_err());
}

/// Service with MockFido2Provider: begin_fido2_registration returns NoFlow
/// because the mock's start_registration fails.
#[tokio::test]
async fn service_begin_registration_with_mock_returns_error() {
    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors).with_fido2(MockFido2Provider::new());

    let session = test_session();
    let result = service
        .begin_fido2_registration(&test_user("u1", "alice"), &session)
        .await;

    assert!(result.is_err(), "expected error from mock provider");
}

/// Service without FIDO2 provider configured: begin_fido2_registration
/// returns NoFlow.
#[tokio::test]
async fn service_begin_registration_without_provider_returns_no_flow() {
    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);

    let session = test_session();
    let result = service
        .begin_fido2_registration(&test_user("u1", "alice"), &session)
        .await;

    assert!(result.is_err(), "expected NoFlow without FIDO2 provider");
}

/// Service without FIDO2 provider: begin_discoverable_login returns NoFlow.
#[tokio::test]
async fn service_discoverable_login_without_provider_returns_no_flow() {
    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);

    let session = test_session();
    let result = service.begin_discoverable_login(&session).await;
    assert!(result.is_err());
}

/// Use a real DefaultFido2Provider with a test origin to verify that
/// begin_registration produces a valid challenge and stores ceremony
/// state in the session.
#[tokio::test]
async fn real_provider_begin_registration_stores_ceremony_state() {
    let rp_origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .unwrap()
        .build()
        .unwrap();
    let provider = DefaultFido2Provider::new(webauthn);

    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors).with_fido2(provider);

    let session = test_session();
    let result = service
        .begin_fido2_registration(&test_user("u1", "alice"), &session)
        .await;

    assert!(
        result.is_ok(),
        "begin_registration should succeed: {result:?}"
    );
    let (challenge_json, new_webauthn_id) = result.unwrap();

    assert!(
        challenge_json.is_object(),
        "challenge should be a JSON object"
    );
    assert!(
        challenge_json.get("publicKey").is_some(),
        "challenge should contain publicKey"
    );

    // Since test_user has no webauthn_id, a new one should be generated.
    assert!(
        new_webauthn_id.is_some(),
        "new webauthn_id should be generated for user without one"
    );

    let reg_state = session.get_custom("axess.fido2.reg_state").await;
    assert!(
        reg_state.is_some() && !reg_state.as_ref().unwrap().is_null(),
        "registration state should be stored in session"
    );

    let ceremony_ts = session.get_custom("axess.fido2.ceremony_started").await;
    assert!(
        ceremony_ts.is_some() && !ceremony_ts.as_ref().unwrap().is_null(),
        "ceremony timestamp should be stored in session"
    );
}

/// Use a real DefaultFido2Provider to verify begin_authentication
/// produces a challenge when credentials exist.
#[tokio::test]
async fn real_provider_begin_discoverable_authentication() {
    let rp_origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .unwrap()
        .build()
        .unwrap();
    let provider = DefaultFido2Provider::new(webauthn);

    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors).with_fido2(provider);

    let session = test_session();
    let result = service.begin_discoverable_login(&session).await;

    assert!(
        result.is_ok(),
        "begin_discoverable_login should succeed: {result:?}"
    );
    let challenge = result.unwrap();
    assert!(challenge.is_object(), "challenge should be a JSON object");

    let disc_state = session.get_custom("axess.fido2.disc_state").await;
    assert!(
        disc_state.is_some() && !disc_state.as_ref().unwrap().is_null(),
        "discoverable auth state should be stored in session"
    );
}

/// Verify that finish_fido2_registration fails gracefully when no
/// ceremony state exists (simulating an out-of-order call).
#[tokio::test]
async fn finish_registration_without_begin_returns_error() {
    let rp_origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .unwrap()
        .build()
        .unwrap();
    let provider = DefaultFido2Provider::new(webauthn);

    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors).with_fido2(provider);

    let session = test_session();

    // Construct a dummy RegisterPublicKeyCredential: it won't validate,
    // but the service should reject it before crypto validation because
    // no ceremony state exists in the session.
    let dummy_response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "attestationObject": "AAAA",
            "clientDataJSON": "AAAA"
        }
    }))
    .unwrap();

    let result = service
        .finish_fido2_registration(
            &test_user("u1", "alice"),
            &dummy_response,
            "my-key",
            &session,
        )
        .await;

    assert!(
        result.is_err(),
        "should fail without prior begin_registration"
    );
}
