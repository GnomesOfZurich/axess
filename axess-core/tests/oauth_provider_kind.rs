//! The kind a global OAuth provider is registered with is what every login
//! through it records: the finish's row, the login's row and the session's
//! assurance, a refused callback, a refresh the provider refuses and both
//! rows of a revocation. A provider registered without a kind records
//! `Custom(name)`, as before; the tenant providers' kinds are tested in the
//! `oauth_tenant_world` binary.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_provider_kind`

#![cfg(all(feature = "oauth", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventType, AuthFailureReason};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::service::{AuthnService, OAuthCallbackRoute, RequestAuthnService};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::oauth::{OAuthLoginOptions, OAuthProviderConfig};
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

const CLIENT_ID: &str = "example-api";

struct Rig {
    server: MockServer,
    private_der: Vec<u8>,
    kid: String,
    authn: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
}

/// A service whose provider `test` is registered with `kind`, or without
/// one when `kind` is `None`.
async fn rig(kind: Option<FederatedProvider>) -> Rig {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &server.uri(),
        CLIENT_ID,
        "test-secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .expect("discovery")
    .with_clock(std::sync::Arc::new(clock.clone()))
    .build()
    .expect("build");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(common::test_tenant())
        .with_user(common::test_user("u1", "alice"));
    let builder =
        AuthnService::builder(identity.clone(), MockFactorStore::new()).with_clock(clock.clone());
    let builder = match kind {
        Some(kind) => builder.with_oauth_provider_of_kind(provider, kind),
        None => builder.with_oauth_provider(provider),
    };
    Rig {
        server,
        private_der,
        kid,
        authn: builder.build().with_audit_context(AuditContext::default()),
        identity,
    }
}

fn id_token(rig: &Rig, nonce: &str) -> String {
    let now = common::start().unix_seconds();
    let claims = json!({
        "iss": rig.server.uri(),
        "sub": "alice-subject",
        "aud": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(rig.kid.clone());
    axess_factors::jwt::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_der(&rig.private_der),
    )
    .expect("encode")
}

async fn session_value(session: &axess_core::AuthSession, key: &str) -> String {
    session
        .get_custom(key)
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect(key)
}

/// A whole login through `test`, then a refresh the provider refuses and a
/// revocation; the kinds every row and the assurance name.
async fn log_in_refresh_and_revoke(rig: &Rig) -> (Vec<(AuthEventType, FactorKind)>, FactorKind) {
    let session = test_session();
    rig.authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let nonce = session_value(&session, "axess.oauth.nonce").await;
    let csrf = session_value(&session, "axess.oauth.csrf_state").await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .mount(&rig.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token(rig, &nonce),
        })))
        .mount(&rig.server)
        .await;
    let claims = rig
        .authn
        .finish_oauth_login(
            OAuthCallbackRoute::global("test"),
            "code",
            &csrf,
            None,
            &session,
        )
        .await
        .expect("finish");
    rig.authn
        .complete_oauth_login(&common::test_user("u1", "alice"), &claims, &session)
        .await
        .expect("complete");
    let assurance = session.assurance().await;
    assert_eq!(assurance.len(), 1, "{assurance:?}");

    rig.authn
        .oauth_global()
        .refresh_oauth_token("test", "refresh", "alice-subject", None, None)
        .await
        .expect_err("the provider refuses the refresh");
    // The discovery document names no revocation endpoint: the request row
    // is written, and the outcome row records the refusal.
    let revoked = rig
        .authn
        .oauth_global()
        .revoke_oauth_token("test", "access", Some("access_token"), None)
        .await;
    assert!(revoked.is_err(), "{revoked:?}");

    let rows = rig
        .identity
        .events()
        .into_iter()
        .filter_map(|row| row.factor_kind.map(|kind| (row.event_type, kind)))
        .collect();
    (rows, assurance[0].kind.clone())
}

fn expected_types() -> Vec<AuthEventType> {
    vec![
        AuthEventType::LoginAttempt,
        AuthEventType::Authenticated,
        AuthEventType::LoginAttempt,
        AuthEventType::LogoutAttempt,
        AuthEventType::LogoutAttempt,
    ]
}

#[tokio::test]
async fn every_login_path_records_the_kind_the_provider_is_registered_with() {
    let rig = rig(Some(FederatedProvider::Google)).await;
    let (rows, assurance) = log_in_refresh_and_revoke(&rig).await;
    let google = FactorKind::Federated(FederatedProvider::Google);
    assert_eq!(assurance, google);
    assert_eq!(
        rows.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>(),
        expected_types(),
        "the finish, the login, the refused refresh and the revocation's two rows: {rows:?}"
    );
    assert!(rows.iter().all(|(_, kind)| *kind == google), "{rows:?}");
}

#[tokio::test]
async fn a_provider_registered_without_a_kind_records_its_name() {
    let rig = rig(None).await;
    let (rows, assurance) = log_in_refresh_and_revoke(&rig).await;
    let custom = FactorKind::Federated(FederatedProvider::Custom("test".into()));
    assert_eq!(assurance, custom);
    assert_eq!(rows.len(), expected_types().len(), "{rows:?}");
    assert!(rows.iter().all(|(_, kind)| *kind == custom), "{rows:?}");
}

#[tokio::test]
async fn a_refused_callback_records_the_registered_kind() {
    let rig = rig(Some(FederatedProvider::Github)).await;
    let session = test_session();
    rig.authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    rig.authn
        .finish_oauth_login(
            OAuthCallbackRoute::global("test"),
            "code",
            "not-the-state",
            None,
            &session,
        )
        .await
        .expect_err("the state does not match");
    let rows = rig.identity.events();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].error, Some(AuthFailureReason::CsrfMismatch));
    assert_eq!(
        rows[0].factor_kind,
        Some(FactorKind::Federated(FederatedProvider::Github))
    );
}

/// A refresh with no token is refused before its provider is asked, and its
/// row still records the kind the name is registered with.
#[tokio::test]
async fn a_refresh_with_no_token_records_the_registered_kind() {
    let rig = rig(Some(FederatedProvider::Google)).await;
    rig.authn
        .oauth_global()
        .refresh_oauth_token("test", "", "alice-subject", None, None)
        .await
        .expect_err("no refresh token");
    let rows = rig.identity.events();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].error, Some(AuthFailureReason::TokenRefreshNoToken));
    assert_eq!(
        rows[0].factor_kind,
        Some(FactorKind::Federated(FederatedProvider::Google))
    );
}
