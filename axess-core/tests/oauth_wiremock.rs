//! Full-flow OAuth/OIDC integration test using wiremock.
//!
//! Exercises the real HTTP code path: OIDC discovery → JWKS fetch →
//! begin_oauth_login → finish_oauth_login (token exchange + ID token
//! verification). No external services needed; wiremock serves all endpoints.
//!
//! Run with: `cargo test -p axess-core --features oauth,testing --test oauth_wiremock`

#![cfg(all(feature = "oauth", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::OAuthCallbackRoute;
use axess_core::{
    authn::service::AuthnService,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use axess_factors::oauth::{OAuthLoginOptions, OAuthProviderBuilder, OAuthProviderConfig};
use axess_testing::mock_tracing::TracingCapture;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{test_tenant, test_user};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Generate an RSA-2048 key pair and return (private DER, JWK public key JSON, kid).
fn generate_rsa_keypair() -> (Vec<u8>, serde_json::Value, String) {
    use rsa::RsaPrivateKey;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();

    let kid = "test-key-1".to_string();

    // Private key in PKCS#1 DER for jsonwebtoken.
    let private_der = private_key
        .to_pkcs1_der()
        .expect("PKCS1 DER encode")
        .as_bytes()
        .to_vec();

    // Build JWK from the public key components.
    let n_bytes = {
        use rsa::traits::PublicKeyParts;
        public_key.n().to_bytes_be()
    };
    let e_bytes = {
        use rsa::traits::PublicKeyParts;
        public_key.e().to_bytes_be()
    };

    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(&n_bytes),
        "e": URL_SAFE_NO_PAD.encode(&e_bytes),
    });

    (private_der, jwk, kid)
}

/// Build an OIDC discovery document pointing to wiremock endpoints.
fn discovery_document(issuer: &str) -> serde_json::Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "email", "name", "iss", "aud", "exp", "iat", "nonce"],
    })
}

/// Build a signed ID token JWT.
fn build_id_token(
    issuer: &str,
    client_id: &str,
    subject: &str,
    nonce: &str,
    kid: &str,
    private_der: &[u8],
) -> String {
    build_id_token_with(
        issuer,
        client_id,
        subject,
        nonce,
        kid,
        private_der,
        json!({}),
    )
}

/// As [`build_id_token`], with `extra` claims merged over the defaults.
fn build_id_token_with(
    issuer: &str,
    client_id: &str,
    subject: &str,
    nonce: &str,
    kid: &str,
    private_der: &[u8],
    extra: serde_json::Value,
) -> String {
    let now = common::start().unix_seconds();
    let mut claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
        "email": "alice@example.com",
        "email_verified": true,
        "name": "Alice Test",
    });
    claims
        .as_object_mut()
        .expect("object")
        .extend(extra.as_object().expect("extra object").clone());

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());

    let key = EncodingKey::from_rsa_der(private_der);
    axess_factors::jwt::encode(&header, &claims, &key).expect("JWT encode")
}

/// Full OIDC discovery → provider setup succeeds against wiremock.
#[tokio::test]
async fn oidc_discovery_succeeds() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    // Mount discovery endpoint.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    // Mount JWKS endpoint.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "test-client-id",
        "test-client-secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .map(|b| b.with_clock(std::sync::Arc::new(common::test_clock())))
    .and_then(OAuthProviderBuilder::build);

    assert!(provider.is_ok(), "discovery failed: {:?}", provider.err());
}

/// Full flow: discover → begin_oauth_login → finish_oauth_login with signed JWT.
#[tokio::test]
async fn full_oauth_flow_with_signed_id_token() {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client-id";
    let (private_der, jwk, kid) = generate_rsa_keypair();

    // Mount discovery.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    // Mount JWKS.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    // Discover the provider.
    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        client_id,
        "test-secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .expect("discovery should succeed")
    .with_clock(std::sync::Arc::new(clock.clone()))
    .build()
    .expect("build");

    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let authn = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();

    // 1. Begin OAuth login; get the authorization URL.
    let (auth_url, _) = authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin_oauth_login should succeed");

    // Verify the auth URL points to our mock server.
    assert!(
        auth_url
            .as_str()
            .starts_with(&format!("{issuer}/authorize")),
        "auth URL should point to mock: {auth_url}"
    );

    // 2. Extract the nonce from the session (we need it to build a valid ID token).
    let nonce = session
        .get_custom("axess.oauth.nonce")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .expect("nonce should be in session");

    let csrf_state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .expect("CSRF state should be in session");

    // 3. Build a signed ID token.
    let id_token = build_id_token(
        &issuer,
        client_id,
        "alice-subject",
        &nonce,
        &kid,
        &private_der,
    );

    // 4. Mount the token endpoint; returns the signed ID token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;

    // 5. Finish the OAuth login with the correct CSRF state and a dummy code.
    let result = authn
        .finish_oauth_login(
            OAuthCallbackRoute::global("test"),
            "authorization-code-from-idp",
            &csrf_state,
            None,
            &session,
        )
        .await;

    match result {
        Ok(claims) => {
            assert_eq!(claims.subject.as_str(), "alice-subject");
            assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        }
        Err(e) => {
            panic!("finish_oauth_login failed: {e:?}");
        }
    }
}

/// The tenant declared at begin must still be on the session when
/// `complete_oauth_login` runs after a real `finish_oauth_login`, so a
/// resolver that returns a user from another tenant is refused.
#[tokio::test]
async fn cross_tenant_user_refused_after_real_finish() {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client-id";
    let (private_der, jwk, kid) = generate_rsa_keypair();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;
    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        client_id,
        "test-secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .expect("discovery should succeed")
    .with_clock(std::sync::Arc::new(clock.clone()))
    .build()
    .expect("build");

    let other_tenant_user = common::test_user_in_tenant("u1", "alice", "t2");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(other_tenant_user.clone());
    let authn = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();

    authn
        .begin_oauth_login_in_tenant(
            "test",
            &OAuthLoginOptions::default(),
            &common::tid("t1"),
            &session,
        )
        .await
        .expect("begin should succeed");
    let nonce = session
        .get_custom("axess.oauth.nonce")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("nonce");
    let csrf = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("csrf");
    let id_token = build_id_token(
        &issuer,
        client_id,
        "alice-subject",
        &nonce,
        &kid,
        &private_der,
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;

    let claims = authn
        .finish_oauth_login(
            OAuthCallbackRoute::global("test"),
            "code",
            &csrf,
            None,
            &session,
        )
        .await
        .expect("finish should succeed");
    let res = authn
        .complete_oauth_login(&other_tenant_user, &claims, &session)
        .await;
    assert!(
        matches!(res, Err(axess_core::authn::error::AuthnError::CrossTenant)),
        "expected CrossTenant, got {res:?}"
    );
    assert!(!session.is_authenticated().await);
}

/// Log in through a discovered provider, with `extra` claims in the ID
/// token, and return the claims `finish_oauth_login` produced.
async fn login_with_extra_claims(
    extra: serde_json::Value,
) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client-id";
    let (private_der, jwk, kid) = generate_rsa_keypair();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({ "request_uri": "urn:par:1", "expires_in": 60 })),
        )
        .mount(&server)
        .await;
    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        client_id,
        "test-secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .expect("discovery should succeed")
    .with_clock(std::sync::Arc::new(clock.clone()))
    .build()
    .expect("build");
    let authn = AuthnService::builder(
        MockIdentityStore::new().with_clock(clock.clone()),
        MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .with_oauth_provider(provider)
    .build()
    .with_audit_context(AuditContext::default());
    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let nonce = session
        .get_custom("axess.oauth.nonce")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("nonce");
    let csrf = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("csrf");
    let id_token = build_id_token_with(
        &issuer,
        client_id,
        "alice-subject",
        &nonce,
        &kid,
        &private_der,
        extra,
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;
    authn
        .finish_oauth_login(
            OAuthCallbackRoute::global("test"),
            "code",
            &csrf,
            None,
            &session,
        )
        .await
}

/// `groups`, `roles` and `sid` in the ID token reach `OAuthClaims`, so
/// back-channel logout by `sid` has a session to match.
#[tokio::test]
async fn id_token_groups_roles_and_sid_reach_oauth_claims() {
    let claims = login_with_extra_claims(
        json!({ "groups": ["g1", "g2"], "roles": ["admin"], "sid": "idp-session-9" }),
    )
    .await
    .expect("login");
    assert_eq!(claims.groups, vec!["g1", "g2"]);
    assert_eq!(claims.roles, vec!["admin"]);
    assert_eq!(claims.oidc_sid.as_deref(), Some("idp-session-9"));
}

/// Token endpoint returning error should propagate as TokenExchange error.
#[tokio::test]
async fn oauth_token_endpoint_error_propagates() {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    // Token endpoint returns an error.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "authorization code expired"
        })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(std::sync::Arc::new(clock.clone()))
    .build()
    .unwrap();

    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let authn = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .unwrap();

    let csrf = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap();

    let result = authn
        .finish_oauth_login(
            OAuthCallbackRoute::global("test"),
            "expired-code",
            &csrf,
            None,
            &session,
        )
        .await;
    assert!(result.is_err(), "should fail on token exchange error");
}

/// A 400 response carrying `error: "unsupported_token_type"`
/// (RFC 7009 §2.2.1) maps to the typed `UnsupportedTokenType` variant
/// rather than the catch-all `TokenExchange`.
#[tokio::test]
async fn revoke_unsupported_token_type_maps_to_typed_variant() {
    let clock = common::test_clock();
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    let mut discovery = discovery_document(&issuer);
    discovery["revocation_endpoint"] = json!(format!("{issuer}/revoke"));

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    // RFC 7009: AS rejects with 400 + unsupported_token_type.
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "unsupported_token_type",
        })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(std::sync::Arc::new(clock.clone()))
    .with_revocation_endpoint(format!("{issuer}/revoke"))
    .build()
    .unwrap();

    let err = provider
        .revoke_token("dummy-token", Some("access_token"), None)
        .await
        .expect_err("revoke must fail on unsupported_token_type");
    assert!(
        matches!(err, OAuthError::UnsupportedTokenType),
        "expected OAuthError::UnsupportedTokenType, got {err:?}"
    );
}

/// A logout JWT signed by a key whose `kid` is not in the
/// cached JWKS produces the typed `OAuthError::UnknownKid(kid)`,
/// not a `Config(...)` string error. The back-channel logout handler
/// pattern-matches on this variant to drive the JWKS-refresh + retry.
#[tokio::test]
async fn unknown_kid_yields_typed_variant() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    // JWKS publishes "key-1" only.
    let (_, jwk_published, _) = generate_rsa_keypair();
    // We sign with a different key + a kid the JWKS does NOT carry.
    let (private_unknown, _, _) = generate_rsa_keypair();
    let kid_unknown = "rotated-but-not-yet-published".to_string();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk_published] })))
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(std::sync::Arc::new(common::test_clock()))
    .build()
    .unwrap();

    let now = common::start().unix_seconds();
    let claims = json!({
        "iss": issuer,
        "aud": "client-id",
        "iat": now,
        "jti": "logout-1",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        "sub": "user-123",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid_unknown.clone());
    let key = EncodingKey::from_rsa_der(&private_unknown);
    let token = axess_factors::jwt::encode(&header, &claims, &key).expect("JWT encode");

    let err = provider
        .verify_logout_jwt(&token)
        .expect_err("verify must fail on unknown kid");
    match err {
        OAuthError::UnknownKid(kid) => {
            assert_eq!(kid, kid_unknown);
        }
        other => panic!("expected OAuthError::UnknownKid, got {other:?}"),
    }
}

/// With the explicit-type switch on, a logout token whose `typ` is the plain
/// `JWT` jsonwebtoken writes by default is refused before its key is looked up;
/// with the switch off the same token gets as far as the key lookup.
#[tokio::test]
async fn a_required_logout_typ_refuses_a_generic_jwt_header() {
    let clock = common::test_clock();
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk_published, _) = generate_rsa_keypair();
    let (private_unknown, _, _) = generate_rsa_keypair();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk_published] })))
        .mount(&server)
        .await;

    let discover = || async {
        OAuthProviderConfig::discover_screened(
            "test",
            &issuer,
            "client-id",
            "secret",
            "http://localhost:3000/callback",
            axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
        )
        .await
        .map(|b| b.with_clock(std::sync::Arc::new(clock.clone())))
    };
    let lenient = discover().await.unwrap().build().unwrap();
    let strict = discover()
        .await
        .unwrap()
        .with_required_logout_typ()
        .build()
        .unwrap();

    let claims = json!({
        "iss": issuer,
        "aud": "client-id",
        "iat": common::start().unix_seconds(),
        "jti": "logout-1",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        "sub": "user-123",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("not-published".to_string());
    let key = EncodingKey::from_rsa_der(&private_unknown);
    let token = axess_factors::jwt::encode(&header, &claims, &key).expect("JWT encode");

    match strict.verify_logout_jwt(&token) {
        Err(OAuthError::IdTokenValidation(reason)) => {
            assert!(reason.contains("logout+jwt"), "{reason}");
        }
        other => panic!("expected a refused typ, got {other:?}"),
    }
    assert!(
        matches!(
            lenient.verify_logout_jwt(&token),
            Err(OAuthError::UnknownKid(_))
        ),
        "the lenient provider reaches the key lookup"
    );

    header.typ = Some("logout+jwt".to_string());
    let explicit = axess_factors::jwt::encode(&header, &claims, &key).expect("JWT encode");
    assert!(
        matches!(
            strict.verify_logout_jwt(&explicit),
            Err(OAuthError::UnknownKid(_))
        ),
        "the explicit type passes the check and reaches the key lookup"
    );
}

/// A provider pinned to `RS256` (the default `id_token_signed_response_alg`)
/// refuses a logout token signed with another algorithm, even one the IdP's
/// key set could verify; the same token passes an unpinned provider. The
/// token is signed with a published RS256 key here, so the pin is what
/// decides: a provider pinned to `ES256` refuses it, one pinned to `RS256`
/// takes it, and an empty or symmetric list is refused when it is set.
#[tokio::test]
async fn a_pinned_algorithm_list_decides_which_logout_tokens_verify() {
    let clock = common::test_clock();
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    let (private, jwk_published, kid) = generate_rsa_keypair();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&issuer)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk_published] })))
        .mount(&server)
        .await;

    let discover = || async {
        OAuthProviderConfig::discover_screened(
            "test",
            &issuer,
            "client-id",
            "secret",
            "http://localhost:3000/callback",
            axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
        )
        .await
        .map(|b| b.with_clock(std::sync::Arc::new(clock.clone())))
    };
    let unpinned = discover().await.unwrap().build().unwrap();
    let rs256 = discover()
        .await
        .unwrap()
        .with_id_token_signing_algs(["RS256"])
        .build()
        .unwrap();
    let es256 = discover()
        .await
        .unwrap()
        .with_id_token_signing_algs(["ES256"])
        .build()
        .unwrap();

    let claims = json!({
        "iss": issuer,
        "aud": "client-id",
        "iat": common::start().unix_seconds(),
        "exp": common::start().unix_seconds() + 120,
        "jti": "logout-1",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        "sub": "user-123",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid);
    let token = axess_factors::jwt::encode(&header, &claims, &EncodingKey::from_rsa_der(&private))
        .expect("JWT encode");

    unpinned.verify_logout_jwt(&token).expect("unpinned");
    rs256.verify_logout_jwt(&token).expect("pinned to RS256");
    match es256.verify_logout_jwt(&token) {
        Err(OAuthError::IdTokenValidation(reason)) => {
            assert!(reason.contains("disallowed JWT algorithm"), "{reason}");
        }
        other => panic!("expected the algorithm to be refused, got {other:?}"),
    }

    assert!(matches!(
        discover()
            .await
            .unwrap()
            .with_id_token_signing_algs(Vec::<String>::new())
            .build(),
        Err(OAuthError::Config(_))
    ));
    assert!(matches!(
        discover()
            .await
            .unwrap()
            .with_id_token_signing_algs(["HS256"])
            .build(),
        Err(OAuthError::Config(_))
    ));
}

/// A 503 response from the revocation endpoint maps to the
/// typed `TokenEndpointTransient` variant so callers can decide to
/// retry instead of treating it the same as a permanent rejection.
#[tokio::test]
async fn revoke_5xx_maps_to_transient_variant() {
    let clock = common::test_clock();
    use axess_factors::oauth::{OAuthError, OAuthProvider};

    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();

    let mut discovery = discovery_document(&issuer);
    discovery["revocation_endpoint"] = json!(format!("{issuer}/revoke"));

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("upstream temporarily unavailable"),
        )
        .mount(&server)
        .await;

    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(std::sync::Arc::new(clock.clone()))
    .with_revocation_endpoint(format!("{issuer}/revoke"))
    .build()
    .unwrap();

    let err = provider
        .revoke_token("dummy-token", None, None)
        .await
        .expect_err("revoke must fail on 5xx");
    match err {
        OAuthError::TokenEndpointTransient { status } => {
            assert_eq!(status, Some(503));
        }
        other => panic!("expected TokenEndpointTransient, got {other:?}"),
    }
}

/// Answers 200 (or the given body) only to a request that carries its client
/// secret in a `client_secret_basic` header and not in the form, as an
/// authorization server that accepts nothing else does; any other request
/// is `invalid_client`.
struct BasicOnly(ResponseTemplate);

impl wiremock::Respond for BasicOnly {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let basic = request
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("Basic "));
        let in_form = String::from_utf8_lossy(&request.body).contains("client_secret");
        if basic && !in_form {
            self.0.clone()
        } else {
            ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"}))
        }
    }
}

/// A provider with a client secret, whose token, revocation and device
/// endpoints refuse a secret sent in the form.
async fn basic_only_provider(
    server: &MockServer,
    token_answer: ResponseTemplate,
) -> OAuthProviderBuilder {
    let clock = common::test_clock();
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();
    let mut discovery = discovery_document(&issuer);
    discovery["revocation_endpoint"] = json!(format!("{issuer}/revoke"));
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(BasicOnly(token_answer))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(BasicOnly(ResponseTemplate::new(200)))
        .mount(server)
        .await;
    OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(std::sync::Arc::new(clock.clone()))
    .with_revocation_endpoint(format!("{issuer}/revoke"))
}

#[tokio::test]
async fn revocation_authenticates_with_basic_when_the_client_holds_a_secret() {
    use axess_factors::oauth::OAuthProvider;
    let server = MockServer::start().await;
    let provider = basic_only_provider(&server, ResponseTemplate::new(200))
        .await
        .build()
        .unwrap();
    provider
        .revoke_token("dummy-token", None, None)
        .await
        .expect("an IdP that accepts only Basic revokes the token");
}

#[tokio::test]
async fn client_credentials_authenticates_with_basic_when_the_client_holds_a_secret() {
    use axess_factors::oauth::OAuthProvider;
    let server = MockServer::start().await;
    let answer = ResponseTemplate::new(200).set_body_json(json!({
        "access_token": "at", "token_type": "Bearer", "expires_in": 60
    }));
    let provider = basic_only_provider(&server, answer).await.build().unwrap();
    provider
        .client_credentials(&["scope-a"], None)
        .await
        .expect("an IdP that accepts only Basic grants the token");
}

#[tokio::test]
async fn the_device_poll_authenticates_with_basic_when_the_client_holds_a_secret() {
    use axess_factors::oauth::{DeviceTokenOutcome, OAuthProvider};
    let server = MockServer::start().await;
    let answer = ResponseTemplate::new(200);
    let provider = basic_only_provider(&server, answer).await.build().unwrap();
    // A pending answer is reachable only when the client authenticated.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(BasicOnly(
            ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"})),
        ))
        .with_priority(1)
        .mount(&server)
        .await;
    let outcome = provider
        .poll_device_token("device-code", 5, None, None)
        .await
        .expect("a poll an IdP that accepts only Basic understands");
    assert!(matches!(outcome, DeviceTokenOutcome::Pending));
}

/// The IdP's refusal text reaches the caller with control characters and the
/// Unicode line separators escaped and its length capped, so an IdP (or a
/// party between) cannot forge a log line through a device-flow denial.
#[tokio::test]
async fn the_device_poll_denial_text_is_log_safe() {
    use axess_factors::oauth::{DeviceTokenOutcome, OAuthProvider};
    let server = MockServer::start().await;
    let provider = basic_only_provider(&server, ResponseTemplate::new(200))
        .await
        .build()
        .unwrap();
    // Long enough to cross the 512-byte cap, short enough for the whole
    // error body to stay under the 1 KiB the error reader keeps.
    let mut description = "declined\r\nINFO forged line\x1b[2J\u{2028}".to_string();
    description.push_str(&"A".repeat(600));
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(BasicOnly(ResponseTemplate::new(400).set_body_json(
            json!({"error": "access_denied", "error_description": description}),
        )))
        .with_priority(1)
        .mount(&server)
        .await;

    let outcome = provider
        .poll_device_token("device-code", 5, None, None)
        .await
        .expect("a refusal is an outcome, not an error");
    let DeviceTokenOutcome::Denied(text) = outcome else {
        panic!("expected Denied, got {outcome:?}");
    };
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(!text.contains('\u{2028}'), "{text:?}");
    assert!(
        text.contains("declined") && text.contains("forged line"),
        "{text}"
    );
    assert!(text.len() <= 512, "{} bytes", text.len());
}

/// An upstream `error` code that carries a line break, a terminal escape
/// and a Unicode line separator: what a forged log line is made of.
const FORGED_ERROR_CODE: &str = "invalid_scope\r\nINFO forged line\x1b[2J\u{2028}";

/// `text` kept the words of the forged code and none of its control
/// characters or line separators.
fn assert_log_safe(text: &str) {
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(!text.contains('\u{2028}'), "{text:?}");
    assert!(
        text.contains("invalid_scope") && text.contains("forged line"),
        "{text}"
    );
}

/// The captured log line whose message holds `message` carries the code
/// escaped, not raw.
fn assert_log_line_is_safe(capture: &TracingCapture, message: &str) {
    let events = capture.events();
    let line = events
        .iter()
        .find(|e| e.message.contains(message))
        .unwrap_or_else(|| panic!("no log line {message:?} among {events:?}"));
    assert_log_safe(&line.message);
}

/// The `error` code of a refused device authorization request is the
/// identity provider's text as much as a description is: it comes out with
/// control characters and the line separators escaped, in the error the
/// caller gets and in the log line.
#[tokio::test]
async fn the_device_authorization_refusal_code_is_log_safe() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};
    let capture = TracingCapture::install();
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(BasicOnly(
            ResponseTemplate::new(400).set_body_json(json!({"error": FORGED_ERROR_CODE})),
        ))
        .mount(&server)
        .await;
    let provider = basic_only_provider(&server, ResponseTemplate::new(200))
        .await
        .with_device_authorization_endpoint(format!("{issuer}/device"))
        .build()
        .unwrap();

    let err = provider
        .request_device_code(&["openid"])
        .await
        .expect_err("a refused request is an error");
    let OAuthError::DeviceAuthorization(code) = &err else {
        panic!("expected DeviceAuthorization, got {err:?}");
    };
    assert_log_safe(code);
    assert_log_line_is_safe(&capture, "device authorization endpoint error");
}

/// The `error` code of a refused `client_credentials` grant comes out
/// escaped, in the error and in the log line.
#[tokio::test]
async fn the_client_credentials_refusal_code_is_log_safe() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};
    let capture = TracingCapture::install();
    let server = MockServer::start().await;
    let answer = ResponseTemplate::new(400).set_body_json(json!({"error": FORGED_ERROR_CODE}));
    let provider = basic_only_provider(&server, answer).await.build().unwrap();

    let err = provider
        .client_credentials(&["scope-a"], None)
        .await
        .expect_err("a refused grant is an error");
    let OAuthError::TokenExchange(code) = &err else {
        panic!("expected TokenExchange, got {err:?}");
    };
    assert_log_safe(code);
    assert_log_line_is_safe(&capture, "client_credentials token endpoint error");
}

/// A refused revocation names the server's `error` code in its log line
/// only (the error keeps the status): the code comes out escaped there.
#[tokio::test]
async fn the_revocation_refusal_code_is_log_safe() {
    use axess_factors::oauth::OAuthProvider;
    let capture = TracingCapture::install();
    let server = MockServer::start().await;
    let provider = basic_only_provider(&server, ResponseTemplate::new(200))
        .await
        .build()
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(BasicOnly(
            ResponseTemplate::new(400).set_body_json(json!({"error": FORGED_ERROR_CODE})),
        ))
        .with_priority(1)
        .mount(&server)
        .await;

    provider
        .revoke_token("dummy-token", None, None)
        .await
        .expect_err("a refused revocation is an error");
    assert_log_line_is_safe(&capture, "token revocation failed");
}

/// A refused authorization-code or refresh grant keeps the token endpoint's
/// `error` and `error_description` in its message, which the login logs:
/// both are the identity provider's text and come out with control
/// characters and the line separators escaped.
#[tokio::test]
async fn the_code_and_refresh_grant_refusal_text_is_log_safe() {
    use axess_factors::oauth::{OAuthError, OAuthProvider};
    let server = MockServer::start().await;
    let answer = ResponseTemplate::new(400).set_body_json(json!({
        "error": FORGED_ERROR_CODE,
        "error_description": "code expired\nERROR forged description\x1b[2J\u{2029}",
    }));
    let provider = basic_only_provider(&server, answer).await.build().unwrap();

    let code = provider
        .exchange_code("code", "verifier".to_string(), "nonce".to_string(), None)
        .await
        .expect_err("a refused code grant is an error");
    let refresh = provider
        .refresh_token("refresh-token", "subject", None, None)
        .await
        .expect_err("a refused refresh grant is an error");
    for err in [code, refresh] {
        let OAuthError::TokenExchange(text) = &err else {
            panic!("expected TokenExchange, got {err:?}");
        };
        assert_log_safe(text);
        assert!(!text.contains('\u{2029}'), "{text:?}");
        assert!(
            text.contains("invalid_scope\\r\\nINFO forged line\\u{1b}[2J\\u{2028}"),
            "the code is kept, escaped: {text}"
        );
        assert!(
            text.contains("code expired\\nERROR forged description\\u{1b}[2J\\u{2029}"),
            "the description is kept, escaped: {text}"
        );
        // The message is what a log line carries.
        assert!(!err.to_string().chars().any(char::is_control), "{err:?}");
    }
}

/// A token endpoint that answers 200 and then drops the connection before
/// the body is complete. Returns the endpoint's address.
async fn token_endpoint_that_cuts_off_its_body() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                          content-length: 500\r\n\r\n{\"access_token\":\"at",
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

/// The connection broke while the answer was being read: the IdP may answer
/// whole next time, so the failure is one a retry can cure.
#[tokio::test]
async fn a_token_answer_cut_off_after_a_200_is_transient() {
    use axess_factors::oauth::OAuthProvider;
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (_, jwk, _) = generate_rsa_keypair();
    let cut = token_endpoint_that_cuts_off_its_body().await;
    let mut discovery = discovery_document(&issuer);
    discovery["token_endpoint"] = json!(format!("http://{cut}/token"));
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;
    let provider = OAuthProviderConfig::discover_screened(
        "test",
        &issuer,
        "client-id",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(std::sync::Arc::new(common::test_clock()))
    .build()
    .unwrap();

    let err = provider
        .client_credentials(&["scope-a"], None)
        .await
        .expect_err("the answer was cut off");

    assert!(
        err.is_transient(),
        "a cut-off body is not permanent: {err:?}"
    );
}
