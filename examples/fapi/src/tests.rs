use super::*;

const REALM: &str = include_str!("../keycloak/fapi-realm.json");
const COMPOSE: &str = include_str!("../keycloak/compose.yml");
const REALM_ISSUER: &str = "http://localhost:8080/realms/fapi";

fn realm() -> serde_json::Value {
    serde_json::from_str(REALM).expect("realm JSON")
}

fn realm_client() -> serde_json::Value {
    realm()["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .find(|c| c["clientId"] == "axess-fapi-client")
        .expect("the example's client")
        .clone()
}

/// The bundled realm authenticates the example's client by
/// `private_key_jwt` with `ES256` and holds no secret for it.
#[test]
fn the_realm_authenticates_the_client_by_private_key_jwt() {
    let client = realm_client();
    assert_eq!(client["clientAuthenticatorType"], "client-jwt");
    assert!(client.get("secret").is_none(), "the realm holds no secret");
    assert_eq!(
        client["attributes"]["token.endpoint.auth.signing.alg"],
        "ES256"
    );
    assert_eq!(client["attributes"]["use.jwks.string"], "true");
}

/// The development key signs assertions that verify under the key the
/// realm registers for the client, with the `kid` it registers it under,
/// so the key file and the realm cannot drift apart unnoticed.
#[test]
fn the_development_key_is_the_key_the_realm_registers() {
    let client = realm_client();
    let jwks: serde_json::Value = serde_json::from_str(
        client["attributes"]["jwks.string"]
            .as_str()
            .expect("jwks.string"),
    )
    .expect("JWKS");
    let jwk = &jwks["keys"][0];
    assert_eq!(jwk["kid"], DEV_CLIENT_KEY_ID);

    let assertion = ClientKey::development()
        .signer("axess-fapi-client")
        .expect("the development key parses")
        .mint(REALM_ISSUER, &axess::SystemClock, &axess::SystemRng)
        .expect("an assertion");
    let key = jsonwebtoken::DecodingKey::from_ec_components(
        jwk["x"].as_str().expect("x"),
        jwk["y"].as_str().expect("y"),
    )
    .expect("the realm's key");
    let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
    validation.set_audience(&[REALM_ISSUER]);
    let verified = jsonwebtoken::decode::<serde_json::Value>(&assertion, &key, &validation)
        .expect("the assertion verifies under the realm's key");
    assert_eq!(verified.header.kid.as_deref(), Some(DEV_CLIENT_KEY_ID));
    assert_eq!(verified.claims["iss"], "axess-fapi-client");
    assert_eq!(verified.claims["sub"], "axess-fapi-client");
}

/// Keycloak signs ID tokens `RS256` unless told otherwise, and the FAPI
/// profile refuses `RS256`: the client must ask for an algorithm the
/// profile accepts, and the realm must hold a key for it.
#[test]
fn the_realm_signs_id_tokens_with_an_algorithm_the_profile_accepts() {
    let realm = realm();
    let alg = realm_client()["attributes"]["id.token.signed.response.alg"]
        .as_str()
        .expect("the client names its ID token algorithm")
        .to_string();
    assert!(
        FapiConfig::default().allowed_id_token_algs.contains(&alg),
        "{alg} is outside the profile's list"
    );
    assert_eq!(realm["defaultSignatureAlgorithm"], alg.as_str());
    let (provider, curve) = match alg.as_str() {
        "ES256" => ("ecdsa-generated", Some("P-256")),
        "PS256" => ("rsa-generated", None),
        "EdDSA" => ("eddsa-generated", None),
        other => panic!("no key provider known for {other}"),
    };
    let providers = realm["components"]["org.keycloak.keys.KeyProvider"]
        .as_array()
        .expect("the realm declares its key providers")
        .clone();
    assert!(
        providers.iter().any(|p| p["providerId"] == provider
            && curve.is_none_or(|c| p["config"]["ecdsaEllipticCurveKey"][0] == c)),
        "no {provider} key for {alg}: {providers:?}"
    );
}

/// Keycloak 26.0 treats DPoP as a preview feature: without the flag it
/// ignores the proof and issues `Bearer` tokens, which the profile
/// refuses.
#[test]
fn the_bundled_keycloak_enables_dpop() {
    assert!(COMPOSE.contains("--features=dpop"));
    assert_eq!(
        realm_client()["attributes"]["dpop.bound.access.tokens"],
        "true"
    );
}

/// The redirect URI and the post-logout redirect the example sends are
/// registered, on the host the example serves.
#[test]
fn the_realm_registers_the_example_s_redirects() {
    let client = realm_client();
    let callback = format!("{APP_ORIGIN}/auth/callback");
    assert!(
        client["redirectUris"]
            .as_array()
            .expect("redirectUris")
            .iter()
            .any(|u| u == callback.as_str()),
        "{callback} is not registered"
    );
    let post_logout = format!("{APP_ORIGIN}/");
    assert!(
        client["attributes"]["post.logout.redirect.uris"]
            .as_str()
            .expect("post.logout.redirect.uris")
            .split("##")
            .any(|u| u == post_logout),
        "{post_logout} is not registered"
    );
}

/// The login asks for `offline_access`, which Keycloak grants only to a
/// user holding that role. A user imported with an explicit role list
/// gets no default roles, so the realm names them.
#[test]
fn the_demo_user_may_have_a_refresh_token() {
    let realm = realm();
    let alice = realm["users"]
        .as_array()
        .expect("users")
        .iter()
        .find(|u| u["username"] == "alice")
        .expect("alice")
        .clone();
    let default_roles = format!("default-roles-{}", realm["realm"].as_str().expect("realm"));
    assert!(
        alice["realmRoles"]
            .as_array()
            .expect("realmRoles")
            .iter()
            .any(|r| r == default_roles.as_str()),
        "alice lacks {default_roles}, which holds offline_access"
    );
}

/// The success page shows `groups` and `roles`, which the library reads
/// from top-level ID token claims; Keycloak puts neither there unless the
/// client maps them.
#[test]
fn the_client_maps_groups_and_roles_into_the_id_token() {
    let client = realm_client();
    let mappers = client["protocolMappers"]
        .as_array()
        .expect("protocolMappers");
    for claim in ["groups", "roles"] {
        assert!(
            mappers
                .iter()
                .any(|m| m["config"]["claim.name"] == claim
                    && m["config"]["id.token.claim"] == "true"),
            "no ID token mapper for {claim}"
        );
    }
}

/// The DPoP key survives the session: restored, it is the same key.
#[test]
fn the_dpop_key_round_trips_through_the_session_value() {
    let key = DpopKey::generate(&SystemRng);
    let restored = dpop_key_from_json(dpop_key_to_json(&key)).expect("restored");
    assert_eq!(
        restored.thumbprint().expect("thumbprint"),
        key.thumbprint().expect("thumbprint")
    );
}

/// The mock IdP accepts any code, so it runs only when asked for.
#[test]
fn the_mock_idp_runs_only_when_asked_for() {
    assert!(run_mode(None, None).is_err(), "unset issuer must not mock");
    assert!(run_mode(Some(""), None).is_err());
    assert!(run_mode(None, Some("0")).is_err());
    assert!(run_mode(None, Some("yes")).is_err());
    assert_eq!(run_mode(None, Some("1")), Ok(Mode::Mock));
    assert_eq!(run_mode(Some("https://idp.example"), None), Ok(Mode::Live));
    assert!(run_mode(Some("https://idp.example"), Some("1")).is_err());
}

/// The published development key signs only for a local issuer.
#[test]
fn the_development_key_signs_only_for_a_local_issuer() {
    for local in [
        "http://localhost:8080/realms/fapi",
        "http://127.0.0.1:8080/realms/fapi",
        "http://LOCALHOST/realms/fapi",
    ] {
        assert!(ClientKey::load(local, None).is_ok(), "{local}");
    }
    for remote in [
        "https://idp.bank.example/realms/fapi",
        "https://localhost.evil.example/realms/fapi",
        "http://localhost@evil.example/realms/fapi",
        "https://evil.example/localhost",
        "localhost",
    ] {
        let err = ClientKey::load(remote, None).err().expect(remote);
        assert!(err.contains("FAPI_PRIVATE_KEY_FILE is required"), "{err}");
    }
}

fn test_app() -> Router {
    let (provider, provider_name) = build_mock_provider();
    let tenant = TenantId::new(&SystemRng);
    let identity = MockIdentityStore::new().with_tenant(
        Tenant::new(
            tenant.to_string(),
            "fapi-test",
            "FAPI test tenant",
            EntityState::Active,
            UserId::system(),
            SystemClock.now(),
        )
        .expect("tenant"),
    );
    let registry = axess::MemorySessionRegistry::new();
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry.clone())
        .with_oauth_provider(provider)
        .build();
    let state = AppState {
        authn: Arc::new(authn),
        identity,
        tenant,
        allowed_email_domains: vec!["bank.example.com".to_string()],
        provider_name,
        post_logout_redirect: format!("{APP_ORIGIN}/"),
    };
    let layer = SessionLayer::new(
        MemorySessionStore::new(),
        *b"0123456789abcdef0123456789abcdeF",
        registry.handle(),
    )
    .with_secure(false);
    routes().with_state(state).layer(layer)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
) -> axum::http::StatusCode {
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    app.clone()
        .oneshot(req.body(axum::body::Body::empty()).expect("request"))
        .await
        .expect("response")
        .status()
}

/// The login asks for `form_post`, so a code in the URL is not accepted.
#[tokio::test]
async fn a_code_in_the_query_of_a_get_callback_is_not_accepted() {
    let status = send(&test_app(), "GET", "/auth/callback?code=c&state=s", &[]).await;
    assert_eq!(status, axum::http::StatusCode::METHOD_NOT_ALLOWED);
}

/// A cross-site page cannot refresh or log the user out.
#[tokio::test]
async fn refresh_and_logout_refuse_a_cross_origin_post() {
    let app = test_app();
    for uri in ["/auth/refresh", "/auth/logout"] {
        for headers in [
            &[("origin", "https://evil.example")][..],
            &[("sec-fetch-site", "cross-site")][..],
            &[][..],
        ] {
            let status = send(&app, "POST", uri, headers).await;
            assert_eq!(
                status,
                axum::http::StatusCode::FORBIDDEN,
                "{uri} {headers:?}"
            );
        }
        for headers in [
            &[("origin", APP_ORIGIN)][..],
            &[("sec-fetch-site", "same-origin")][..],
        ] {
            let status = send(&app, "POST", uri, headers).await;
            assert_ne!(
                status,
                axum::http::StatusCode::FORBIDDEN,
                "{uri} {headers:?}"
            );
        }
    }
}

/// Only identities the tenant policy names are created as local users.
#[test]
fn the_tenant_policy_decides_who_may_sign_up() {
    let allowed = parse_domains(" Bank.Example.com , ");
    assert_eq!(allowed, ["bank.example.com"]);
    assert!(domain_allowed(&allowed, Some("alice@bank.example.com")));
    assert!(domain_allowed(&allowed, Some("alice@BANK.example.com")));
    assert!(!domain_allowed(&allowed, Some("alice@evil.example")));
    assert!(!domain_allowed(
        &allowed,
        Some("alice@sub.bank.example.com")
    ));
    assert!(!domain_allowed(&allowed, Some("@bank.example.com")));
    assert!(!domain_allowed(&allowed, Some("bank.example.com")));
    assert!(!domain_allowed(&allowed, None));
    assert!(!domain_allowed(&[], Some("alice@bank.example.com")));
}

fn claims(sub: &str, email: &str) -> OAuthClaims {
    OAuthClaims {
        provider: "fapi-mock".into(),
        subject: sub.to_string(),
        email: Some(email.to_string()),
        email_verified: Some(true),
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: None,
        nonce: None,
        id_token_hint: None,
        additional_claims: serde_json::json!({"iss": "https://idp.example"}),
        dpop_key: None,
    }
}

fn test_state() -> AppState {
    let tenant = TenantId::new(&SystemRng);
    let identity = MockIdentityStore::new().with_tenant(
        Tenant::new(
            tenant.to_string(),
            "fapi-test",
            "FAPI test tenant",
            EntityState::Active,
            UserId::system(),
            SystemClock.now(),
        )
        .expect("tenant"),
    );
    let (provider, provider_name) = build_mock_provider();
    AppState {
        authn: Arc::new(
            AuthnService::builder(identity.clone(), MockFactorStore::new())
                .with_oauth_provider(provider)
                .build(),
        ),
        identity,
        tenant,
        allowed_email_domains: vec!["bank.example.com".to_string()],
        provider_name,
        post_logout_redirect: format!("{APP_ORIGIN}/"),
    }
}

/// An identity outside the tenant policy gets no local user; one inside
/// it gets the same user on every login.
#[tokio::test]
async fn an_identity_outside_the_policy_is_not_provisioned() {
    let state = test_state();
    let outsider = claims("s-1", "mallory@evil.example");
    assert!(local_user(&state, &outsider).await.is_err());
    let identifier = "https://idp.example#s-1";
    assert!(
        state
            .identity
            .find_user(identifier, &state.tenant)
            .await
            .expect("lookup")
            .is_none(),
        "a refused identity must leave no user behind"
    );
    let member = claims("s-2", "alice@bank.example.com");
    let first = local_user(&state, &member).await.expect("created");
    let again = local_user(&state, &member).await.expect("found");
    assert_eq!(first.id, again.id);
}

/// One client address cannot start logins without bound.
#[tokio::test]
async fn login_is_rate_limited_per_client() {
    let app = test_app();
    for i in 0..LOGIN_LIMIT {
        let status = send(&app, "GET", "/auth/login", &[]).await;
        assert_ne!(
            status,
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "request {i}"
        );
    }
    let status = send(&app, "GET", "/auth/login", &[]).await;
    assert_eq!(status, axum::http::StatusCode::TOO_MANY_REQUESTS);
    // Other routes are not counted against it.
    let status = send(&app, "GET", "/", &[]).await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

/// An address the IdP did not verify, or did not say anything about, creates
/// no user, even inside the allowed domain; a verified one still does.
#[tokio::test]
async fn an_unverified_email_is_not_provisioned() {
    let state = test_state();
    let mut unverified = claims("sub-unverified", "alice@bank.example.com");
    unverified.email_verified = Some(false);
    let mut silent = claims("sub-silent", "alice@bank.example.com");
    silent.email_verified = None;
    for (sub, c) in [("sub-unverified", &unverified), ("sub-silent", &silent)] {
        assert!(local_user(&state, c).await.is_err(), "{sub}");
        let identifier = format!("https://idp.example#{sub}");
        assert!(
            state
                .identity
                .find_user(&identifier, &state.tenant)
                .await
                .expect("lookup")
                .is_none(),
            "{sub} left a user behind"
        );
    }
    let verified = claims("sub-verified", "alice@bank.example.com");
    assert!(local_user(&state, &verified).await.is_ok());
}

/// The development key signs only for an issuer whose host, as an HTTP client
/// parses it, is local. A backslash, which a client reads as a slash, a
/// `user@` prefix and a look-alike host do not make a remote host local.
#[test]
fn only_a_local_host_is_a_local_issuer() {
    for local in [
        "http://localhost:8080/realms/fapi",
        "http://LOCALHOST/realms/fapi",
        "https://127.0.0.1:8443/",
        "http://localhost",
    ] {
        assert!(is_local_issuer(local), "{local}");
    }
    for remote in [
        "http://evil.example\\@localhost",
        "http://evil.example\\@127.0.0.1/",
        "http://localhost@evil.example/",
        "http://localhost.evil.example/",
        "http://evil.example/localhost",
        "http://evil.example/?x=@localhost",
        "ftp://localhost/",
        "localhost",
        "",
    ] {
        assert!(!is_local_issuer(remote), "{remote}");
    }
}
