//! Bring your own IdP: `private_key_jwt` on the user login's token requests,
//! and providers resolved per tenant from a store.
//!
//! The mock IdP verifies every client assertion against the client's
//! registered public key, rejects a request that carries a client secret or
//! a Basic header, and refuses a `jti` it has seen.
//!
//! Fixtures: `fixtures/entra-openid-configuration.json` is the discovery
//! document `https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0/.well-known/openid-configuration`
//! as served on 2026-10-30; `fixtures/keycloak-openid-configuration.json` is
//! the one `http://127.0.0.1:18080/realms/fapi/.well-known/openid-configuration`
//! returned on 2026-10-30 from `quay.io/keycloak/keycloak:26.0` (26.0.8)
//! started with `examples/fapi/keycloak/fapi-realm.json`. The tests replace
//! the recorded host with the wiremock server's, and nothing else.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth,jwt-aws-lc,sqlite --test oauth_byo_idp`

#![cfg(feature = "testing-oauth")]

use axess_core::authn::AuditContext;
use axess_core::authn::factor_secret::{FactorSecretCipher, FactorSecretError};
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders, TenantClientCredential, TenantDpop,
    TenantOAuthProviderRecord, TenantOAuthProviderStore,
};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair},
    test_session,
};
use axess_factors::FactorSecret;
use axess_factors::client_assertion::{ClientAssertionSigner, SignerSpec};
use axess_factors::oauth::{
    FapiConfig, OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProvider, OAuthProviderBuilder,
    OAuthProviderConfig,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "byo-client";
const REDIRECT: &str = "http://localhost:3000/callback";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

type Authn = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn tenant(label: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(label)
}

// ── The client's key ─────────────────────────────────────────────────────────

/// The client's `private_key_jwt` key pair: the private half for the signer,
/// the public JWK for the IdP to verify with.
struct ClientKey {
    der: Vec<u8>,
    jwk: Value,
}

impl ClientKey {
    fn new() -> Self {
        let (der, jwk, _) = oauth_generate_rsa_keypair();
        Self { der, jwk }
    }

    fn signer(&self) -> ClientAssertionSigner {
        axess_factors::jwt::ensure_crypto_provider();
        ClientAssertionSigner::new(
            CLIENT_ID,
            EncodingKey::from_rsa_der(&self.der),
            Algorithm::RS256,
        )
        .expect("the key signs under its algorithm")
        .with_key_id("client-key-1")
    }

    /// The private key as the PKCS#1 PEM text a tenant record holds.
    fn pem(&self) -> String {
        let body = base64::engine::general_purpose::STANDARD.encode(&self.der);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            lines.join("\n")
        )
    }
}

// ── The IdP ──────────────────────────────────────────────────────────────────

/// A token request as the IdP's endpoint saw it.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: Option<String>,
    form: Vec<(String, String)>,
    /// The verified assertion's header and claims, when it verified.
    assertion: Option<(Value, Value)>,
}

impl Seen {
    fn form(&self, key: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// How the token endpoint judges a request's client authentication.
#[derive(Clone)]
struct ClientAuthRules {
    /// The registered public key of the client (`None`: no assertion is
    /// accepted at all).
    jwk: Option<Value>,
    client_id: String,
    /// `aud` values the endpoint accepts in an assertion.
    audiences: Vec<String>,
    /// Header members an assertion must carry (Entra: `x5t#S256`).
    required_header: Vec<String>,
}

struct TokenEndpoint {
    rules: ClientAuthRules,
    id_token: Arc<Mutex<Option<String>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn error(status: u16, code: &str, why: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(json!({ "error": code, "error_description": why }))
}

impl TokenEndpoint {
    /// `Ok(header, claims)` of a verified assertion, or why not.
    fn check(
        &self,
        request: &Request,
        form: &[(String, String)],
    ) -> Result<(Value, Value), String> {
        let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        if get("client_secret").is_some() {
            return Err("a client secret was sent".into());
        }
        if request.headers.get("authorization").is_some() {
            return Err("an Authorization header was sent".into());
        }
        if get("client_id") != Some(&self.rules.client_id) {
            return Err("client_id missing or wrong".into());
        }
        if get("client_assertion_type") != Some(ASSERTION_TYPE) {
            return Err("client_assertion_type missing".into());
        }
        let assertion = get("client_assertion").ok_or("no client_assertion")?;
        let jwk = self.rules.jwk.as_ref().ok_or("no key registered")?;
        let header = jsonwebtoken::decode_header(assertion).map_err(|e| e.to_string())?;
        for member in &self.rules.required_header {
            let raw: Value =
                serde_json::from_slice(&B64.decode(assertion.split('.').next().unwrap()).unwrap())
                    .unwrap();
            if raw.get(member).is_none() {
                return Err(format!("assertion header lacks {member}"));
            }
        }
        axess_factors::jwt::ensure_crypto_provider();
        let key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .map_err(|e| e.to_string())?;
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&self.rules.audiences);
        validation.set_issuer(&[self.rules.client_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        // The clock under test may be a mock.
        validation.validate_exp = false;
        let claims = jsonwebtoken::decode::<Value>(assertion, &key, &validation)
            .map_err(|e| e.to_string())?
            .claims;
        if claims["sub"] != claims["iss"] {
            return Err("sub differs from iss".into());
        }
        let jti = claims["jti"].as_str().ok_or("no jti")?.to_string();
        if self.seen.lock().unwrap().iter().any(|s| {
            s.assertion
                .as_ref()
                .is_some_and(|(_, c)| c["jti"] == json!(jti))
        }) {
            return Err("jti replayed".into());
        }
        let raw_header: Value =
            serde_json::from_slice(&B64.decode(assertion.split('.').next().unwrap()).unwrap())
                .unwrap();
        Ok((raw_header, claims))
    }
}

impl Respond for TokenEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&request.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let verdict = self.check(request, &form);
        let mut seen = Seen {
            path: request.url.path().to_string(),
            authorization: request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            form,
            assertion: None,
        };
        let response = match verdict {
            Err(why) => error(401, "invalid_client", &why),
            Ok(verified) => {
                seen.assertion = Some(verified);
                let mut body = json!({
                    "access_token": "access-1",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "refresh_token": "rt1",
                });
                if seen.form("grant_type") == Some("authorization_code")
                    && let Some(id) = self.id_token.lock().unwrap().clone()
                {
                    body["id_token"] = json!(id);
                }
                ResponseTemplate::new(200).set_body_json(body)
            }
        };
        self.seen.lock().unwrap().push(seen);
        response
    }
}

struct Idp {
    server: MockServer,
    issuer: String,
    token_path: String,
    idp_der: Vec<u8>,
    idp_kid: String,
    id_token: Arc<Mutex<Option<String>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// The discovery document an IdP serves and where.
struct Layout {
    /// Path of the issuer under the server (`""`, `/realms/fapi`, `/<tid>/v2.0`).
    issuer_path: String,
    doc: Value,
    jwks_path: String,
    token_path: String,
}

impl Layout {
    fn plain() -> impl FnOnce(&str) -> Layout {
        |uri| Layout {
            issuer_path: String::new(),
            doc: oauth_discovery_document(uri),
            jwks_path: "/jwks".into(),
            token_path: "/token".into(),
        }
    }

    /// A recorded discovery document, its recorded host replaced with the
    /// server's.
    fn recorded(
        fixture: &'static str,
        recorded_host: &'static str,
        issuer_path: &'static str,
        jwks_path: &'static str,
        token_path: &'static str,
    ) -> impl FnOnce(&str) -> Layout {
        move |uri| {
            let text = std::fs::read_to_string(format!(
                "{}/tests/fixtures/{fixture}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect("fixture");
            let doc: Value = serde_json::from_str(&text.replace(recorded_host, uri)).unwrap();
            Layout {
                issuer_path: issuer_path.into(),
                doc,
                jwks_path: jwks_path.into(),
                token_path: token_path.into(),
            }
        }
    }
}

impl Idp {
    async fn start(
        layout: impl FnOnce(&str) -> Layout,
        rules: impl FnOnce(&str) -> ClientAuthRules,
    ) -> Self {
        let server = MockServer::start().await;
        let uri = server.uri();
        let layout = layout(&uri);
        let rules = rules(&uri);
        let (idp_der, mut idp_jwk, idp_kid) = oauth_generate_rsa_keypair();
        idp_jwk["alg"] = json!("RS256");
        Mock::given(method("GET"))
            .and(path(format!(
                "{}/.well-known/openid-configuration",
                layout.issuer_path
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(layout.doc.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(layout.jwks_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [idp_jwk] })))
            .mount(&server)
            .await;
        let id_token = Arc::new(Mutex::new(None));
        let seen = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path(layout.token_path.clone()))
            .respond_with(TokenEndpoint {
                rules,
                id_token: id_token.clone(),
                seen: seen.clone(),
            })
            .mount(&server)
            .await;
        let issuer = layout.doc["issuer"].as_str().unwrap().to_string();
        Self {
            server,
            issuer,
            token_path: layout.token_path,
            idp_der,
            idp_kid,
            id_token,
            seen,
        }
    }

    /// An IdP in the plain wiremock layout that accepts `key`'s assertions.
    async fn plain(key: &ClientKey) -> Self {
        let jwk = key.jwk.clone();
        Self::start(Layout::plain(), move |uri| ClientAuthRules {
            jwk: Some(jwk),
            client_id: CLIENT_ID.into(),
            audiences: vec![format!("{uri}/token"), uri.to_string()],
            required_header: vec![],
        })
        .await
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn token_requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == self.token_path)
            .cloned()
            .collect()
    }

    /// Have the token endpoint answer the next code exchange with an ID
    /// token for `nonce`, naming `subject` and carrying `extra`.
    fn issue(&self, nonce: &str, subject: &str, extra: Value) {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer, "sub": subject, "aud": CLIENT_ID,
            "exp": now + 3600, "iat": now, "nonce": nonce,
            "email": format!("{subject}@example.com"), "email_verified": true,
        });
        claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        axess_factors::jwt::ensure_crypto_provider();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.idp_kid.clone());
        let jwt = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_rsa_der(&self.idp_der))
            .expect("sign");
        *self.id_token.lock().unwrap() = Some(jwt);
    }

    /// The builder of a provider that authenticates with `signer`, found by
    /// discovery.
    async fn provider(&self, name: &str, signer: ClientAssertionSigner) -> OAuthProviderBuilder {
        OAuthProviderConfig::discover_with_private_key_jwt(name, &self.issuer, signer, REDIRECT)
            .await
            .expect("discovery")
    }
}

async fn session_values(session: &axess_core::session::extractor::AuthSession) -> (String, String) {
    let get = |key: &'static str| async move {
        session
            .get_custom(key)
            .await
            .and_then(|v| v.as_str().map(str::to_owned))
            .expect(key)
    };
    (
        get("axess.oauth.nonce").await,
        get("axess.oauth.csrf_state").await,
    )
}

fn service() -> AuthnService<MockIdentityStore, MockFactorStore> {
    AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new()).build()
}

fn global_service(provider: OAuthProviderConfig) -> Authn {
    AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default())
}

/// A global-provider login: begin, have the IdP issue, finish.
async fn global_login(
    authn: &Authn,
    idp: &Idp,
    name: &str,
    subject: &str,
) -> Result<OAuthClaims, OAuthError> {
    let session = test_session();
    authn
        .begin_oauth_login(name, &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let (nonce, csrf) = session_values(&session).await;
    idp.issue(&nonce, subject, json!({}));
    // A real callback carries the issuer (RFC 9207), and an IdP that
    // advertises the parameter (the recorded Keycloak document does) refuses
    // the plain finish.
    authn
        .finish_oauth_login_with_iss("code-1", &csrf, Some(&idp.issuer), &session)
        .await
}

// ── private_key_jwt on the login ─────────────────────────────────────────────

#[tokio::test]
async fn the_code_exchange_is_authenticated_by_a_verified_assertion_and_no_secret() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    // Built with a secret, then switched: the secret must not be sent.
    let provider =
        OAuthProviderConfig::discover("p", &idp.issuer, CLIENT_ID, "SECRET-VALUE", REDIRECT)
            .await
            .expect("discovery")
            .with_private_key_jwt(key.signer())
            .build()
            .expect("build");
    let authn = global_service(provider);

    let claims = global_login(&authn, &idp, "p", "alice")
        .await
        .expect("login");
    assert_eq!(claims.subject.as_str(), "alice");

    let requests = idp.token_requests();
    assert_eq!(requests.len(), 1);
    let seen = &requests[0];
    assert_eq!(seen.form("client_secret"), None);
    assert_eq!(seen.authorization, None);
    let (header, assertion) = seen.assertion.as_ref().expect("a verified assertion");
    assert_eq!(header["kid"], "client-key-1");
    assert_eq!(assertion["iss"], CLIENT_ID);
    assert_eq!(assertion["aud"], format!("{}/token", idp.uri()));
    let lifetime = assertion["exp"].as_i64().unwrap() - assertion["iat"].as_i64().unwrap();
    assert_eq!(lifetime, 60);
}

#[tokio::test]
async fn a_provider_discovered_without_a_secret_logs_in_the_same_way() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let authn = global_service(
        idp.provider("p", key.signer())
            .await
            .build()
            .expect("build"),
    );
    global_login(&authn, &idp, "p", "bob").await.expect("login");
    assert!(idp.token_requests()[0].assertion.is_some());
}

#[tokio::test]
async fn an_assertion_signed_by_another_key_is_refused_by_the_idp() {
    let registered = ClientKey::new();
    let impostor = ClientKey::new();
    let idp = Idp::plain(&registered).await;
    let authn = global_service(
        idp.provider("p", impostor.signer())
            .await
            .build()
            .expect("build"),
    );
    let refused = global_login(&authn, &idp, "p", "mallory").await;
    assert!(
        matches!(refused, Err(OAuthError::TokenExchange(_))),
        "{refused:?}"
    );
    assert!(idp.token_requests()[0].assertion.is_none());
}

#[tokio::test]
async fn jti_and_times_come_from_the_injected_rng_and_clock() {
    use axess_clock::testing::MockClock;
    use axess_rng::SecureRng;
    use axess_rng::testing::MockRng;

    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let provider = idp
        .provider(
            "p",
            key.signer()
                .with_assertion_ttl(std::time::Duration::from_secs(25)),
        )
        .await
        .with_clock(Arc::new(MockClock::at(now)))
        .with_rng(Arc::new(MockRng::new(11)))
        .build()
        .expect("build");
    let authn = global_service(provider);
    global_login(&authn, &idp, "p", "carol")
        .await
        .expect("login");

    let (_, assertion) = idp.token_requests()[0].assertion.clone().unwrap();
    assert_eq!(assertion["iat"], now.timestamp());
    assert_eq!(assertion["exp"], now.timestamp() + 25);
    let mut bytes = [0u8; 16];
    MockRng::new(11).fill_bytes(&mut bytes);
    let jti = uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string();
    assert_eq!(assertion["jti"], jti);
}

#[tokio::test]
async fn a_refresh_carries_its_own_fresh_assertion() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let provider = Arc::new(
        idp.provider("p", key.signer())
            .await
            .build()
            .expect("build"),
    );
    let authn = {
        // The service owns a provider; keep a second handle to call refresh.
        global_service(
            idp.provider("p", key.signer())
                .await
                .build()
                .expect("build"),
        )
    };
    let claims = global_login(&authn, &idp, "p", "dave")
        .await
        .expect("login");
    let refresh = claims.refresh_token.as_ref().expect("a refresh token");

    provider
        .refresh_token(refresh, None, None)
        .await
        .expect("the refresh authenticates");

    let requests = idp.token_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].form("grant_type"), Some("refresh_token"));
    assert_eq!(requests[1].form("client_secret"), None);
    let jtis: Vec<_> = requests
        .iter()
        .map(|s| s.assertion.as_ref().expect("verified").1["jti"].clone())
        .collect();
    assert_ne!(jtis[0], jtis[1]);
}

#[tokio::test]
async fn revocation_and_client_credentials_use_the_assertion_too() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let provider = idp
        .provider("p", key.signer())
        .await
        .build()
        .expect("build");
    let token = provider
        .client_credentials(&["scope-a"], None)
        .await
        .expect("client_credentials authenticates by assertion");
    assert_eq!(&*token.access_token, "access-1");
    let seen = &idp.token_requests()[0];
    assert_eq!(seen.form("grant_type"), Some("client_credentials"));
    assert_eq!(seen.form("client_secret"), None);
    assert!(seen.assertion.is_some());
}

#[tokio::test]
async fn under_fapi_the_assertion_is_for_the_issuer_and_dpop_still_binds_the_token() {
    // FAPI wants PS256 ID tokens with `nbf`; the plain mock signs RS256, so
    // this test serves its own discovery and PAR.
    let key = ClientKey::new();
    let server = MockServer::start().await;
    let issuer = server.uri();
    let (idp_der, mut idp_jwk, idp_kid) = oauth_generate_rsa_keypair();
    idp_jwk.as_object_mut().unwrap().remove("alg");
    let mut doc = oauth_discovery_document(&issuer);
    doc["id_token_signing_alg_values_supported"] = json!(["PS256"]);
    doc["pushed_authorization_request_endpoint"] = json!(format!("{issuer}/par"));
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [idp_jwk] })))
        .mount(&server)
        .await;
    let rules = ClientAuthRules {
        jwk: Some(key.jwk.clone()),
        client_id: CLIENT_ID.into(),
        audiences: vec![issuer.clone()],
        required_header: vec![],
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let id_token = Arc::new(Mutex::new(None));
    // Both endpoints share one verifier, which also tells PAR from the token
    // request by the presence of a grant.
    struct Fapi(TokenEndpoint);
    impl Respond for Fapi {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let response = self.0.respond(request);
            if request.url.path() == "/par" {
                return if response_is_ok(&self.0) {
                    ResponseTemplate::new(201)
                        .set_body_json(json!({ "request_uri": "urn:par:1", "expires_in": 60 }))
                } else {
                    response
                };
            }
            if response_is_ok(&self.0) {
                let mut body = json!({
                    "access_token": "access-1", "token_type": "DPoP",
                    "expires_in": 300, "refresh_token": "rt1",
                });
                if let Some(id) = self.0.id_token.lock().unwrap().clone() {
                    body["id_token"] = json!(id);
                }
                return ResponseTemplate::new(200).set_body_json(body);
            }
            response
        }
    }
    fn response_is_ok(endpoint: &TokenEndpoint) -> bool {
        endpoint
            .seen
            .lock()
            .unwrap()
            .last()
            .is_some_and(|s| s.assertion.is_some())
    }
    for at in ["/par", "/token"] {
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(Fapi(TokenEndpoint {
                rules: rules.clone(),
                id_token: id_token.clone(),
                seen: seen.clone(),
            }))
            .mount(&server)
            .await;
    }

    let provider =
        OAuthProviderConfig::discover_with_private_key_jwt("p", &issuer, key.signer(), REDIRECT)
            .await
            .expect("discovery")
            .with_fapi(FapiConfig::default())
            .build()
            .expect("FAPI composes with private_key_jwt");
    let authn = global_service(provider);
    let session = test_session();
    authn
        .begin_oauth_login("p", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin over PAR");
    let (nonce, csrf) = session_values(&session).await;
    let now = chrono::Utc::now().timestamp();
    axess_factors::jwt::ensure_crypto_provider();
    let mut header = Header::new(Algorithm::PS256);
    header.kid = Some(idp_kid);
    *id_token.lock().unwrap() = Some(
        jsonwebtoken::encode(
            &header,
            &json!({"iss": issuer, "sub": "erin", "aud": CLIENT_ID, "exp": now + 120,
                    "iat": now, "nbf": now - 5, "nonce": nonce}),
            &EncodingKey::from_rsa_der(&idp_der),
        )
        .unwrap(),
    );
    let claims = authn
        .finish_oauth_login("code-1", &csrf, &session)
        .await
        .expect("login over FAPI with private_key_jwt");
    assert!(claims.dpop_key.is_some(), "tokens stay DPoP bound");

    let all = seen.lock().unwrap().clone();
    let par = all.iter().find(|s| s.path == "/par").expect("PAR request");
    let token = all
        .iter()
        .find(|s| s.path == "/token")
        .expect("token request");
    for request in [par, token] {
        assert_eq!(request.form("client_secret"), None);
        assert_eq!(request.authorization, None);
        let (_, assertion) = request.assertion.as_ref().expect("verified assertion");
        assert_eq!(assertion["aud"], issuer, "FAPI audience is the issuer");
    }
}

// ── Per-tenant providers ─────────────────────────────────────────────────────

fn record(tenant_id: TenantId, issuer: &str, key: &ClientKey) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id,
        name: "sso".into(),
        issuer: issuer.to_string(),
        client_id: CLIENT_ID.into(),
        redirect_url: REDIRECT.into(),
        scopes: vec![],
        credential: TenantClientCredential::PrivateKeyJwt {
            key_pem: FactorSecret::Plain(key.pem().into()),
            signer: SignerSpec {
                key_id: Some("client-key-1".into()),
                ..SignerSpec::new(Algorithm::RS256)
            },
        },
        dpop: TenantDpop::Advertised,
        revision: 0,
    }
}

type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

fn tenant_service(directory: &Arc<Directory>) -> Authn {
    AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default())
}

async fn tenant_login(
    authn: &Authn,
    idp: &Idp,
    tenant_id: &TenantId,
    subject: &str,
) -> Result<OAuthClaims, OAuthError> {
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            tenant_id,
            &session,
        )
        .await?;
    let (nonce, csrf) = session_values(&session).await;
    idp.issue(&nonce, subject, json!({}));
    authn
        .finish_oauth_login_with_iss("code-1", &csrf, Some(&idp.issuer), &session)
        .await
}

#[tokio::test]
async fn two_tenants_with_a_provider_of_the_same_name_log_in_against_different_issuers() {
    let key_a = ClientKey::new();
    let key_b = ClientKey::new();
    let idp_a = Idp::plain(&key_a).await;
    let idp_b = Idp::plain(&key_b).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp_a.issuer, &key_a))
        .await
        .unwrap();
    directory
        .upsert(record(tenant("beta"), &idp_b.issuer, &key_b))
        .await
        .unwrap();
    let authn = tenant_service(&directory);

    let a = tenant_login(&authn, &idp_a, &tenant("acme"), "alice")
        .await
        .expect("acme login");
    let b = tenant_login(&authn, &idp_b, &tenant("beta"), "bob")
        .await
        .expect("beta login");

    assert_eq!(a.additional_claims["iss"], idp_a.issuer);
    assert_eq!(b.additional_claims["iss"], idp_b.issuer);
    assert_ne!(idp_a.issuer, idp_b.issuer);
    assert_eq!(a.provider.as_ref(), "sso");
    assert_eq!(b.provider.as_ref(), "sso");
    // Each IdP verified an assertion of its own client key and no other.
    assert_eq!(idp_a.token_requests().len(), 1);
    assert_eq!(idp_b.token_requests().len(), 1);
    assert!(idp_a.token_requests()[0].assertion.is_some());
    assert!(idp_b.token_requests()[0].assertion.is_some());
}

#[tokio::test]
async fn tenant_a_cannot_reach_tenant_bs_provider_even_when_the_name_matches() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("beta"), &idp.issuer, &key))
        .await
        .unwrap();
    let authn = tenant_service(&directory);
    let session = test_session();
    let refused = authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("acme"),
            &session,
        )
        .await;
    assert!(
        matches!(refused, Err(OAuthError::UnknownProvider(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_providers_update_in_the_store_is_used_by_the_next_login_without_a_restart() {
    let key = ClientKey::new();
    let first = Idp::plain(&key).await;
    let second = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    let stored = directory
        .upsert(record(tenant("acme"), &first.issuer, &key))
        .await
        .unwrap();
    assert_eq!(stored.revision, 1);
    let authn = tenant_service(&directory);

    let before = tenant_login(&authn, &first, &tenant("acme"), "alice")
        .await
        .expect("login");
    assert_eq!(before.additional_claims["iss"], first.issuer);

    // The operator points the tenant at another issuer. Written straight to
    // the store, as another process would: nothing tells the directory.
    let mut moved = record(tenant("acme"), &second.issuer, &key);
    moved = directory.store().put(moved).await.unwrap();
    assert_eq!(moved.revision, 2);

    let after = tenant_login(&authn, &second, &tenant("acme"), "alice")
        .await
        .expect("login");
    assert_eq!(after.additional_claims["iss"], second.issuer);
    assert_eq!(
        first.token_requests().len(),
        1,
        "the old issuer saw no second login"
    );
}

#[tokio::test]
async fn a_ceremony_begun_before_an_update_does_not_finish_against_the_new_issuer() {
    let key = ClientKey::new();
    let first = Idp::plain(&key).await;
    let second = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &first.issuer, &key))
        .await
        .unwrap();
    let authn = tenant_service(&directory);
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("acme"),
            &session,
        )
        .await
        .expect("begin");
    let (nonce, csrf) = session_values(&session).await;

    directory
        .upsert(record(tenant("acme"), &second.issuer, &key))
        .await
        .unwrap();
    second.issue(&nonce, "alice", json!({}));
    let refused = authn.finish_oauth_login("code-1", &csrf, &session).await;
    assert!(refused.is_err(), "the pinned issuer no longer matches");
    assert!(
        second.token_requests().is_empty(),
        "the code was never sent to the new issuer"
    );
}

#[tokio::test]
async fn a_removed_provider_stops_resolving_and_invalidate_forces_a_rebuild() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let authn = tenant_service(&directory);
    tenant_login(&authn, &idp, &tenant("acme"), "alice")
        .await
        .expect("login");

    let held = authn
        .tenant_oauth_provider(&tenant("acme"), "sso")
        .await
        .unwrap()
        .unwrap();
    let again = authn
        .tenant_oauth_provider(&tenant("acme"), "sso")
        .await
        .unwrap()
        .unwrap();
    assert!(
        Arc::ptr_eq(&held, &again),
        "an unchanged record reuses the built provider"
    );
    directory.invalidate(&tenant("acme"), "sso");
    let rebuilt = authn
        .tenant_oauth_provider(&tenant("acme"), "sso")
        .await
        .unwrap()
        .unwrap();
    assert!(!Arc::ptr_eq(&held, &rebuilt));

    assert!(directory.remove(&tenant("acme"), "sso").await.unwrap());
    let gone = tenant_login(&authn, &idp, &tenant("acme"), "alice").await;
    assert!(
        matches!(gone, Err(OAuthError::UnknownProvider(_))),
        "{gone:?}"
    );
}

#[tokio::test]
async fn the_global_registration_and_a_tenants_provider_of_one_name_never_shadow_each_other() {
    let global_key = ClientKey::new();
    let tenant_key = ClientKey::new();
    let global_idp = Idp::plain(&global_key).await;
    let tenant_idp = Idp::plain(&tenant_key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &tenant_idp.issuer, &tenant_key))
        .await
        .unwrap();
    let authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(
            global_idp
                .provider("sso", global_key.signer())
                .await
                .build()
                .expect("build"),
        )
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let tenants = tenant_login(&authn, &tenant_idp, &tenant("acme"), "alice")
        .await
        .expect("tenant");
    let global = global_login(&authn, &global_idp, "sso", "zed")
        .await
        .expect("global");
    assert_eq!(tenants.additional_claims["iss"], tenant_idp.issuer);
    assert_eq!(global.additional_claims["iss"], global_idp.issuer);
}

#[tokio::test]
async fn without_a_tenant_source_a_tenant_login_names_an_unknown_provider() {
    let authn = service().with_audit_context(AuditContext::default());
    let session = test_session();
    let refused = authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("acme"),
            &session,
        )
        .await;
    assert!(
        matches!(refused, Err(OAuthError::UnknownProvider(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_tenant_login_is_bound_to_its_tenant_at_completion() {
    use axess_core::authn::error::AuthnError;
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let authn = tenant_service(&directory);
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("acme"),
            &session,
        )
        .await
        .expect("begin");
    let (nonce, csrf) = session_values(&session).await;
    idp.issue(&nonce, "alice", json!({}));
    let claims = authn
        .finish_oauth_login("code-1", &csrf, &session)
        .await
        .expect("finish");

    let mut elsewhere = axess_core::authn::types::User::clone(&test_user("u1", "alice", "beta"));
    elsewhere.tenant_id = tenant("beta");
    let refused = authn
        .complete_oauth_login(&elsewhere, &claims, &session)
        .await;
    assert!(matches!(refused, Err(AuthnError::CrossTenant)));
    assert!(!session.is_authenticated().await);
}

fn test_user(id: &str, identifier: &str, tenant_label: &str) -> axess_core::authn::types::User {
    use axess_core::authn::{
        ids::UserId,
        types::{EntityState, User},
    };
    let now = chrono::Utc::now();
    User {
        id: axess_core::authn::ids::testing::user(id),
        tenant_id: tenant(tenant_label),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

// ── Credentials at rest ──────────────────────────────────────────────────────

fn cipher() -> Arc<FactorSecretCipher> {
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    Arc::new(FactorSecretCipher::new(key))
}

#[tokio::test]
async fn a_credential_is_sealed_in_the_store_and_opens_only_for_its_tenant_and_name() {
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(
        StoredTenantOAuthProviders::new(MemoryTenantOAuthProviderStore::new())
            .with_cipher(cipher()),
    );
    let stored = directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let TenantClientCredential::PrivateKeyJwt { key_pem, .. } = &stored.credential else {
        panic!("a key credential");
    };
    assert!(
        key_pem.is_sealed(),
        "the private key is not at rest in clear text"
    );
    let authn = tenant_service(&directory);
    tenant_login(&authn, &idp, &tenant("acme"), "alice")
        .await
        .expect("login with a sealed key");

    // The row copied under another tenant does not open.
    let mut moved = stored.clone();
    moved.tenant_id = tenant("beta");
    directory.store().put(moved).await.unwrap();
    let refused = authn.tenant_oauth_provider(&tenant("beta"), "sso").await;
    // A cipher fault, reported as one: not a setting the caller can correct.
    assert!(
        matches!(&refused, Err(OAuthError::Store(cause)) if cause.is::<FactorSecretError>()),
        "{:?}",
        refused.map(|_| ())
    );
}

/// The signer settings ride flat beside the key in the stored record, the
/// shape records were written in before the settings had a type of their
/// own, and such a record reads back.
#[test]
fn a_key_credential_keeps_its_stored_json_shape() {
    let key = ClientKey::new();
    let stored = serde_json::to_value(record(tenant("acme"), "https://idp.example", &key))
        .expect("serialises");
    let credential = &stored["credential"]["PrivateKeyJwt"];
    assert_eq!(credential["algorithm"], "RS256");
    assert_eq!(credential["key_id"], "client-key-1");
    assert!(credential["x5t_s256"].is_null());
    assert!(credential.get("signer").is_none(), "{credential}");
    let read: TenantOAuthProviderRecord =
        serde_json::from_value(stored).expect("the stored shape reads back");
    let TenantClientCredential::PrivateKeyJwt { signer, .. } = read.credential else {
        panic!("a key credential");
    };
    assert_eq!(signer.key_id.as_deref(), Some("client-key-1"));
}

// ── Recorded IdP documents ───────────────────────────────────────────────────

const ENTRA_TID: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

#[tokio::test]
async fn entra_shaped_idp_certificate_credential_and_tid_claim() {
    let key = ClientKey::new();
    let jwk = key.jwk.clone();
    let idp = Idp::start(
        Layout::recorded(
            "entra-openid-configuration.json",
            "https://login.microsoftonline.com",
            "/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
            "/72f988bf-86f1-41af-91ab-2d7cd011db47/discovery/v2.0/keys",
            "/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
        ),
        move |uri| ClientAuthRules {
            jwk: Some(jwk),
            client_id: CLIENT_ID.into(),
            // Entra takes the token endpoint as the audience.
            audiences: vec![format!("{uri}/{ENTRA_TID}/oauth2/v2.0/token")],
            // A certificate credential is found by its thumbprint header.
            required_header: vec!["x5t#S256".into()],
        },
    )
    .await;
    assert_eq!(idp.issuer, format!("{}/{ENTRA_TID}/v2.0", idp.uri()));

    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    let mut rec = record(tenant("acme"), &idp.issuer, &key);
    rec.scopes = vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "offline_access".into(),
    ];
    // Without the certificate thumbprint Entra would not find the credential.
    let no_thumbprint = directory.upsert(rec.clone()).await.unwrap();
    assert_eq!(no_thumbprint.revision, 1);
    let authn = tenant_service(&directory);
    let refused = tenant_login(&authn, &idp, &tenant("acme"), "oid-1").await;
    assert!(
        matches!(refused, Err(OAuthError::TokenExchange(_))),
        "{refused:?}"
    );

    if let TenantClientCredential::PrivateKeyJwt { signer, .. } = &mut rec.credential {
        signer.x5t_s256 = Some("c3VwcG9zZWRseS1hLXNoYTI1Ni10aHVtYnByaW50".into());
    }
    directory.upsert(rec).await.unwrap();
    let claims = idp_login_with_tid(&authn, &idp).await;
    assert_eq!(claims.additional_claims["tid"], ENTRA_TID);
    assert_eq!(claims.additional_claims["iss"], idp.issuer);
    let request = idp.token_requests().pop().unwrap();
    let (header, _) = request.assertion.expect("verified");
    assert_eq!(
        header["x5t#S256"],
        "c3VwcG9zZWRseS1hLXNoYTI1Ni10aHVtYnByaW50"
    );
}

/// An Entra v2.0 ID token carries `tid`, `oid`, `ver` and
/// `preferred_username` beside the standard claims.
async fn idp_login_with_tid(authn: &Authn, idp: &Idp) -> OAuthClaims {
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("acme"),
            &session,
        )
        .await
        .expect("begin");
    let (nonce, csrf) = session_values(&session).await;
    idp.issue(
        &nonce,
        "AAAAAAAAAAAAAAAAAAAAAIIcyYmtGMYoK1VQp",
        json!({
            "tid": ENTRA_TID, "ver": "2.0",
            "oid": "11111111-2222-3333-4444-555555555555",
            "preferred_username": "alice@contoso.example",
        }),
    );
    authn
        .finish_oauth_login("code-1", &csrf, &session)
        .await
        .expect("login")
}

#[tokio::test]
async fn keycloak_shaped_idp_private_key_jwt_with_the_issuer_or_token_endpoint_as_audience() {
    let key = ClientKey::new();
    let jwk = key.jwk.clone();
    let idp = Idp::start(
        Layout::recorded(
            "keycloak-openid-configuration.json",
            "http://127.0.0.1:18080",
            "/realms/fapi",
            "/realms/fapi/protocol/openid-connect/certs",
            "/realms/fapi/protocol/openid-connect/token",
        ),
        move |uri| ClientAuthRules {
            jwk: Some(jwk),
            client_id: CLIENT_ID.into(),
            audiences: vec![
                format!("{uri}/realms/fapi"),
                format!("{uri}/realms/fapi/protocol/openid-connect/token"),
            ],
            required_header: vec![],
        },
    )
    .await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let authn = tenant_service(&directory);
    let claims = tenant_login(&authn, &idp, &tenant("acme"), "alice")
        .await
        .expect("login");
    assert_eq!(claims.additional_claims["iss"], idp.issuer);
    assert!(idp.token_requests()[0].assertion.is_some());
}

// ── The stores ───────────────────────────────────────────────────────────────

async fn store_contract<S: TenantOAuthProviderStore>(store: &S) {
    let key = ClientKey::new();
    let a = tenant("acme");
    let b = tenant("beta");
    assert!(store.get(&a, "sso").await.unwrap().is_none());

    let one = store
        .put(record(a, "https://idp.example/one", &key))
        .await
        .unwrap();
    assert_eq!(one.revision, 1);
    let two = store
        .put(record(a, "https://idp.example/two", &key))
        .await
        .unwrap();
    assert_eq!(two.revision, 2);
    store
        .put(record(b, "https://idp.example/b", &key))
        .await
        .unwrap();
    let mut other_name = record(a, "https://idp.example/x", &key);
    other_name.name = "azure".into();
    store.put(other_name).await.unwrap();

    let got = store.get(&a, "sso").await.unwrap().expect("stored");
    assert_eq!(got.issuer, "https://idp.example/two");
    assert_eq!(got.revision, 2);
    let names: Vec<_> = store
        .list(&a)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["azure", "sso"]);
    assert_eq!(store.list(&b).await.unwrap().len(), 1);

    // By issuer: across tenants, exact match only (a replaced record's old
    // issuer no longer finds it).
    let mut shared = record(b, "https://idp.example/two", &key);
    shared.name = "shared".into();
    store.put(shared).await.unwrap();
    let found: Vec<_> = store
        .list_by_issuer("https://idp.example/two")
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.tenant_id, r.name))
        .collect();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.contains(&(a, "sso".to_string())));
    assert!(found.contains(&(b, "shared".to_string())));
    assert!(
        store
            .list_by_issuer("https://idp.example/one")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_by_issuer("https://idp.example")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(store.delete(&b, "shared").await.unwrap());

    assert!(store.delete(&a, "sso").await.unwrap());
    assert!(!store.delete(&a, "sso").await.unwrap());
    assert!(store.get(&a, "sso").await.unwrap().is_none());
    assert!(
        store.get(&b, "sso").await.unwrap().is_some(),
        "another tenant's row stays"
    );
}

#[tokio::test]
async fn the_memory_store_keeps_its_contract() {
    store_contract(&MemoryTenantOAuthProviderStore::new()).await;
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use axess_core::federation::oauth_tenant::SqliteTenantOAuthProviderStore;

    async fn store() -> (SqliteTenantOAuthProviderStore, sqlx::SqlitePool) {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        let store = SqliteTenantOAuthProviderStore::new(pool.clone());
        store.init_schema().await.expect("schema");
        store.init_schema().await.expect("schema is idempotent");
        (store, pool)
    }

    #[tokio::test]
    async fn the_sqlite_store_keeps_its_contract() {
        let (store, _) = store().await;
        store_contract(&store).await;
    }

    #[tokio::test]
    async fn a_sealed_credential_never_reaches_the_table_in_clear_text() {
        let (store, pool) = store().await;
        let key = ClientKey::new();
        let idp = Idp::plain(&key).await;
        let directory = Arc::new(StoredTenantOAuthProviders::new(store).with_cipher(cipher()));
        directory
            .upsert(record(tenant("acme"), &idp.issuer, &key))
            .await
            .unwrap();

        let (raw,): (String,) = sqlx::query_as("SELECT record FROM tenant_oauth_providers")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!raw.contains("BEGIN RSA PRIVATE KEY"), "{raw}");
        assert!(raw.contains("ciphertext"));

        let authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
            .with_tenant_oauth_providers(directory.clone())
            .build()
            .with_audit_context(AuditContext::default());
        tenant_login(&authn, &idp, &tenant("acme"), "alice")
            .await
            .expect("login from a row read back out of SQLite");
    }
}

// ── Audit attribution of federated rows ──────────────────────────────────────

/// The success row of a tenant's OAuth login belongs to that tenant and names
/// no local user: the IdP subject is not a local user id, even when it parses
/// as one. A tenant-B query that includes platform rows therefore never sees
/// tenant A's logins.
#[tokio::test]
async fn a_tenant_login_row_is_the_tenants_and_names_no_user_from_the_subject() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let identity = MockIdentityStore::new();
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());
    // A subject shaped like a local user id, which must still not be one.
    let mallory = axess_identity::testing::user("mallory");
    tenant_login(&authn, &idp, &tenant("acme"), &mallory.to_string())
        .await
        .expect("login");

    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::LoginAttempt
                && e.event_status == AuthEventStatus::Success
        })
        .collect();
    assert_eq!(rows.len(), 1, "the login wrote its row");
    assert_eq!(
        rows[0].tenant_id,
        Some(tenant("acme")),
        "the row is tenant A's"
    );
    assert_eq!(rows[0].user_id, None, "the IdP subject is never a UserId");

    // What a tenant-B query with include_unscoped sees: its own rows and the
    // platform rows with no tenant.
    let seen_by_beta = rows
        .iter()
        .filter(|e| e.tenant_id.is_none() || e.tenant_id == Some(tenant("beta")))
        .count();
    assert_eq!(seen_by_beta, 0, "tenant B never sees tenant A's login");
}

/// A refresh run under a tenant scope for a known user writes its row to
/// that tenant and user; the by-name refresh with neither stays a platform
/// row, and neither names the IdP subject as a user.
#[tokio::test]
async fn a_scoped_refresh_row_names_the_tenant_and_user_it_was_given() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType, AuthFailureReason};
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let identity = MockIdentityStore::new();
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let mallory = axess_identity::testing::user("mallory");
    let claims = tenant_login(&authn, &idp, &tenant("acme"), &mallory.to_string())
        .await
        .expect("login");
    let refresh = claims.refresh_token.as_ref().expect("a refresh token");
    let alice = axess_identity::testing::user("alice");

    authn
        .oauth_in_tenant(&tenant("acme"))
        .as_user(alice)
        .refresh_oauth_token("sso", refresh, &mallory.to_string(), None, None)
        .await
        .expect("refresh");
    let refreshes: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::LoginAttempt
                && e.event_status == AuthEventStatus::Success
                && e.error == Some(AuthFailureReason::TokenRefresh)
        })
        .collect();
    assert_eq!(refreshes.len(), 1, "the refresh wrote its row");
    assert_eq!(refreshes[0].tenant_id, Some(tenant("acme")));
    assert_eq!(
        refreshes[0].user_id,
        Some(alice),
        "the user the scope was given"
    );

    // A failure under the scope is the tenant's too.
    authn
        .oauth_in_tenant(&tenant("acme"))
        .as_user(alice)
        .refresh_oauth_token("sso", "", &mallory.to_string(), None, None)
        .await
        .expect_err("an empty token is refused");
    let failed = identity
        .events()
        .into_iter()
        .rfind(|e| e.error == Some(AuthFailureReason::TokenRefreshNoToken))
        .expect("the failure row");
    assert_eq!(failed.tenant_id, Some(tenant("acme")));
    assert_eq!(failed.user_id, Some(alice));
}

/// The provider a tenant ceremony began with no longer resolves at the
/// callback (the record was removed meanwhile): the failure is audited and
/// the ceremony cleared, as every other failure of the callback is.
#[tokio::test]
async fn a_tenant_provider_gone_at_the_callback_is_audited_and_clears_the_ceremony() {
    use axess_core::authn::event::AuthFailureReason;
    let key = ClientKey::new();
    let idp = Idp::plain(&key).await;
    let directory = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &idp.issuer, &key))
        .await
        .unwrap();
    let identity = MockIdentityStore::new();
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("acme"),
            &session,
        )
        .await
        .expect("begin");
    let (_, csrf) = session_values(&session).await;
    assert!(
        directory.remove(&tenant("acme"), "sso").await.unwrap(),
        "the case: the record is gone"
    );

    let err = authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect_err("no provider to finish against");
    assert!(matches!(err, OAuthError::UnknownProvider(_)), "{err:?}");
    assert!(
        session.get_custom("axess.oauth.csrf_state").await.is_none(),
        "the ceremony is cleared"
    );
    assert!(
        identity
            .events()
            .iter()
            .any(|e| e.error == Some(AuthFailureReason::ProviderUnavailable)),
        "the failure is audited"
    );
}
