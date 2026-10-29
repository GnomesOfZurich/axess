//! The FAPI 2.0 profile against a wiremock IdP: the DPoP proof on the token
//! request, the nonce retry, the `token_type` check, the refresh and userinfo
//! calls bound to the same key, JARM, the ID-token algorithm allow-list and
//! mTLS client authentication.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth --test oauth_fapi_wiremock`

#![cfg(feature = "testing-oauth")]

use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair},
    test_session,
};
use axess_factors::oauth::{
    DpopKey, FapiConfig, OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProviderConfig,
    SenderConstraint,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::Digest;
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "test-client-id";

type Authn = RequestAuthnService<MockIdentityStore, MockFactorStore>;

// ── The IdP ──────────────────────────────────────────────────────────────────

/// What the IdP's endpoints saw, in arrival order.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: Option<String>,
    dpop: Option<String>,
    form: Vec<(String, String)>,
}

impl Seen {
    fn form(&self, key: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

type Answer = Box<dyn Fn(&Seen, usize) -> ResponseTemplate + Send + Sync>;
type Tamper = Box<dyn Fn(&mut Value)>;

/// A token endpoint that records its requests and answers as scripted.
struct Recorder {
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Answer,
}

impl Respond for Recorder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let seen = Seen {
            path: request.url.path().to_string(),
            authorization: header("authorization"),
            dpop: header("dpop"),
            form: url::form_urlencoded::parse(&request.body)
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        };
        let mut all = self.seen.lock().unwrap();
        let count = all.iter().filter(|s| s.path == seen.path).count();
        all.push(seen.clone());
        (self.answer)(&seen, count)
    }
}

struct Idp {
    server: MockServer,
    issuer: String,
    private_der: Vec<u8>,
    kid: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Idp {
    /// An IdP signing with `PS256`, whose discovery document advertises
    /// `extra` members and which has a PAR endpoint at `/par`.
    async fn start(extra: Value) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let (private_der, mut jwk, kid) = oauth_generate_rsa_keypair();
        jwk.as_object_mut().unwrap().remove("alg");
        let mut doc = oauth_discovery_document(&issuer);
        doc["id_token_signing_alg_values_supported"] = json!(["PS256"]);
        doc["pushed_authorization_request_endpoint"] = json!(format!("{issuer}/par"));
        doc["mtls_endpoint_aliases"] = json!({ "token_endpoint": format!("{issuer}/mtls/token") });
        doc.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;
        let idp = Self {
            server,
            issuer,
            private_der,
            kid,
            seen: Arc::default(),
        };
        idp.mount("POST", "/par", |_, _| {
            ResponseTemplate::new(201)
                .set_body_json(json!({ "request_uri": "urn:par:1", "expires_in": 60 }))
        })
        .await;
        idp
    }

    async fn mount(
        &self,
        verb: &str,
        at: &str,
        answer: impl Fn(&Seen, usize) -> ResponseTemplate + Send + Sync + 'static,
    ) {
        Mock::given(method(verb))
            .and(path(at))
            .respond_with(Recorder {
                seen: self.seen.clone(),
                answer: Box::new(answer),
            })
            .mount(&self.server)
            .await;
    }

    fn requests_to(&self, at: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == at)
            .cloned()
            .collect()
    }

    /// An ID token for `nonce`, signed with `alg` and carrying `extra`.
    fn id_token(&self, alg: Algorithm, nonce: &str, extra: Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer,
            "sub": "alice-subject",
            "aud": CLIENT_ID,
            "exp": now + 120,
            "iat": now,
            "nbf": now - 5,
            "nonce": nonce,
        });
        claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        self.sign(alg, &claims)
    }

    fn sign(&self, alg: Algorithm, claims: &Value) -> String {
        axess_factors::jwt::ensure_crypto_provider();
        let mut header = Header::new(alg);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_rsa_der(&self.private_der),
        )
        .expect("sign")
    }

    async fn provider(&self) -> OAuthProviderConfig {
        OAuthProviderConfig::discover(
            "test",
            &self.issuer,
            CLIENT_ID,
            "test-secret",
            "http://localhost:3000/callback",
        )
        .await
        .expect("discovery")
    }
}

fn service(provider: OAuthProviderConfig) -> Authn {
    AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default())
}

/// The nonce and state the ceremony put in the session.
async fn begin(
    authn: &Authn,
    session: &axess_core::session::extractor::AuthSession,
) -> (String, String) {
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), session)
        .await
        .expect("begin");
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

fn token_json(token_type: &str, id_token: Option<String>) -> Value {
    let mut body = json!({
        "access_token": "access-1",
        "token_type": token_type,
        "expires_in": 300,
        "refresh_token": "rt1",
    });
    if let Some(id) = id_token {
        body["id_token"] = json!(id);
    }
    body
}

// ── Reading a proof ──────────────────────────────────────────────────────────

fn segment(jwt: &str, index: usize) -> Value {
    let part = jwt.split('.').nth(index).expect("segment");
    serde_json::from_slice(&B64.decode(part).expect("base64")).expect("json")
}

/// The RFC 7638 thumbprint of the `jwk` member of a proof header.
fn header_thumbprint(header: &Value) -> String {
    let jwk = &header["jwk"];
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap(),
        jwk["kty"].as_str().unwrap(),
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    B64.encode(sha2::Sha256::digest(canonical.as_bytes()))
}

/// Verify the proof's own signature with the key in its header and return
/// `(header, payload)`.
fn checked_proof(jwt: &str) -> (Value, Value) {
    let header = segment(jwt, 0);
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    axess_factors::jwt::ensure_crypto_provider();
    let key = jsonwebtoken::DecodingKey::from_ec_components(
        header["jwk"]["x"].as_str().unwrap(),
        header["jwk"]["y"].as_str().unwrap(),
    )
    .expect("key");
    let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let payload = jsonwebtoken::decode::<Value>(jwt, &key, &validation)
        .expect("the proof verifies under the key in its header")
        .claims;
    (header, payload)
}

fn proof_of(seen: &Seen) -> (Value, Value) {
    checked_proof(seen.dpop.as_deref().expect("a DPoP header"))
}

fn dpop_provider_config() -> FapiConfig {
    FapiConfig::default()
}

async fn dpop_provider(idp: &Idp) -> OAuthProviderConfig {
    idp.provider()
        .await
        .with_fapi(dpop_provider_config())
        .expect("with_fapi")
}

/// Log in through a DPoP provider whose token endpoint answers `token_type`.
async fn dpop_login(
    idp: &Idp,
    token_type: &'static str,
) -> (Authn, Result<OAuthClaims, OAuthError>) {
    let authn = service(dpop_provider(idp).await);
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/token", move |seen, _| {
        if seen.form("grant_type") == Some("refresh_token") {
            // A refresh answers without an ID token and rotates the token.
            return ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access-2",
                "token_type": token_type,
                "expires_in": 300,
                "refresh_token": "rt2",
            }));
        }
        ResponseTemplate::new(200).set_body_json(token_json(token_type, Some(id.clone())))
    })
    .await;
    let result = authn.finish_oauth_login("code", &csrf, &session).await;
    (authn, result)
}

// ── DPoP on the token request ────────────────────────────────────────────────

#[tokio::test]
async fn the_token_request_carries_a_proof_for_the_key_the_claims_return() {
    let idp = Idp::start(json!({})).await;
    let (_authn, claims) = dpop_login(&idp, "DPoP").await;
    let claims = claims.expect("login");

    let requests = idp.requests_to("/token");
    assert_eq!(requests.len(), 1);
    let (header, payload) = proof_of(&requests[0]);
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], format!("{}/token", idp.issuer));
    assert!(payload["jti"].as_str().is_some_and(|j| !j.is_empty()));
    let key = claims.dpop_key.expect("the login returns its DPoP key");
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    // A proof for a token request names no access token.
    assert!(payload.get("ath").is_none());
}

#[tokio::test]
async fn a_bearer_response_to_a_dpop_request_is_refused() {
    let idp = Idp::start(json!({})).await;
    let (_authn, result) = dpop_login(&idp, "Bearer").await;
    assert!(
        matches!(result, Err(OAuthError::TokenExchange(_))),
        "an unbound token must not be taken for a bound one: {result:?}"
    );
}

#[tokio::test]
async fn use_dpop_nonce_is_answered_with_a_proof_that_echoes_it() {
    let idp = Idp::start(json!({})).await;
    let authn = service(dpop_provider(&idp).await);
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/token", move |seen, _| {
        let has_nonce = seen
            .dpop
            .as_deref()
            .is_some_and(|p| segment(p, 1).get("nonce") == Some(&json!("server-nonce-1")));
        if has_nonce {
            ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
        } else {
            ResponseTemplate::new(400)
                .insert_header("DPoP-Nonce", "server-nonce-1")
                .set_body_json(json!({ "error": "use_dpop_nonce" }))
        }
    })
    .await;

    authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect("the retry with the nonce succeeds");

    let requests = idp.requests_to("/token");
    assert_eq!(requests.len(), 2, "one refusal, one retry");
    let (first_header, first) = proof_of(&requests[0]);
    let (second_header, second) = proof_of(&requests[1]);
    assert!(first.get("nonce").is_none());
    assert_eq!(second["nonce"], "server-nonce-1");
    assert_ne!(first["jti"], second["jti"], "each proof has its own jti");
    assert_eq!(
        header_thumbprint(&first_header),
        header_thumbprint(&second_header)
    );
}

#[tokio::test]
async fn a_provider_configured_for_dpop_refuses_a_request_without_a_key() {
    let idp = Idp::start(json!({})).await;
    let provider = dpop_provider(&idp).await;
    use axess_factors::oauth::OAuthProvider as _;
    let err = provider
        .exchange_code("code", "v".repeat(43), "n".to_string())
        .await
        .expect_err("the bare form must not send a bearer request");
    assert!(matches!(err, OAuthError::Config(_)), "{err:?}");
    assert!(idp.requests_to("/token").is_empty(), "nothing was sent");
}

// ── The same key on refresh and userinfo ─────────────────────────────────────

#[tokio::test]
async fn refresh_and_userinfo_use_the_key_the_login_returned() {
    let idp = Idp::start(json!({})).await;
    let (authn, claims) = dpop_login(&idp, "DPoP").await;
    let claims = claims.expect("login");
    let key = claims.dpop_key.clone().expect("key");

    // The userinfo answer is the subject of the login.
    idp.mount("GET", "/userinfo", |_, _| {
        ResponseTemplate::new(200).set_body_json(json!({ "sub": "alice-subject" }))
    })
    .await;

    let outcome = authn
        .refresh_oauth_token_with_key("test", "rt1", "alice-subject", None, Some(&key))
        .await
        .expect("refresh");
    assert_eq!(&*outcome.refresh_token, "rt2");
    let refresh = idp
        .requests_to("/token")
        .into_iter()
        .rfind(|s| s.form("grant_type") == Some("refresh_token"))
        .expect("a refresh request");
    let (header, payload) = proof_of(&refresh);
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    assert_eq!(payload["htm"], "POST");

    authn
        .fetch_userinfo_with_key("test", "access-2", "alice-subject", Some(&key))
        .await
        .expect("userinfo");
    let userinfo = &idp.requests_to("/userinfo")[0];
    assert_eq!(userinfo.authorization.as_deref(), Some("DPoP access-2"));
    let (header, payload) = proof_of(userinfo);
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    assert_eq!(payload["htm"], "GET");
    assert_eq!(
        payload["ath"],
        B64.encode(sha2::Sha256::digest(b"access-2")),
        "the proof names the token it travels with"
    );

    // Without the key the call is refused before anything is sent.
    let before = idp.requests_to("/token").len();
    let err = authn
        .refresh_oauth_token("test", "rt2", "alice-subject", None)
        .await
        .expect_err("a bound token is not refreshed bare");
    assert!(matches!(err, OAuthError::Config(_)), "{err:?}");
    assert_eq!(idp.requests_to("/token").len(), before);
}

#[tokio::test]
async fn a_restored_key_is_the_same_key() {
    let idp = Idp::start(json!({})).await;
    let (_authn, claims) = dpop_login(&idp, "DPoP").await;
    let key = claims.expect("login").dpop_key.expect("key");
    let restored = DpopKey::from_seed(*key.to_seed_bytes());
    assert_eq!(restored.thumbprint().unwrap(), key.thumbprint().unwrap());
}

// ── ID-token rules of the profile ────────────────────────────────────────────

/// FAPI requires `nbf`; a token that carries a valid one passes, and one
/// without it is refused.
#[tokio::test]
async fn fapi_login_reads_nbf_from_the_id_token() {
    for accepted in [true, false] {
        let idp = Idp::start(json!({})).await;
        let authn = service(dpop_provider(&idp).await);
        let session = test_session();
        let (nonce, csrf) = begin(&authn, &session).await;
        let mut id_claims = json!({
            "iss": idp.issuer, "sub": "alice-subject", "aud": CLIENT_ID,
            "exp": chrono::Utc::now().timestamp() + 120,
            "iat": chrono::Utc::now().timestamp(), "nonce": nonce,
        });
        if accepted {
            id_claims["nbf"] = json!(chrono::Utc::now().timestamp() - 5);
        }
        let id = idp.sign(Algorithm::PS256, &id_claims);
        idp.mount("POST", "/token", move |_, _| {
            ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
        })
        .await;
        let result = authn.finish_oauth_login("code", &csrf, &session).await;
        assert_eq!(result.is_ok(), accepted, "{result:?}");
        if !accepted {
            // The provider reports every token-validation failure to the
            // caller as a generic exchange failure.
            assert!(
                matches!(result, Err(OAuthError::TokenExchange(_))),
                "{result:?}"
            );
        }
    }
}

#[tokio::test]
async fn the_profile_refuses_an_rs256_id_token_unless_the_list_is_widened() {
    for (algs, accepted) in [
        (None, false),
        (Some(vec!["RS256".to_string(), "PS256".to_string()]), true),
    ] {
        let idp = Idp::start(json!({ "id_token_signing_alg_values_supported": ["RS256"] })).await;
        let mut config = dpop_provider_config();
        if let Some(algs) = algs {
            config.allowed_id_token_algs = algs;
        }
        let authn = service(idp.provider().await.with_fapi(config).expect("with_fapi"));
        let session = test_session();
        let (nonce, csrf) = begin(&authn, &session).await;
        let id = idp.id_token(Algorithm::RS256, &nonce, json!({}));
        idp.mount("POST", "/token", move |_, _| {
            ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
        })
        .await;
        let result = authn.finish_oauth_login("code", &csrf, &session).await;
        assert_eq!(result.is_ok(), accepted, "{result:?}");
    }
}

// ── with_fapi's own checks ───────────────────────────────────────────────────

#[tokio::test]
async fn with_fapi_refuses_what_the_profile_cannot_keep() {
    let idp = Idp::start(json!({})).await;
    let config_err = |r: Result<OAuthProviderConfig, OAuthError>| match r {
        Err(OAuthError::Config(m)) => m,
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    };

    // No PAR endpoint at the IdP, none configured.
    let bare = Idp::start(json!({ "pushed_authorization_request_endpoint": null })).await;
    let msg = config_err(bare.provider().await.with_fapi(FapiConfig::default()));
    assert!(
        msg.contains("pushed_authorization_request_endpoint"),
        "{msg}"
    );

    // An empty list accepts no ID token; a symmetric name never verifies one.
    for algs in [vec![], vec!["HS256".to_string()], vec!["none".to_string()]] {
        let msg = config_err(idp.provider().await.with_fapi(FapiConfig {
            allowed_id_token_algs: algs,
            ..Default::default()
        }));
        assert!(msg.contains("allowed_id_token_algs"), "{msg}");
    }

    // The default profile is available.
    assert!(
        idp.provider()
            .await
            .with_fapi(FapiConfig::default())
            .is_ok()
    );
}

// ── JARM ─────────────────────────────────────────────────────────────────────

fn jarm_provider_config() -> FapiConfig {
    FapiConfig {
        require_jarm: true,
        ..Default::default()
    }
}

/// Begin a JARM login and finish it with a response JWT built from `claims`
/// (`iss`, `aud`, `exp`, `code` and `state` filled in unless overridden).
async fn jarm_login(
    idp: &Idp,
    tamper: impl Fn(&mut Value),
    finish: impl FnOnce(String, String) -> (String, bool),
) -> (Result<OAuthClaims, OAuthError>, Authn) {
    let provider = idp
        .provider()
        .await
        .with_fapi(jarm_provider_config())
        .expect("with_fapi");
    let authn = service(provider);
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/token", move |_, _| {
        ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
    })
    .await;
    let mut response = json!({
        "iss": idp.issuer,
        "aud": CLIENT_ID,
        "exp": chrono::Utc::now().timestamp() + 60,
        "code": "the-code",
        "state": csrf,
    });
    tamper(&mut response);
    let jwt = idp.sign(Algorithm::PS256, &response);
    let (jwt, plain) = finish(jwt, csrf);
    let result = if plain {
        authn.finish_oauth_login("the-code", &jwt, &session).await
    } else {
        authn.finish_oauth_login_jarm(&jwt, &session).await
    };
    (result, authn)
}

#[tokio::test]
async fn jarm_asks_for_response_mode_jwt_and_accepts_a_signed_response() {
    let idp = Idp::start(json!({})).await;
    let (result, _) = jarm_login(&idp, |_| {}, |jwt, _| (jwt, false)).await;
    result.expect("a verified response finishes the login");
    let par = &idp.requests_to("/par")[0];
    assert_eq!(par.form("response_mode"), Some("jwt"));
}

#[tokio::test]
async fn a_plain_callback_to_a_jarm_provider_is_refused() {
    let idp = Idp::start(json!({})).await;
    // The plain form would pass `code` and `state` straight to the exchange.
    let (result, _) = jarm_login(&idp, |_| {}, |_, csrf| (csrf, true)).await;
    assert!(
        matches!(result, Err(OAuthError::InvalidParameter)),
        "{result:?}"
    );
    assert!(
        idp.requests_to("/token").is_empty(),
        "no code was exchanged"
    );
}

#[tokio::test]
async fn a_response_that_does_not_verify_or_does_not_match_is_refused() {
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "wrong audience",
            Box::new(|c| c["aud"] = json!("someone-else")),
        ),
        (
            "wrong issuer",
            Box::new(|c| c["iss"] = json!("https://evil.example")),
        ),
        (
            "expired",
            Box::new(|c| c["exp"] = json!(chrono::Utc::now().timestamp() - 3600)),
        ),
        (
            "no exp",
            Box::new(|c| {
                c.as_object_mut().unwrap().remove("exp");
            }),
        ),
    ];
    for (name, tamper) in cases {
        let idp = Idp::start(json!({})).await;
        let (result, _) = jarm_login(&idp, tamper, |jwt, _| (jwt, false)).await;
        assert!(
            matches!(result, Err(OAuthError::IdTokenValidation(_))),
            "{name}: {result:?}"
        );
        assert!(
            idp.requests_to("/token").is_empty(),
            "{name}: nothing exchanged"
        );
    }

    // A state that is not the ceremony's is the same CSRF mismatch as ever.
    let idp = Idp::start(json!({})).await;
    let (result, _) =
        jarm_login(&idp, |c| c["state"] = json!("other"), |jwt, _| (jwt, false)).await;
    assert!(
        matches!(result, Err(OAuthError::CsrfMismatch)),
        "{result:?}"
    );

    // A flipped signature byte.
    let idp = Idp::start(json!({})).await;
    let (result, _) = jarm_login(
        &idp,
        |_| {},
        |jwt, _| {
            let mut bytes = jwt.into_bytes();
            let last = bytes.len() - 3;
            bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
            (String::from_utf8(bytes).unwrap(), false)
        },
    )
    .await;
    assert!(
        matches!(result, Err(OAuthError::IdTokenValidation(_))),
        "{result:?}"
    );

    // An unsigned response.
    let idp = Idp::start(json!({})).await;
    let (result, _) = jarm_login(
        &idp,
        |_| {},
        |jwt, _| {
            let payload = jwt.split('.').nth(1).unwrap().to_string();
            let header = B64.encode(br#"{"alg":"none","kid":"test-key-1"}"#);
            (format!("{header}.{payload}."), false)
        },
    )
    .await;
    assert!(
        matches!(result, Err(OAuthError::IdTokenValidation(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn an_error_response_ends_the_ceremony() {
    let idp = Idp::start(json!({})).await;
    let (result, _) = jarm_login(
        &idp,
        |c| {
            c.as_object_mut().unwrap().remove("code");
            c["error"] = json!("access_denied");
        },
        |jwt, _| (jwt, false),
    )
    .await;
    assert!(
        matches!(result, Err(OAuthError::TokenExchange(_))),
        "{result:?}"
    );
}

// ── mTLS ─────────────────────────────────────────────────────────────────────

/// A self-signed client certificate and key written under a temp directory
/// that is removed when the value drops.
struct ClientCert {
    dir: std::path::PathBuf,
}

impl ClientCert {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("axess-fapi-mtls-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client.example".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("client.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("client.key"), key.serialize_pem()).unwrap();
        Self { dir }
    }

    fn constraint(&self) -> SenderConstraint {
        SenderConstraint::Mtls {
            client_cert_path: self.dir.join("client.pem").to_string_lossy().into_owned(),
            client_key_path: self.dir.join("client.key").to_string_lossy().into_owned(),
        }
    }
}

impl Drop for ClientCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn mtls_uses_the_advertised_alias_and_authenticates_with_the_certificate() {
    let idp = Idp::start(json!({})).await;
    let cert = ClientCert::new("alias");
    let provider = idp
        .provider()
        .await
        .with_fapi(FapiConfig {
            sender_constraint: cert.constraint(),
            ..Default::default()
        })
        .expect("with_fapi");
    let authn = service(provider);
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/mtls/token", move |_, _| {
        // RFC 8705: the tokens are certificate-bound but still `Bearer`.
        ResponseTemplate::new(200).set_body_json(token_json("Bearer", Some(id.clone())))
    })
    .await;

    let claims = authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect("login");
    assert!(claims.dpop_key.is_none(), "an mTLS login has no DPoP key");
    assert!(
        idp.requests_to("/token").is_empty(),
        "the plain endpoint is not used"
    );
    let request = &idp.requests_to("/mtls/token")[0];
    assert!(request.dpop.is_none());
    assert!(
        request.authorization.is_none(),
        "the certificate authenticates the client; the secret is not sent"
    );
    assert_eq!(request.form("client_id"), Some(CLIENT_ID));
    assert!(request.form("client_secret").is_none());
    // PAR goes to the plain endpoint here: no alias was advertised for it.
    assert_eq!(idp.requests_to("/par").len(), 1);
}

#[tokio::test]
async fn mtls_with_unusable_files_is_a_config_error() {
    let idp = Idp::start(json!({})).await;
    let cert = ClientCert::new("bad");
    let SenderConstraint::Mtls {
        client_cert_path,
        client_key_path,
    } = cert.constraint()
    else {
        unreachable!()
    };

    let attempt = |constraint| async {
        idp.provider()
            .await
            .with_fapi(FapiConfig {
                sender_constraint: constraint,
                ..Default::default()
            })
            .map(|_| ())
    };
    // A path that does not exist.
    let missing = SenderConstraint::Mtls {
        client_cert_path: format!("{client_cert_path}.missing"),
        client_key_path: client_key_path.clone(),
    };
    assert!(matches!(attempt(missing).await, Err(OAuthError::Config(_))));
    // A key file that is not a key.
    std::fs::write(&client_key_path, "not a pem").unwrap();
    let garbage = SenderConstraint::Mtls {
        client_cert_path,
        client_key_path,
    };
    assert!(matches!(attempt(garbage).await, Err(OAuthError::Config(_))));
}
