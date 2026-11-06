//! The FAPI 2.0 profile against a wiremock IdP: the DPoP proof on the token
//! request, the nonce retry, the `token_type` check, the refresh and userinfo
//! calls bound to the same key, JARM, the ID-token algorithm allow-list, and
//! client authentication by `private_key_jwt` or mTLS, never a client secret.
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
use axess_factors::client_assertion::{CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAssertionSigner};
use axess_factors::oauth::{
    DpopKey, FapiConfig, OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProviderBuilder,
    OAuthProviderConfig, SenderConstraint,
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
    /// The client's `private_key_jwt` key: a P-256 key in PKCS#8 DER and
    /// its public point, as the IdP holds it for the client.
    client_der: Vec<u8>,
    client_public: Vec<u8>,
}

impl Idp {
    /// An IdP signing with `PS256`, whose discovery document advertises
    /// `extra` members (with `{issuer}` in a string replaced by the issuer)
    /// and which has a PAR endpoint at `/par` that accepts every push.
    async fn start(extra: Value) -> Self {
        Self::start_with_par(extra, |_, _| {
            ResponseTemplate::new(201)
                .set_body_json(json!({ "request_uri": "urn:par:1", "expires_in": 60 }))
        })
        .await
    }

    /// [`start`](Self::start) with the PAR endpoint answering as `par` says.
    async fn start_with_par(
        extra: Value,
        par: impl Fn(&Seen, usize) -> ResponseTemplate + Send + Sync + 'static,
    ) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let (private_der, mut jwk, kid) = oauth_generate_rsa_keypair();
        jwk.as_object_mut().unwrap().remove("alg");
        let mut doc = oauth_discovery_document(&issuer);
        doc["id_token_signing_alg_values_supported"] = json!(["PS256"]);
        doc["pushed_authorization_request_endpoint"] = json!(format!("{issuer}/par"));
        doc["mtls_endpoint_aliases"] = json!({ "token_endpoint": format!("{issuer}/mtls/token") });
        let extra: Value =
            serde_json::from_str(&extra.to_string().replace("{issuer}", &issuer)).unwrap();
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
        let client_key = rcgen::KeyPair::generate().unwrap();
        let idp = Self {
            server,
            issuer,
            private_der,
            kid,
            seen: Arc::default(),
            client_der: client_key.serialize_der(),
            client_public: client_key.public_key_raw().to_vec(),
        };
        idp.mount("POST", "/par", par).await;
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

    async fn provider(&self) -> OAuthProviderBuilder {
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

    /// The client's `private_key_jwt` signer.
    fn signer(&self) -> ClientAssertionSigner {
        axess_factors::jwt::ensure_crypto_provider();
        ClientAssertionSigner::new(
            CLIENT_ID,
            EncodingKey::from_ec_der(&self.client_der),
            Algorithm::ES256,
        )
        .expect("the key signs under its algorithm")
    }

    /// A provider that can carry the FAPI profile: discovered with a secret,
    /// as [`provider`](Self::provider) is, then switched to
    /// `private_key_jwt`, which drops the secret.
    async fn fapi_provider(&self) -> OAuthProviderBuilder {
        self.provider().await.with_private_key_jwt(self.signer())
    }

    /// The claims of the client assertion `seen` carries, after its
    /// signature verified under the client's public key.
    fn assertion_claims(&self, seen: &Seen) -> Value {
        self.assertion_claims_for(seen, &self.issuer)
    }

    /// [`assertion_claims`](Self::assertion_claims) for an assertion
    /// addressed to `audience`.
    fn assertion_claims_for(&self, seen: &Seen, audience: &str) -> Value {
        assert_eq!(
            seen.form("client_assertion_type"),
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            "{} carries the assertion type",
            seen.path
        );
        let assertion = seen.form("client_assertion").expect("a client assertion");
        let (x, y) = self.client_public[1..].split_at(32);
        let key = jsonwebtoken::DecodingKey::from_ec_components(&B64.encode(x), &B64.encode(y))
            .expect("key");
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.set_audience(&[audience]);
        jsonwebtoken::decode::<Value>(assertion, &key, &validation)
            .expect("the assertion verifies under the client's key, for the issuer")
            .claims
    }
}

/// `seen` carries no client secret, in the form or in a Basic header.
fn assert_no_secret(seen: &Seen) {
    assert_eq!(
        seen.form("client_secret"),
        None,
        "{} sent the secret",
        seen.path
    );
    assert_eq!(
        seen.authorization, None,
        "{} sent an Authorization header",
        seen.path
    );
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
    idp.fapi_provider()
        .await
        .with_fapi(dpop_provider_config())
        .build()
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
        .exchange_code("code", "v".repeat(43), "n".to_string(), None)
        .await
        .expect_err("the bare form must not send a bearer request");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
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
        .refresh_oauth_token("test", "rt1", "alice-subject", None, Some(&key))
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
        .fetch_userinfo("test", "access-2", "alice-subject", Some(&key))
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
        .refresh_oauth_token("test", "rt2", "alice-subject", None, None)
        .await
        .expect_err("a bound token is not refreshed bare");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
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

/// The profile asks nothing of an ID token's `nbf` beyond the rule for any
/// JWT (FAPI 2.0 section 5.3.2.1): one more than 60 seconds in the future is
/// refused. A token without `nbf`, as Keycloak issues them, is accepted, and
/// so is one whose `nbf` has passed.
#[tokio::test]
async fn fapi_login_refuses_only_an_nbf_in_the_future() {
    let now = chrono::Utc::now().timestamp();
    for (nbf, accepted) in [
        (None, true),
        (Some(now - 5), true),
        (Some(now + 600), false),
    ] {
        let idp = Idp::start(json!({})).await;
        let authn = service(dpop_provider(&idp).await);
        let session = test_session();
        let (nonce, csrf) = begin(&authn, &session).await;
        let mut id_claims = json!({
            "iss": idp.issuer, "sub": "alice-subject", "aud": CLIENT_ID,
            "exp": now + 120, "iat": now, "nonce": nonce,
        });
        if let Some(nbf) = nbf {
            id_claims["nbf"] = json!(nbf);
        }
        let id = idp.sign(Algorithm::PS256, &id_claims);
        idp.mount("POST", "/token", move |_, _| {
            ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
        })
        .await;
        let result = authn.finish_oauth_login("code", &csrf, &session).await;
        assert_eq!(result.is_ok(), accepted, "nbf {nbf:?}: {result:?}");
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
        let authn = service(
            idp.fapi_provider()
                .await
                .with_fapi(config)
                .build()
                .expect("with_fapi"),
        );
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
    let msg = config_err(
        bare.fapi_provider()
            .await
            .with_fapi(FapiConfig::default())
            .build(),
    );
    assert!(
        msg.contains("pushed_authorization_request_endpoint"),
        "{msg}"
    );

    // An empty list accepts no ID token; a symmetric name never verifies one.
    for algs in [vec![], vec!["HS256".to_string()], vec!["none".to_string()]] {
        let msg = config_err(
            idp.fapi_provider()
                .await
                .with_fapi(FapiConfig {
                    allowed_id_token_algs: algs,
                    ..Default::default()
                })
                .build(),
        );
        assert!(msg.contains("allowed_id_token_algs"), "{msg}");
    }

    // The default profile is available.
    assert!(
        idp.fapi_provider()
            .await
            .with_fapi(FapiConfig::default())
            .build()
            .is_ok()
    );
}

/// A setting of the builder, applied by [`both_orders`].
type Setting<'a> = Box<dyn Fn(OAuthProviderBuilder) -> OAuthProviderBuilder + 'a>;

/// `first` then `second`, and `second` then `first`, each built from
/// `base`.
async fn both_orders<F, Fut>(
    base: F,
    first: &Setting<'_>,
    second: &Setting<'_>,
) -> [Result<OAuthProviderConfig, OAuthError>; 2]
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = OAuthProviderBuilder>,
{
    [
        second(first(base().await)).build(),
        first(second(base().await)).build(),
    ]
}

/// `outcomes` are the same verdict: both built, or both refused with a
/// `Config` error that contains `refusal`.
fn same_verdict(outcomes: &[Result<OAuthProviderConfig, OAuthError>; 2], refusal: Option<&str>) {
    for outcome in outcomes {
        match (outcome, refusal) {
            (Ok(_), None) => {}
            (Err(OAuthError::Config(m)), Some(want)) => assert!(m.contains(want), "{m}"),
            (other, _) => panic!(
                "expected {refusal:?}, got {:?}",
                other.as_ref().map(|_| ()).map_err(ToString::to_string)
            ),
        }
    }
}

/// Every builder setting gives one verdict whatever the order of the
/// calls: each pair that used to depend on it builds, or is refused, the
/// same way both ways round. The refusals the profile makes still happen.
#[tokio::test]
async fn every_setting_gives_one_verdict_in_either_order() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({})).await;
    let fapi: Setting = Box::new(|b| b.with_fapi(FapiConfig::default()));

    // The signer before or after the profile: built.
    let signer: Setting = Box::new(|b| b.with_private_key_jwt(idp.signer()));
    same_verdict(&both_orders(|| idp.provider(), &signer, &fapi).await, None);
    // No signer at all: refused, as before.
    assert!(matches!(
        idp.provider().await.with_fapi(FapiConfig::default()).build(),
        Err(OAuthError::Config(m)) if m.contains("private_key_jwt")
    ));

    // A PAR endpoint named before or after the profile, at an IdP that
    // advertises none: built. With none named: refused.
    let bare = Idp::start(json!({ "pushed_authorization_request_endpoint": null })).await;
    let par: Setting = Box::new(|b| b.with_par_endpoint(format!("{}/par", bare.issuer)));
    same_verdict(
        &both_orders(|| bare.fapi_provider(), &par, &fapi).await,
        None,
    );
    same_verdict(
        &[
            bare.fapi_provider()
                .await
                .with_fapi(FapiConfig::default())
                .build(),
            bare.fapi_provider()
                .await
                .with_fapi(FapiConfig::default())
                .build(),
        ],
        Some("pushed_authorization_request_endpoint"),
    );

    // A pin the profile shares nothing with: refused both ways. One inside
    // it: built both ways.
    let rs256: Setting = Box::new(|b| b.with_id_token_signing_algs(["RS256"]));
    same_verdict(
        &both_orders(|| idp.fapi_provider(), &rs256, &fapi).await,
        Some("shares no algorithm"),
    );
    let es256: Setting = Box::new(|b| b.with_id_token_signing_algs(["ES256"]));
    same_verdict(
        &both_orders(|| idp.fapi_provider(), &es256, &fapi).await,
        None,
    );
    // A bad list on its own names the pin, not the profile.
    match idp
        .provider()
        .await
        .with_id_token_signing_algs(["HS256"])
        .build()
    {
        Err(OAuthError::Config(m)) => assert!(m.contains("ID token algorithm list"), "{m}"),
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    }

    // `without_dpop` against the DPoP profile: refused both ways.
    let off: Setting = Box::new(OAuthProviderBuilder::without_dpop);
    same_verdict(
        &both_orders(|| idp.fapi_provider(), &off, &fapi).await,
        Some("requires DPoP"),
    );
    // `with_dpop` with the DPoP profile at an IdP that does not advertise
    // DPoP: built and bound both ways, since the profile binds anyway.
    let on: Setting = Box::new(OAuthProviderBuilder::with_dpop);
    let outcomes = both_orders(|| idp.fapi_provider(), &on, &fapi).await;
    same_verdict(&outcomes, None);
    for provider in outcomes.iter().flatten() {
        assert!(provider.binds_to_dpop());
    }
    // `with_dpop` against the mTLS profile: refused both ways.
    let cert = ClientCert::new("order");
    let mtls: Setting = Box::new(|b| {
        b.with_fapi(FapiConfig {
            sender_constraint: cert.constraint(),
            ..Default::default()
        })
    });
    same_verdict(
        &both_orders(|| idp.provider(), &on, &mtls).await,
        Some("mTLS"),
    );
}

/// Under mTLS the advertised aliases are put in place last: an endpoint a
/// setter named, before or after the profile, does not move the pushed
/// authorization request or the revocation off the certificate-bound
/// endpoint.
#[tokio::test]
async fn the_mtls_aliases_win_over_a_named_endpoint_in_either_order() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({ "mtls_endpoint_aliases": {
        "token_endpoint": "{issuer}/mtls/token",
        "pushed_authorization_request_endpoint": "{issuer}/mtls/par",
        "revocation_endpoint": "{issuer}/mtls/revoke",
    }}))
    .await;
    idp.mount("POST", "/mtls/par", |_, _| {
        ResponseTemplate::new(201)
            .set_body_json(json!({ "request_uri": "urn:par:mtls", "expires_in": 60 }))
    })
    .await;
    idp.mount("POST", "/mtls/revoke", |_, _| ResponseTemplate::new(200))
        .await;
    let cert = ClientCert::new("aliases");
    let mtls: Setting = Box::new(|b| {
        b.with_fapi(FapiConfig {
            sender_constraint: cert.constraint(),
            ..Default::default()
        })
    });
    let named: Setting = Box::new(|b| {
        b.with_par_endpoint(format!("{}/par", idp.issuer))
            .with_revocation_endpoint(format!("{}/revoke", idp.issuer))
    });
    for provider in both_orders(|| idp.provider(), &named, &mtls).await {
        let provider = provider.expect("build");
        let rng = axess_rng::SystemRng;
        provider
            .build_auth_url_par(&OAuthLoginOptions::default(), &rng, None)
            .await
            .expect("PAR");
        provider
            .revoke_token("rt", Some("refresh_token"), None)
            .await
            .expect("revocation");
    }
    assert_eq!(idp.requests_to("/mtls/par").len(), 2);
    assert_eq!(idp.requests_to("/mtls/revoke").len(), 2);
    assert!(
        idp.requests_to("/par").is_empty(),
        "the named PAR endpoint is not used"
    );
    assert!(idp.requests_to("/revoke").is_empty());
}

/// A pin narrows the profile and never widens it, whichever comes first:
/// with the profile widened to `RS256` and `PS256` and the client pinned
/// to `PS256`, an `RS256` ID token is refused both ways, and a `PS256` one
/// from the same IdP is accepted.
#[tokio::test]
async fn a_pin_narrows_the_profile_in_either_order() {
    let widened: Setting = Box::new(|b| {
        b.with_fapi(FapiConfig {
            allowed_id_token_algs: vec!["RS256".into(), "PS256".into()],
            ..FapiConfig::default()
        })
    });
    let ps256: Setting = Box::new(|b| b.with_id_token_signing_algs(["PS256"]));
    for pin_first in [true, false] {
        for (alg, accepted) in [(Algorithm::PS256, true), (Algorithm::RS256, false)] {
            let idp =
                Idp::start(json!({ "id_token_signing_alg_values_supported": ["RS256", "PS256"] }))
                    .await;
            let builder = idp.fapi_provider().await;
            let builder = if pin_first {
                widened(ps256(builder))
            } else {
                ps256(widened(builder))
            };
            let authn = service(builder.build().expect("build"));
            let session = test_session();
            let (nonce, csrf) = begin(&authn, &session).await;
            let id = idp.id_token(alg, &nonce, json!({}));
            idp.mount("POST", "/token", move |_, _| {
                ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
            })
            .await;
            let result = authn.finish_oauth_login("code", &csrf, &session).await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "{alg:?}, pin first: {pin_first}: {result:?}"
            );
        }
    }
}

// ── Client authentication under the profile ──────────────────────────────────

/// FAPI 2.0 Security Profile section 5.3.1.1 lets a client authenticate by
/// `private_key_jwt` or mTLS only. A provider that holds nothing but a client
/// secret is refused at `with_fapi`, before any login, whatever else the
/// profile asks for, and the refusal names both methods. Switched to
/// `private_key_jwt` first, the same provider carries the profile.
#[tokio::test]
async fn a_fapi_provider_with_only_a_client_secret_is_refused() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({})).await;
    grant_any(&idp, "Bearer").await;

    // The case: this provider authenticates with its secret.
    idp.provider()
        .await
        .build()
        .expect("build")
        .client_credentials(&["scope-a"], None)
        .await
        .expect("a grant without the profile");
    let seen = &idp.requests_to("/token")[0];
    assert_eq!(
        seen.form("client_secret"),
        None,
        "the secret is not in the form"
    );
    assert!(
        seen.authorization
            .as_deref()
            .is_some_and(|a| a.starts_with("Basic ")),
        "the provider holds a secret and sends it as a Basic header"
    );

    for config in [FapiConfig::default(), jarm_provider_config()] {
        match idp.provider().await.with_fapi(config).build() {
            Err(OAuthError::Config(m)) => assert!(
                m.contains("private_key_jwt") && m.contains("mTLS"),
                "the refusal names the allowed methods: {m}"
            ),
            other => panic!("expected Config, got {:?}", other.map(|_| ())),
        }
    }

    assert!(
        idp.provider()
            .await
            .with_private_key_jwt(idp.signer())
            .with_fapi(FapiConfig::default())
            .build()
            .is_ok()
    );
}

/// Under the profile with `private_key_jwt`, every request that proves the
/// client's identity (the pushed authorization request, the code exchange,
/// the refresh, `client_credentials` and revocation) carries a fresh
/// assertion for the issuer and no secret, though the provider was
/// discovered with one.
#[tokio::test]
async fn a_fapi_provider_with_private_key_jwt_sends_an_assertion_and_no_secret() {
    use axess_factors::oauth::{DpopSigner, OAuthProvider as _};
    let idp = Idp::start(json!({})).await;
    idp.mount("POST", "/revoke", |_, _| ResponseTemplate::new(200))
        .await;
    let (authn, claims) = dpop_login(&idp, "DPoP").await;
    let key = claims.expect("login").dpop_key.expect("key");
    authn
        .refresh_oauth_token("test", "rt1", "alice-subject", None, Some(&key))
        .await
        .expect("refresh");
    let provider = idp
        .fapi_provider()
        .await
        .with_fapi(dpop_provider_config())
        .with_revocation_endpoint(format!("{}/revoke", idp.issuer))
        .build()
        .expect("build");
    let rng = axess_rng::SystemRng;
    provider
        .client_credentials(
            &["scope-a"],
            Some(DpopSigner {
                key: &key,
                rng: &rng,
            }),
        )
        .await
        .expect("client_credentials");
    provider
        .revoke_token("rt2", Some("refresh_token"), None)
        .await
        .expect("revocation");

    let par = idp.requests_to("/par");
    let token = idp.requests_to("/token");
    let revoke = idp.requests_to("/revoke");
    let grants: Vec<_> = token.iter().filter_map(|s| s.form("grant_type")).collect();
    assert_eq!(
        grants,
        ["authorization_code", "refresh_token", "client_credentials"]
    );
    let mut jtis = std::collections::HashSet::new();
    for seen in par.iter().chain(&token).chain(&revoke) {
        assert_no_secret(seen);
        let claims = idp.assertion_claims(seen);
        assert_eq!(claims["iss"], CLIENT_ID);
        assert_eq!(claims["sub"], CLIENT_ID);
        assert!(
            jtis.insert(claims["jti"].as_str().expect("jti").to_string()),
            "every request signs a new assertion"
        );
    }
    assert_eq!(jtis.len(), 5, "PAR, three token requests and revocation");
}

/// Under the profile with mTLS the certificate authenticates the client
/// (`tls_client_auth`): the pushed authorization request, the code exchange,
/// the refresh, `client_credentials` and revocation carry the client id and
/// neither the secret the provider was discovered with nor an assertion.
/// `with_private_key_jwt` with it adds an assertion and still no secret.
#[tokio::test]
async fn a_fapi_provider_with_mtls_sends_no_secret() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({})).await;
    let cert = ClientCert::new("nosecret");
    let mtls_provider = || async {
        idp.provider()
            .await
            .with_fapi(FapiConfig {
                sender_constraint: cert.constraint(),
                ..Default::default()
            })
            .with_revocation_endpoint(format!("{}/revoke", idp.issuer))
    };
    let authn = service(mtls_provider().await.build().expect("with_fapi"));
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/mtls/token", move |seen, _| {
        let id = (seen.form("grant_type") == Some("authorization_code")).then(|| id.clone());
        ResponseTemplate::new(200).set_body_json(token_json("Bearer", id))
    })
    .await;
    idp.mount("POST", "/revoke", |_, _| ResponseTemplate::new(200))
        .await;

    authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect("login");
    authn
        .refresh_oauth_token("test", "rt1", "alice-subject", None, None)
        .await
        .expect("refresh");
    authn
        .revoke_oauth_token("test", "rt1", Some("refresh_token"), None)
        .await
        .expect("revocation");
    mtls_provider()
        .await
        .build()
        .expect("with_fapi")
        .client_credentials(&["scope-a"], None)
        .await
        .expect("client_credentials");

    let par = idp.requests_to("/par");
    let token = idp.requests_to("/mtls/token");
    let revoke = idp.requests_to("/revoke");
    let grants: Vec<_> = token.iter().filter_map(|s| s.form("grant_type")).collect();
    assert_eq!(
        grants,
        ["authorization_code", "refresh_token", "client_credentials"]
    );
    assert_eq!((par.len(), revoke.len()), (1, 1));
    for seen in par.iter().chain(&token).chain(&revoke) {
        assert_no_secret(seen);
        assert_eq!(seen.form("client_id"), Some(CLIENT_ID));
        assert_eq!(seen.form("client_assertion"), None);
    }

    mtls_provider()
        .await
        .with_private_key_jwt(idp.signer())
        .build()
        .expect("with_fapi")
        .client_credentials(&["scope-a"], None)
        .await
        .expect("client_credentials");
    let last = idp.requests_to("/mtls/token").pop().expect("a request");
    assert_no_secret(&last);
    idp.assertion_claims(&last);
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
        .fapi_provider()
        .await
        .with_fapi(jarm_provider_config())
        .build()
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

/// A response that is not this ceremony's cannot end it. Garbage, and a
/// signed error response an attacker obtained for their own flow, are
/// refused and leave the victim's ceremony in place; the real response then
/// finishes. Only an error response carrying this ceremony's own `state`
/// ends it.
#[tokio::test]
async fn a_response_that_is_not_the_ceremonys_leaves_the_flow_in_place() {
    let idp = Idp::start(json!({})).await;
    let provider = idp
        .fapi_provider()
        .await
        .with_fapi(jarm_provider_config())
        .build()
        .expect("with_fapi");
    let authn = service(provider);
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/token", move |_, _| {
        ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
    })
    .await;
    let now = chrono::Utc::now().timestamp();
    let response = |extra: Value| {
        let mut claims = json!({ "iss": idp.issuer, "aud": CLIENT_ID, "exp": now + 60 });
        claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        idp.sign(Algorithm::PS256, &claims)
    };

    let err = authn
        .finish_oauth_login_jarm("not-a-jwt", &session)
        .await
        .expect_err("garbage is refused");
    assert!(matches!(err, OAuthError::IdTokenValidation(_)), "{err:?}");

    let foreign_error = response(json!({ "error": "access_denied", "state": "someone-elses" }));
    let err = authn
        .finish_oauth_login_jarm(&foreign_error, &session)
        .await
        .expect_err("another flow's error response is refused");
    assert!(matches!(err, OAuthError::CsrfMismatch), "{err:?}");

    let real = response(json!({ "code": "the-code", "state": csrf }));
    authn
        .finish_oauth_login_jarm(&real, &session)
        .await
        .expect("the victim's ceremony survived both");

    // The ceremony's own error response ends it.
    let session = test_session();
    let (_nonce, csrf) = begin(&authn, &session).await;
    let own_error = response(json!({ "error": "access_denied", "state": csrf }));
    let err = authn
        .finish_oauth_login_jarm(&own_error, &session)
        .await
        .expect_err("the IdP refused this flow");
    assert!(matches!(err, OAuthError::TokenExchange(_)), "{err:?}");
    let real = response(json!({ "code": "the-code", "state": csrf }));
    let err = authn
        .finish_oauth_login_jarm(&real, &session)
        .await
        .expect_err("the ceremony is over");
    assert!(matches!(err, OAuthError::NoFlow), "{err:?}");
}

// ── The login's nonce on a refresh ───────────────────────────────────────────

/// The login returns its nonce as a typed field, and passing it back as the
/// original nonce accepts a refresh ID token that repeats it; without it the
/// same refresh response is refused.
#[tokio::test]
async fn the_login_returns_its_nonce_and_a_refresh_id_token_that_repeats_it_is_accepted() {
    let idp = Idp::start(json!({})).await;
    let authn = service(idp.provider().await.build().expect("build"));
    let session = test_session();
    let (nonce, csrf) = begin(&authn, &session).await;
    let id = idp.id_token(Algorithm::PS256, &nonce, json!({}));
    idp.mount("POST", "/token", move |_, _| {
        // Both the code exchange and the refresh answer with an ID token
        // carrying the login's nonce, as Keycloak does.
        ResponseTemplate::new(200).set_body_json(token_json("Bearer", Some(id.clone())))
    })
    .await;
    let claims = authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect("login");
    assert_eq!(
        claims.nonce.as_deref(),
        Some(nonce.as_str()),
        "the typed nonce is the login's"
    );
    assert_eq!(
        claims.additional_claims["nonce"].as_str(),
        Some(nonce.as_str()),
        "and the raw claim still carries it"
    );

    authn
        .refresh_oauth_token(
            "test",
            "rt1",
            "alice-subject",
            claims.nonce.as_deref(),
            None,
        )
        .await
        .expect("a refresh ID token that repeats the login nonce is accepted");
    let err = authn
        .refresh_oauth_token("test", "rt1", "alice-subject", None, None)
        .await
        .expect_err("a nonce with no original to compare it with is refused");
    assert!(matches!(err, OAuthError::IdTokenValidation(_)), "{err:?}");
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
        .build()
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
            .build()
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

// ── Client credentials, the device grant and revocation on a DPoP provider ──

/// A token endpoint that grants `token_type` to any grant and records what
/// it saw.
async fn grant_any(idp: &Idp, token_type: &'static str) {
    idp.mount("POST", "/token", move |_, _| {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "cc-1",
            "token_type": token_type,
            "expires_in": 300,
        }))
    })
    .await;
}

#[tokio::test]
async fn client_credentials_on_a_dpop_provider_is_refused_bare() {
    let idp = Idp::start(json!({})).await;
    grant_any(&idp, "Bearer").await;
    let provider = dpop_provider(&idp).await;
    use axess_factors::oauth::OAuthProvider as _;
    let err = provider
        .client_credentials(&["scope-a"], None)
        .await
        .expect_err("the bare form must not fetch a bearer token from a DPoP provider");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
    assert!(idp.requests_to("/token").is_empty(), "nothing was sent");
}

#[tokio::test]
async fn the_device_grant_on_a_dpop_provider_is_refused_bare() {
    let idp = Idp::start(json!({})).await;
    grant_any(&idp, "Bearer").await;
    let provider = dpop_provider(&idp).await;
    use axess_factors::oauth::OAuthProvider as _;
    let err = provider
        .poll_device_token("device-code-1", 5, None, None)
        .await
        .expect_err("the bare poll must not fetch a bearer token from a DPoP provider");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
    assert!(idp.requests_to("/token").is_empty(), "nothing was sent");
}

#[tokio::test]
async fn client_credentials_with_a_key_carries_a_proof_and_wants_a_bound_answer() {
    use axess_factors::oauth::{DpopSigner, OAuthProvider as _};
    let idp = Idp::start(json!({})).await;
    grant_any(&idp, "DPoP").await;
    let provider = dpop_provider(&idp).await;
    let rng = axess_rng::SystemRng;
    let key = DpopKey::generate(&rng);
    let signer = DpopSigner {
        key: &key,
        rng: &rng,
    };

    let token = provider
        .client_credentials(&["scope-a"], Some(signer))
        .await
        .expect("a bound client_credentials grant");
    assert_eq!(token.token_type, "DPoP");
    let seen = &idp.requests_to("/token")[0];
    assert_eq!(seen.form("grant_type"), Some("client_credentials"));
    let (header, payload) = proof_of(seen);
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], format!("{}/token", idp.issuer));

    // A bearer answer to a bound request is refused.
    let bearer = Idp::start(json!({})).await;
    grant_any(&bearer, "Bearer").await;
    let provider = dpop_provider(&bearer).await;
    let err = provider
        .client_credentials(&["scope-a"], Some(signer))
        .await
        .expect_err("a bearer token is not what was asked for");
    assert!(matches!(err, OAuthError::TokenExchange(_)), "{err:?}");
}

#[tokio::test]
async fn the_device_grant_with_a_key_carries_a_proof_and_returns_the_key() {
    use axess_factors::oauth::{DpopSigner, OAuthProvider as _};
    let idp = Idp::start(json!({})).await;
    let id = idp.id_token(Algorithm::PS256, "", json!({}));
    idp.mount("POST", "/token", move |_, _| {
        ResponseTemplate::new(200).set_body_json(token_json("DPoP", Some(id.clone())))
    })
    .await;
    let provider = dpop_provider(&idp).await;
    let rng = axess_rng::SystemRng;
    let key = DpopKey::generate(&rng);
    let signer = DpopSigner {
        key: &key,
        rng: &rng,
    };

    let outcome = provider
        .poll_device_token("device-code-1", 5, None, Some(signer))
        .await
        .expect("a bound device grant");
    let axess_factors::oauth::DeviceTokenOutcome::Authorized(claims) = outcome else {
        panic!("authorized, got {outcome:?}");
    };
    assert_eq!(
        claims
            .dpop_key
            .expect("the claims carry the key")
            .thumbprint()
            .unwrap(),
        key.thumbprint().unwrap()
    );
    let seen = &idp.requests_to("/token")[0];
    assert_eq!(
        seen.form("grant_type"),
        Some("urn:ietf:params:oauth:grant-type:device_code")
    );
    let (header, _) = proof_of(seen);
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
}

#[tokio::test]
async fn revocation_sends_bare_and_carries_a_proof_when_given_the_key() {
    use axess_factors::oauth::{DpopSigner, OAuthProvider as _};
    let idp = Idp::start(json!({})).await;
    idp.mount("POST", "/revoke", |_, _| ResponseTemplate::new(200))
        .await;
    let provider = idp
        .fapi_provider()
        .await
        .with_fapi(dpop_provider_config())
        .with_revocation_endpoint(format!("{}/revoke", idp.issuer))
        .build()
        .expect("build");

    provider
        .revoke_token("rt1", Some("refresh_token"), None)
        .await
        .expect("a bare revocation is sent: it issues no token");
    assert!(idp.requests_to("/revoke")[0].dpop.is_none());

    let rng = axess_rng::SystemRng;
    let key = DpopKey::generate(&rng);
    provider
        .revoke_token(
            "rt1",
            Some("refresh_token"),
            Some(DpopSigner {
                key: &key,
                rng: &rng,
            }),
        )
        .await
        .expect("revocation with a proof");
    let (header, payload) = proof_of(&idp.requests_to("/revoke")[1]);
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    assert_eq!(payload["htm"], "POST");
}

// ── Userinfo on a DPoP provider ──────────────────────────────────────────────

/// A DPoP provider's access tokens are bound: the bare userinfo forms send
/// nothing, as the bare token-request forms do, instead of presenting the
/// bound token as `Bearer`.
#[tokio::test]
async fn userinfo_on_a_dpop_provider_is_refused_bare() {
    let idp = Idp::start(json!({})).await;
    let (authn, claims) = dpop_login(&idp, "DPoP").await;
    let access = claims
        .expect("login")
        .access_token
        .expect("an access token");
    idp.mount("GET", "/userinfo", |_, _| {
        ResponseTemplate::new(200).set_body_json(json!({ "sub": "alice-subject" }))
    })
    .await;

    let err = authn
        .fetch_userinfo("test", &access, "alice-subject", None)
        .await
        .expect_err("a bound token is not sent as Bearer");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");

    let provider = dpop_provider(&idp).await;
    use axess_factors::oauth::OAuthProvider as _;
    let err = provider
        .fetch_userinfo_unchecked(&access, None)
        .await
        .expect_err("the provider's bare form is refused too");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
    assert!(idp.requests_to("/userinfo").is_empty(), "nothing was sent");
}

/// A `401` from the userinfo endpoint is retried with a nonce only when it
/// is the `use_dpop_nonce` challenge of RFC 9449 section 9; a `401` that
/// says `invalid_token` is the refusal it says it is, whatever headers it
/// carries.
#[tokio::test]
async fn userinfo_retries_with_a_nonce_only_on_a_use_dpop_nonce_challenge() {
    let idp = Idp::start(json!({})).await;
    let (authn, claims) = dpop_login(&idp, "DPoP").await;
    let claims = claims.expect("login");
    let key = claims.dpop_key.clone().expect("key");
    let access = claims.access_token.clone().expect("an access token");
    // First call: a refusal that happens to carry a nonce. Second call: the
    // challenge. Third: accepted when the proof echoes the nonce.
    idp.mount("GET", "/userinfo", |seen, count| match count {
        0 => ResponseTemplate::new(401)
            .insert_header("WWW-Authenticate", "DPoP error=\"invalid_token\"")
            .insert_header("DPoP-Nonce", "unasked-nonce"),
        1 => ResponseTemplate::new(401)
            .insert_header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
            .insert_header("DPoP-Nonce", "rs-nonce-1"),
        _ => {
            let (_, payload) = proof_of(seen);
            if payload["nonce"] == "rs-nonce-1" {
                ResponseTemplate::new(200).set_body_json(json!({ "sub": "alice-subject" }))
            } else {
                ResponseTemplate::new(401)
                    .insert_header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
                    .insert_header("DPoP-Nonce", "rs-nonce-1")
            }
        }
    })
    .await;

    let err = authn
        .fetch_userinfo("test", &access, "alice-subject", Some(&key))
        .await
        .expect_err("invalid_token is a refusal");
    assert!(matches!(err, OAuthError::AccessTokenExpired), "{err:?}");
    assert_eq!(
        idp.requests_to("/userinfo").len(),
        1,
        "a 401 that is not the nonce challenge is not retried"
    );

    authn
        .fetch_userinfo("test", &access, "alice-subject", Some(&key))
        .await
        .expect("the challenge is answered with the nonce");
    let calls = idp.requests_to("/userinfo");
    assert_eq!(calls.len(), 3, "one challenge, one retry");
    let (_, first) = proof_of(&calls[1]);
    assert!(
        first.get("nonce").is_none(),
        "the first proof carries no nonce"
    );
    let (_, retry) = proof_of(&calls[2]);
    assert_eq!(retry["nonce"], "rs-nonce-1");
}

// ── The DPoP key at the pushed authorization request ─────────────────────────

/// A DPoP login makes its key at begin: the pushed authorization request
/// names it in `dpop_jkt` and carries a proof signed by it (RFC 9449
/// sections 10 and 10.1), and the token request presents the same key, so
/// the code the authorization server issued bound to the key is redeemed
/// with it.
#[tokio::test]
async fn par_names_the_key_the_token_request_presents() {
    let idp = Idp::start(json!({})).await;
    let (_authn, claims) = dpop_login(&idp, "DPoP").await;
    let key = claims.expect("login").dpop_key.expect("key");
    let jkt = key.thumbprint().unwrap();

    let pushes = idp.requests_to("/par");
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        pushes[0].form("dpop_jkt"),
        Some(jkt.as_str()),
        "the push names the login's key"
    );
    let (header, payload) = proof_of(&pushes[0]);
    assert_eq!(header_thumbprint(&header), jkt, "the push is signed by it");
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], format!("{}/par", idp.issuer));

    let token = &idp.requests_to("/token")[0];
    let (header, _) = proof_of(token);
    assert_eq!(
        header_thumbprint(&header),
        jkt,
        "the token request presents the key the push named"
    );
}

/// A PAR endpoint that wants a nonce refuses the first push with
/// `use_dpop_nonce` and is answered once with a proof that echoes it, as the
/// token endpoint is.
#[tokio::test]
async fn a_par_use_dpop_nonce_refusal_is_answered_with_the_nonce() {
    let idp = Idp::start_with_par(json!({}), |seen, _| {
        let (_, payload) = proof_of(seen);
        if payload["nonce"] == "par-nonce-1" {
            ResponseTemplate::new(201)
                .set_body_json(json!({ "request_uri": "urn:par:2", "expires_in": 60 }))
        } else {
            ResponseTemplate::new(400)
                .insert_header("DPoP-Nonce", "par-nonce-1")
                .set_body_json(json!({ "error": "use_dpop_nonce" }))
        }
    })
    .await;
    let authn = service(dpop_provider(&idp).await);
    let session = test_session();
    let (_nonce, _csrf) = begin(&authn, &session).await;

    let pushes = idp.requests_to("/par");
    assert_eq!(pushes.len(), 2, "one refusal, one retry");
    let (_, first) = proof_of(&pushes[0]);
    assert!(first.get("nonce").is_none());
    let (_, retry) = proof_of(&pushes[1]);
    assert_eq!(retry["nonce"], "par-nonce-1");
    assert_eq!(pushes[0].form("dpop_jkt"), pushes[1].form("dpop_jkt"));
}

// ── Client authentication on a retried request ───────────────────────────────

/// A token request answered with `use_dpop_nonce` is sent again with a proof
/// that echoes the nonce, and with a client assertion of its own: FAPI 2.0
/// has the authorization server refuse an assertion whose `jti` it has seen.
#[tokio::test]
async fn the_nonce_retry_signs_a_fresh_client_assertion() {
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
    let first = idp.assertion_claims(&requests[0]);
    let second = idp.assertion_claims(&requests[1]);
    assert_ne!(
        first["jti"], second["jti"],
        "the retry replays the first request's client assertion"
    );
}

// ── The device authorization request ─────────────────────────────────────────

/// The device authorization request proves the client's identity like every
/// other request to the IdP (RFC 8628 section 3.1 defers to RFC 6749
/// section 3.2.1): a `private_key_jwt` client sends its assertion, and no
/// secret.
#[tokio::test]
async fn the_device_authorization_request_carries_the_clients_assertion() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({})).await;
    idp.mount("POST", "/device", |_, _| {
        ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dc",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://idp.example/device",
            "expires_in": 600,
            "interval": 5,
        }))
    })
    .await;
    let provider = idp
        .fapi_provider()
        .await
        .with_device_authorization_endpoint(format!("{}/device", idp.issuer))
        .build()
        .expect("build");
    provider
        .request_device_code(&["openid"])
        .await
        .expect("a device code");

    let requests = idp.requests_to("/device");
    assert_eq!(requests.len(), 1);
    assert_no_secret(&requests[0]);
    assert_eq!(requests[0].form("scope"), Some("openid"));
    let claims = idp.assertion_claims_for(&requests[0], &format!("{}/device", idp.issuer));
    assert_eq!(claims["iss"], CLIENT_ID);
}

/// A client with a secret sends it, as a form member next to its id, and
/// the id once.
#[tokio::test]
async fn the_device_authorization_request_authenticates_the_client() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({})).await;
    idp.mount("POST", "/device", |_, _| {
        ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dc",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://idp.example/device",
            "expires_in": 600,
        }))
    })
    .await;
    let provider = idp
        .provider()
        .await
        .with_device_authorization_endpoint(format!("{}/device", idp.issuer))
        .build()
        .expect("build");
    provider
        .request_device_code(&["openid"])
        .await
        .expect("a device code");

    let requests = idp.requests_to("/device");
    assert!(requests[0].form("client_secret").is_none());
    let basic = requests[0]
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Basic "))
        .expect("the secret is sent as a Basic header");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(basic)
        .expect("base64");
    assert_eq!(
        String::from_utf8(decoded).expect("utf-8"),
        format!("{CLIENT_ID}:test-secret")
    );
    let ids = requests[0]
        .form
        .iter()
        .filter(|(k, _)| k == "client_id")
        .count();
    assert_eq!(ids, 1, "the client id is sent once");
}

// ── Failures of the token endpoint ───────────────────────────────────────────

/// A `5xx` from the token endpoint is the transient failure a caller may
/// retry, whichever grant met it, and its message does not carry the body: an
/// error page can echo the request.
#[tokio::test]
async fn a_5xx_from_the_token_endpoint_is_transient_and_its_message_has_no_body() {
    use axess_factors::oauth::OAuthProvider as _;
    let idp = Idp::start(json!({})).await;
    idp.mount("POST", "/token", |_, _| {
        ResponseTemplate::new(503).set_body_string("upstream echo: client_secret=LEAKED-SECRET")
    })
    .await;
    idp.mount("POST", "/revoke", |_, _| {
        ResponseTemplate::new(503).set_body_string("upstream echo: token=LEAKED-TOKEN")
    })
    .await;
    let provider = idp
        .provider()
        .await
        .without_dpop()
        .with_revocation_endpoint(format!("{}/revoke", idp.issuer))
        .build()
        .expect("build");

    let errors = [
        provider
            .client_credentials(&["scope-a"], None)
            .await
            .expect_err("503"),
        provider
            .refresh_token_unchecked("rt1", None, None)
            .await
            .expect_err("503"),
        provider
            .revoke_token("rt1", Some("refresh_token"), None)
            .await
            .expect_err("503"),
    ];
    // A device-code poll that meets a 5xx is not a denial.
    let polled = provider.poll_device_token("dc", 5, None, None).await;
    assert!(
        matches!(&polled, Err(e) if e.is_transient()),
        "a 503 is not the user's refusal: {:?}",
        polled.map(|_| ())
    );
    for err in errors {
        assert!(err.is_transient(), "a 503 can be retried: {err:?}");
        let shown = err.to_string();
        assert!(!shown.contains("LEAKED"), "{shown}");
    }
}

/// A token endpoint that cannot be reached is as transient as one that
/// answers 5xx.
#[tokio::test]
async fn an_unreachable_token_endpoint_is_transient() {
    use axess_factors::oauth::OAuthProvider as _;
    // The discovery document names a token endpoint nothing listens on.
    let idp = Idp::start(json!({ "token_endpoint": "http://127.0.0.1:1/token" })).await;
    let provider = idp.provider().await.without_dpop().build().expect("build");
    let err = provider
        .client_credentials(&["scope-a"], None)
        .await
        .expect_err("nothing answers");
    assert!(err.is_transient(), "{err:?}");
}

// ── Challenges in one header ─────────────────────────────────────────────────

/// A `WWW-Authenticate` value may carry several challenges (RFC 9110
/// section 11.6.1); the nonce challenge is answered wherever it stands.
#[tokio::test]
async fn userinfo_answers_a_nonce_challenge_that_is_not_the_first_in_its_header() {
    let idp = Idp::start(json!({})).await;
    let (authn, claims) = dpop_login(&idp, "DPoP").await;
    let claims = claims.expect("login");
    let key = claims.dpop_key.clone().expect("key");
    let access = claims.access_token.clone().expect("an access token");
    idp.mount("GET", "/userinfo", |seen, _| {
        let (_, payload) = proof_of(seen);
        if payload["nonce"] == "rs-nonce-1" {
            ResponseTemplate::new(200).set_body_json(json!({ "sub": "alice-subject" }))
        } else {
            ResponseTemplate::new(401)
                .insert_header(
                    "WWW-Authenticate",
                    "Bearer realm=\"api\", DPoP error=\"use_dpop_nonce\", \
                     error_description=\"a, nonce\"",
                )
                .insert_header("DPoP-Nonce", "rs-nonce-1")
        }
    })
    .await;

    authn
        .fetch_userinfo("test", &access, "alice-subject", Some(&key))
        .await
        .expect("the DPoP challenge is answered though a Bearer one comes first");
    assert_eq!(idp.requests_to("/userinfo").len(), 2);
}

/// A response the IdP signed for this ceremony, with neither a code nor an
/// error, is an answer that will not be followed by a better one: it ends
/// the ceremony as the error response does, instead of leaving it open.
#[tokio::test]
async fn a_signed_response_with_no_code_and_no_error_ends_the_ceremony() {
    let idp = Idp::start(json!({})).await;
    let provider = idp
        .fapi_provider()
        .await
        .with_fapi(jarm_provider_config())
        .build()
        .expect("with_fapi");
    let authn = service(provider);
    let session = test_session();
    let (_nonce, csrf) = begin(&authn, &session).await;
    let jwt = idp.sign(
        Algorithm::PS256,
        &json!({
            "iss": idp.issuer,
            "aud": CLIENT_ID,
            "exp": chrono::Utc::now().timestamp() + 60,
            "state": csrf,
        }),
    );

    let result = authn.finish_oauth_login_jarm(&jwt, &session).await;
    assert!(
        matches!(result, Err(OAuthError::InvalidParameter)),
        "{result:?}"
    );
    assert!(
        session.get_custom("axess.oauth.csrf_state").await.is_none(),
        "the ceremony is cleared"
    );
}

// ── The client id of the signer ──────────────────────────────────────────────

/// The assertion names the signer's client id as `iss` and `sub`, and the
/// request names the provider's: a signer for another client is refused when
/// the provider is built, not by the IdP on every request.
#[tokio::test]
async fn a_signer_for_another_client_is_refused_at_build() {
    let idp = Idp::start(json!({})).await;
    axess_factors::jwt::ensure_crypto_provider();
    let other = ClientAssertionSigner::new(
        "another-client",
        EncodingKey::from_ec_der(&idp.client_der),
        Algorithm::ES256,
    )
    .expect("signer");
    let built = idp.provider().await.with_private_key_jwt(other).build();
    assert!(
        matches!(&built, Err(OAuthError::Config(m)) if m.contains("client")),
        "{:?}",
        built.map(|_| ())
    );
    // The signer of the provider's own client builds.
    idp.fapi_provider().await.build().expect("same client id");
}
