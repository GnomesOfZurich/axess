//! DPoP without the FAPI profile, against a wiremock IdP: a provider that
//! authenticates with a client secret binds its tokens to a DPoP key when the
//! IdP advertises DPoP, sends Bearer requests when it does not or when the
//! deployment opts out, and refreshes with the key the login returned, after
//! a restart too.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth --test oauth_dpop_wiremock`

#![cfg(feature = "testing-oauth")]

use axess_core::authn::AuditContext;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders, TenantClientCredential, TenantDpop,
    TenantOAuthProviderRecord, TenantOAuthProviders as _,
};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair},
    test_session,
};
use axess_factors::FactorSecret;
use axess_factors::client_assertion::ClientAssertionSigner;
use axess_factors::oauth::{
    DpopKey, FapiConfig, OAuthClaims, OAuthError, OAuthLoginOptions, OAuthProvider as _,
    OAuthProviderBuilder, OAuthProviderConfig, SenderConstraint,
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
const SECRET: &str = "test-secret";

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

type Answer = Box<dyn Fn(&Seen) -> ResponseTemplate + Send + Sync>;

/// An endpoint that records its requests and answers as scripted.
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
        self.seen.lock().unwrap().push(seen.clone());
        (self.answer)(&seen)
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
    /// An IdP signing ID tokens with `RS256`, with a PAR endpoint, whose
    /// discovery document carries `extra` on top of the usual members.
    async fn start(extra: Value) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let (private_der, jwk, kid) = oauth_generate_rsa_keypair();
        let mut doc = oauth_discovery_document(&issuer);
        doc["pushed_authorization_request_endpoint"] = json!(format!("{issuer}/par"));
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
        Self {
            server,
            issuer,
            private_der,
            kid,
            seen: Arc::default(),
        }
    }

    /// An IdP that advertises DPoP with the algorithm axess signs proofs
    /// with.
    async fn advertising_dpop() -> Self {
        Self::start(json!({ "dpop_signing_alg_values_supported": ["ES256", "PS256"] })).await
    }

    async fn mount(
        &self,
        verb: &str,
        at: &str,
        answer: impl Fn(&Seen) -> ResponseTemplate + Send + Sync + 'static,
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

    fn id_token(&self, nonce: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        axess_factors::jwt::ensure_crypto_provider();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(
            &header,
            &json!({
                "iss": self.issuer,
                "sub": "alice-subject",
                "aud": CLIENT_ID,
                "exp": now + 120,
                "iat": now,
                "nonce": nonce,
            }),
            &EncodingKey::from_rsa_der(&self.private_der),
        )
        .expect("sign")
    }

    /// The builder of a provider discovered with a client secret.
    async fn builder(&self) -> OAuthProviderBuilder {
        OAuthProviderConfig::discover(
            "test",
            &self.issuer,
            CLIENT_ID,
            SECRET,
            "http://localhost:3000/callback",
        )
        .await
        .expect("discovery")
    }

    /// A provider discovered with a client secret and nothing else
    /// configured.
    async fn provider(&self) -> OAuthProviderConfig {
        self.builder().await.build().expect("build")
    }

    /// A token endpoint that answers every grant: with `token_type` `DPoP`
    /// and an access token whose `cnf.jkt` names the key of the request's
    /// proof (or `jkt` when given) when a proof came, and with `Bearer`
    /// when none did. The code exchange carries `id_token`.
    async fn mount_token(&self, id_token: Option<String>, jkt: Option<&'static str>) {
        self.mount("POST", "/token", move |seen| {
            let refresh = seen.form("grant_type") == Some("refresh_token");
            let n = if refresh { 2 } else { 1 };
            let mut body = match &seen.dpop {
                Some(proof) => {
                    let bound =
                        jkt.map_or_else(|| header_thumbprint(&segment(proof, 0)), str::to_string);
                    json!({ "access_token": access_jwt(n, &bound), "token_type": "DPoP" })
                }
                None => json!({ "access_token": format!("access-{n}"), "token_type": "Bearer" }),
            };
            body["expires_in"] = json!(300);
            body["refresh_token"] = json!(format!("rt{n}"));
            if let (false, Some(id)) = (refresh, &id_token) {
                body["id_token"] = json!(id);
            }
            ResponseTemplate::new(200).set_body_json(body)
        })
        .await;
    }

    async fn mount_userinfo(&self) {
        self.mount("GET", "/userinfo", |_| {
            ResponseTemplate::new(200).set_body_json(json!({ "sub": "alice-subject" }))
        })
        .await;
    }
}

/// An access token in JWT form whose `cnf.jkt` is `jkt`. The client reads
/// the claim without verifying the signature, which is the resource
/// server's to check.
fn access_jwt(n: usize, jkt: &str) -> String {
    let part = |v: Value| B64.encode(v.to_string());
    format!(
        "{}.{}.{}",
        part(json!({ "alg": "ES256", "typ": "at+jwt" })),
        part(json!({ "jti": format!("access-{n}"), "cnf": { "jkt": jkt } })),
        B64.encode("signature"),
    )
}

fn service(provider: OAuthProviderConfig) -> Authn {
    AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default())
}

/// Log in through `provider` against `idp`, whose token endpoint answers as
/// [`Idp::mount_token`] does with `jkt`.
async fn login(
    idp: &Idp,
    provider: OAuthProviderConfig,
    jkt: Option<&'static str>,
) -> (Authn, Result<OAuthClaims, OAuthError>) {
    let authn = service(provider);
    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let get = |key: &'static str| {
        let session = &session;
        async move {
            session
                .get_custom(key)
                .await
                .and_then(|v| v.as_str().map(str::to_owned))
                .expect(key)
        }
    };
    let nonce = get("axess.oauth.nonce").await;
    let csrf = get("axess.oauth.csrf_state").await;
    idp.mount_token(Some(idp.id_token(&nonce)), jkt).await;
    let result = authn.finish_oauth_login("code", &csrf, &session).await;
    (authn, result)
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

/// `(header, payload)` of the proof `seen` carries.
fn proof_of(seen: &Seen) -> (Value, Value) {
    let proof = seen.dpop.as_deref().expect("a DPoP header");
    let header = segment(proof, 0);
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    (header, segment(proof, 1))
}

/// The client secret travelled, as a Basic header (openidconnect's default)
/// or in the form.
fn authenticated_by_secret(seen: &Seen) -> bool {
    let basic = B64.encode(format!("{CLIENT_ID}:{SECRET}"));
    let basic_padded =
        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{SECRET}"));
    seen.form("client_secret") == Some(SECRET)
        || seen
            .authorization
            .as_deref()
            .is_some_and(|a| a == format!("Basic {basic}") || a == format!("Basic {basic_padded}"))
}

// ── The default follows the discovery document ───────────────────────────────

#[tokio::test]
async fn a_client_secret_provider_binds_tokens_when_the_idp_advertises_dpop() {
    let idp = Idp::advertising_dpop().await;
    let provider = idp.provider().await;
    assert!(provider.binds_to_dpop(), "on by default when advertised");

    let (authn, claims) = login(&idp, provider, None).await;
    let claims = claims.expect("login");

    let exchange = &idp.requests_to("/token")[0];
    assert!(
        authenticated_by_secret(exchange),
        "the client still authenticates with its secret: {exchange:?}"
    );
    let (header, payload) = proof_of(exchange);
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], format!("{}/token", idp.issuer));
    let key = claims
        .dpop_key
        .clone()
        .expect("the login returns its DPoP key");
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    assert!(
        idp.requests_to("/par").is_empty(),
        "standalone DPoP does not switch PAR on"
    );

    idp.mount_userinfo().await;
    let access = String::from(&*claims.access_token.clone().expect("an access token"));
    authn
        .fetch_userinfo("test", &access, "alice-subject", Some(&key))
        .await
        .expect("userinfo");
    let userinfo = &idp.requests_to("/userinfo")[0];
    assert_eq!(
        userinfo.authorization.as_deref(),
        Some(format!("DPoP {access}").as_str())
    );
    let (header, payload) = proof_of(userinfo);
    assert_eq!(header_thumbprint(&header), key.thumbprint().unwrap());
    assert_eq!(
        payload["ath"],
        B64.encode(sha2::Sha256::digest(access.as_bytes()))
    );

    let err = authn
        .fetch_userinfo("test", &access, "alice-subject", None)
        .await
        .expect_err("a bound token is not sent as Bearer");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
    assert_eq!(
        idp.requests_to("/userinfo").len(),
        1,
        "nothing more was sent"
    );
}

#[tokio::test]
async fn an_access_token_bound_to_another_key_is_refused() {
    let idp = Idp::advertising_dpop().await;
    let provider = idp.provider().await;
    let (_authn, result) = login(&idp, provider, Some("some-other-thumbprint")).await;
    assert!(
        matches!(result, Err(OAuthError::TokenExchange(_))),
        "cnf.jkt names another key: {result:?}"
    );
    assert!(
        idp.requests_to("/token")[0].dpop.is_some(),
        "a proof was sent"
    );
}

#[tokio::test]
async fn an_idp_that_does_not_advertise_dpop_gets_bearer_requests() {
    for extra in [
        json!({}),
        json!({ "dpop_signing_alg_values_supported": [] }),
        json!({ "dpop_signing_alg_values_supported": ["PS256", "EdDSA"] }),
    ] {
        let idp = Idp::start(extra.clone()).await;
        let provider = idp.provider().await;
        assert!(!provider.binds_to_dpop(), "off for {extra}");

        let (authn, claims) = login(&idp, provider, None).await;
        let claims = claims.expect("login");
        assert!(claims.dpop_key.is_none(), "{extra}");
        assert!(idp.requests_to("/token")[0].dpop.is_none(), "{extra}");

        idp.mount_userinfo().await;
        authn
            .fetch_userinfo("test", "access-1", "alice-subject", None)
            .await
            .expect("userinfo");
        assert_eq!(
            idp.requests_to("/userinfo")[0].authorization.as_deref(),
            Some("Bearer access-1"),
            "{extra}"
        );
    }
}

// ── The explicit settings ────────────────────────────────────────────────────

#[tokio::test]
async fn without_dpop_sends_no_proof_and_takes_bearer() {
    let idp = Idp::advertising_dpop().await;
    let provider = idp
        .builder()
        .await
        .without_dpop()
        .build()
        .expect("without_dpop");
    assert!(!provider.binds_to_dpop());

    let (authn, claims) = login(&idp, provider, None).await;
    let claims = claims.expect("login");
    assert!(claims.dpop_key.is_none());
    assert!(idp.requests_to("/token")[0].dpop.is_none(), "no proof");

    let outcome = authn
        .refresh_oauth_token("test", "rt1", "alice-subject", None, None)
        .await
        .expect("a bare refresh");
    assert_eq!(&*outcome.refresh_token, "rt2");
    assert!(idp.requests_to("/token")[1].dpop.is_none(), "no proof");

    idp.mount_userinfo().await;
    authn
        .fetch_userinfo("test", "access-2", "alice-subject", None)
        .await
        .expect("userinfo");
    assert_eq!(
        idp.requests_to("/userinfo")[0].authorization.as_deref(),
        Some("Bearer access-2")
    );
}

#[tokio::test]
async fn with_dpop_requires_the_idp_to_advertise_it() {
    let idp = Idp::start(json!({})).await;
    let err = idp
        .builder()
        .await
        .with_dpop()
        .build()
        .err()
        .expect("refused when the IdP does not advertise DPoP");
    assert!(matches!(err, OAuthError::Config(_)), "{err:?}");

    let idp = Idp::advertising_dpop().await;
    let provider = idp
        .builder()
        .await
        .without_dpop()
        .with_dpop()
        .build()
        .expect("with_dpop");
    assert!(provider.binds_to_dpop(), "the later setting wins");
}

/// The FAPI profile binds tokens to a DPoP key through the same switch, and
/// `without_dpop` is refused under it whichever comes first.
#[tokio::test]
async fn the_fapi_profile_keeps_dpop_on_whatever_the_order() {
    let idp = Idp::start(json!({})).await;
    let client_key = rcgen::KeyPair::generate().unwrap();
    axess_factors::jwt::ensure_crypto_provider();
    let signer = || {
        ClientAssertionSigner::new(
            CLIENT_ID,
            EncodingKey::from_ec_der(&client_key.serialize_der()),
            Algorithm::ES256,
        )
        .expect("the key signs under its algorithm")
    };

    let fapi = idp
        .builder()
        .await
        .with_private_key_jwt(signer())
        .with_fapi(FapiConfig::default())
        .build()
        .expect("with_fapi");
    assert!(
        fapi.binds_to_dpop(),
        "FAPI with DPoP binds, advertised or not"
    );
    for without_first in [true, false] {
        let builder = idp.builder().await.with_private_key_jwt(signer());
        let builder = if without_first {
            builder.without_dpop().with_fapi(FapiConfig::default())
        } else {
            builder.with_fapi(FapiConfig::default()).without_dpop()
        };
        let err = builder
            .build()
            .err()
            .expect("FAPI's DPoP cannot be switched off");
        assert!(matches!(err, OAuthError::Config(_)), "{err:?}");
    }
}

/// Under the FAPI profile with mTLS the certificate binds the tokens: DPoP
/// is off even where the IdP advertises it, and `with_dpop` is refused
/// rather than adding a second binding the profile did not ask for, in
/// either order.
#[tokio::test]
async fn the_fapi_profile_with_mtls_turns_dpop_off() {
    let idp = Idp::advertising_dpop().await;
    // Removed on drop, whether or not the assertions below pass.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["client.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.join("client.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("client.key"), key.serialize_pem()).unwrap();
    let mtls = || FapiConfig {
        sender_constraint: SenderConstraint::Mtls {
            client_cert_path: dir.join("client.pem").to_string_lossy().into_owned(),
            client_key_path: dir.join("client.key").to_string_lossy().into_owned(),
        },
        ..Default::default()
    };

    assert!(
        idp.provider().await.binds_to_dpop(),
        "the IdP advertises DPoP"
    );
    let built = idp.builder().await.with_fapi(mtls()).build();
    let refused = [
        idp.builder().await.with_dpop().with_fapi(mtls()).build(),
        idp.builder().await.with_fapi(mtls()).with_dpop().build(),
    ];
    assert!(
        !built.expect("with_fapi").binds_to_dpop(),
        "the certificate binds the tokens"
    );
    for outcome in refused {
        let err = outcome.err().expect("no second binding under the profile");
        assert!(matches!(err, OAuthError::Config(_)), "{err:?}");
    }
}

// ── Refresh with the bound key ───────────────────────────────────────────────

/// The key is the adopter's to keep: stored as its seed beside the refresh
/// token, restored with `DpopKey::from_seed` by another process (a new
/// provider and service here), and presented on the refresh. Without it the
/// refresh is refused before anything is sent.
#[tokio::test]
async fn a_refresh_after_a_restart_presents_the_key_restored_from_its_seed() {
    let idp = Idp::advertising_dpop().await;
    let (_first_process, claims) = login(&idp, idp.provider().await, None).await;
    let claims = claims.expect("login");
    let seed = claims.dpop_key.expect("key").to_seed_bytes();
    let thumbprint = DpopKey::from_seed(*seed).thumbprint().unwrap();

    let restarted = service(idp.provider().await);
    let err = restarted
        .refresh_oauth_token("test", "rt1", "alice-subject", None, None)
        .await
        .expect_err("a bound refresh token is not refreshed bare");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
    assert_eq!(idp.requests_to("/token").len(), 1, "nothing was sent");

    let key = DpopKey::from_seed(*seed);
    let outcome = restarted
        .refresh_oauth_token("test", "rt1", "alice-subject", None, Some(&key))
        .await
        .expect("refresh");
    assert_eq!(&*outcome.refresh_token, "rt2");
    let refresh = &idp.requests_to("/token")[1];
    assert_eq!(refresh.form("grant_type"), Some("refresh_token"));
    assert!(authenticated_by_secret(refresh));
    let (header, payload) = proof_of(refresh);
    assert_eq!(header_thumbprint(&header), thumbprint);
    assert_eq!(payload["htm"], "POST");
    let access = segment(&outcome.access_token, 1);
    assert_eq!(
        access["cnf"]["jkt"], thumbprint,
        "the rotated token is bound to it"
    );
}

// ── Per-tenant providers ─────────────────────────────────────────────────────

fn tenant() -> TenantId {
    axess_core::authn::ids::testing::tenant("acme")
}

/// A tenant's provider against `idp`, authenticating with a client secret.
fn tenant_record(idp: &Idp, dpop: TenantDpop) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(),
        name: "test".into(),
        issuer: idp.issuer.clone(),
        client_id: CLIENT_ID.into(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain(SECRET.into())),
        dpop,
        revision: 0,
    }
}

async fn tenant_directory(
    record: TenantOAuthProviderRecord,
) -> Arc<StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>> {
    let directory = Arc::new(
        StoredTenantOAuthProviders::new_unencrypted(MemoryTenantOAuthProviderStore::new())
            .with_egress_policy(
                axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
            ),
    );
    directory.upsert(record).await.expect("upsert");
    directory
}

/// A tenant whose resource servers take only Bearer tokens sets its record
/// to `Off`: the login against an IdP that advertises DPoP sends no proof
/// and returns no key.
#[tokio::test]
async fn a_tenant_record_set_to_off_sends_bearer_requests() {
    let idp = Idp::advertising_dpop().await;
    let directory = tenant_directory(tenant_record(&idp, TenantDpop::Off)).await;
    let provider = directory
        .provider(&tenant(), "test")
        .await
        .expect("built")
        .expect("a provider");
    assert!(!provider.binds_to_dpop(), "off whatever the IdP advertises");

    let authn: Authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "test",
            &OAuthLoginOptions::default(),
            &tenant(),
            &session,
        )
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
    idp.mount_token(Some(idp.id_token(&nonce)), None).await;
    let claims = authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect("login");
    assert!(claims.dpop_key.is_none());
    let exchange = &idp.requests_to("/token")[0];
    assert!(exchange.dpop.is_none(), "no proof");
    assert!(authenticated_by_secret(exchange));
}

/// `Required` builds a bound provider against an IdP that advertises DPoP,
/// and refuses to build one against an IdP that does not.
#[tokio::test]
async fn a_tenant_record_that_requires_dpop_is_refused_where_the_idp_does_not_advertise_it() {
    let silent = Idp::start(json!({})).await;
    let directory = tenant_directory(tenant_record(&silent, TenantDpop::Required)).await;
    let err = directory
        .provider(&tenant(), "test")
        .await
        .err()
        .expect("refused when the provider is built");
    assert!(matches!(err, OAuthError::Config(_)), "{err:?}");

    let advertising = Idp::advertising_dpop().await;
    let directory = tenant_directory(tenant_record(&advertising, TenantDpop::Required)).await;
    let provider = directory
        .provider(&tenant(), "test")
        .await
        .expect("built")
        .expect("a provider");
    assert!(provider.binds_to_dpop());
}

/// A record stored before the field existed reads as `Advertised`, and the
/// provider built from it binds its tokens where the IdP advertises DPoP and
/// sends Bearer requests where it does not.
#[tokio::test]
async fn a_tenant_record_without_the_field_follows_the_advertisement() {
    for (idp, binds) in [
        (Idp::advertising_dpop().await, true),
        (Idp::start(json!({})).await, false),
    ] {
        let mut stored = serde_json::to_value(tenant_record(&idp, TenantDpop::Off)).unwrap();
        assert!(
            stored.as_object_mut().unwrap().remove("dpop").is_some(),
            "the serialised record carries the field"
        );
        let record: TenantOAuthProviderRecord = serde_json::from_value(stored).expect("reads");
        assert_eq!(record.dpop, TenantDpop::Advertised);

        let directory = tenant_directory(record).await;
        let provider = directory
            .provider(&tenant(), "test")
            .await
            .expect("built")
            .expect("a provider");
        assert_eq!(provider.binds_to_dpop(), binds);
    }
}

// ── The ceremony's state ─────────────────────────────────────────────────────

/// A refresh asked of a binding provider without the key is refused before
/// anything is sent, and its audit row says the key was missing: a caller
/// fault, not the IdP rejecting the token.
#[tokio::test]
async fn a_refresh_without_the_key_is_audited_as_a_missing_key() {
    use axess_core::authn::event::AuthFailureReason;
    let idp = Idp::advertising_dpop().await;
    let identity = MockIdentityStore::new();
    let authn: Authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_oauth_provider(idp.provider().await)
        .build()
        .with_audit_context(AuditContext::default());
    let err = authn
        .refresh_oauth_token("test", "rt1", "alice-subject", None, None)
        .await
        .expect_err("a bound refresh token is not refreshed without its key");
    assert!(matches!(err, OAuthError::DpopKeyRequired), "{err:?}");
    assert!(idp.requests_to("/token").is_empty(), "nothing was sent");
    let reasons: Vec<_> = identity
        .events()
        .into_iter()
        .filter_map(|e| e.error)
        .collect();
    assert_eq!(reasons, [AuthFailureReason::TokenRefreshDpopKeyMissing]);
}

/// A ceremony that reaches the callback without its DPoP key, for a
/// provider that binds (it started binding after a rediscovery between
/// begin and callback), is refused, audited and cleared: no key is
/// improvised and no token request is sent.
#[tokio::test]
async fn a_ceremony_without_its_dpop_key_is_refused_and_restarts() {
    use axess_core::authn::event::AuthFailureReason;
    let idp = Idp::advertising_dpop().await;
    let identity = MockIdentityStore::new();
    let authn: Authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_oauth_provider(idp.provider().await)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    authn
        .begin_oauth_login("test", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    assert!(
        session.remove_custom("axess.oauth.dpop_key").await,
        "the case: the binding provider's ceremony stashed a key, now gone"
    );
    let csrf = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("csrf");
    idp.mount_token(Some(idp.id_token("unused")), None).await;

    let err = authn
        .finish_oauth_login("code", &csrf, &session)
        .await
        .expect_err("no improvised key");
    assert!(matches!(err, OAuthError::InvalidParameter), "{err:?}");
    assert!(idp.requests_to("/token").is_empty(), "no token request");
    assert!(
        session.get_custom("axess.oauth.csrf_state").await.is_none(),
        "the ceremony is cleared"
    );
    assert!(
        identity
            .events()
            .iter()
            .any(|e| e.error == Some(AuthFailureReason::DpopKeyInvalid)),
        "the refusal is audited"
    );
}

/// The two tenant-bound begins take the same arguments in the same order
/// and stash one binding each, saying whether the provider came from the
/// tenant; the binding is part of the ceremony and cleared with it.
#[tokio::test]
async fn a_tenant_bound_ceremony_keeps_one_binding() {
    let idp = Idp::advertising_dpop().await;
    let directory = tenant_directory(tenant_record(&idp, TenantDpop::Advertised)).await;
    let authn: Authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(idp.provider().await)
        .with_tenant_oauth_providers(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let options = OAuthLoginOptions::default();
    let binding = |session: axess_core::session::extractor::AuthSession| async move {
        session.get_custom("axess.oauth.expected_tenant").await
    };

    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider("test", &options, &tenant(), &session)
        .await
        .expect("begin");
    assert_eq!(
        binding(session.clone()).await,
        Some(json!({ "tenant": tenant().to_string(), "provider_from_tenant": true }))
    );
    assert!(
        session
            .get_custom("axess.oauth.provider_tenant")
            .await
            .is_none(),
        "no second key records the same tenant"
    );

    let session = test_session();
    authn
        .begin_oauth_login_in_tenant("test", &options, &tenant(), &session)
        .await
        .expect("begin");
    assert_eq!(
        binding(session.clone()).await,
        Some(json!({ "tenant": tenant().to_string(), "provider_from_tenant": false }))
    );
    // A new begin clears the whole ceremony, the binding with it.
    authn
        .begin_oauth_login("test", &options, &session)
        .await
        .expect("begin");
    assert_eq!(binding(session.clone()).await, None);
}
