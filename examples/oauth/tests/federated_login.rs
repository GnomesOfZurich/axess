//! Drives the example the way a browser does, against an in-process OIDC
//! provider: follow the redirect to the IdP, come back with a code, carry the
//! cookie. Nothing here calls a handler directly.

use axess::authn::AuditContext;
use axess::federation::oauth::OAuthLoginOptions;
use axess_example_oauth::app::{self, App, ClientAuth, Config, ProviderSettings};
use axess_example_oauth::provisioning::Provisioning;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::json;
use std::collections::HashMap;
use tower::ServiceExt;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BASE: &str = "http://localhost:3000";

// ── The identity provider ────────────────────────────────────────────────────

/// A wiremock OIDC provider with its own signing key.
struct Idp {
    server: MockServer,
    client_id: String,
    kid: String,
    der: Vec<u8>,
    /// The `token_type` the token endpoint answers: `DPoP` for an IdP that
    /// advertises DPoP, `Bearer` otherwise.
    token_type: &'static str,
}

impl Idp {
    async fn start(client_id: &str) -> Self {
        Self::start_with(client_id, false).await
    }

    /// An IdP whose discovery document advertises DPoP, so the example's
    /// provider binds its tokens to a DPoP key without being told to.
    async fn advertising_dpop(client_id: &str) -> Self {
        Self::start_with(client_id, true).await
    }

    async fn start_with(client_id: &str, dpop: bool) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("key");
        let public = key.to_public_key();
        let kid = "idp-key".to_string();
        let jwk = json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        });
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "end_session_endpoint": format!("{issuer}/logout"),
            "revocation_endpoint": format!("{issuer}/revoke"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        });
        let mut discovery = discovery;
        if dpop {
            discovery["dpop_signing_alg_values_supported"] = json!(["ES256"]);
        }
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;
        Self {
            server,
            client_id: client_id.to_string(),
            kid,
            der: key.to_pkcs1_der().expect("der").as_bytes().to_vec(),
            token_type: if dpop { "DPoP" } else { "Bearer" },
        }
    }

    fn issuer(&self) -> String {
        self.server.uri()
    }

    fn sign(&self, claims: &serde_json::Value, der: &[u8]) -> String {
        axess_factors::jwt::ensure_crypto_provider();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_der(der)).expect("sign")
    }

    /// The ID token this provider would issue for a login with `nonce`.
    fn id_token(&self, who: &Who, nonce: &str) -> String {
        let now = chrono_now();
        self.sign(
            &json!({
                "iss": self.issuer(), "sub": who.subject, "aud": self.client_id,
                "exp": now + 3600, "iat": now, "nonce": nonce, "sid": who.sid,
                "email": who.email, "email_verified": who.email_verified, "name": who.name,
            }),
            &self.der,
        )
    }

    /// A back-channel logout token for `sid`, signed with `der`.
    fn logout_token(&self, sid: &str, der: &[u8]) -> String {
        let now = chrono_now();
        self.sign(
            &json!({
                "iss": self.issuer(), "aud": self.client_id, "iat": now, "exp": now + 120,
                "jti": format!("jti-{sid}-{now}"), "sid": sid,
                "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
            }),
            der,
        )
    }

    /// Answer the next authorization-code request with `id_token`, and a
    /// refresh token `refresh`.
    async fn queue_token_with_refresh(&self, id_token: String, refresh: &str) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access", "token_type": self.token_type, "expires_in": 3600,
                "id_token": id_token, "refresh_token": refresh,
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Answer a refresh request that carries `presented` with a new refresh
    /// token `rotated`, and `id_token` when there is one.
    async fn queue_refresh(&self, presented: &str, rotated: &str, id_token: Option<String>) {
        let mut body = json!({
            "access_token": "access-2", "token_type": self.token_type, "expires_in": 3600,
            "refresh_token": rotated,
        });
        if let Some(t) = id_token {
            body["id_token"] = json!(t);
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains(format!("refresh_token={presented}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Answer userinfo requests as the subject `sub`.
    async fn queue_userinfo(&self, sub: &str) {
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "sub": sub })))
            .mount(&self.server)
            .await;
    }

    /// The form bodies of the revocation requests received so far.
    async fn revocation_requests(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .expect("recording")
            .into_iter()
            .filter(|r| r.url.path() == "/revoke")
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    }

    /// The token-endpoint requests received so far, as (headers, form body).
    async fn token_requests(&self) -> Vec<(wiremock::http::HeaderMap, String)> {
        self.server
            .received_requests()
            .await
            .expect("recording")
            .into_iter()
            .filter(|r| r.url.path() == "/token")
            .map(|r| {
                (
                    r.headers.clone(),
                    String::from_utf8_lossy(&r.body).into_owned(),
                )
            })
            .collect()
    }

    /// Answer the next token request with `id_token`.
    async fn queue_token(&self, id_token: String) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access", "token_type": self.token_type,
                "expires_in": 3600, "id_token": id_token,
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Who signs in at the provider.
struct Who {
    subject: &'static str,
    email: &'static str,
    email_verified: bool,
    name: &'static str,
    sid: &'static str,
}

const ALICE: Who = Who {
    subject: "alice-1",
    email: "alice@example.com",
    email_verified: true,
    name: "Alice",
    sid: "sid-alice",
};

// ── The browser ──────────────────────────────────────────────────────────────

struct Reply {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

/// Holds cookies and speaks to the router; follows no redirect by itself.
struct Browser {
    router: axum::Router,
    cookies: HashMap<String, String>,
}

impl Browser {
    fn new(app: &App) -> Self {
        Self {
            router: app.router.clone(),
            cookies: HashMap::new(),
        }
    }

    async fn send(&mut self, request: axum::http::request::Builder, body: Body) -> Reply {
        let jar: Vec<String> = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let request = request
            .header(header::COOKIE, jar.join("; "))
            .body(body)
            .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        for set in response.headers().get_all(header::SET_COOKIE) {
            let set = set.to_str().expect("cookie");
            let pair = set.split(';').next().expect("pair");
            if let Some((name, value)) = pair.split_once('=') {
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().expect("location").to_string());
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        Reply {
            status,
            location,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn get(&mut self, uri: &str) -> Reply {
        self.send(Request::get(uri), Body::empty()).await
    }

    /// A `POST` from the application's own page, as a browser sends it.
    async fn post(&mut self, uri: &str) -> Reply {
        self.send(
            Request::post(uri).header(header::ORIGIN, BASE),
            Body::empty(),
        )
        .await
    }

    /// A `POST` that carries the given `Origin`, or none.
    async fn post_from(&mut self, uri: &str, origin: Option<&str>) -> Reply {
        let request = match origin {
            Some(o) => Request::post(uri).header(header::ORIGIN, o),
            None => Request::post(uri),
        };
        self.send(request, Body::empty()).await
    }

    /// Sign in at `provider` as `who`: the login redirect, the IdP's answer
    /// (the test plays the IdP), and the callback. Returns the callback reply.
    async fn sign_in(&mut self, idp: &Idp, provider: &str, who: &Who) -> Reply {
        self.sign_in_with(idp, provider, who, None).await
    }

    /// [`sign_in`](Self::sign_in), with the IdP issuing `refresh` when given.
    async fn sign_in_with(
        &mut self,
        idp: &Idp,
        provider: &str,
        who: &Who,
        refresh: Option<&str>,
    ) -> Reply {
        let start = self.get(&format!("/auth/login/{provider}")).await;
        assert_eq!(
            start.status,
            StatusCode::TEMPORARY_REDIRECT,
            "{}",
            start.body
        );
        let to_idp = url::Url::parse(&start.location.expect("redirect to the IdP")).expect("url");
        assert_eq!(to_idp.origin().ascii_serialization(), idp.issuer());
        let query: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
        let id_token = idp.id_token(who, &query["nonce"]);
        match refresh {
            Some(r) => idp.queue_token_with_refresh(id_token, r).await,
            None => idp.queue_token(id_token).await,
        }
        self.get(&format!(
            "/auth/callback/{provider}?code=the-code&state={}",
            query["state"]
        ))
        .await
    }
}

fn settings(name: &str, idp: &Idp) -> ProviderSettings {
    ProviderSettings {
        name: name.to_string(),
        issuer: idp.issuer(),
        client_id: idp.client_id.clone(),
        client_auth: ClientAuth::Secret("secret".to_string()),
        post_logout_redirect: format!("{BASE}/"),
        base_url: BASE.to_string(),
        // The provider signs with RS256, the OpenID Connect default; naming
        // it keeps the pinned path under test.
        id_token_algs: vec!["RS256".to_string()],
    }
}

async fn app_with(providers: Vec<ProviderSettings>, provisioning: Provisioning) -> App {
    app::build(Config {
        providers,
        provisioning,
        require_verified_email: false,
        secure_cookies: false,
    })
    .await
    .expect("app")
}

/// The `User id` line of a profile page.
fn user_id_on(profile: &str) -> String {
    let after = profile
        .split("<strong>User id:</strong> ")
        .nth(1)
        .expect("user id line");
    after
        .split("</li>")
        .next()
        .expect("end of line")
        .to_string()
}

// ── The tests ────────────────────────────────────────────────────────────────

/// The first login of an identity creates its user; the second, in a fresh
/// browser, finds the same one.
#[tokio::test]
async fn first_login_creates_the_user_and_the_second_finds_it() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;

    let mut first = Browser::new(&app);
    let reply = first.sign_in(&idp, "idp", &ALICE).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location.as_deref(), Some("/profile?welcome=1"));
    let profile = first.get("/profile?welcome=1").await;
    assert_eq!(profile.status, StatusCode::OK);
    assert!(profile.body.contains("your account was created"));
    let created = user_id_on(&profile.body);
    assert_eq!(app.identities.len(), 1);

    let mut second = Browser::new(&app);
    let reply = second.sign_in(&idp, "idp", &ALICE).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.location.as_deref(),
        Some("/profile"),
        "found, not created"
    );
    let profile = second.get("/profile").await;
    assert_eq!(user_id_on(&profile.body), created);
    assert_eq!(
        app.identities.len(),
        1,
        "no second row for the same identity"
    );
}

/// The profile is built from the user the session names, and what the IdP
/// sent is escaped on the way to the page.
#[tokio::test]
async fn profile_reads_the_session_and_escapes_the_name() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    let who = Who {
        name: "<script>alert(1)</script>",
        ..ALICE
    };
    browser.sign_in(&idp, "idp", &who).await;

    let profile = browser.get("/profile").await;
    assert!(profile.body.contains("&lt;script&gt;"));
    assert!(!profile.body.contains("<script>"));
    assert!(profile.body.contains(&format!("{}#alice-1", idp.issuer())));
    assert!(
        !profile.body.contains("alice@example.com"),
        "the address is not the identity"
    );
}

/// The same address from a second issuer is a second identity and a second
/// user: the e-mail address is never the link, even with the same subject.
#[tokio::test]
async fn same_email_from_another_issuer_is_a_second_user() {
    let one = Idp::start("client-a").await;
    let two = Idp::start("client-b").await;
    let app = app_with(
        vec![settings("one", &one), settings("two", &two)],
        Provisioning::JustInTime,
    )
    .await;

    let mut first = Browser::new(&app);
    first.sign_in(&one, "one", &ALICE).await;
    let id_one = user_id_on(&first.get("/profile").await.body);

    let mut second = Browser::new(&app);
    let reply = second.sign_in(&two, "two", &ALICE).await;
    assert_eq!(
        reply.location.as_deref(),
        Some("/profile?welcome=1"),
        "created, not linked: {}",
        reply.body
    );
    let id_two = user_id_on(&second.get("/profile").await.body);

    assert_ne!(id_one, id_two);
    assert_eq!(app.identities.len(), 2);
}

/// A tenant that does not provision just in time refuses an identity it has
/// no link for, and creates nobody.
#[tokio::test]
async fn linked_only_tenant_refuses_an_unknown_identity() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::LinkedOnly).await;
    let mut browser = Browser::new(&app);

    let reply = browser.sign_in(&idp, "idp", &ALICE).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
    assert!(app.identities.is_empty());
    let profile = browser.get("/profile").await;
    assert_eq!(profile.location.as_deref(), Some("/"), "still signed out");
}

/// A linked identity signs in even where the tenant creates no one: an
/// administrator linked it beforehand.
#[tokio::test]
async fn linked_only_tenant_admits_a_linked_identity() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::LinkedOnly).await;
    let invited = app
        .provisioner
        .invite(&idp.issuer(), ALICE.subject, "Alice")
        .await
        .expect("invite");
    let mut browser = Browser::new(&app);

    let reply = browser.sign_in(&idp, "idp", &ALICE).await;

    assert_eq!(
        reply.location.as_deref(),
        Some("/profile"),
        "{}",
        reply.body
    );
    let profile = browser.get("/profile").await;
    assert_eq!(user_id_on(&profile.body), invited.id.to_string());
}

/// The claims `complete_oauth_login` is given must be the ones
/// `finish_oauth_login_with_iss` returned for this session: claims for a
/// different subject do not complete, and the genuine ones do.
#[tokio::test]
async fn claims_that_are_not_this_sessions_do_not_complete() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let authn = app.authn.with_audit_context(AuditContext::default());

    for forged in [true, false] {
        let session = axess_core::testing::test_session();
        let (to_idp, state) = app
            .authn
            .begin_oauth_login_in_tenant(
                "idp",
                &OAuthLoginOptions::default(),
                &app.tenant,
                &session,
            )
            .await
            .expect("begin");
        let nonce = to_idp
            .query_pairs()
            .find(|(k, _)| k == "nonce")
            .map(|(_, v)| v.into_owned())
            .expect("nonce");
        idp.queue_token(idp.id_token(&ALICE, &nonce)).await;
        let mut claims = authn
            .finish_oauth_login_with_iss("code", &state, None, &session)
            .await
            .expect("finish");
        let user = app.provisioner.resolve(&claims).await.expect("resolve");
        if forged {
            claims.subject = "someone-else".to_string();
        }

        let done = authn
            .complete_oauth_login(user.user(), &claims, &session)
            .await;

        assert_eq!(done.is_ok(), !forged, "forged={forged}: {done:?}");
        assert_eq!(session.is_authenticated().await, !forged);
    }
}

/// A provider that did not verify the address cannot create a user under a
/// policy that asks for one.
#[tokio::test]
async fn unverified_email_is_refused_when_the_policy_requires_it() {
    let idp = Idp::start("client-a").await;
    let app = app::build(Config {
        providers: vec![settings("idp", &idp)],
        provisioning: Provisioning::JustInTime,
        require_verified_email: true,
        secure_cookies: false,
    })
    .await
    .expect("app");
    let mut browser = Browser::new(&app);
    let who = Who {
        email_verified: false,
        ..ALICE
    };

    let reply = browser.sign_in(&idp, "idp", &who).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
    assert!(app.identities.is_empty());
}

/// Local logout ends the session and sends the browser to the IdP's logout
/// endpoint with the ID token as the hint.
#[tokio::test]
async fn logout_ends_the_session_and_goes_to_the_idp() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser.sign_in(&idp, "idp", &ALICE).await;
    assert_eq!(browser.get("/profile").await.status, StatusCode::OK);

    let reply = browser.post("/auth/logout").await;

    let location = reply.location.expect("redirect");
    assert!(
        location.starts_with(&format!("{}/logout", idp.issuer())),
        "{location}"
    );
    assert!(location.contains("id_token_hint="), "{location}");
    assert_eq!(browser.get("/profile").await.location.as_deref(), Some("/"));
}

/// The IdP ends a session: a signed logout token posted to the back-channel
/// endpoint signs the browser out on its next request. A token signed by
/// anyone else is refused and ends nothing.
#[tokio::test]
async fn back_channel_logout_ends_the_session() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser.sign_in(&idp, "idp", &ALICE).await;

    let forger = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("key");
    let forged = idp.logout_token(ALICE.sid, forger.to_pkcs1_der().expect("der").as_bytes());
    let refused = back_channel(&app, &forged).await;
    assert_eq!(refused, StatusCode::BAD_REQUEST);
    assert_eq!(
        browser.get("/profile").await.status,
        StatusCode::OK,
        "still signed in"
    );

    let genuine = idp.logout_token(ALICE.sid, &idp.der);
    assert_eq!(back_channel(&app, &genuine).await, StatusCode::OK);
    assert_eq!(browser.get("/profile").await.location.as_deref(), Some("/"));
}

async fn back_channel(app: &App, token: &str) -> StatusCode {
    let request = Request::post("/auth/backchannel-logout")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("logout_token={token}")))
        .expect("request");
    app.router
        .clone()
        .oneshot(request)
        .await
        .expect("response")
        .status()
}

// ── Refresh ──────────────────────────────────────────────────────────────────

/// `POST /auth/refresh` presents the refresh token the login stored, keeps the
/// one the IdP rotated to, and presents that next time. Without the example
/// storing the rotated token the second refresh would present `refresh-1`, no
/// mock matches it, and the second `assert_eq!(.., OK)` fails.
#[tokio::test]
async fn refresh_presents_the_stored_token_and_keeps_the_rotated_one() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser
        .sign_in_with(&idp, "idp", &ALICE, Some("refresh-1"))
        .await;

    idp.queue_refresh("refresh-1", "refresh-2", None).await;
    idp.queue_refresh("refresh-2", "refresh-3", None).await;
    let first = browser.post("/auth/refresh").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let second = browser.post("/auth/refresh").await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);

    let bodies: Vec<String> = idp
        .token_requests()
        .await
        .into_iter()
        .map(|(_, b)| b)
        .filter(|b| b.contains("grant_type=refresh_token"))
        .collect();
    assert_eq!(bodies.len(), 2);
    assert!(bodies[0].contains("refresh_token=refresh-1"));
    assert!(bodies[1].contains("refresh_token=refresh-2"));
}

/// An IdP that advertises DPoP binds the tokens to a key the login made; the
/// example keeps the key beside the refresh token and presents it on every
/// refresh. Without the key the library refuses the refresh before sending
/// it, and the first `assert_eq!(.., OK)` fails.
#[tokio::test]
async fn refresh_presents_the_dpop_key_the_login_bound_the_tokens_to() {
    let idp = Idp::advertising_dpop("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    let callback = browser
        .sign_in_with(&idp, "idp", &ALICE, Some("refresh-1"))
        .await;
    assert_eq!(callback.status, StatusCode::SEE_OTHER, "{}", callback.body);

    idp.queue_refresh("refresh-1", "refresh-2", None).await;
    idp.queue_refresh("refresh-2", "refresh-3", None).await;
    for _ in 0..2 {
        let reply = browser.post("/auth/refresh").await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    }

    let proof_jwk = |headers: &wiremock::http::HeaderMap| {
        let proof = headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .expect("a DPoP proof");
        let header = proof.split('.').next().expect("header");
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("base64")).expect("json");
        header["jwk"].clone()
    };
    let requests = idp.token_requests().await;
    assert_eq!(requests.len(), 3, "the exchange and two refreshes");
    let login_key = proof_jwk(&requests[0].0);
    for (headers, body) in &requests[1..] {
        assert!(body.contains("grant_type=refresh_token"));
        assert_eq!(proof_jwk(headers), login_key, "the key the login bound");
    }
}

/// A refresh whose ID token names another issuer is refused (502), and
/// without the session a refresh is sent home. Without the library's check on
/// the refreshed ID token, or without the example surfacing its error, the
/// first assertion fails with a 200.
#[tokio::test]
async fn refresh_with_a_wrong_issuer_is_refused() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser
        .sign_in_with(&idp, "idp", &ALICE, Some("refresh-1"))
        .await;

    let now = chrono_now();
    let wrong = idp.sign(
        &json!({
            "iss": "https://elsewhere.example", "sub": ALICE.subject, "aud": idp.client_id,
            "exp": now + 3600, "iat": now,
        }),
        &idp.der,
    );
    idp.queue_refresh("refresh-1", "refresh-2", Some(wrong))
        .await;
    let reply = browser.post("/auth/refresh").await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{}", reply.body);

    let mut stranger = Browser::new(&app);
    let reply = stranger.post("/auth/refresh").await;
    assert_eq!(reply.location.as_deref(), Some("/"));
}

/// A refresh whose userinfo answer describes another subject is refused (502)
/// and ends the session: the next refresh is sent home. Before the check the
/// example kept the session, so the second assertion fails.
#[tokio::test]
async fn refresh_with_userinfo_for_another_subject_ends_the_session() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser
        .sign_in_with(&idp, "idp", &ALICE, Some("refresh-1"))
        .await;

    idp.queue_userinfo("someone-else").await;
    idp.queue_refresh("refresh-1", "refresh-2", None).await;
    let reply = browser.post("/auth/refresh").await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{}", reply.body);

    let again = browser.post("/auth/refresh").await;
    assert_eq!(again.location.as_deref(), Some("/"), "the session survived");
}

/// The tokens a refresh just issued for a subject the IdP then disowned are
/// revoked at the IdP before the session ends, not left alive there.
#[tokio::test]
async fn refresh_with_userinfo_for_another_subject_revokes_the_new_tokens() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser
        .sign_in_with(&idp, "idp", &ALICE, Some("refresh-1"))
        .await;

    idp.queue_userinfo("someone-else").await;
    idp.queue_refresh("refresh-1", "refresh-2", None).await;
    let reply = browser.post("/auth/refresh").await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{}", reply.body);

    let revoked = idp.revocation_requests().await;
    assert!(
        revoked.iter().any(|b| b.contains("token=refresh-2")),
        "the rotated refresh token was not revoked: {revoked:?}"
    );
    assert!(
        revoked.iter().any(|b| b.contains("token=access-2")),
        "the new access token was not revoked: {revoked:?}"
    );
}

/// A cross-site page cannot log the user out or refresh their tokens.
#[tokio::test]
async fn logout_and_refresh_refuse_a_post_from_another_origin() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    browser
        .sign_in_with(&idp, "idp", &ALICE, Some("refresh-1"))
        .await;

    for uri in ["/auth/logout", "/auth/refresh"] {
        for origin in [Some("https://evil.example"), Some("null"), None] {
            let reply = browser.post_from(uri, origin).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri} from {origin:?}");
        }
    }
    let profile = browser.get("/profile").await;
    assert_eq!(profile.status, StatusCode::OK, "the session must survive");
}

// ── Client authentication ────────────────────────────────────────────────────

/// With `ClientAuth::Secret` the token request carries the secret (a Basic
/// header) and no assertion. If the example built the provider with a signer
/// here, the header assertion fails.
#[tokio::test]
async fn a_secret_client_sends_the_secret_and_no_assertion() {
    let idp = Idp::start("client-a").await;
    let app = app_with(vec![settings("idp", &idp)], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    let reply = browser.sign_in(&idp, "idp", &ALICE).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

    let requests = idp.token_requests().await;
    assert_eq!(requests.len(), 1);
    let (headers, body) = &requests[0];
    let basic = headers
        .get("authorization")
        .expect("a Basic header")
        .to_str()
        .expect("ascii")
        .strip_prefix("Basic ")
        .expect("Basic")
        .to_string();
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(basic)
            .expect("base64"),
    )
    .expect("utf8");
    assert!(decoded.ends_with(":secret"), "{decoded}");
    assert!(!body.contains("client_assertion"), "{body}");
}

/// With `ClientAuth::PrivateKeyJwt` the token request carries an assertion
/// that verifies against the registered public key, naming the client as
/// issuer and subject, and no secret in the body or a Basic header. If the
/// example ignored the key and sent a secret, the `client_assertion` assertion
/// fails; if it sent both, the final two assertions fail.
#[tokio::test]
async fn a_private_key_jwt_client_sends_a_verifiable_assertion_and_no_secret() {
    let idp = Idp::start("client-a").await;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("key");
    let public = key.to_public_key();
    let pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&key, rsa::pkcs8::LineEnding::LF)
        .expect("pem")
        .to_string();
    let mut settings = settings("idp", &idp);
    settings.client_auth = ClientAuth::PrivateKeyJwt {
        pem,
        algorithm: Algorithm::RS256,
        key_id: Some("client-key".to_string()),
    };
    let app = app_with(vec![settings], Provisioning::JustInTime).await;
    let mut browser = Browser::new(&app);
    let reply = browser.sign_in(&idp, "idp", &ALICE).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

    let requests = idp.token_requests().await;
    assert_eq!(requests.len(), 1);
    let (headers, body) = &requests[0];
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let assertion = form.get("client_assertion").expect("client_assertion");
    assert_eq!(
        form.get("client_assertion_type").map(String::as_str),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );

    axess_factors::jwt::ensure_crypto_provider();
    let header = jsonwebtoken::decode_header(assertion).expect("header");
    assert_eq!(header.kid.as_deref(), Some("client-key"));
    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    let claims = jsonwebtoken::decode::<serde_json::Value>(
        assertion,
        &jsonwebtoken::DecodingKey::from_rsa_components(
            &URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            &URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        )
        .expect("jwk"),
        &validation,
    )
    .expect("the assertion verifies against the registered key")
    .claims;
    assert_eq!(claims["iss"], "client-a");
    assert_eq!(claims["sub"], "client-a");
    assert!(claims["jti"].is_string());

    assert!(!form.contains_key("client_secret"), "{body}");
    assert!(headers.get("authorization").is_none());
}
