//! The by-name OAuth helpers follow the login: a session logged in through a
//! tenant's provider refreshes, reads userinfo, revokes and builds its logout
//! URL against that tenant's IdP, and an IdP-initiated logout token ends the
//! session of the tenant whose issuer sent it.
//!
//! Two wiremock IdPs stand for two tenants' IdPs; both tenants call their
//! provider `sso`. Each IdP records the requests it receives, so every
//! assertion is about which IdP was reached.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth,jwt-aws-lc --test oauth_tenant_helpers`

#![cfg(feature = "testing-oauth")]

use axess_core::authn::AuditContext;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::federation::backchannel_logout::{BackChannelLogoutHandler, LogoutParams};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders, TenantClientCredential, TenantDpop,
    TenantOAuthProviderRecord,
};
use axess_core::session::extractor::AuthSession;
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair},
    test_session,
};
use axess_factors::FactorSecret;
use axess_factors::oauth::{OAuthClaims, OAuthError, OAuthLoginOptions};
use axum::extract::{Form, State};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

const REDIRECT: &str = "http://localhost:3000/callback";
/// Both tenants' users carry the same `sid`: a `sid` is unique per issuer
/// only, so the logout must tell them apart by issuer.
const SID: &str = "idp-session-1";

type Authn = RequestAuthnService<MockIdentityStore, MockFactorStore>;
type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

fn tenant(label: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(label)
}

// ── An IdP that answers every endpoint a helper calls ────────────────────────

struct TokenEndpoint {
    label: String,
    id_token: Arc<Mutex<Option<String>>>,
}

impl Respond for TokenEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&request.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let grant = form
            .iter()
            .find(|(k, _)| k == "grant_type")
            .map(|(_, v)| v.as_str());
        let mut body = json!({
            "access_token": format!("access-from-{}", self.label),
            "token_type": "Bearer",
            "expires_in": 300,
            "refresh_token": format!("refresh-from-{}", self.label),
        });
        if grant == Some("authorization_code")
            && let Some(id) = self.id_token.lock().unwrap().clone()
        {
            body["id_token"] = json!(id);
        }
        ResponseTemplate::new(200).set_body_json(body)
    }
}

struct Idp {
    label: String,
    server: MockServer,
    issuer: String,
    client_id: String,
    der: Vec<u8>,
    kid: String,
    id_token: Arc<Mutex<Option<String>>>,
}

impl Idp {
    async fn start(label: &str, client_id: &str) -> Self {
        let server = MockServer::start().await;
        let uri = server.uri();
        let mut doc = oauth_discovery_document(&uri);
        doc["end_session_endpoint"] = json!(format!("{uri}/logout"));
        doc["revocation_endpoint"] = json!(format!("{uri}/revoke"));
        let (der, mut jwk, kid) = oauth_generate_rsa_keypair();
        jwk["alg"] = json!("RS256");
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
        let id_token = Arc::new(Mutex::new(None));
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(TokenEndpoint {
                label: label.to_string(),
                id_token: id_token.clone(),
            })
            .mount(&server)
            .await;
        let userinfo =
            json!({ "sub": format!("user-of-{label}"), "email": format!("{label}@example.com") });
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(userinfo))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Self {
            label: label.to_string(),
            issuer: uri,
            server,
            client_id: client_id.to_string(),
            der,
            kid,
            id_token,
        }
    }

    fn subject(&self) -> String {
        format!("user-of-{}", self.label)
    }

    fn sign(&self, claims: &Value) -> String {
        axess_factors::jwt::ensure_crypto_provider();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_der(&self.der)).expect("sign")
    }

    /// Answer the next code exchange with an ID token for `nonce`.
    fn issue(&self, nonce: &str) {
        let now = chrono::Utc::now().timestamp();
        let token = self.sign(&json!({
            "iss": self.issuer, "sub": self.subject(), "aud": self.client_id,
            "exp": now + 3600, "iat": now, "nonce": nonce, "sid": SID,
            "email": format!("{}@example.com", self.label), "email_verified": true,
        }));
        *self.id_token.lock().unwrap() = Some(token);
    }

    /// A signed back-channel logout token naming `SID`.
    fn logout_token(&self, jti: &str) -> String {
        self.sign(&json!({
            "iss": self.issuer, "aud": self.client_id, "iat": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 120, "jti": jti, "sid": SID,
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }))
    }

    /// The `(method, path)` of every request this IdP has received after
    /// discovery, in order.
    async fn calls(&self) -> Vec<(String, String)> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| (r.method.to_string(), r.url.path().to_string()))
            .filter(|(_, p)| !p.starts_with("/.well-known") && p != "/jwks")
            .collect()
    }

    async fn form_of_last(&self, endpoint: &str) -> Vec<(String, String)> {
        let requests = self.server.received_requests().await.unwrap();
        let last = requests
            .iter()
            .rev()
            .find(|r| r.url.path() == endpoint)
            .expect("a request");
        url::form_urlencoded::parse(&last.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
}

fn record(tenant_id: TenantId, idp: &Idp) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id,
        name: "sso".into(),
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        redirect_url: REDIRECT.into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
        dpop: TenantDpop::Advertised,
        revision: 0,
    }
}

async fn nonce_and_csrf(session: &AuthSession) -> (String, String) {
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

fn tenant_row(label: &str) -> axess_core::authn::types::Tenant {
    use axess_core::authn::{ids::UserId, types::EntityState};
    let now = chrono::Utc::now();
    axess_core::authn::types::Tenant {
        id: tenant(label),
        identifier: label.into(),
        display_name: label.into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn user(label: &str, tenant_label: &str) -> axess_core::authn::types::User {
    use axess_core::authn::{
        ids::UserId,
        types::{EntityState, User},
    };
    let now = chrono::Utc::now();
    User {
        id: axess_core::authn::ids::testing::user(label),
        tenant_id: tenant(tenant_label),
        identifier: label.into(),
        display_name: label.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

/// A logged-in tenant session and what a caller keeps from the login.
struct Login {
    session: AuthSession,
    claims: OAuthClaims,
    user: axess_core::authn::types::User,
}

impl Login {
    fn nonce(&self) -> Option<&str> {
        self.claims
            .additional_claims
            .get("nonce")
            .and_then(Value::as_str)
    }
}

async fn tenant_login(authn: &Authn, idp: &Idp, tenant_label: &str, who: &str) -> Login {
    let session = test_session();
    authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant(tenant_label),
            &session,
        )
        .await
        .expect("begin");
    let (nonce, csrf) = nonce_and_csrf(&session).await;
    idp.issue(&nonce);
    let claims = authn
        .finish_oauth_login("code-1", &csrf, &session)
        .await
        .expect("finish");
    let user = user(who, tenant_label);
    authn
        .complete_oauth_login(&user, &claims, &session)
        .await
        .expect("complete");
    Login {
        session,
        claims,
        user,
    }
}

struct World {
    acme: Idp,
    beta: Idp,
    authn: Authn,
    registry: MemorySessionRegistry,
}

async fn world() -> World {
    let acme = Idp::start("acme", "client-acme").await;
    let beta = Idp::start("beta", "client-beta").await;
    let directory: Arc<Directory> = Arc::new(StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
    ));
    directory
        .upsert(record(tenant("acme"), &acme))
        .await
        .unwrap();
    directory
        .upsert(record(tenant("beta"), &beta))
        .await
        .unwrap();
    let registry = MemorySessionRegistry::new();
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_row("acme"))
        .with_tenant(tenant_row("beta"))
        .with_user(user("alice", "acme"))
        .with_user(user("bob", "beta"));
    let authn = AuthnService::builder(identity, MockFactorStore::new())
        .with_tenant_oauth_providers(directory)
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    World {
        acme,
        beta,
        authn,
        registry,
    }
}

fn path_of(call: &(String, String)) -> &str {
    &call.1
}

// ── The helpers ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn two_tenants_refresh_each_against_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    let refreshed_a = w
        .authn
        .oauth_for_session(&a.session)
        .await
        .refresh_oauth_token(
            "sso",
            "refresh-from-acme",
            &w.acme.subject(),
            a.nonce(),
            None,
        )
        .await
        .expect("acme refresh");
    let refreshed_b = w
        .authn
        .oauth_for_session(&b.session)
        .await
        .refresh_oauth_token(
            "sso",
            "refresh-from-beta",
            &w.beta.subject(),
            b.nonce(),
            None,
        )
        .await
        .expect("beta refresh");

    assert_eq!(&*refreshed_a.refresh_token, "refresh-from-acme");
    assert_eq!(&*refreshed_b.refresh_token, "refresh-from-beta");
    // Each IdP saw its own refresh grant and no other.
    for (idp, token) in [
        (&w.acme, "refresh-from-acme"),
        (&w.beta, "refresh-from-beta"),
    ] {
        let calls = idp.calls().await;
        assert_eq!(
            calls.iter().filter(|c| path_of(c) == "/token").count(),
            2,
            "one code exchange and one refresh at {}",
            idp.label
        );
        let form = idp.form_of_last("/token").await;
        assert!(form.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(form.contains(&("refresh_token".into(), token.into())));
    }
}

#[tokio::test]
async fn two_tenants_read_userinfo_each_from_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    let info_a = w
        .authn
        .oauth_for_session(&a.session)
        .await
        .fetch_userinfo("sso", "access-from-acme", &w.acme.subject(), None)
        .await
        .expect("acme userinfo");
    let info_b = w
        .authn
        .oauth_for_session(&b.session)
        .await
        .fetch_userinfo("sso", "access-from-beta", &w.beta.subject(), None)
        .await
        .expect("beta userinfo");

    assert_eq!(info_a.sub, w.acme.subject());
    assert_eq!(info_b.sub, w.beta.subject());
    for idp in [&w.acme, &w.beta] {
        let calls = idp.calls().await;
        assert_eq!(
            calls.iter().filter(|c| path_of(c) == "/userinfo").count(),
            1,
            "{}",
            idp.label
        );
    }
}

#[tokio::test]
async fn two_tenants_revoke_each_at_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    w.authn
        .oauth_for_session(&a.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-acme", Some("refresh_token"), None)
        .await
        .expect("acme revoke");
    w.authn
        .oauth_for_session(&b.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-beta", Some("refresh_token"), None)
        .await
        .expect("beta revoke");

    for (idp, token) in [
        (&w.acme, "refresh-from-acme"),
        (&w.beta, "refresh-from-beta"),
    ] {
        let calls = idp.calls().await;
        assert_eq!(calls.iter().filter(|c| path_of(c) == "/revoke").count(), 1);
        let form = idp.form_of_last("/revoke").await;
        assert!(form.contains(&("token".into(), token.into())), "{form:?}");
    }
}

#[tokio::test]
async fn two_tenants_get_the_logout_url_of_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    let url_a = w
        .authn
        .oauth_for_session(&a.session)
        .await
        .build_end_session_url("sso", Some("hint"), None, None)
        .await
        .expect("resolves")
        .expect("acme advertises an end-session endpoint");
    let url_b = w
        .authn
        .oauth_for_session(&b.session)
        .await
        .build_end_session_url("sso", Some("hint"), None, None)
        .await
        .expect("resolves")
        .expect("beta advertises an end-session endpoint");

    assert_eq!(
        url_a.origin(),
        url::Url::parse(&w.acme.issuer).unwrap().origin()
    );
    assert_eq!(
        url_b.origin(),
        url::Url::parse(&w.beta.issuer).unwrap().origin()
    );
    assert_ne!(url_a.origin(), url_b.origin());

    // With no session, the tenant alone says the same.
    let by_tenant = w
        .authn
        .oauth_in_tenant(&tenant("beta"))
        .build_end_session_url("sso", Some("hint"), None, None)
        .await
        .expect("resolves")
        .expect("an end-session endpoint");
    assert_eq!(by_tenant.origin(), url_b.origin());
}

#[tokio::test]
async fn a_tenant_scope_never_reaches_another_tenants_provider_or_the_global_map() {
    let w = world().await;
    tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    // A tenant with no provider of that name.
    let none = w
        .authn
        .oauth_in_tenant(&tenant("gamma"))
        .revoke_oauth_token("sso", "t", None, None)
        .await;
    assert!(
        matches!(none, Err(OAuthError::UnknownProvider(_))),
        "{none:?}"
    );
    // The by-name method on the service reads the global registration only.
    let global = w.authn.revoke_oauth_token("sso", "t", None, None).await;
    assert!(
        matches!(global, Err(OAuthError::UnknownProvider(_))),
        "{global:?}"
    );
    assert!(w.acme.calls().await.iter().all(|c| path_of(c) != "/revoke"));
}

#[tokio::test]
async fn a_session_with_no_tenant_login_reads_the_global_registration() {
    let idp = Idp::start("solo", "client-solo").await;
    let provider = axess_factors::oauth::OAuthProviderConfig::discover(
        "sso",
        &idp.issuer,
        &idp.client_id,
        "s3cret",
        REDIRECT,
    )
    .await
    .unwrap()
    .build()
    .unwrap();
    let authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();

    // No login at all: the scope is the global registration, and the answer
    // is the one the by-name method gives.
    let scoped = authn.oauth_for_session(&session).await;
    assert!(scoped.tenant().is_none());
    scoped
        .revoke_oauth_token("sso", "t1", None, None)
        .await
        .expect("scoped, global");
    authn
        .revoke_oauth_token("sso", "t2", None, None)
        .await
        .expect("by name");
    assert_eq!(
        idp.calls()
            .await
            .iter()
            .filter(|c| path_of(c) == "/revoke")
            .count(),
        2
    );
}

// ── Back-channel logout ──────────────────────────────────────────────────────

async fn post_logout(handler: &BackChannelLogoutHandler, token: String) -> u16 {
    use axum::response::IntoResponse;
    BackChannelLogoutHandler::handle_backchannel_logout(
        State(handler.clone()),
        Form(LogoutParams {
            logout_token: token,
        }),
    )
    .await
    .into_response()
    .status()
    .as_u16()
}

#[tokio::test]
async fn a_logout_token_from_tenant_bs_issuer_ends_only_tenant_bs_session() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;
    let sid_a = a.session.session_id().await;
    let sid_b = b.session.session_id().await;
    assert!(w.registry.is_valid(&a.user.id, &sid_a).await.unwrap());
    assert!(w.registry.is_valid(&b.user.id, &sid_b).await.unwrap());

    let handler = BackChannelLogoutHandler::for_tenants(
        w.authn.tenant_oauth_providers().expect("configured"),
        Arc::new(SessionRegistryAdapter(w.registry.clone())),
        w.authn.sid_map(),
        Arc::new(axess_clock::SystemClock),
    );

    // The same `sid` at both IdPs; B's token ends B's session alone.
    assert_eq!(
        post_logout(&handler, w.beta.logout_token("jb-1")).await,
        200
    );
    assert!(
        !w.registry.is_valid(&b.user.id, &sid_b).await.unwrap(),
        "tenant B's session ended"
    );
    assert!(
        w.registry.is_valid(&a.user.id, &sid_a).await.unwrap(),
        "tenant A's session stands"
    );

    // A token signed by B's key but naming A's issuer does not verify.
    let forged = w.beta.sign(&json!({
        "iss": w.acme.issuer, "aud": w.acme.client_id,
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 120, "jti": "forged", "sid": SID,
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
    }));
    assert_eq!(post_logout(&handler, forged).await, 400);
    assert!(w.registry.is_valid(&a.user.id, &sid_a).await.unwrap());

    // A's own token ends A's.
    assert_eq!(
        post_logout(&handler, w.acme.logout_token("ja-1")).await,
        200
    );
    assert!(!w.registry.is_valid(&a.user.id, &sid_a).await.unwrap());
}
