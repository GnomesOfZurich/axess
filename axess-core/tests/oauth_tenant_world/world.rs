//! Two tenants, each with a wiremock IdP and a provider called `sso`, and
//! a service whose tenant directory holds both: the world the by-name OAuth
//! helper tests, the revocation audit tests and the callback route tests log
//! in to.

use axess_core::authn::AuditContext;
use axess_core::authn::factor::FederatedProvider;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::OAuthCallbackRoute;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders, TenantClientCredential, TenantDpop,
    TenantOAuthProviderRecord,
};
use axess_core::session::extractor::AuthSession;
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::FactorSecret;
use axess_factors::oauth::{OAuthClaims, OAuthLoginOptions};
use axess_testing::oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

pub const REDIRECT: &str = "http://localhost:3000/callback";

/// The instant the world's clock is frozen at: the service, the tenant
/// directory's providers and the tokens the IdPs sign all read it.
pub fn t0() -> axess_clock::Timestamp {
    axess_clock::Timestamp::from_unix_seconds(1_800_000_000).expect("a valid instant")
}

/// A clock frozen at [`t0`].
pub fn frozen_clock() -> axess_clock::testing::MockClock {
    axess_clock::testing::MockClock::at(t0())
}
/// Both tenants' users carry the same `sid`: a `sid` is unique per issuer
/// only, so the logout must tell them apart by issuer.
pub const SID: &str = "idp-session-1";

pub type Authn = RequestAuthnService<MockIdentityStore, MockFactorStore>;
pub type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

pub fn tenant(label: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(label)
}

// ── An IdP that answers every endpoint a helper calls ────────────────────────

pub struct TokenEndpoint {
    pub label: String,
    pub id_token: Arc<Mutex<Option<String>>>,
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

pub struct Idp {
    pub label: String,
    pub server: MockServer,
    pub issuer: String,
    pub client_id: String,
    pub der: Vec<u8>,
    pub kid: String,
    pub id_token: Arc<Mutex<Option<String>>>,
}

impl Idp {
    pub async fn start(label: &str, client_id: &str) -> Self {
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

    pub fn subject(&self) -> String {
        format!("user-of-{}", self.label)
    }

    pub fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        axess_factors::jwt::encode(&header, claims, &EncodingKey::from_rsa_der(&self.der))
            .expect("sign")
    }

    /// Answer the next code exchange with an ID token for `nonce`.
    pub fn issue(&self, nonce: &str) {
        let now = t0().unix_seconds();
        let token = self.sign(&json!({
            "iss": self.issuer, "sub": self.subject(), "aud": self.client_id,
            "exp": now + 3600, "iat": now, "nonce": nonce, "sid": SID,
            "email": format!("{}@example.com", self.label), "email_verified": true,
        }));
        *self.id_token.lock().unwrap() = Some(token);
    }

    /// A signed back-channel logout token naming `SID`.
    pub fn logout_token(&self, jti: &str) -> String {
        self.sign(&json!({
            "iss": self.issuer, "aud": self.client_id, "iat": t0().unix_seconds(),
            "exp": t0().unix_seconds() + 120, "jti": jti, "sid": SID,
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }))
    }

    /// The `(method, path)` of every request this IdP has received after
    /// discovery, in order.
    pub async fn calls(&self) -> Vec<(String, String)> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| (r.method.to_string(), r.url.path().to_string()))
            .filter(|(_, p)| !p.starts_with("/.well-known") && p != "/jwks")
            .collect()
    }
    pub async fn form_of_last(&self, endpoint: &str) -> Vec<(String, String)> {
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

pub fn record(tenant_id: TenantId, idp: &Idp) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id,
        name: "sso".into(),
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        redirect_url: REDIRECT.into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

pub async fn nonce_and_csrf(session: &AuthSession) -> (String, String) {
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

pub fn tenant_row(label: &str) -> axess_core::authn::types::Tenant {
    use axess_core::authn::{ids::UserId, types::EntityState};
    let now = t0();
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

pub fn user(label: &str, tenant_label: &str) -> axess_core::authn::types::User {
    use axess_core::authn::{
        ids::UserId,
        types::{EntityState, User},
    };
    let now = t0();
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
pub struct Login {
    pub session: AuthSession,
    pub claims: OAuthClaims,
    pub user: axess_core::authn::types::User,
}

impl Login {
    pub fn nonce(&self) -> Option<&str> {
        self.claims
            .additional_claims
            .get("nonce")
            .and_then(Value::as_str)
    }
}

pub async fn tenant_login(authn: &Authn, idp: &Idp, tenant_label: &str, who: &str) -> Login {
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
        .finish_oauth_login(
            OAuthCallbackRoute::of_tenant(&tenant(tenant_label), "sso"),
            "code-1",
            &csrf,
            None,
            &session,
        )
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

pub struct World {
    /// The clock every part of the world runs on.
    pub clock: axess_clock::testing::MockClock,
    pub acme: Idp,
    pub beta: Idp,
    pub authn: Authn,
    pub registry: MemorySessionRegistry,
    pub identity: MockIdentityStore,
}

pub async fn world() -> World {
    world_with_beta_kind(None).await
}

/// The world, with beta's provider configured with `kind`.
pub async fn world_with_beta_kind(kind: Option<FederatedProvider>) -> World {
    let clock = frozen_clock();
    let acme = Idp::start("acme", "client-acme").await;
    let beta = Idp::start("beta", "client-beta").await;
    let directory: Arc<Directory> = Arc::new(
        StoredTenantOAuthProviders::new_unencrypted(
            MemoryTenantOAuthProviderStore::new(),
            axess_core::testing::oauth_tenant::ownership_assumed(),
        )
        .with_egress_policy(axess_factors::egress::EgressPolicy::screened_allowing_loopback_http())
        .with_clock(Arc::new(clock.clone())),
    );
    directory
        .upsert(record(tenant("acme"), &acme))
        .await
        .unwrap();
    directory
        .upsert(TenantOAuthProviderRecord {
            kind,
            ..record(tenant("beta"), &beta)
        })
        .await
        .unwrap();
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(tenant_row("acme"))
        .with_tenant(tenant_row("beta"))
        .with_user(user("alice", "acme"))
        .with_user(user("bob", "beta"));
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_tenant_oauth_providers(directory)
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    World {
        clock,
        acme,
        beta,
        authn,
        registry,
        identity,
    }
}

pub fn path_of(call: &(String, String)) -> &str {
    &call.1
}
