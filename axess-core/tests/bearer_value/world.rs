//! The application every flow runs through: a real session layer and a real
//! service, with random session ids, a device-key service, an OAuth provider
//! whose logouts reach the session through the sid store, and the
//! recorders of [`doors`](crate::doors) at every door.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::device_key::{DeviceKeyConfig, DeviceKeyService};
use axess_core::federation::backchannel_logout::{BackChannelLogoutHandler, LogoutParams};
use axess_core::federation::frontchannel_logout::BoundFrontChannelLogoutHandler;
use axess_core::federation::sid_map::SidMap;
use axess_core::federation::sid_store::SidStore;
use axess_core::metrics::MetricSinks;
use axess_core::session::extractor::AuthSession;
use axess_core::session::layer::SessionLayer;
use axess_core::session::store::{
    SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle, SessionStore,
};
use axess_core::testing::RecordingMetrics;
use axess_core::testing::fixtures as common;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::{
    DefaultFingerprintExtractor, DeviceLifecycleService, LifecycleDeviceResolver, MemoryDeviceStore,
};
use axess_factors::key_proof::testing::SoftwareKey;
use axess_factors::key_proof::{KeyProofShape, ProofTarget, browser_draft as draft};
use axess_factors::oauth::{MockOAuthProvider, OAuthClaims, OAuthProvider};
use axum::extract::{Form, State};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use common::{
    password_config, password_totp_method, test_tenant, test_user, totp_config, user_scope,
};
use tower::ServiceExt;

use crate::doors::{RecordingEnds, RecordingLogouts, RecordingSid, Seen};
use crate::search::{Bearers, SESSION_COOKIE, bearer_of};
use crate::totp_code::generate_totp_code;

pub type Authn = RequestAuthnService<MockIdentityStore, MockFactorStore>;

const UA: &str = "Mozilla/5.0 (a browser)";
pub const ORIGIN: &str = "https://app.example";
pub const ISSUER: &str = "https://idp.example";
const CLIENT: &str = "app-client";
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const PASSWORD: &str = "Sample2+";
/// The longest a session lives from its login.
pub const MAX_AGE: Duration = Duration::from_secs(8 * 3600);

/// The parts of a world besides its session store, registry and sid store.
pub struct World {
    pub app: Router,
    pub clock: MockClock,
    pub authn: Arc<Authn>,
    pub identity: MockIdentityStore,
    pub provider: Arc<MockOAuthProvider>,
    pub backchannel: BackChannelLogoutHandler,
    pub config: DeviceKeyConfig,
    pub ends: Seen,
    pub logouts: Seen,
    pub metrics: Arc<RecordingMetrics>,
    pub bearers: std::sync::Mutex<Bearers>,
}

/// A world on `clock`, `store`, `registry` and `sid`, which the caller
/// built on the same clock.
pub fn world<S, R>(clock: MockClock, store: S, registry: R, sid: RecordingSid) -> World
where
    S: SessionStore,
    R: SessionRegistry + Clone + 'static,
{
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_user(test_user("u2", "bob"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_factor(user_scope(), totp_config(SECRET))
        .with_method(&common::uid("u1"), password_totp_method());
    let mock_provider = || {
        MockOAuthProvider::new("idp")
            .with_issuer(ISSUER)
            .with_client_id(CLIENT)
            .with_clock(Arc::new(clock.clone()))
    };
    // The service's registration and the one the logout handler verifies
    // tokens with are two values of one configuration.
    let provider = Arc::new(mock_provider());
    let metrics = Arc::new(RecordingMetrics::default());
    let sid: Arc<dyn SidStore> = Arc::new(sid);
    let service = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .allow_plaintext_factor_secrets()
        .with_registry(registry.clone())
        .with_session_store(store.clone())
        .with_oauth_provider(mock_provider())
        .with_sid_store(sid.clone())
        .with_metrics(MetricSinks::all(metrics.clone()))
        .build();
    let ends = Seen::default();
    let logouts = Seen::default();
    let end_audit = Arc::new(RecordingEnds {
        inner: service.session_end_audit(),
        seen: ends.clone(),
    });
    let logout_audit = Arc::new(RecordingLogouts {
        inner: service.backchannel_logout_audit(),
        seen: logouts.clone(),
    });
    let authn = Arc::new(service.with_audit_context(AuditContext::default()));
    let service = Arc::new(service);
    let revoker = Arc::new(SessionRegistryAdapter(registry.clone()));
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![provider.clone()];
    let backchannel = BackChannelLogoutHandler::new(
        &providers,
        revoker.clone(),
        SidMap::new(),
        Arc::new(clock.clone()),
    )
    .expect("a provider with an issuer and a client id")
    .with_sid_store(sid.clone())
    .with_audit(logout_audit);
    let frontchannel = BoundFrontChannelLogoutHandler::new(
        SidMap::new(),
        revoker,
        HashSet::from([ISSUER.to_owned()]),
    )
    .with_sid_store(sid);

    let devices = MemoryDeviceStore::new();
    let config = DeviceKeyConfig::new(ORIGIN);
    let keys =
        DeviceKeyService::new(devices.clone(), config.clone()).expect("the default configuration");
    let resolver = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32])),
        DeviceLifecycleService::new(devices),
        clock.clone(),
    );
    let handle: Arc<dyn SessionRegistryHandle> = Arc::new(SessionRegistryAdapter(registry));
    let layer = SessionLayer::new(store, axess_core::testing::test_key(42), handle, end_audit)
        .with_clock(clock.clone())
        .with_max_session_age(Some(MAX_AGE))
        .with_metrics(MetricSinks::all(metrics.clone()))
        .with_device_resolver(resolver)
        .with_device_keys(keys.clone());
    let app = routes(&service, &clock)
        .merge(
            Router::new()
                .route(
                    "/frontchannel",
                    get(BoundFrontChannelLogoutHandler::handle_frontchannel_logout),
                )
                .with_state(frontchannel),
        )
        .merge(keys.router())
        .layer(layer);
    World {
        app,
        clock,
        authn,
        identity,
        provider,
        backchannel,
        config,
        ends,
        logouts,
        metrics,
        bearers: std::sync::Mutex::default(),
    }
}

/// The claims an identity provider vouched for alice with, naming its own
/// session `sid`.
pub fn claims(sid: &str) -> OAuthClaims {
    OAuthClaims {
        provider: Arc::from("idp"),
        subject: "idp-alice".to_owned(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: Some(sid.to_owned()),
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
        nonce: None,
        dpop_key: None,
    }
}

/// The claim lock the ceremony's finish stores, as it computes it.
async fn stash_claim_lock(session: &AuthSession, claims: &OAuthClaims) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    let key = session.session_key().await;
    let mut hasher = Sha256::new();
    for field in [
        claims.provider.as_bytes(),
        claims.subject.as_bytes(),
        key.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    session
        .set_custom(
            "axess.oauth.claim_lock",
            serde_json::Value::String(URL_SAFE_NO_PAD.encode(hasher.finalize())),
        )
        .await;
}

/// The service every route answers with, under the audit context its
/// request carries: what the audit rows of a route name is what the
/// request's own context held.
type Service = AuthnService<MockIdentityStore, MockFactorStore>;

fn routes(service: &Arc<Service>, clock: &MockClock) -> Router {
    let login = {
        let (service, clock) = (service.clone(), clock.clone());
        move |audit: AuditContext, session: AuthSession| {
            let (authn, clock) = (service.with_audit_context(audit), clock.clone());
            async move {
                authn
                    .begin_login("alice", "default", &session)
                    .await
                    .expect("begin");
                let password = FactorCredential::Password(ZeroizedString::new(PASSWORD));
                authn
                    .verify_factor(&password, &session)
                    .await
                    .expect("password");
                let code = generate_totp_code(SECRET, clock.now().try_into().unwrap());
                let done = authn
                    .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
                    .await
                    .expect("second factor");
                format!("{done:?}")
            }
        }
    };
    let step_up = {
        let service = service.clone();
        move |audit: AuditContext, session: AuthSession| {
            let authn = service.with_audit_context(audit);
            async move {
                authn
                    .begin_step_up(&session, vec![FactorKind::Password])
                    .await
                    .expect("step-up");
                let password = FactorCredential::Password(ZeroizedString::new(PASSWORD));
                let done = authn
                    .verify_factor(&password, &session)
                    .await
                    .expect("password");
                format!("{done:?}")
            }
        }
    };
    let rotate = {
        let service = service.clone();
        move |audit: AuditContext, session: AuthSession| {
            let authn = service.with_audit_context(audit);
            async move {
                match authn.rotate_session(&session).await {
                    Ok(()) => "rotated",
                    Err(_) => "refused",
                }
            }
        }
    };
    let cut_off = {
        let service = service.clone();
        move |audit: AuditContext, session: AuthSession| {
            let authn = service.with_audit_context(audit);
            async move {
                let user = session.user_id().await.expect("signed in");
                let keep = session.session_key().await;
                authn
                    .invalidate_other_sessions(
                        &user,
                        &keep,
                        axess_core::authn::service::Actor::System,
                    )
                    .await
                    .expect("cut-off");
                "cut off"
            }
        }
    };
    let oauth = {
        let service = service.clone();
        move |audit: AuditContext,
              session: AuthSession,
              axum::extract::Path(sid): axum::extract::Path<String>| {
            let authn = service.with_audit_context(audit);
            async move {
                let claims = claims(&sid);
                stash_claim_lock(&session, &claims).await;
                authn
                    .complete_oauth_login(&test_user("u1", "alice"), &claims, &session)
                    .await
                    .expect("an OAuth login");
                "in"
            }
        }
    };
    let logout = {
        let service = service.clone();
        move |audit: AuditContext, session: AuthSession| {
            let authn = service.with_audit_context(audit);
            async move {
                authn.logout(&session).await.expect("logout");
                "out"
            }
        }
    };
    Router::new()
        .route(
            "/guest",
            get(|session: AuthSession| async move {
                session.set_custom("visit", serde_json::json!(1)).await;
                "guest"
            }),
        )
        .route("/login", get(login))
        .route(
            "/whoami",
            get(|session: AuthSession| async move {
                if session.is_authenticated().await {
                    "user"
                } else {
                    "guest"
                }
            }),
        )
        .route(
            "/bound",
            get(|session: AuthSession| async move { session.key_bound().await.to_string() }),
        )
        .route("/step-up", get(step_up))
        .route("/rotate", get(rotate))
        .route(
            "/regenerate",
            get(|session: AuthSession| async move {
                session.regenerate().await;
                "regenerated"
            }),
        )
        .route("/cut-off", get(cut_off))
        .route("/oauth/{sid}", get(oauth))
        .route("/logout", get(logout))
}

/// What a browser holds: its cookies and the registration it was offered.
#[derive(Clone, Default)]
pub struct Browser {
    pub cookies: BTreeMap<String, String>,
    pub offer: Option<String>,
}

impl Browser {
    /// The bearer value of the session cookie the browser holds now.
    pub fn bearer(&self) -> axess_core::session::SessionId {
        bearer_of(self.cookies.get(SESSION_COOKIE).expect("a session cookie"))
    }

    pub fn key(&self) -> axess_core::session::SessionKey {
        axess_core::session::SessionKey::of(&self.bearer())
    }
}

impl World {
    /// Send `request` with the browser's cookies, keep what the answer
    /// sets, note every session cookie's bearer value, and return the body.
    pub async fn send(
        &self,
        browser: &mut Browser,
        request: axum::http::request::Builder,
    ) -> String {
        let jar = browser
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut request = request.header(header::USER_AGENT, UA);
        if !jar.is_empty() {
            request = request.header(header::COOKIE, jar);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        for value in response.headers().get_all(header::SET_COOKIE) {
            let text = value.to_str().unwrap();
            let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if name == SESSION_COOKIE && !value.is_empty() {
                self.bearers.lock().unwrap().note(bearer_of(value));
            }
            if attributes.contains("Max-Age=0") {
                browser.cookies.remove(name);
            } else {
                browser.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        if let Some(value) = response.headers().get(draft::REGISTRATION_HEADER) {
            // `(ES256);path="<path>";challenge="<offer>"`
            browser.offer = value.to_str().unwrap().split('"').nth(3).map(str::to_owned);
        }
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    pub async fn get(&self, browser: &mut Browser, uri: &str) -> String {
        self.send(browser, Request::get(uri)).await
    }

    /// Register `key` against the browser's offer, then make a request the
    /// key proves.
    pub async fn register(&self, browser: &mut Browser, key: &SoftwareKey) {
        let offer = browser.offer.clone().expect("a registration offer");
        let url = self.config.registration_url(ORIGIN);
        let jws = key.sign(
            KeyProofShape::Browser,
            ProofTarget {
                method: "POST",
                url: &url,
            },
            &offer,
            true,
        );
        self.send(
            browser,
            Request::post(self.config.registration_path()).header(draft::RESPONSE_HEADER, jws),
        )
        .await;
    }

    /// The identity provider's back-channel logout of its session `sid`.
    pub async fn backchannel_logout(&self, sid: &str) -> u16 {
        use axum::response::IntoResponse;
        BackChannelLogoutHandler::handle_backchannel_logout(
            State(self.backchannel.clone()),
            Form(LogoutParams {
                logout_token: self.provider.mock_logout_token(None, Some(sid)),
            }),
        )
        .await
        .into_response()
        .status()
        .as_u16()
    }

    /// Move the world's clock on past one step of the second factor, so the
    /// next login's code is a new one.
    pub fn next_code(&self) {
        self.clock.advance_secs(31);
    }
}
