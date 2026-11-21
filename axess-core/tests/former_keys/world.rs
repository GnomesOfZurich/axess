//! One application for every test of the binary: a real session layer and
//! a real authentication service over one registry, one session store, one
//! sid store and one clock, with the identity provider's two logout
//! handlers beside them and recorders at the audit doors.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::AuthEventType;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::UserId;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::federation::backchannel_logout::{
    BackChannelLogoutHandler, IdpSessionEnded, LogoutAudit, LogoutParams,
};
use axess_core::federation::frontchannel_logout::BoundFrontChannelLogoutHandler;
use axess_core::federation::sid_map::SidMap;
use axess_core::federation::sid_store::SidStore;
use axess_core::metrics::MetricSinks;
use axess_core::session::SessionKey;
use axess_core::session::extractor::AuthSession;
use axess_core::session::layer::SessionLayer;
use axess_core::session::store::{
    MemorySessionStore, SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle,
    SessionStore,
};
use axess_core::testing::RecordingMetrics;
use axess_core::testing::fixtures as common;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::oauth::{MockOAuthProvider, OAuthClaims, OAuthProvider};
use axum::extract::{Form, State};
use axum::response::IntoResponse;
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use tower::ServiceExt;

pub type Authn = RequestAuthnService<MockIdentityStore, MockFactorStore>;
type Service = AuthnService<MockIdentityStore, MockFactorStore>;

pub const ISSUER: &str = "https://idp.example.org";
/// The identity provider's subject for alice.
pub const SUBJECT: &str = "idp-alice";
const CLIENT: &str = "app-client";
const PASSWORD: &str = "Sample2+";

pub fn alice() -> UserId {
    uid("u1")
}

/// The administrator who kicks a session.
pub fn admin() -> UserId {
    uid("admin")
}

/// What the back-channel handler reported as ended, in order.
#[derive(Default, Clone)]
pub struct Reported(Arc<Mutex<Vec<IdpSessionEnded>>>);

impl Reported {
    pub fn keys(&self) -> Vec<SessionKey> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.session_id)
            .collect()
    }
}

/// Records what it is told, then hands it to the service's own audit.
struct RecordingLogouts {
    inner: Arc<dyn LogoutAudit>,
    seen: Reported,
}

impl LogoutAudit for RecordingLogouts {
    fn session_ended<'a>(
        &'a self,
        ended: &'a IdpSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.seen.0.lock().unwrap().push(ended.clone());
        self.inner.session_ended(ended)
    }
}

pub struct World {
    pub app: Router,
    pub authn: Arc<Authn>,
    pub identity: MockIdentityStore,
    pub store: MemorySessionStore,
    pub provider: Arc<MockOAuthProvider>,
    pub backchannel: BackChannelLogoutHandler,
    pub reported: Reported,
    pub metrics: Arc<RecordingMetrics>,
    pub sid: Arc<dyn SidStore>,
    registry: Arc<dyn SessionRegistryHandle>,
}

/// A world on `clock`, `registry` and `sid`, which the caller built on the
/// same clock.
pub fn world<R>(clock: MockClock, registry: R, sid: Arc<dyn SidStore>) -> World
where
    R: SessionRegistry + Clone + 'static,
{
    let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_method(&alice(), password_method());
    let mock_provider = || {
        MockOAuthProvider::new("idp")
            .with_issuer(ISSUER)
            .with_client_id(CLIENT)
            .with_clock(Arc::new(clock.clone()))
    };
    // The service's provider and the one the logout handler verifies tokens
    // with are two values of one configuration.
    let provider = Arc::new(mock_provider());
    let metrics = Arc::new(RecordingMetrics::default());
    let service = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .with_session_store(store.clone())
        .with_oauth_provider(mock_provider())
        .with_sid_store(sid.clone())
        .build();
    let reported = Reported::default();
    let logout_audit = Arc::new(RecordingLogouts {
        inner: service.backchannel_logout_audit(),
        seen: reported.clone(),
    });
    let end_audit = service.session_end_audit();
    let authn = Arc::new(service.with_audit_context(AuditContext::default()));
    let service = Arc::new(service);
    let handle: Arc<dyn SessionRegistryHandle> = Arc::new(SessionRegistryAdapter(registry));
    let providers: Vec<Arc<dyn OAuthProvider>> = vec![provider.clone()];
    let backchannel = BackChannelLogoutHandler::new(
        &providers,
        handle.clone(),
        SidMap::new(),
        Arc::new(clock.clone()),
    )
    .expect("a provider with an issuer and a client id")
    .with_sid_store(sid.clone())
    .with_audit(logout_audit)
    .with_metrics(metrics.clone());
    let frontchannel = BoundFrontChannelLogoutHandler::new(
        SidMap::new(),
        handle.clone(),
        HashSet::from([ISSUER.to_owned()]),
    )
    .with_sid_store(sid.clone());
    let layer = SessionLayer::new(
        store.clone(),
        axess_core::testing::test_key(44),
        handle.clone(),
        end_audit,
    )
    .with_clock(clock.clone())
    .with_metrics(MetricSinks::all(metrics.clone()))
    .with_secure(false);
    let app = routes(&service)
        .merge(
            Router::new()
                .route(
                    "/frontchannel",
                    get(BoundFrontChannelLogoutHandler::handle_frontchannel_logout),
                )
                .with_state(frontchannel),
        )
        .layer(layer);
    World {
        app,
        authn,
        identity,
        store,
        provider,
        backchannel,
        reported,
        metrics,
        sid,
        registry: handle,
    }
}

/// The claims the identity provider vouched for alice with, naming its own
/// session `sid` when there is one.
pub fn claims(sid: Option<&str>) -> OAuthClaims {
    OAuthClaims {
        provider: Arc::from("idp"),
        subject: SUBJECT.to_owned(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: sid.map(str::to_owned),
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

fn routes(service: &Arc<Service>) -> Router {
    let oauth = {
        let service = service.clone();
        move |audit: AuditContext,
              session: AuthSession,
              axum::extract::Path(sid): axum::extract::Path<String>| {
            let authn = service.with_audit_context(audit);
            async move {
                // `-` stands for an ID token without a `sid`: the login is
                // recorded in the subject records only.
                let claims = claims(Some(sid.as_str()).filter(|sid| *sid != "-"));
                stash_claim_lock(&session, &claims).await;
                match authn
                    .complete_oauth_login(&test_user("u1", "alice"), &claims, &session)
                    .await
                {
                    Ok(_) => "in".to_owned(),
                    Err(e) => format!("refused: {e}"),
                }
            }
        }
    };
    let step_up = {
        let service = service.clone();
        move |audit: AuditContext, session: AuthSession| {
            let authn = service.with_audit_context(audit);
            async move {
                if let Err(e) = authn
                    .begin_step_up(&session, vec![FactorKind::Password])
                    .await
                {
                    return format!("refused: {e}");
                }
                let password = FactorCredential::Password(ZeroizedString::new(PASSWORD));
                match authn.verify_factor(&password, &session).await {
                    Ok(outcome) => format!("{outcome:?}"),
                    Err(e) => format!("refused: {e}"),
                }
            }
        }
    };
    let rotate = {
        let service = service.clone();
        move |audit: AuditContext, session: AuthSession| {
            let authn = service.with_audit_context(audit);
            async move {
                match authn.rotate_session(&session).await {
                    Ok(()) => "rotated".to_owned(),
                    Err(e) => format!("refused: {e}"),
                }
            }
        }
    };
    Router::new()
        .route("/oauth/{sid}", get(oauth))
        .route("/step-up", get(step_up))
        .route("/rotate", get(rotate))
        .route(
            "/regenerate",
            get(|session: AuthSession| async move {
                session.regenerate().await;
                "regenerated"
            }),
        )
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
            "/key",
            get(|session: AuthSession| async move { session.session_key().await.to_string() }),
        )
}

/// A browser: the session cookie it holds.
#[derive(Default, Clone)]
pub struct Browser {
    pub jar: Option<String>,
}

impl World {
    /// Send a GET for `path` with the browser's cookie; keep the cookie the
    /// response sets.
    pub async fn get(&self, browser: &mut Browser, path: &str) -> String {
        let mut req = Request::get(path);
        if let Some(c) = browser.jar.as_deref() {
            req = req.header(header::COOKIE, c);
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        if let Some(v) = resp.headers().get(header::SET_COOKIE) {
            browser.jar = Some(v.to_str().unwrap().split(';').next().unwrap().to_owned());
        }
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The key the browser's session is stored under, read through the
    /// layer.
    pub async fn key(&self, browser: &mut Browser) -> SessionKey {
        self.get(browser, "/key").await.parse().expect("a key")
    }

    /// An OAuth login of alice on `browser`, the provider naming its own
    /// session `sid` (`-` for none); returns the key the login registered.
    pub async fn oauth_login(&self, browser: &mut Browser, sid: &str) -> SessionKey {
        assert_eq!(self.get(browser, &format!("/oauth/{sid}")).await, "in");
        self.key(browser).await
    }

    /// The identity provider's back-channel logout naming `sub`, `sid` or
    /// both; the status it was answered with.
    pub async fn backchannel_logout(&self, sub: Option<&str>, sid: Option<&str>) -> u16 {
        BackChannelLogoutHandler::handle_backchannel_logout(
            State(self.backchannel.clone()),
            Form(LogoutParams {
                logout_token: self.provider.mock_logout_token(sub, sid),
            }),
        )
        .await
        .into_response()
        .status()
        .as_u16()
    }

    /// The front-channel logout of `sid`, sent with the browser's cookie.
    pub async fn frontchannel_logout(&self, browser: &mut Browser, sid: &str) -> String {
        self.get(browser, &format!("/frontchannel?iss={ISSUER}&sid={sid}"))
            .await
    }

    /// The keys the registry holds for alice, oldest first.
    pub async fn held(&self) -> Vec<SessionKey> {
        self.registry
            .held_sessions(&alice())
            .await
            .expect("the registry lists")
    }

    /// Whether the store holds a row under `key`.
    pub async fn row(&self, key: &SessionKey) -> bool {
        let Ok(row) = self.store.load(key).await;
        row.is_some()
    }

    /// The sessions the audit rows of type `SessionInvalidated` name, in
    /// order.
    pub fn invalidation_rows(&self) -> Vec<Option<SessionKey>> {
        self.identity
            .events()
            .iter()
            .filter(|e| e.event_type == AuthEventType::SessionInvalidated)
            .map(|e| e.session_id)
            .collect()
    }

    /// How many verified logout tokens ended nothing.
    pub fn unmatched(&self) -> u64 {
        self.metrics.count("back_channel_logout_unmatched")
    }
}
