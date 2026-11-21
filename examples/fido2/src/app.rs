//! The application: its settings, the seeded account, and the router.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axess::authn::{
    AuthMethod, AuthnScope, AuthnService, EntityState, FactorConfig, FactorKind, FactorStep,
    FactorStore, IdentityAdmin, IdentityLookup, PasswordConfig, PasswordRules, Tenant, User,
    UserId, ZeroizedString, generate_password_hash,
};
use axess::authz::{AssuranceContextProvider, AuthzError, AuthzInstallation, PolicyStore};
use axess::federation::fido2::{
    AttestationCaList, DefaultFido2Provider, DiscoverableCredential, Fido2Ceremony, Fido2Key,
    Fido2Options, Fido2Provider, SecurityKeyVerification,
};
use axess::{
    AuthSession, Clock, InMemoryBackend, KeyExtractor, MemorySessionRegistry, MemorySessionStore,
    RateLimitConfig, RateLimitLayer, SecureRng, SessionLayer, SystemClock, SystemRng,
    require_authz,
};
use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use webauthn_rs::prelude::{Url, Uuid, WebauthnBuilder};

use crate::{login, passkeys, payments, reply};

/// The demo account, and the tenant it lives in.
pub const DEMO_USER: &str = "alice";
/// The demo account's password.
pub const DEMO_PASSWORD: &str = "Sample2+";
/// The identifier of the one tenant.
pub const TENANT: &str = "default";

/// Where the example is served unless `FIDO2_ORIGIN` says otherwise. A
/// browser treats `localhost` as a secure context, so WebAuthn works over
/// plain HTTP there and nowhere else.
pub const LOCAL_ORIGIN: &str = "http://localhost:3000";

/// The name the provider holds the configured attestation roots under: the
/// attested registration runs `attested_passkey:configured-roots`.
pub const TRUST_ANCHOR: &str = "configured-roots";

// Session limits tighter than the library's defaults (24 hours idle, 7 days
// in all): a session left open on a shared machine, or a stolen cookie, is
// useful for far less time.
const STRICT_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
const STRICT_MAX_SESSION_AGE: Duration = Duration::from_secs(10 * 60 * 60);

/// Requests one client address may make per minute on each sign-in route,
/// the routes that begin a sign-in and those that finish one or a step-up.
const LOGIN_LIMIT: u32 = 10;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);

/// The service type every handler shares: one in-memory backend is both the
/// identity store and the factor store.
pub(crate) type Authn = AuthnService<InMemoryBackend, InMemoryBackend>;

/// What can stop the example from starting.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The origin does not parse as a URL.
    #[error("the origin {origin:?} is not a URL: {reason}")]
    Origin {
        /// The value that was refused.
        origin: String,
        /// Why it does not parse.
        reason: String,
    },
    /// The origin has no host to take the relying-party id from.
    #[error("the origin {0:?} has no host; set FIDO2_RP_ID")]
    NoHost(String),
    /// `webauthn-rs` refused the relying party: the id is not the origin's
    /// host or a suffix of it.
    #[error("the relying party {rp_id:?} does not fit the origin {origin:?}: {reason}")]
    RelyingParty {
        /// The relying-party id.
        rp_id: String,
        /// The origin it was paired with.
        origin: String,
        /// What `webauthn-rs` said.
        reason: String,
    },
    /// The attestation root file cannot be read.
    #[error("the attestation root {path:?} cannot be read: {source}")]
    TrustAnchorFile {
        /// The path named by `FIDO2_ATTESTATION_ROOT`.
        path: String,
        /// The read error.
        source: std::io::Error,
    },
    /// The attestation root is not a PEM certificate.
    #[error("the attestation root is not a PEM certificate: {0}")]
    TrustAnchor(String),
    /// The bundled Cedar policy or schema does not validate.
    #[error("the payment policy is refused: {0}")]
    Policy(#[from] AuthzError),
}

/// Where the example is served, and which attestation roots it trusts.
#[derive(Clone)]
pub struct Settings {
    origin: Url,
    rp_id: String,
    trust_anchor: Option<AttestationCaList>,
}

impl Settings {
    /// Settings for `origin` (scheme, host and port, as the browser shows
    /// it), with the origin's host as the relying-party id and no
    /// attestation root.
    pub fn new(origin: &str) -> Result<Self, AppError> {
        let url = Url::parse(origin).map_err(|e| AppError::Origin {
            origin: origin.to_string(),
            reason: e.to_string(),
        })?;
        let rp_id = url
            .host_str()
            .ok_or_else(|| AppError::NoHost(origin.to_string()))?
            .to_string();
        Ok(Self {
            origin: url,
            rp_id,
            trust_anchor: None,
        })
    }

    /// The same settings with `rp_id` as the relying-party id: the origin's
    /// host or a registrable suffix of it (`example.com` for an origin on
    /// `accounts.example.com`). Every credential is bound to it, so it does
    /// not change once users have registered.
    #[must_use]
    pub fn with_rp_id(mut self, rp_id: impl Into<String>) -> Self {
        self.rp_id = rp_id.into();
        self
    }

    /// The same settings, trusting the authenticators attested under the
    /// root certificate in `pem`. With a root, the page offers the attested
    /// registration; without one it does not.
    pub fn with_trust_anchor_pem(mut self, pem: &[u8]) -> Result<Self, AppError> {
        let list = AttestationCaList::try_from(pem)
            .map_err(|e| AppError::TrustAnchor(format!("{e:?}")))?;
        self.trust_anchor = Some(list);
        Ok(self)
    }

    /// Settings from the environment: `FIDO2_ORIGIN` (default
    /// [`LOCAL_ORIGIN`]), `FIDO2_RP_ID` (default: the origin's host) and
    /// `FIDO2_ATTESTATION_ROOT`, the path of a PEM root certificate.
    pub fn from_env() -> Result<Self, AppError> {
        let origin = std::env::var("FIDO2_ORIGIN").unwrap_or_else(|_| LOCAL_ORIGIN.to_string());
        let mut settings = Self::new(&origin)?;
        if let Ok(rp_id) = std::env::var("FIDO2_RP_ID") {
            settings = settings.with_rp_id(rp_id);
        }
        if let Ok(path) = std::env::var("FIDO2_ATTESTATION_ROOT") {
            let pem = std::fs::read(&path)
                .map_err(|source| AppError::TrustAnchorFile { path, source })?;
            settings = settings.with_trust_anchor_pem(&pem)?;
        }
        Ok(settings)
    }

    /// The origin as a browser sends it in the `Origin` header: scheme, host
    /// and port, no path.
    pub fn origin(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    /// The relying-party id.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The FIDO2 provider for these settings: `webauthn-rs` for the relying
    /// party, holding the attestation roots under [`TRUST_ANCHOR`] when
    /// there are any.
    pub fn provider(&self) -> Result<DefaultFido2Provider, AppError> {
        let refused = |reason: String| AppError::RelyingParty {
            rp_id: self.rp_id.clone(),
            origin: self.origin(),
            reason,
        };
        let webauthn = WebauthnBuilder::new(&self.rp_id, &self.origin)
            .map_err(|e| refused(format!("{e:?}")))?
            .rp_name("axess FIDO2 example")
            .build()
            .map_err(|e| refused(format!("{e:?}")))?;
        let provider = DefaultFido2Provider::new(webauthn);
        Ok(match &self.trust_anchor {
            Some(roots) => provider.with_trust_anchor(TRUST_ANCHOR, roots.clone()),
            None => provider,
        })
    }
}

/// What every handler reads.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) authn: Arc<Authn>,
    pub(crate) backend: InMemoryBackend,
    pub(crate) tenant: Tenant,
    pub(crate) clock: Arc<dyn Clock>,
    /// The attested registration ceremony, when a root is configured.
    pub(crate) attested: Option<Fido2Ceremony>,
    /// How recently a session must have authenticated to change its
    /// passkeys: the service's own `Fido2Options::max_authn_age`.
    pub(crate) max_authn_age: Option<Duration>,
    /// Which account holds each passkey credential id of this page's
    /// tenant: where a passwordless sign-in starts, since its assertion
    /// names a credential and not a user. axess keeps no lookup by
    /// credential id (a store answers a registration's claim on an id, and
    /// nothing more), so the application keeps one beside its accounts; in
    /// a database it is a table keyed by tenant and credential id, written
    /// with the credential.
    pub(crate) passkey_holders: Arc<Mutex<HashMap<Vec<u8>, UserId>>>,
}

impl AppState {
    /// The user an authenticated session belongs to; `None` for every other
    /// session, a half-finished login and an open step-up included.
    pub(crate) async fn current_user(&self, session: &AuthSession) -> Option<User> {
        let user_id = session.user_id().await?;
        self.backend.get_user(&user_id).await.ok().flatten()
    }

    /// The account that holds the passkey credential `credential_id`, if
    /// any account of this page's tenant does.
    pub(crate) fn passkey_holder(&self, credential_id: &[u8]) -> Option<UserId> {
        self.holders().get(credential_id).copied()
    }

    /// Index the credentials `user` holds now, after a registration or a
    /// deletion changed them. A store that cannot be read leaves the index
    /// as it was: a credential deleted meanwhile is still found, and the
    /// service then refuses its assertion, as it holds no such key for the
    /// user; a credential registered meanwhile signs in by username until
    /// the next change indexes it.
    pub(crate) async fn index_passkeys(&self, user: &User) {
        match self.authn.list_fido2_credentials(user).await {
            Ok(credentials) => {
                let mut holders = self.holders();
                holders.retain(|_, holder| *holder != user.id);
                for credential in &credentials {
                    let id: &[u8] = credential.cred_id().as_ref();
                    holders.insert(id.to_vec(), user.id);
                }
            }
            Err(error) => {
                tracing::error!(%error, "the account's credentials could not be indexed");
            }
        }
    }

    fn holders(&self) -> MutexGuard<'_, HashMap<Vec<u8>, UserId>> {
        self.passkey_holders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Build the application on the system clock, verifying with `webauthn-rs`.
///
/// Returns the router and the session store, whose expired sessions the
/// caller purges on a timer.
pub async fn build_router(settings: &Settings) -> Result<(Router, MemorySessionStore), AppError> {
    build_router_on(Arc::new(SystemClock), settings.provider()?, settings).await
}

/// [`build_router`], with every time-bound part of the application on
/// `clock` (the stores, the authentication service, the session layer, the
/// rate limits and the age the payment policy reads) and `provider` running
/// the ceremonies. A test passes a mock clock and a provider that stands in
/// for the authenticator; `provider` must serve the relying party of
/// `settings` and hold its attestation roots, as
/// [`Settings::provider`] does.
pub async fn build_router_on(
    clock: Arc<dyn Clock>,
    provider: impl Fido2Provider,
    settings: &Settings,
) -> Result<(Router, MemorySessionStore), AppError> {
    let backend = InMemoryBackend::new()
        .with_clock(clock.clone())
        .with_default_tenant(TENANT, "Default tenant");
    let tenant = seed(&backend, &clock).await;

    // The registry is what a logout or a forced logout revokes against; the
    // session layer below reads the same one. It is per process: production
    // uses the Valkey registry.
    let registry = MemorySessionRegistry::new().with_clock(clock.clone());

    // One ceremony per operation. A login's FIDO2 step is the security-key
    // ceremony with user verification preferred; registration defaults to
    // the passkey ceremony and each request may name another; the
    // passwordless login is its own ceremony; and the step-up takes its
    // ceremony from the policy that asks for it. A passkey is registered as
    // a credential the authenticator stores, so that every passkey, a
    // hardware key's included, can sign in with no username.
    let fido2_options = Fido2Options {
        login_ceremony: Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        discoverable_credential: DiscoverableCredential::Required,
        ..Fido2Options::default()
    };
    let max_authn_age = fido2_options.max_authn_age;
    let authn = Arc::new(
        AuthnService::builder_from_backend(backend.clone())
            .with_clock(clock.clone())
            .with_registry(registry.clone())
            .with_fido2(provider)
            .with_fido2_options(fido2_options)
            .build(),
    );

    // `MemorySessionStore` is unbounded and per process: it is for demos.
    let sessions = MemorySessionStore::new().with_clock(clock.clone());
    // A fresh random key per start: a restart signs everyone out. Production
    // loads the key from a secrets manager.
    let mut signing_key = [0u8; 32];
    SystemRng.fill_bytes(&mut signing_key);
    let session_layer = SessionLayer::new(
        sessions.clone(),
        signing_key,
        registry.handle(),
        // The service's sink writes an audit row for each session the
        // layer ends by itself: one past an age cap, one the registry no
        // longer holds.
        authn.session_end_audit(),
    )
    .with_clock(clock.clone())
    .with_ttl(STRICT_IDLE_TTL)
    .with_max_session_age(Some(STRICT_MAX_SESSION_AGE))
    .with_secure(secure_cookies());

    // What `require_authz!` decides with, built in one call: the policies,
    // the entity provider, and the context provider that turns what each
    // factor of the session proved into `context.assurance`. The payment
    // rule reads `context`, so leaving the provider out is refused here, at
    // startup, and not at the first payment.
    let policies = Arc::new(PolicyStore::from_text(
        payments::POLICY,
        &payments::schema()?,
    )?);
    let authz = AuthzInstallation::new(
        policies,
        Arc::new(payments::NoEntities),
        Some(Arc::new(AssuranceContextProvider::new(clock.clone()))),
    )?;

    // Each sign-in route gets a limiter of its own: clones of one limiter
    // share its bucket.
    let limiter = || {
        RateLimitLayer::new(
            RateLimitConfig::builder()
                .max_requests(LOGIN_LIMIT)
                .window(LOGIN_WINDOW)
                .key(KeyExtractor::ClientIp)
                .clock(clock.clone())
                .build(),
        )
    };
    let payment_gate = require_authz!(
        payments::NAMESPACE,
        "ApprovePayment",
        "Payment:{id}",
        validator = authn.session_validator()
    );

    let state = AppState {
        authn,
        backend,
        tenant,
        clock: clock.clone(),
        attested: settings
            .trust_anchor
            .is_some()
            .then(|| Fido2Ceremony::AttestedPasskey {
                trust_anchor: TRUST_ANCHOR.to_string(),
            }),
        max_authn_age,
        passkey_holders: Arc::default(),
    };

    let api = Router::new()
        .route("/api/session", get(session_info))
        .route(
            "/api/login/password",
            post(login::password).route_layer(limiter()),
        )
        .route(
            "/api/login/security-key/begin",
            post(login::security_key_begin).route_layer(limiter()),
        )
        .route(
            "/api/login/security-key/finish",
            post(login::security_key_finish).route_layer(limiter()),
        )
        .route(
            "/api/login/passkey/begin",
            post(login::passkey_begin).route_layer(limiter()),
        )
        .route(
            "/api/login/passkey/finish",
            post(login::passkey_finish).route_layer(limiter()),
        )
        .route(
            "/api/login/cancel",
            post(login::cancel).route_layer(limiter()),
        )
        .route("/api/logout", post(login::logout))
        .route("/api/passkeys/begin", post(passkeys::begin))
        .route("/api/passkeys/finish", post(passkeys::finish))
        .route("/api/passkeys/{id}", delete(passkeys::remove))
        .route(
            "/api/payments/{id}/approve",
            post(payments::approve).layer(payment_gate),
        )
        .route("/api/step-up/begin", post(payments::step_up_begin))
        .route(
            "/api/step-up/finish",
            post(payments::step_up_finish).route_layer(limiter()),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::<str>::from(settings.origin()),
            same_origin_only,
        ))
        .with_state(state);

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(script))
        .route("/style.css", get(style))
        .merge(api)
        .layer(authz)
        .layer(session_layer);

    // Resolve the client address once, outside everything that reads one:
    // the rate limits key on it and the audit rows record it.
    // `loopback_only` suits a server bound to 127.0.0.1; a deployment
    // behind a proxy names that proxy's ranges instead.
    let app = axess::client_ip::layer(app, axess::client_ip::TrustedProxies::loopback_only());
    Ok((app, sessions))
}

/// Create the demo account: a password, and a login method whose one step
/// is the password or a FIDO2 credential.
///
/// The step is what lets one account sign in three ways. A username and
/// password complete it; so does a security key after the username; and a
/// passkey with no username at all completes it too, because the
/// passwordless login is finished only for a user whose method accepts a
/// FIDO2 credential first.
async fn seed(backend: &InMemoryBackend, clock: &Arc<dyn Clock>) -> Tenant {
    let tenant = backend
        .default_tenant()
        .await
        .expect("the backend was built with a default tenant");
    let now = clock.now();
    // WebAuthn's user handle: random, never shown, the same for every
    // credential of the user. It is assigned once, when the user is created.
    let mut handle = [0u8; 16];
    SystemRng.fill_bytes(&mut handle);
    let user = User {
        id: UserId::new(&SystemRng),
        tenant_id: tenant.id,
        identifier: DEMO_USER.into(),
        display_name: "Alice".into(),
        status: EntityState::Active,
        webauthn_id: Some(Uuid::from_bytes(handle)),
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    };
    let scope = AuthnScope::User {
        tenant_id: tenant.id,
        user_id: user.id,
    };
    backend
        .create_user(user)
        .await
        .expect("the empty store takes the demo user");
    backend
        .save_factor(
            &scope,
            FactorConfig::Password(PasswordConfig {
                hash: ZeroizedString::new(generate_password_hash(DEMO_PASSWORD)),
                rules: PasswordRules::default(),
                password_id: None,
            }),
        )
        .await
        .expect("the in-memory store takes the password");
    backend
        .save_method(
            &scope,
            AuthMethod {
                name: "password-or-fido2".into(),
                steps: vec![FactorStep::AnyOf(vec![
                    FactorKind::Password,
                    FactorKind::Fido2,
                ])],
                scope: scope.clone(),
            },
        )
        .await
        .expect("the in-memory store takes the login method");
    tenant
}

/// Cookies are `Secure` unless `AXESS_DEV_INSECURE_COOKIES=1` is set, for a
/// browser that refuses `Secure` cookies over plain HTTP on `localhost`.
/// Local use only.
fn secure_cookies() -> bool {
    let insecure = std::env::var("AXESS_DEV_INSECURE_COOKIES").is_ok_and(|v| v == "1");
    if insecure {
        tracing::warn!(
            "AXESS_DEV_INSECURE_COOKIES=1: the session cookie is sent WITHOUT the Secure \
             attribute. Local development only."
        );
    }
    !insecure
}

/// Refuse a state-changing request that does not come from the
/// application's own origin.
///
/// A browser sends `Origin` with every `POST` and `DELETE`;
/// `Sec-Fetch-Site` is the fallback for one that omits it. A request with
/// neither is not the page and is refused too. The session cookie is
/// `SameSite=Lax`, which already keeps it off a cross-site `POST`; this
/// check does not depend on that default staying as it is.
async fn same_origin_only(
    State(origin): State<Arc<str>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let read_only = matches!(*request.method(), Method::GET | Method::HEAD);
    if !read_only && !origin_allowed(request.headers(), &origin) {
        return reply::refuse(StatusCode::FORBIDDEN, "cross_origin_request");
    }
    next.run(request).await
}

/// Whether the `Origin` (or, without one, `Sec-Fetch-Site`) names the app.
fn origin_allowed(headers: &axum::http::HeaderMap, origin: &str) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match (header("origin"), header("sec-fetch-site")) {
        (Some(sent), _) => sent == origin,
        (None, Some(site)) => site == "same-origin",
        (None, None) => false,
    }
}

/// What the page shows about the session: who is signed in, what each
/// factor of the session proved (the record the payment policy reads), the
/// account's FIDO2 credentials, and the registrations on offer.
async fn session_info(State(state): State<AppState>, session: AuthSession) -> Response {
    let mut kinds = vec!["passkey", "security_key"];
    if state.attested.is_some() {
        kinds.push("attested_passkey");
    }
    let Some(user) = state.current_user(&session).await else {
        return Json(serde_json::json!({
            "authenticated": false,
            // A step-up is open and waits for its factor. A login in
            // progress is not reported: only its own finish route ends it.
            "pending": session.step_up_pending().await,
            "registration_kinds": kinds,
        }))
        .into_response();
    };
    let now = state.clock.now();
    let factors: Vec<_> = session
        .assurance()
        .await
        .iter()
        .map(|proof| {
            serde_json::json!({
                "kind": proof.kind.as_str(),
                "user_verified": proof.user_verified,
                "credential": proof.credential.as_str(),
                "trust_anchor": proof.trust_anchor.as_deref(),
                "age_seconds": now.since(proof.at).whole_seconds(),
            })
        })
        .collect();
    let credentials = match state.authn.list_fido2_credentials(&user).await {
        Ok(list) => list,
        Err(error) => {
            tracing::error!(%error, "the account's credentials could not be read");
            return reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable");
        }
    };
    let credentials: Vec<_> = credentials
        .iter()
        .map(|credential| {
            serde_json::json!({
                "id": URL_SAFE_NO_PAD.encode(credential.cred_id()),
                "name": credential.name,
                "kind": match &credential.key {
                    Fido2Key::Passkey(_) => "passkey",
                    Fido2Key::SecurityKey(_) => "security_key",
                    Fido2Key::AttestedPasskey { .. } => "attested_passkey",
                },
                "registered_at": credential.registered_at.to_rfc3339_numeric_offset(),
                "last_used_at": credential.last_used_at.map(|at| at.to_rfc3339_numeric_offset()),
            })
        })
        .collect();
    Json(serde_json::json!({
        "authenticated": true,
        "username": &*user.identifier,
        "factors": factors,
        "credentials": credentials,
        "registration_kinds": kinds,
    }))
    .into_response()
}

/// A static asset: the page's own files only, and no framing.
fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body,
    )
        .into_response()
}

async fn index() -> Response {
    asset(
        "text/html; charset=utf-8",
        include_str!("../static/index.html"),
    )
}

async fn script() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        include_str!("../static/app.js"),
    )
}

async fn style() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("../static/style.css"),
    )
}
