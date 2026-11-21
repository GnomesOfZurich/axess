#![cfg(all(feature = "testing", feature = "memory", feature = "device-keys"))]
//! Device keys end to end, on the in-memory stores and a software key: a
//! session bound to a key is served only to a request that carries a proof
//! cookie the key bought, and a device that has a key is proven only by it.

use axess_core::testing::fixtures as common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axess_clock::Timestamp;
use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::UserId;
use axess_core::authn::ids::{DeviceId, TenantId};
use axess_core::authn::service::AuthnService;
use axess_core::authn::types::LockoutPolicy;
use axess_core::device_key::{
    DeviceKeyConfig, DeviceKeyService, DeviceProof, KeyBindingPolicy, KeyProof, KeyProofShape,
};
use axess_core::metrics::MetricSinks;
use axess_core::session::refresh::{
    IssueRequest, Refresh, RefreshError, RefreshTokenConfig, issue_refresh_token,
};
use axess_core::session::store::SessionStore;
use axess_core::session::{
    ConditionalUpdate, CycleOutcome, SessionData, SessionEndAudit, SessionKey,
};
use axess_core::session::{extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::{
    AuthSessionTestExt, MemoryRefreshTokenStore, MockRng, RecordingMetrics, test_session,
};
use axess_core::{
    BindingsUpdate, CascadingRefreshStore, DefaultFingerprintExtractor, Device, DeviceBinding,
    DeviceLifecycleService, DeviceStore, DeviceTrustLevel, FingerprintHash,
    LifecycleDeviceResolver, MemoryDeviceStore, OwnerClaim, SweepCounts, TrustTransition,
};
use axess_factors::jwt::verifier::{JtiReplayError, JtiReplayStore};
use axess_factors::key_proof::testing::SoftwareKey;
use axess_factors::key_proof::{ProofTarget, browser_draft as draft};
use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, StatusCode, header},
    routing::get,
};
use common::{
    password_config, password_method, test_tenant, test_user, test_user_in_tenant, tid, uid,
    user_scope,
};
use std::future::Future;
use tower::ServiceExt;

const UA: &str = "Mozilla/5.0 (the owner's browser)";
const ORIGIN: &str = "https://app.example";
const SESSION: &str = "__Host-axess.sid";
const DEVICE: &str = "__Host-axess_device";
const PROOF: &str = "__Host-axess_device_proof";

fn tenant() -> TenantId {
    test_tenant().id
}

/// The tenant served at `beta.example`; every other host, and a request
/// with no `Host`, is the first tenant's.
fn beta_tenant() -> TenantId {
    TenantId::try_new("0b0b0b0b-0000-4000-8000-000000000002").unwrap()
}

fn tenant_at(headers: &axum::http::HeaderMap) -> TenantId {
    match headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        Some("beta.example") => beta_tenant(),
        _ => tenant(),
    }
}

struct World {
    app: Router,
    clock: MockClock,
    sessions: MemorySessionStore,
    devices: MemoryDeviceStore,
    config: DeviceKeyConfig,
    keys: DeviceKeyService<MemoryDeviceStore>,
}

async fn whoami(session: AuthSession) -> &'static str {
    if session.is_authenticated().await {
        "user"
    } else {
        "guest"
    }
}

async fn proven(session: AuthSession) -> &'static str {
    match session.proven_device().await.map(|device| device.proof()) {
        Some(DeviceProof::Key(_)) => "key",
        Some(DeviceProof::Token) => "token",
        None => "unproven",
    }
}

async fn bound(session: AuthSession) -> &'static str {
    if session.data().await.key_binding.is_some() {
        "bound"
    } else {
        "unbound"
    }
}

/// A replay store of the test's own: a `jti` is accepted once.
#[derive(Clone, Default)]
struct SeenJtis(Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Duration>>>);

impl JtiReplayStore for SeenJtis {
    async fn check_and_record(
        &self,
        jti: &str,
        ttl: std::time::Duration,
    ) -> Result<(), JtiReplayError> {
        match self.0.lock().unwrap().insert(jti.to_owned(), ttl) {
            None => Ok(()),
            Some(_) => Err(JtiReplayError::already_used(jti)),
        }
    }
}

fn world(policy: KeyBindingPolicy) -> World {
    world_with(policy, false)
}

const ACME: &str = "https://acme.example";
const BETA: &str = "https://beta.example";

/// A world whose key service reports to `recorder`.
fn world_metered(recorder: Arc<RecordingMetrics>) -> World {
    let mut world = world_with(KeyBindingPolicy::Prefer, false);
    world.keys = world
        .keys
        .clone()
        .with_metrics(MetricSinks::noop().with_device_keys(recorder));
    let resolver = resolver(&world.clock, &world.devices);
    world.app = app(&world.clock, &world.sessions, world.keys.clone(), resolver);
    world
}

/// A world served at two hosts, one per tenant.
fn world_on_hosts() -> World {
    let mut world = world_with(KeyBindingPolicy::Prefer, false);
    world.config = DeviceKeyConfig::new(ORIGIN).with_origins([ACME, BETA]);
    world.keys = DeviceKeyService::new(world.devices.clone(), world.config.clone())
        .expect("two listed origins")
        .with_rng(MockRng::new(80));
    let resolver = resolver(&world.clock, &world.devices);
    world.app = app(&world.clock, &world.sessions, world.keys.clone(), resolver);
    world
}

/// A world whose key service takes a proof on every request when
/// `request_proofs` is set.
fn world_with(policy: KeyBindingPolicy, request_proofs: bool) -> World {
    world_on(common::test_clock(), policy, request_proofs)
}

/// [`world_with`] on a clock the caller holds.
fn world_on(clock: MockClock, policy: KeyBindingPolicy, request_proofs: bool) -> World {
    let devices = MemoryDeviceStore::new();
    let sessions = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let config = DeviceKeyConfig::new(ORIGIN).with_policy(policy);
    let mut keys = DeviceKeyService::new(devices.clone(), config.clone())
        .expect("the default configuration")
        .with_rng(MockRng::new(77));
    if request_proofs {
        keys = keys
            .with_request_proofs(SeenJtis::default(), std::time::Duration::from_secs(60))
            .expect("a skew of a minute");
    }
    let resolver = resolver(&clock, &devices);

    let app = app(&clock, &sessions, keys.clone(), resolver);
    World {
        app,
        clock,
        sessions,
        devices,
        config,
        keys,
    }
}

type TestResolver =
    LifecycleDeviceResolver<DefaultFingerprintExtractor, MemoryDeviceStore, MockClock>;

/// The stock resolver as it is built by default: the tenant is the one the
/// session signed in to, which the session layer hands it, so a request of
/// nobody signed in has no device. A fixed pepper.
fn session_tenant_resolver(clock: &MockClock, devices: &MemoryDeviceStore) -> TestResolver {
    LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32])),
        DeviceLifecycleService::new(devices.clone()),
        clock.clone(),
    )
    .with_rng(MockRng::new(78))
}

/// The resolver every world uses: the tenant of the request's host, a
/// fixed pepper.
fn resolver(clock: &MockClock, devices: &MemoryDeviceStore) -> TestResolver {
    LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(Arc::new(|_: &TenantId| [9u8; 32])),
        DeviceLifecycleService::new(devices.clone()),
        clock.clone(),
    )
    .with_tenant_fn(|parts| Some(tenant_at(&parts.headers)))
    .with_rng(MockRng::new(78))
}

/// What an application of a world is built with besides the world's own
/// parts: more routes, the session layer's signing keys, and the sink the
/// layer tells of the sessions it ends.
struct Wiring {
    extra: Router,
    signing_key: u8,
    previous_signing_key: Option<u8>,
    audit: Arc<dyn SessionEndAudit>,
}

impl Default for Wiring {
    fn default() -> Self {
        Self {
            extra: Router::new(),
            signing_key: 42,
            previous_signing_key: None,
            audit: Arc::new(axess_core::session::UnrecordedSessionEnds),
        }
    }
}

/// The application of a world: the test routes, the key routes, and the
/// session layer holding sessions to `keys`.
fn app<D: DeviceStore>(
    clock: &MockClock,
    sessions: &MemorySessionStore,
    keys: DeviceKeyService<D>,
    resolver: TestResolver,
) -> Router {
    app_with(Wiring::default(), clock, sessions, keys, resolver)
}

/// [`app`] with more routes, other signing keys, another audit sink, or
/// another session store.
fn app_with<D: DeviceStore, S: SessionStore>(
    wiring: Wiring,
    clock: &MockClock,
    sessions: &S,
    keys: DeviceKeyService<D>,
    resolver: TestResolver,
) -> Router {
    let sign_in_clock = clock.clone();
    let mut layer = SessionLayer::without_registry_insecure(
        sessions.clone(),
        axess_core::testing::test_key(wiring.signing_key),
        wiring.audit,
    )
    .with_clock(clock.clone())
    .with_rng(MockRng::new(79))
    .with_device_resolver(resolver)
    .with_device_keys(keys.clone());
    if let Some(previous) = wiring.previous_signing_key {
        layer = layer.with_previous_signing_key(axess_core::testing::test_key(previous));
    }
    Router::new()
        .route(
            "/sign-in",
            get(
                move |headers: axum::http::HeaderMap, session: AuthSession| {
                    let now = sign_in_clock.now();
                    let tenant = tenant_at(&headers);
                    async move {
                        session.set_authenticated(uid("u1"), tenant, now).await;
                        "in"
                    }
                },
            ),
        )
        .route(
            "/sign-in-as-other",
            get({
                let clock = clock.clone();
                move |session: AuthSession| {
                    let now = clock.now();
                    async move {
                        session.set_authenticated(uid("u2"), tenant(), now).await;
                        "in"
                    }
                }
            }),
        )
        .route(
            "/sign-in-as-other-asking",
            get({
                let clock = clock.clone();
                move |session: AuthSession| {
                    let now = clock.now();
                    async move {
                        let before = session.key_bound().await;
                        session
                            .begin_authenticating(
                                uid("u2"),
                                tenant(),
                                Arc::from("password"),
                                vec![FactorKind::Password],
                            )
                            .await;
                        let begun = session.key_bound().await;
                        session.advance_factor(&FactorKind::Password, now).await;
                        let done = session.key_bound().await;
                        format!("{before} {begun} {done}")
                    }
                }
            }),
        )
        .route(
            "/log-in-again-asking",
            get(|session: AuthSession| async move {
                let before = session.key_bound().await;
                session
                    .begin_authenticating(
                        uid("u1"),
                        tenant(),
                        Arc::from("password"),
                        vec![FactorKind::Password],
                    )
                    .await;
                let begun = session.key_bound().await;
                format!("{before} {begun}")
            }),
        )
        .route(
            "/complete-login",
            get({
                let clock = clock.clone();
                move |session: AuthSession| {
                    let now = clock.now();
                    async move {
                        session.advance_factor(&FactorKind::Password, now).await;
                        "done"
                    }
                }
            }),
        )
        .route(
            "/sign-out",
            get(|session: AuthSession| async move {
                session.clear().await;
                "out"
            }),
        )
        .route("/whoami", get(whoami))
        .route("/proven", get(proven))
        .route("/bound", get(bound))
        .route(
            "/key-bound",
            get(|session: AuthSession| async move { session.key_bound().await.to_string() }),
        )
        .route(
            "/bound-device",
            get(|session: AuthSession| async move {
                match session.data().await.key_binding {
                    Some(binding) => binding.device_id.to_string(),
                    None => "none".to_string(),
                }
            }),
        )
        .merge(wiring.extra)
        .merge(keys.router())
        .layer(layer)
}

/// What a client holds: its cookies, the challenge it was last handed, and
/// the registration it was last offered.
#[derive(Clone, Default)]
struct Client {
    /// The host the client sends its requests to; `None` sends no `Host`.
    host: Option<String>,
    cookies: BTreeMap<String, String>,
    challenge: Option<String>,
    offer: Option<String>,
    identifier: Option<String>,
}

impl Client {
    /// The origin the client's proofs are made for.
    fn origin(&self) -> String {
        match &self.host {
            Some(host) => format!("https://{host}"),
            None => ORIGIN.to_string(),
        }
    }

    fn cookie_header(&self, only: Option<&[&str]>) -> String {
        self.cookies
            .iter()
            .filter(|(name, _)| only.is_none_or(|only| only.contains(&name.as_str())))
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Keep what a response sets: cookies (a `Max-Age=0` removes one), the
    /// challenge, the offer.
    fn absorb(&mut self, response: &axum::response::Response) {
        for value in response.headers().get_all(header::SET_COOKIE) {
            let text = value.to_str().unwrap();
            let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attributes.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
        if let Some(value) = response.headers().get(draft::CHALLENGE_HEADER) {
            // `"<challenge>";id="<identifier>"`
            let text = value.to_str().unwrap();
            let mut quoted = text.split('"');
            self.challenge = quoted.nth(1).map(str::to_string);
            self.identifier = quoted.nth(1).map(str::to_string);
        }
        if let Some(value) = response.headers().get(draft::REGISTRATION_HEADER) {
            // `(ES256);path="<path>";challenge="<offer>"`
            self.offer = value
                .to_str()
                .unwrap()
                .split('"')
                .nth(3)
                .map(str::to_string);
        }
    }

    fn proof_cookie(&self) -> Option<&String> {
        self.cookies
            .iter()
            .find(|(name, _)| name.starts_with(PROOF))
            .map(|(_, value)| value)
    }
}

impl World {
    async fn send(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.unwrap()
    }

    /// `GET uri` with the client's cookies (`only`: those of exactly these
    /// names), keeping what the answer sets.
    async fn get(&self, client: &mut Client, uri: &str, only: Option<&[&str]>) -> String {
        self.get_with(client, uri, only, &[]).await
    }

    /// [`get`](Self::get) with more request headers.
    async fn get_with(
        &self,
        client: &mut Client,
        uri: &str,
        only: Option<&[&str]>,
        headers: &[(&str, &str)],
    ) -> String {
        let request = Request::get(uri).header(header::USER_AGENT, UA);
        self.get_from(request, client, only, headers).await
    }

    /// [`get`](Self::get) from a client that sends no `User-Agent`, so the
    /// default extractor computes no fingerprint for the request.
    async fn get_without_user_agent(
        &self,
        client: &mut Client,
        uri: &str,
        only: Option<&[&str]>,
    ) -> String {
        self.get_from(Request::get(uri), client, only, &[]).await
    }

    /// Send `request` with the client's host, `headers` and cookies (`only`:
    /// those of exactly these names), keeping what the answer sets.
    async fn get_from(
        &self,
        mut request: axum::http::request::Builder,
        client: &mut Client,
        only: Option<&[&str]>,
        headers: &[(&str, &str)],
    ) -> String {
        if let Some(host) = &client.host {
            request = request.header(header::HOST, host);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let cookies = client.cookie_header(only);
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        let response = self.send(request.body(Body::empty()).unwrap()).await;
        client.absorb(&response);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// `POST path` with the client's cookies and the given headers.
    async fn post(
        &self,
        client: &mut Client,
        path: &str,
        headers: &[(&str, &str)],
    ) -> axum::response::Response {
        let mut request = Request::post(path).header(header::USER_AGENT, UA);
        if let Some(host) = &client.host {
            request = request.header(header::HOST, host);
        }
        let cookies = client.cookie_header(None);
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self.send(request.body(Body::empty()).unwrap()).await;
        client.absorb(&response);
        response
    }

    /// A client that has signed in and made its first signed-in request, so
    /// it holds a session cookie, a device cookie and a registration offer.
    async fn signed_in(&self) -> Client {
        self.signed_in_at(None).await
    }

    /// [`signed_in`](Self::signed_in), for a client that sends its requests
    /// to `host`.
    async fn signed_in_at(&self, host: Option<&str>) -> Client {
        let mut client = Client {
            host: host.map(str::to_string),
            ..Client::default()
        };
        assert_eq!(self.get(&mut client, "/sign-in", None).await, "in");
        assert_eq!(self.get(&mut client, "/whoami", None).await, "user");
        assert!(client.cookies.contains_key(DEVICE), "the device cookie");
        assert!(client.offer.is_some(), "a keyless device is offered a key");
        client
    }

    fn proof_header(shape: KeyProofShape) -> &'static str {
        match shape {
            KeyProofShape::Browser => draft::RESPONSE_HEADER,
            KeyProofShape::App => "dpop",
        }
    }

    fn sign(
        key: &SoftwareKey,
        shape: KeyProofShape,
        url: &str,
        challenge: &str,
        with_key: bool,
    ) -> String {
        let shape = match shape {
            KeyProofShape::Browser => axess_factors::key_proof::KeyProofShape::Browser,
            KeyProofShape::App => axess_factors::key_proof::KeyProofShape::App,
        };
        let target = ProofTarget {
            method: "POST",
            url,
        };
        key.sign(shape, target, challenge, with_key)
    }

    /// Register `key` against the client's offer.
    async fn register(
        &self,
        client: &mut Client,
        key: &SoftwareKey,
        shape: KeyProofShape,
    ) -> StatusCode {
        let offer = client.offer.clone().expect("an offer");
        let url = self.config.registration_url(&client.origin());
        let jws = Self::sign(key, shape, &url, &offer, true);
        let response = self
            .post(
                client,
                self.config.registration_path(),
                &[(Self::proof_header(shape), jws.as_str())],
            )
            .await;
        response.status()
    }

    /// Refresh the client's proof with `key` over `challenge`.
    async fn refresh(
        &self,
        client: &mut Client,
        key: Option<&SoftwareKey>,
        shape: KeyProofShape,
        challenge: &str,
    ) -> StatusCode {
        let identifier = client.identifier.clone().expect("a registration");
        let jws = key.map(|key| {
            Self::sign(
                key,
                shape,
                &self.config.refresh_url(&client.origin()),
                challenge,
                false,
            )
        });
        let mut headers = vec![(draft::SESSION_ID_HEADER, identifier.as_str())];
        if let Some(jws) = &jws {
            headers.push((Self::proof_header(shape), jws.as_str()));
        }
        self.post(client, self.config.refresh_path(), &headers)
            .await
            .status()
    }

    /// A signed-in client whose device has `key` and whose session is bound.
    async fn bound_client(&self, key: &SoftwareKey, shape: KeyProofShape) -> Client {
        let mut client = self.signed_in().await;
        assert_eq!(self.register(&mut client, key, shape).await, StatusCode::OK);
        assert!(client.proof_cookie().is_some(), "a proof cookie");
        assert!(client.challenge.is_some(), "the first challenge");
        assert_eq!(self.get(&mut client, "/bound", None).await, "bound");
        client
    }

    /// An app that registered its key where request proofs are taken: it
    /// holds a session cookie, a device cookie, its first challenge and no
    /// proof cookie.
    async fn signing_app(&self, key: &SoftwareKey) -> Client {
        let mut client = self.signed_in().await;
        assert_eq!(
            self.register(&mut client, key, KeyProofShape::App).await,
            StatusCode::OK
        );
        assert!(
            client.proof_cookie().is_none(),
            "an app that signs every request is handed no proof cookie"
        );
        assert!(client.identifier.is_some(), "the device's identifier");
        client
    }

    fn proof_lifetime(&self) -> i64 {
        (self.config.proof_ttl() + self.config.acceptance_grace()).as_secs() as i64
    }
}

fn key() -> SoftwareKey {
    SoftwareKey::from_seed([7; 32])
}

/// A fault of the device store behind the key service in a test: the store
/// is down, or the inner store failed.
#[derive(Debug)]
enum Fault {
    Down,
    Inner(axess_core::MemoryDeviceStoreError),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Down => f.write_str("the device store is down"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Fault {}

/// The device store as the key service sees it in a test of faults: it can
/// be down, and it can lose a number of compare-and-swaps.
#[derive(Clone, Default)]
struct Shaky {
    inner: MemoryDeviceStore,
    down: Arc<std::sync::atomic::AtomicBool>,
    conflicts: Arc<std::sync::atomic::AtomicUsize>,
}

impl Shaky {
    fn set_down(&self, down: bool) {
        self.down.store(down, std::sync::atomic::Ordering::SeqCst);
    }

    fn lose(&self, swaps: usize) {
        self.conflicts
            .store(swaps, std::sync::atomic::Ordering::SeqCst);
    }

    fn is_down(&self) -> bool {
        self.down.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl DeviceStore for Shaky {
    type Error = Fault;

    async fn load_fresh(&self, t: &TenantId, id: &DeviceId) -> Result<Option<Device>, Fault> {
        if self.is_down() {
            return Err(Fault::Down);
        }
        self.inner.load_fresh(t, id).await.map_err(Fault::Inner)
    }
    async fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: Timestamp,
    ) -> Result<BindingsUpdate, Fault> {
        use std::sync::atomic::Ordering;
        if self.is_down() {
            return Err(Fault::Down);
        }
        if self.conflicts.load(Ordering::SeqCst) > 0 {
            self.conflicts.fetch_sub(1, Ordering::SeqCst);
            return Ok(BindingsUpdate::Conflict);
        }
        self.inner
            .replace_bindings(t, id, expected, bindings, now)
            .await
            .map_err(Fault::Inner)
    }
    async fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<OwnerClaim, Fault> {
        self.inner
            .claim_owner(t, id, user, now)
            .await
            .map_err(Fault::Inner)
    }
    async fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> Result<TrustTransition, Fault> {
        self.inner
            .set_trust_level_if(t, id, expected, level, now)
            .await
            .map_err(Fault::Inner)
    }
    fn load(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let answer = self.inner.load(t, id);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let answer = self.inner.find_by_fingerprint(t, h);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn find_for_user(
        &self,
        t: &TenantId,
        u: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let answer = self.inner.find_for_user(t, u, limit);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn find_by_refresh_family(
        &self,
        t: &TenantId,
        f: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let answer = self.inner.find_by_refresh_family(t, f);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn save(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let answer = self.inner.save(d, now);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn create_or_find(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<Device, Self::Error>> + Send {
        let answer = self.inner.create_or_find(d, now);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: Timestamp,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        let answer = self.inner.record_sighting(t, id, now);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let answer = self.inner.set_trust_level(t, id, level, now);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn delete(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let answer = self.inner.delete(t, id);
        async move { answer.await.map_err(Fault::Inner) }
    }
    fn sweep(
        &self,
        t: &TenantId,
        now: Timestamp,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        let answer = self.inner.sweep(t, now);
        async move { answer.await.map_err(Fault::Inner) }
    }
}

/// The answer to a `POST` of `headers` at the refresh path: the status, the
/// body, and whether a challenge came with it.
async fn refresh_answer(world: &World, headers: &[(&str, &str)]) -> (StatusCode, String, bool) {
    let response = world
        .post(&mut Client::default(), world.config.refresh_path(), headers)
        .await;
    let status = response.status();
    let challenged = response.headers().contains_key(draft::CHALLENGE_HEADER);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    (
        status,
        String::from_utf8(body.to_vec()).unwrap(),
        challenged,
    )
}

/// The id of the client's device, from its device cookie.
fn device_of(client: &Client) -> DeviceId {
    client.cookies[DEVICE]
        .split_once('.')
        .expect("an id and a token")
        .0
        .parse()
        .expect("a device id")
}

/// The store behind the key service fails, or its row keeps changing under
/// the write: both paths answer 503, which says "again later" and not "no",
/// set no proof cookie, and leave the offer and the challenge to be used
/// when the store is back.
#[tokio::test]
async fn a_failing_store_or_a_contended_row_is_answered_503() {
    let mut world = world(KeyBindingPolicy::Prefer);
    let shaky = Shaky {
        inner: world.devices.clone(),
        ..Shaky::default()
    };
    let keys = DeviceKeyService::new(shaky.clone(), world.config.clone())
        .expect("the default configuration")
        .with_rng(MockRng::new(90));
    world.app = app(
        &world.clock,
        &world.sessions,
        keys,
        resolver(&world.clock, &world.devices),
    );
    let mut client = world.signed_in().await;
    let register = KeyProofShape::Browser;

    shaky.set_down(true);
    assert_eq!(
        world.register(&mut client, &key(), register).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    shaky.set_down(false);
    shaky.lose(usize::MAX);
    assert_eq!(
        world.register(&mut client, &key(), register).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(client.proof_cookie().is_none());
    shaky.lose(0);
    assert_eq!(
        world.register(&mut client, &key(), register).await,
        StatusCode::OK
    );

    let challenge = client.challenge.clone().unwrap();
    let proof_before = client.proof_cookie().cloned();
    shaky.set_down(true);
    assert_eq!(
        world
            .refresh(&mut client, Some(&key()), register, &challenge)
            .await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    shaky.set_down(false);
    shaky.lose(usize::MAX);
    assert_eq!(
        world
            .refresh(&mut client, Some(&key()), register, &challenge)
            .await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(client.proof_cookie().cloned(), proof_before);
    shaky.lose(0);
    assert_eq!(
        world
            .refresh(&mut client, Some(&key()), register, &challenge)
            .await,
        StatusCode::OK
    );
}

/// At the refresh path a device that is gone, one that is revoked and one
/// that has no key get one and the same answer, so the path tells a caller
/// who holds nothing but an identifier nothing about the device; and a
/// request that names no device is refused.
#[tokio::test]
async fn the_refresh_path_answers_alike_for_a_device_gone_revoked_or_keyless() {
    let world = world(KeyBindingPolicy::Prefer);
    let keyed = world.bound_client(&key(), KeyProofShape::Browser).await;
    let keyless = world.signed_in().await;
    let named = |device: DeviceId| format!("{}.{device}", tenant());
    let gone = named("0e0e0e0e-0000-4000-8000-00000000000e".parse().unwrap());
    let no_key = named(device_of(&keyless));
    let revoked = keyed.identifier.clone().unwrap();
    world
        .devices
        .set_trust_level(
            &tenant(),
            &device_of(&keyed),
            DeviceTrustLevel::Revoked,
            world.clock.now(),
        )
        .await
        .unwrap();

    let ended = (
        StatusCode::from_u16(draft::ENDED_STATUS).unwrap(),
        draft::ENDED_BODY.to_string(),
        false,
    );
    for identifier in [&gone, &no_key, &revoked] {
        assert_eq!(
            refresh_answer(&world, &[(draft::SESSION_ID_HEADER, identifier.as_str())]).await,
            ended,
            "{identifier}"
        );
    }
    let (status, _, challenged) = refresh_answer(&world, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no device named");
    assert!(!challenged);
    let (status, _, challenged) =
        refresh_answer(&world, &[(draft::SESSION_ID_HEADER, "not-an-identifier")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!challenged);
}

/// `Off` is the switch that serves what is stored without checking a key: a
/// session bound to a key is served to the bare session cookie, its keyed
/// device is proven by its token again, and nothing is key bound.
#[tokio::test]
async fn off_serves_a_bound_session_and_proves_a_keyed_device_by_its_token() {
    let mut world = world(KeyBindingPolicy::Prefer);
    let client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let off = DeviceKeyService::new(
        world.devices.clone(),
        world.config.clone().with_policy(KeyBindingPolicy::Off),
    )
    .expect("the default configuration, switched off");
    world.app = app(
        &world.clock,
        &world.sessions,
        off,
        resolver(&world.clock, &world.devices),
    );
    let cookies: &[&str] = &[SESSION, DEVICE];
    for (path, expected) in [
        ("/whoami", "user"),
        ("/bound", "bound"),
        ("/proven", "token"),
        ("/key-bound", "false"),
    ] {
        assert_eq!(
            world.get(&mut client.clone(), path, Some(cookies)).await,
            expected,
            "{path}"
        );
    }
}

/// With a CSRF layer between the session layer and the routes, a `POST` to
/// one of the two key paths passes without a token, because the session
/// layer marked it, and nothing else does: another route, a path that only
/// begins like a key path, and the same request under a layer that marks
/// nothing are refused before they reach a handler.
#[tokio::test]
async fn the_csrf_exemption_covers_the_two_key_paths_and_nothing_else() {
    use axess_core::middleware::csrf::{CsrfConfig, CsrfLayer};
    let world = world(KeyBindingPolicy::Prefer);
    let client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let identifier = client.identifier.clone().unwrap();
    let routes = || {
        Router::new()
            .route("/act", axum::routing::post(|| async { "done" }))
            .merge(world.keys.router())
            .layer(CsrfLayer::new(CsrfConfig::new([7; 32])))
    };
    let session_layer = || {
        SessionLayer::without_registry_insecure(
            world.sessions.clone(),
            axess_core::testing::test_key(42),
            std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
        )
        .with_clock(world.clock.clone())
        .with_rng(MockRng::new(83))
    };
    let guarded = routes().layer(
        session_layer()
            .with_device_resolver(resolver(&world.clock, &world.devices))
            .with_device_keys(world.keys.clone()),
    );
    let unmarked = routes().layer(session_layer());
    let post = |app: &Router, path: &str| {
        let request = Request::post(path)
            .header(header::USER_AGENT, UA)
            .header(header::COOKIE, client.cookie_header(None))
            .header(draft::SESSION_ID_HEADER, identifier.as_str())
            .body(Body::empty())
            .unwrap();
        let app = app.clone();
        async move {
            let response = app.oneshot(request).await.unwrap();
            (
                response.status(),
                response.headers().contains_key(draft::CHALLENGE_HEADER),
            )
        }
    };
    let refresh = world.config.refresh_path();
    // Marked: it reaches the handler, which hands out the challenge.
    assert_eq!(
        post(&guarded, refresh).await,
        (StatusCode::from_u16(draft::CHALLENGE_STATUS).unwrap(), true)
    );
    // Not marked: refused by the CSRF layer, no handler, no challenge.
    for path in ["/act", &format!("{refresh}/more"), "/axess"] {
        assert_eq!(
            post(&guarded, path).await,
            (StatusCode::FORBIDDEN, false),
            "{path}"
        );
    }
    assert_eq!(
        post(&unmarked, refresh).await,
        (StatusCode::FORBIDDEN, false)
    );
}

/// Invariants 4 and 5: once the key is registered, the session is served
/// only with the proof cookie, and the device is proven only by its key.
#[tokio::test]
async fn a_bound_session_is_served_only_with_its_proof() {
    for shape in [KeyProofShape::Browser, KeyProofShape::App] {
        let world = world(KeyBindingPolicy::Prefer);
        let mut client = world.bound_client(&key(), shape).await;

        assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
        assert_eq!(world.get(&mut client, "/proven", None).await, "key");
        assert_eq!(world.get(&mut client, "/key-bound", None).await, "true");

        // The copied long-lived cookies, without the proof.
        let stolen: &[&str] = &[SESSION, DEVICE];
        let mut thief = client.clone();
        assert_eq!(
            world.get(&mut thief, "/whoami", Some(stolen)).await,
            "guest"
        );
        assert_eq!(
            world.get(&mut thief, "/proven", Some(stolen)).await,
            "unproven"
        );
        // The device token alone, as a guest presents it before signing in.
        assert_eq!(
            world.get(&mut thief, "/proven", Some(&[DEVICE][..])).await,
            "unproven"
        );

        // The row is untouched: the owner is still served.
        assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
        assert_eq!(world.get(&mut client, "/bound", None).await, "bound");
    }
}

/// A copy of every cookie is worth the rest of the proof cookie's life and
/// not a second more; a refresh, which needs the key, restores the owner.
#[tokio::test]
async fn a_proof_cookie_ends_at_its_lifetime_and_a_refresh_restores_it() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let thief = client.clone();

    world.clock.advance_secs(world.proof_lifetime() - 1);
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    world.clock.advance_secs(1);
    assert_eq!(world.get(&mut client, "/whoami", None).await, "guest");
    assert_eq!(
        world.get(&mut thief.clone(), "/whoami", None).await,
        "guest"
    );

    let challenge = client.challenge.clone().unwrap();
    let before = client.proof_cookie().cloned();
    assert_eq!(
        world
            .refresh(
                &mut client,
                Some(&key()),
                KeyProofShape::Browser,
                &challenge
            )
            .await,
        StatusCode::OK
    );
    assert_ne!(client.proof_cookie().cloned(), before, "a new proof cookie");
    assert_ne!(client.challenge.as_deref(), Some(challenge.as_str()));
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    // The thief's copy did not come back to life with the owner's refresh.
    assert_eq!(
        world.get(&mut thief.clone(), "/whoami", None).await,
        "guest"
    );
}

/// Invariant 3 at the refresh path: no proof and a replayed proof are both
/// answered with the challenge to sign and no cookie; a proof by another
/// key is refused.
#[tokio::test]
async fn the_refresh_path_hands_out_challenges_and_accepts_each_once() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let challenged = StatusCode::from_u16(draft::CHALLENGE_STATUS).unwrap();
    let first = client.challenge.clone().unwrap();
    let cookie = client.proof_cookie().cloned();

    let mut asking = client.clone();
    assert_eq!(
        world
            .refresh(&mut asking, None, KeyProofShape::Browser, "")
            .await,
        challenged
    );
    assert_eq!(asking.challenge.as_deref(), Some(first.as_str()));
    assert_eq!(
        asking.proof_cookie().cloned(),
        cookie,
        "no cookie for asking"
    );

    let stranger = SoftwareKey::from_seed([8; 32]);
    assert_eq!(
        world
            .refresh(
                &mut client.clone(),
                Some(&stranger),
                KeyProofShape::Browser,
                &first
            )
            .await,
        StatusCode::BAD_REQUEST,
        "final, and not the status a browser reads as a challenge"
    );

    assert_eq!(
        world
            .refresh(&mut client, Some(&key()), KeyProofShape::Browser, &first)
            .await,
        StatusCode::OK
    );
    let second = client.challenge.clone().unwrap();
    assert_ne!(second, first);
    let mut replaying = client.clone();
    assert_eq!(
        world
            .refresh(&mut replaying, Some(&key()), KeyProofShape::Browser, &first)
            .await,
        challenged,
        "the accepted proof is not accepted again"
    );
    assert_eq!(replaying.challenge.as_deref(), Some(second.as_str()));
}

/// A device that is revoked ends its registration: the refresh answers the
/// ended form and takes the proof cookie away, and the bound session stops
/// being served when the last proof runs out.
#[tokio::test]
async fn revoking_the_device_ends_its_proofs() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let identifier = client.identifier.clone().unwrap();
    let device = identifier.split_once('.').unwrap().1.parse().unwrap();
    world
        .devices
        .set_trust_level(
            &tenant(),
            &device,
            DeviceTrustLevel::Revoked,
            world.clock.now(),
        )
        .await
        .unwrap();

    let challenge = client.challenge.clone().unwrap();
    let jws = World::sign(
        &key(),
        KeyProofShape::Browser,
        &world.config.refresh_url(ORIGIN),
        &challenge,
        false,
    );
    let response = world
        .post(
            &mut client,
            world.config.refresh_path(),
            &[
                (draft::SESSION_ID_HEADER, identifier.as_str()),
                (draft::RESPONSE_HEADER, jws.as_str()),
            ],
        )
        .await;
    assert_eq!(response.status().as_u16(), draft::ENDED_STATUS);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(body, draft::ENDED_BODY.as_bytes());
    assert!(
        client.proof_cookie().is_none(),
        "the proof cookie is expired"
    );
    assert_eq!(world.get(&mut client, "/whoami", None).await, "guest");
}

/// A registration needs the offer this session was made: a proof over
/// anything else is refused, a second key is refused, and a session past
/// its window may not register at all.
#[tokio::test]
async fn a_registration_needs_its_offer_and_its_window() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.signed_in().await;
    let offer = client.offer.clone().unwrap();

    let mut forging = client.clone();
    forging.offer = Some("v1.9999999999.AAAA".to_string());
    assert_eq!(
        world
            .register(&mut forging, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::FORBIDDEN
    );
    // Another session cannot use this session's offer.
    let mut other = world.signed_in().await;
    other.offer = Some(offer.clone());
    assert_eq!(
        world
            .register(&mut other, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::FORBIDDEN
    );

    // Past the window the same offer is dead, and no new one is made.
    let window = world.config.registration_window().as_secs() as i64;
    let mut late = client.clone();
    world.clock.advance_secs(window + 1);
    assert_eq!(
        world
            .register(&mut late, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::FORBIDDEN
    );
    late.offer = None;
    assert_eq!(world.get(&mut late, "/whoami", None).await, "user");
    assert_eq!(late.offer, None, "no offer outside the window");
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");
}

/// After a sign-out the device keeps its key and the client its proof, so
/// the next sign-in is bound by the request that completes it: no offer, no
/// registration, and no moment in which the new session is a bearer one.
#[tokio::test]
async fn a_sign_in_on_a_proven_key_is_bound_at_once() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    assert_eq!(world.get(&mut client, "/sign-out", None).await, "out");
    assert_eq!(world.get(&mut client, "/whoami", None).await, "guest");
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");

    client.offer = None;
    assert_eq!(world.get(&mut client, "/sign-in", None).await, "in");
    assert_eq!(client.offer, None, "a device with a key is offered none");
    assert_eq!(world.get(&mut client, "/bound", None).await, "bound");
    // And it is held to the key from then on.
    let stolen: &[&str] = &[SESSION, DEVICE];
    assert_eq!(
        world
            .get(&mut client.clone(), "/whoami", Some(stolen))
            .await,
        "guest"
    );
}

/// A second account signs in on a browser profile whose only device is the
/// first account's, key and all. The request that completes the sign-in
/// proves that device, and the new session is not bound to it: the device
/// stays the first account's, and the second account's next request is
/// given a device of its own and offered a key for it.
#[tokio::test]
async fn a_sign_in_is_not_bound_to_another_accounts_device() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let identifier = client.identifier.clone().unwrap();
    let first_device: DeviceId = identifier.split_once('.').unwrap().1.parse().unwrap();
    assert_eq!(world.get(&mut client, "/sign-out", None).await, "out");
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");

    client.offer = None;
    assert_eq!(
        world.get(&mut client, "/sign-in-as-other", None).await,
        "in"
    );
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "false");
    assert!(
        client.offer.is_some(),
        "the second account's own device is offered a key"
    );
    let row = world
        .devices
        .load_fresh(&tenant(), &first_device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.user_id, Some(uid("u1")), "the device keeps its owner");
    assert_eq!(row.trust_level, DeviceTrustLevel::Unknown);
}

/// A bound session's request that carries the proof and not the device's
/// token still proved the key: the session's device counts as proven by it,
/// and `key_bound` says so.
#[tokio::test]
async fn a_bound_request_without_the_device_token_is_still_key_bound() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let proof_name = client
        .cookies
        .keys()
        .find(|name| name.starts_with(PROOF))
        .cloned()
        .expect("a proof cookie");
    let cookies: &[&str] = &[SESSION, proof_name.as_str()];
    for (path, expected) in [
        ("/whoami", "user"),
        ("/key-bound", "true"),
        ("/proven", "key"),
    ] {
        assert_eq!(
            world.get(&mut client.clone(), path, Some(cookies)).await,
            expected,
            "{path}"
        );
    }
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "true");
}

/// A bound session's request that sends no `User-Agent` cannot be
/// fingerprinted, and the fingerprint has no part in finding a device: the
/// bound device is proven by the key the request proves, with the device
/// token or without it.
#[tokio::test]
async fn a_bound_request_without_a_user_agent_is_proven_by_its_key() {
    let world = world(KeyBindingPolicy::Prefer);
    let client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let proof_name = client
        .cookies
        .keys()
        .find(|name| name.starts_with(PROOF))
        .cloned()
        .expect("a proof cookie");
    let without_token: &[&str] = &[SESSION, proof_name.as_str()];
    for only in [None, Some(without_token)] {
        for (path, expected) in [
            ("/whoami", "user"),
            ("/key-bound", "true"),
            ("/proven", "key"),
        ] {
            assert_eq!(
                world
                    .get_without_user_agent(&mut client.clone(), path, only)
                    .await,
                expected,
                "{path}, cookies {only:?}"
            );
        }
    }
    assert_eq!(world.devices.len(), 1, "no device is created");
}

/// A session that is bound stays bound to what it was bound to. When its
/// browser profile presents a second, keyless device of the same user ahead
/// of the bound one, that device becomes the session's, is offered a key and
/// registers it, and the session's binding is still the first device's key:
/// the first key's proof alone serves the session, the second key's does
/// not.
#[tokio::test]
async fn a_registration_leaves_an_existing_binding_as_it_is() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut first = world.bound_client(&key(), KeyProofShape::Browser).await;
    let second = world.signed_in().await;
    let first_proof = first
        .cookies
        .keys()
        .find(|name| name.starts_with(PROOF))
        .cloned()
        .expect("the bound device's proof cookie");
    let both = format!("{}~{}", second.cookies[DEVICE], first.cookies[DEVICE]);
    first.cookies.insert(DEVICE.to_string(), both);
    first.offer = None;
    assert_eq!(world.get(&mut first, "/proven", None).await, "token");
    assert!(
        first.offer.is_some(),
        "the keyless device that became the session's is offered a key"
    );
    let another = SoftwareKey::from_seed([9; 32]);
    assert_eq!(
        world
            .register(&mut first, &another, KeyProofShape::Browser)
            .await,
        StatusCode::OK
    );
    let second_proof = first
        .cookies
        .keys()
        .find(|name| name.starts_with(PROOF) && **name != first_proof)
        .cloned()
        .expect("the second device's proof cookie");
    let with_first: &[&str] = &[SESSION, first_proof.as_str()];
    let with_second: &[&str] = &[SESSION, second_proof.as_str()];
    assert_eq!(
        world
            .get(&mut first.clone(), "/whoami", Some(with_first))
            .await,
        "user"
    );
    assert_eq!(
        world
            .get(&mut first.clone(), "/whoami", Some(with_second))
            .await,
        "guest"
    );
}

/// A browser that writes its two request headers as the draft defines them,
/// in double quotes, registers and refreshes like one that sends them bare.
/// The answers of the key paths may not be embedded by another origin, and
/// a final refusal at the refresh path has a status of its own, without a
/// challenge, so a browser does not answer it by signing again.
#[tokio::test]
async fn a_browser_that_quotes_its_headers_registers_and_refreshes() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.signed_in().await;
    let quoted = |text: &str| format!("\"{text}\"");
    let offer = client.offer.clone().unwrap();
    let url = world.config.registration_url(ORIGIN);
    let proof = quoted(&World::sign(
        &key(),
        KeyProofShape::Browser,
        &url,
        &offer,
        true,
    ));
    let registered = world
        .post(
            &mut client,
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, proof.as_str())],
        )
        .await;
    assert_eq!(registered.status(), StatusCode::OK);
    assert_eq!(
        registered.headers()["cross-origin-resource-policy"],
        "same-origin"
    );
    assert_eq!(registered.headers()[header::X_FRAME_OPTIONS], "DENY");

    let challenge = client.challenge.clone().unwrap();
    let identifier = quoted(client.identifier.as_deref().unwrap());
    let refresh_url = world.config.refresh_url(ORIGIN);
    let signed_by = |signer: &SoftwareKey| {
        quoted(&World::sign(
            signer,
            KeyProofShape::Browser,
            &refresh_url,
            &challenge,
            false,
        ))
    };
    let forged = signed_by(&SoftwareKey::from_seed([8; 32]));
    let refused = world
        .post(
            &mut client.clone(),
            world.config.refresh_path(),
            &[
                (draft::SESSION_ID_HEADER, identifier.as_str()),
                (draft::RESPONSE_HEADER, forged.as_str()),
            ],
        )
        .await;
    assert_eq!(refused.status().as_u16(), draft::REFRESH_REFUSED_STATUS);
    assert_ne!(refused.status().as_u16(), draft::CHALLENGE_STATUS);
    assert!(!refused.headers().contains_key(draft::CHALLENGE_HEADER));
    assert_eq!(refused.headers()[header::X_FRAME_OPTIONS], "DENY");

    let sound = signed_by(&key());
    let refreshed = world
        .post(
            &mut client,
            world.config.refresh_path(),
            &[
                (draft::SESSION_ID_HEADER, identifier.as_str()),
                (draft::RESPONSE_HEADER, sound.as_str()),
            ],
        )
        .await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    assert_ne!(client.challenge, Some(challenge));
}

/// The offer is delivered once: the response that gave the session its
/// device carries it, and no later response inside the window does, to the
/// owner or to anyone who presents the same cookies.
#[tokio::test]
async fn the_registration_offer_is_delivered_once() {
    let recorder = Arc::new(RecordingMetrics::default());
    let world = world_metered(recorder.clone());
    let mut client = world.signed_in().await;
    assert_eq!(recorder.count("key_offered"), 1);

    client.offer = None;
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(client.offer, None, "a second response carries no offer");
    let mut copy = client.clone();
    assert_eq!(world.get(&mut copy, "/proven", None).await, "token");
    assert_eq!(copy.offer, None, "nor does one to a copy of the cookies");
    assert_eq!(recorder.count("key_offered"), 1);
}

/// A second service that shares the session store and the signing key but
/// was given no key service cannot check a key, and does not serve a bound
/// session: the request runs as a guest, and the row stays for the layer
/// that can check it.
#[tokio::test]
async fn a_layer_without_the_key_service_does_not_serve_a_bound_session() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let bare = Router::new().route("/whoami", get(whoami)).layer(
        SessionLayer::without_registry_insecure(
            world.sessions.clone(),
            axess_core::testing::test_key(42),
            std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
        )
        .with_clock(world.clock.clone())
        .with_rng(MockRng::new(81)),
    );
    let request = Request::get("/whoami")
        .header(header::USER_AGENT, UA)
        .header(header::COOKIE, client.cookie_header(None))
        .body(Body::empty())
        .unwrap();
    let response = bare.oneshot(request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 64)
        .await
        .unwrap();
    assert_eq!(&body[..], b"guest");
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
}

/// `Require`: a session that is not bound is served for the registration
/// window and ended one second past it, row and all; a bound one stays.
#[tokio::test]
async fn require_ends_an_unbound_session_after_the_window() {
    let world = world(KeyBindingPolicy::Require);
    let window = world.config.registration_window().as_secs() as i64;

    let mut unbound = world.signed_in().await;
    world.clock.advance_secs(window);
    assert_eq!(world.get(&mut unbound, "/whoami", None).await, "user");
    world.clock.advance_secs(1);
    assert_eq!(world.get(&mut unbound, "/whoami", None).await, "guest");
    let rows = world
        .sessions
        .find_sessions_for_user(&uid("u1"), 10)
        .await
        .unwrap();
    assert!(rows.is_empty(), "the ended row is deleted");

    let world = self::world(KeyBindingPolicy::Require);
    let mut bound = world.bound_client(&key(), KeyProofShape::Browser).await;
    world.clock.advance_secs(window + 1);
    assert_eq!(world.get(&mut bound, "/whoami", None).await, "user");
}

/// `Off` restores what was there before: no offer, the key paths answer
/// nothing, and a device is proven by its token.
#[tokio::test]
async fn off_offers_nothing_and_answers_neither_path() {
    let world = world(KeyBindingPolicy::Off);
    let mut client = Client::default();
    assert_eq!(world.get(&mut client, "/sign-in", None).await, "in");
    assert_eq!(world.get(&mut client, "/proven", None).await, "token");
    assert_eq!(client.offer, None);
    for path in [
        world.config.registration_path(),
        world.config.refresh_path(),
    ] {
        let response = world.post(&mut client, path, &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

/// Under `Prefer` a client that registers nothing keeps what it had: a
/// session served on its cookie and a device proven by its token.
#[tokio::test]
async fn prefer_leaves_a_client_without_a_key_as_it_was() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.signed_in().await;
    assert_eq!(world.get(&mut client, "/proven", None).await, "token");
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "false");
    world
        .clock
        .advance_secs(world.config.registration_window().as_secs() as i64 + 60);
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");
    let rows = world
        .sessions
        .find_sessions_for_user(&uid("u1"), 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "the session is stored, and not bound");
    assert!(rows[0].1.key_binding.is_none());
}

/// A refresh token of a keyed device refreshes only with the key. A sound
/// signature over a stale challenge changes nothing; the token without the
/// key is a token in the wrong hands, and its family is revoked.
#[tokio::test]
async fn a_refresh_token_of_a_keyed_device_needs_the_key() {
    let world = world(KeyBindingPolicy::Prefer);
    let client = world.bound_client(&key(), KeyProofShape::App).await;
    let identifier = client.identifier.clone().unwrap();
    let device = identifier.split_once('.').unwrap().1.parse().unwrap();
    let (tokens, config, rng) = (
        MemoryRefreshTokenStore::new().with_clock(Arc::new(world.clock.clone())),
        RefreshTokenConfig::default(),
        MockRng::new(5),
    );
    let now = world.clock.now();
    let url = "https://app.example/token";

    // A sound signature over a challenge that is not the current one.
    let token = issue_token(&tokens, &config, &rng, device, now).await;
    let stale = World::sign(&key(), KeyProofShape::App, url, "an-old-challenge", false);
    let refused = Refresh::new(&token, &tenant(), |_| async { true })
        .device_key(&world.keys, app_proof(&stale, url))
        .device_store(&world.devices)
        .run(&tokens, &config, &rng, now)
        .await;
    let Err(RefreshError::KeyProofRequired { challenge }) = refused else {
        panic!("a stale challenge asks for the current one");
    };
    assert_eq!(Some(challenge.as_str()), client.challenge.as_deref());

    // The same token, with the challenge signed: it rotates, and the session
    // it yields is bound to the key.
    let good = World::sign(&key(), KeyProofShape::App, url, &challenge, false);
    let (session, rotated) = Refresh::new(&token, &tenant(), |_| async { true })
        .device_key(&world.keys, app_proof(&good, url))
        .device_store(&world.devices)
        .run(&tokens, &config, &rng, now)
        .await
        .expect("the key's proof over the current challenge refreshes");
    assert_eq!(
        session.key_binding.map(|binding| binding.device_id),
        Some(device)
    );
    let (next_token, _) = rotated.expect("rotation is on by default");

    // The rotated token presented without the key: the family is revoked.
    let stolen = Refresh::new(&next_token, &tenant(), |_| async { true })
        .device_key(&world.keys, None)
        .device_store(&world.devices)
        .run(&tokens, &config, &rng, now)
        .await;
    assert!(matches!(stolen, Err(RefreshError::KeyProofInvalid)));
    let challenge = world
        .keys
        .current_key_challenge(&tenant(), &device, now)
        .await
        .unwrap()
        .to_text();
    let late = World::sign(&key(), KeyProofShape::App, url, &challenge, false);
    let after = Refresh::new(&next_token, &tenant(), |_| async { true })
        .device_key(&world.keys, app_proof(&late, url))
        .device_store(&world.devices)
        .run(&tokens, &config, &rng, now)
        .await;
    assert!(
        matches!(after, Err(RefreshError::Revoked)),
        "the family was revoked: even the key holder signs in again"
    );

    // A proof by another key is the same theft signal.
    let other = issue_token(&tokens, &config, &rng, device, now).await;
    let stranger = SoftwareKey::from_seed([8; 32]);
    let forged = World::sign(&stranger, KeyProofShape::App, url, &challenge, false);
    let refused = Refresh::new(&other, &tenant(), |_| async { true })
        .device_key(&world.keys, app_proof(&forged, url))
        .device_store(&world.devices)
        .run(&tokens, &config, &rng, now)
        .await;
    assert!(matches!(refused, Err(RefreshError::KeyProofInvalid)));
}

/// A refresh token issued at `now` to the test user on `device`.
/// A refresh that cannot check a key refreshes no keyed device's token: one
/// given the device store and not the key service is refused by name, with
/// nothing rotated or revoked, and the token still refreshes where the key
/// is checked.
#[tokio::test]
async fn a_refresh_without_the_key_service_refuses_a_keyed_devices_token() {
    let world = world(KeyBindingPolicy::Prefer);
    let client = world.bound_client(&key(), KeyProofShape::App).await;
    let identifier = client.identifier.clone().unwrap();
    let device = identifier.split_once('.').unwrap().1.parse().unwrap();
    let (tokens, config, rng) = (
        MemoryRefreshTokenStore::new().with_clock(Arc::new(world.clock.clone())),
        RefreshTokenConfig::default(),
        MockRng::new(6),
    );
    let now = world.clock.now();
    let token = issue_token(&tokens, &config, &rng, device, now).await;

    let unchecked = Refresh::new(&token, &tenant(), |_| async { true })
        .device_store(&world.devices)
        .run(&tokens, &config, &rng, now)
        .await;
    assert!(
        matches!(unchecked, Err(RefreshError::KeyCheckMissing)),
        "a keyed device's token is never refreshed into an unbound session"
    );

    let url = "https://app.example/token";
    let challenge = client.challenge.clone().unwrap();
    let good = World::sign(&key(), KeyProofShape::App, url, &challenge, false);
    let (session, _) = Refresh::new(&token, &tenant(), |_| async { true })
        .device_store(&world.devices)
        .device_key(&world.keys, app_proof(&good, url))
        .run(&tokens, &config, &rng, now)
        .await
        .expect("the token was left as it was");
    assert!(session.key_binding.is_some());
}

/// A device that has no key refreshes whatever header comes beside its
/// token: a proof that does not parse, a sound one by some key, or none.
/// Nothing is revoked and no suspicious row is written for it.
#[tokio::test]
async fn a_keyless_devices_token_refreshes_whatever_comes_with_it() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.signed_in().await;
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    let device: DeviceId = client.cookies[DEVICE]
        .split_once('.')
        .unwrap()
        .0
        .parse()
        .unwrap();
    let (tokens, config, rng) = (
        MemoryRefreshTokenStore::new().with_clock(Arc::new(world.clock.clone())),
        RefreshTokenConfig::default(),
        MockRng::new(7),
    );
    let now = world.clock.now();
    let url = "https://app.example/token";
    let sound = World::sign(&key(), KeyProofShape::App, url, "any-challenge", true);
    let mut token = issue_token(&tokens, &config, &rng, device, now).await;
    for proof in [
        Some("not.a.proof"),
        Some("garbage"),
        Some(sound.as_str()),
        None,
    ] {
        let (session, rotated) = Refresh::new(&token, &tenant(), |_| async { true })
            .device_store(&world.devices)
            .device_key(&world.keys, proof.and_then(|jws| app_proof(jws, url)))
            .run(&tokens, &config, &rng, now)
            .await
            .unwrap_or_else(|refusal| panic!("{proof:?}: {refusal}"));
        assert!(session.key_binding.is_none(), "{proof:?}");
        token = rotated.expect("rotation is on by default").0;
    }
}

async fn issue_token(
    tokens: &MemoryRefreshTokenStore,
    config: &RefreshTokenConfig,
    rng: &MockRng,
    device: DeviceId,
    now: Timestamp,
) -> String {
    let (user, tenant) = (uid("u1"), tenant());
    let request = IssueRequest {
        user_id: &user,
        tenant_id: &tenant,
        device_info: None,
        family_id: None,
        device_id: Some(device),
    };
    issue_refresh_token(request, config, tokens, rng, now)
        .await
        .unwrap()
        .0
}

/// An app-shaped proof as the refresh call receives it.
fn app_proof<'a>(jws: &'a str, url: &'a str) -> Option<KeyProof<'a>> {
    Some(KeyProof {
        jws,
        shape: KeyProofShape::App,
        method: "POST",
        url,
    })
}

/// An app that signs every request needs no proof cookie: each request
/// carries a proof by the device key, used once, for that request, at the
/// time it is sent, and nothing else stands in for it.
#[tokio::test]
async fn an_app_proves_its_key_on_every_request() {
    let world = world_with(KeyBindingPolicy::Prefer, true);
    let client = world.signing_app(&key()).await;
    let cookies: &[&str] = &[SESSION, DEVICE];
    let now = world.clock.now().unix_seconds();
    let url = format!("{ORIGIN}/whoami");
    let target = ProofTarget {
        method: "GET",
        url: &url,
    };
    let first = key().sign_request(target, now, "r-1");
    assert_eq!(ask(&world, &client, cookies, &first).await, "user");
    assert_eq!(
        ask(&world, &client, cookies, &first).await,
        "guest",
        "a proof is used once"
    );
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(target, now, "r-2")
        )
        .await,
        "user"
    );

    let stranger = SoftwareKey::from_seed([8; 32]);
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &stranger.sign_request(target, now, "r-3")
        )
        .await,
        "guest"
    );
    let elsewhere = ProofTarget {
        method: "GET",
        url: "https://app.example/proven",
    };
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(elsewhere, now, "r-4")
        )
        .await,
        "guest"
    );
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(target, now - 61, "r-5")
        )
        .await,
        "guest"
    );
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(target, now - 60, "r-6")
        )
        .await,
        "user"
    );
    // Dated ahead by more than clocks differ: made before it is used.
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(target, now + 6, "r-8")
        )
        .await,
        "guest"
    );
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(target, now + 5, "r-9")
        )
        .await,
        "user"
    );

    // Revoking the device ends the session for the next request.
    let identifier = client.identifier.clone().unwrap();
    let device = identifier.split_once('.').unwrap().1.parse().unwrap();
    world
        .devices
        .set_trust_level(
            &tenant(),
            &device,
            DeviceTrustLevel::Revoked,
            world.clock.now(),
        )
        .await
        .unwrap();
    assert_eq!(
        ask(
            &world,
            &client,
            cookies,
            &key().sign_request(target, now, "r-7")
        )
        .await,
        "guest"
    );
}

/// An app that signs every request and holds no proof cookie is recognised
/// at its next sign-in by the request's own proof and the identifier header:
/// the request that signs the user in proves the device by its key, and the
/// new session is bound to it at once, with no registration and no offer.
#[tokio::test]
async fn an_app_is_recognised_by_its_request_proof_at_the_next_sign_in() {
    let world = world_with(KeyBindingPolicy::Prefer, true);
    let mut client = world.signing_app(&key()).await;
    let identifier = client.identifier.clone().unwrap();
    let now = world.clock.now().unix_seconds();
    let signed = |path: &str, jti: &str| {
        let url = format!("{ORIGIN}{path}");
        let target = ProofTarget {
            method: "GET",
            url: &url,
        };
        key().sign_request(target, now, jti)
    };

    let proof = signed("/sign-out", "s-1");
    assert_eq!(
        world
            .get_with(&mut client, "/sign-out", None, &[("dpop", proof.as_str())])
            .await,
        "out"
    );
    client.offer = None;
    let named = |proof: &str| -> Vec<(&'static str, String)> {
        vec![
            ("dpop", proof.to_string()),
            (draft::SESSION_ID_HEADER, identifier.clone()),
        ]
    };
    let headers = named(&signed("/sign-in", "s-2"));
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(
        world
            .get_with(&mut client, "/sign-in", None, &headers)
            .await,
        "in"
    );
    assert_eq!(client.offer, None, "a device with a key is offered none");
    assert!(client.proof_cookie().is_none(), "and no proof cookie");

    let proof = signed("/bound", "s-3");
    assert_eq!(
        world
            .get_with(&mut client, "/bound", None, &[("dpop", proof.as_str())])
            .await,
        "bound"
    );
    // Held to the key: the cookies alone open nothing.
    assert_eq!(
        world.get(&mut client.clone(), "/whoami", None).await,
        "guest"
    );
    // A stranger's proof beside the same identifier recognises nothing.
    let mut guest = Client {
        cookies: client
            .cookies
            .iter()
            .filter(|(name, _)| name.as_str() == DEVICE)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        ..Client::default()
    };
    let url = format!("{ORIGIN}/proven");
    let target = ProofTarget {
        method: "GET",
        url: &url,
    };
    let forged = SoftwareKey::from_seed([8; 32]).sign_request(target, now, "s-4");
    let headers = named(&forged);
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(
        world.get_with(&mut guest, "/proven", None, &headers).await,
        "unproven"
    );
    // And a sign-in beside it is bound to nothing: the stranger's own key,
    // sound as it is, is not the device's.
    let url = format!("{ORIGIN}/sign-in");
    let target = ProofTarget {
        method: "GET",
        url: &url,
    };
    let forged = SoftwareKey::from_seed([8; 32]).sign_request(target, now, "s-5");
    let headers = named(&forged);
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(
        world.get_with(&mut guest, "/sign-in", None, &headers).await,
        "in"
    );
    assert_eq!(world.get(&mut guest, "/bound", None).await, "unbound");
}

/// A service that takes no request proofs ignores them.
#[tokio::test]
async fn a_request_proof_counts_for_nothing_where_none_are_taken() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::App).await;
    let now = world.clock.now().unix_seconds();
    let url = format!("{ORIGIN}/whoami");
    let proof = key().sign_request(
        ProofTarget {
            method: "GET",
            url: &url,
        },
        now,
        "r-1",
    );
    let cookies: &[&str] = &[SESSION, DEVICE];
    assert_eq!(
        world
            .get_with(
                &mut client,
                "/whoami",
                Some(cookies),
                &[("dpop", proof.as_str())]
            )
            .await,
        "guest"
    );
}

/// `GET /whoami` with the client's long-lived cookies and `proof` in the
/// `DPoP` header.
async fn ask(world: &World, client: &Client, cookies: &[&str], proof: &str) -> String {
    world
        .get_with(
            &mut client.clone(),
            "/whoami",
            Some(cookies),
            &[("dpop", proof)],
        )
        .await
}

/// Two tenants on two hosts. An app-shaped proof names its URL and is held
/// to the origin of the host its request was sent to, at the registration
/// path and at the refresh path, in both directions; a host the deployment
/// does not serve has no key paths. A browser-shaped proof names no URL in
/// the constants' revision of the draft, so no claim holds it to a host:
/// what binds it is the challenge, which was minted for one session and
/// device.
#[tokio::test]
async fn each_host_holds_proofs_to_its_own_origin() {
    let world = world_on_hosts();
    let mut acme = world.signed_in_at(Some("acme.example")).await;
    assert_eq!(
        world.register(&mut acme, &key(), KeyProofShape::App).await,
        StatusCode::OK
    );
    assert_eq!(world.get(&mut acme, "/bound", None).await, "bound");
    let (acme_tenant, _) = acme.identifier.as_deref().unwrap().split_once('.').unwrap();
    assert_eq!(acme_tenant, tenant().to_string());

    // A client of the other host signing a proof for the first host's URL.
    let mut beta = world.signed_in_at(Some("beta.example")).await;
    let offer = beta.offer.clone().unwrap();
    let wrong = World::sign(
        &key(),
        KeyProofShape::App,
        &world.config.registration_url(ACME),
        &offer,
        true,
    );
    let refused = world
        .post(
            &mut beta,
            world.config.registration_path(),
            &[("dpop", wrong.as_str())],
        )
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        world.register(&mut beta, &key(), KeyProofShape::App).await,
        StatusCode::OK,
        "the proof made for its own host is accepted"
    );
    let (beta_tenant_text, _) = beta.identifier.as_deref().unwrap().split_once('.').unwrap();
    assert_eq!(
        beta_tenant_text,
        beta_tenant().to_string(),
        "the second tenant"
    );

    // The refresh path, in both directions: a proof over the current
    // challenge made for the other host's URL is refused and consumes
    // nothing; the one made for the client's own host is accepted.
    for (client, other) in [(&mut acme, BETA), (&mut beta, ACME)] {
        let challenge = client.challenge.clone().unwrap();
        let identifier = client.identifier.clone().unwrap();
        let elsewhere = World::sign(
            &key(),
            KeyProofShape::App,
            &world.config.refresh_url(other),
            &challenge,
            false,
        );
        let refused = world
            .post(
                client,
                world.config.refresh_path(),
                &[
                    (draft::SESSION_ID_HEADER, identifier.as_str()),
                    ("dpop", elsewhere.as_str()),
                ],
            )
            .await;
        assert_eq!(
            refused.status(),
            StatusCode::BAD_REQUEST,
            "made for {other}"
        );
        assert_eq!(
            world
                .refresh(client, Some(&key()), KeyProofShape::App, &challenge)
                .await,
            StatusCode::OK
        );
    }

    // The browser shape names no URL: a proof "made for" the other host
    // registers all the same. The offer it answers is what binds it.
    let mut browser = world.signed_in_at(Some("beta.example")).await;
    let offer = browser.offer.clone().unwrap();
    let unbound_by_url = World::sign(
        &key(),
        KeyProofShape::Browser,
        &world.config.registration_url(ACME),
        &offer,
        true,
    );
    let accepted = world
        .post(
            &mut browser,
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, unbound_by_url.as_str())],
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    // And an offer made to another session does not register, whatever the
    // proof says about hosts.
    let mut third = world.signed_in_at(Some("beta.example")).await;
    let borrowed = World::sign(
        &key(),
        KeyProofShape::Browser,
        &world.config.registration_url(BETA),
        &offer,
        true,
    );
    let refused = world
        .post(
            &mut third,
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, borrowed.as_str())],
        )
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    let mut stranger = Client {
        host: Some("evil.example".to_string()),
        ..Client::default()
    };
    for path in [
        world.config.registration_path(),
        world.config.refresh_path(),
    ] {
        let response = world.post(&mut stranger, path, &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

/// The session layer reports what it does with keys to the service's
/// device-key concern: the offer, the registration, and a bound session's
/// request that arrived without the key.
#[tokio::test]
async fn the_layer_reports_to_the_device_key_concern() {
    let recorder = Arc::new(RecordingMetrics::default());
    let world = world_metered(recorder.clone());
    let mut client = world.signed_in().await;
    assert!(recorder.count("key_offered") >= 1);
    assert_eq!(
        world
            .register(&mut client, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::OK
    );
    assert_eq!(recorder.count("key_registered"), 1);
    assert_eq!(recorder.count("bound_session_unproven"), 0);
    let stolen: &[&str] = &[SESSION, DEVICE];
    assert_eq!(
        world
            .get(&mut client.clone(), "/whoami", Some(stolen))
            .await,
        "guest"
    );
    assert_eq!(recorder.count("bound_session_unproven"), 1);
}

// ── A world that signs in through the authentication service ────────────────

const PASSWORD: &str = "Sample2+";

type Authn = AuthnService<MockIdentityStore, MockFactorStore>;

/// A world whose application also takes a password, steps up and
/// impersonates through the authentication service, and whose per-account
/// lockout exempts a device the account has used only when the request
/// proved it by its key.
struct LoginWorld {
    world: World,
    identity: MockIdentityStore,
    service: Authn,
    /// The routes of the application besides the world's own.
    extra: Router,
    /// The sink the session layer tells of the sessions it ends.
    audit: Arc<dyn SessionEndAudit>,
    /// Whether the device resolver reads the tenant from the request's host
    /// (`true`) or, as the stock resolver does by default, from the session
    /// it is handed.
    request_tenant: bool,
}

/// How a [`LoginWorld`] is set up.
struct LoginSetup {
    policy: KeyBindingPolicy,
    /// The session layer records the sessions it ends through the
    /// authentication service, into the identity store's audit rows.
    recorded: bool,
    /// See [`LoginWorld::request_tenant`].
    request_tenant: bool,
}

fn login_world() -> LoginWorld {
    login_world_with(LoginSetup {
        policy: KeyBindingPolicy::Prefer,
        recorded: false,
        request_tenant: true,
    })
}

/// Device keys required, and the sessions the layer ends recorded.
fn required_login_world() -> LoginWorld {
    login_world_with(LoginSetup {
        policy: KeyBindingPolicy::Require,
        recorded: true,
        request_tenant: true,
    })
}

fn login_world_with(setup: LoginSetup) -> LoginWorld {
    let world = world(setup.policy);
    let identity = MockIdentityStore::new()
        .with_clock(world.clock.clone())
        .with_tenant(test_tenant())
        .with_tenant(axess_core::authn::types::Tenant {
            id: tid("t2"),
            identifier: "other".into(),
            ..test_tenant()
        })
        .with_user(test_user("u1", "alice"))
        .with_user(test_user("u2", "bob"))
        .with_user(test_user_in_tenant("u3", "carol", "t2"))
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            duration: Some(std::time::Duration::from_secs(900)),
            ..LockoutPolicy::default()
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_method(&uid("u1"), password_method());
    let service = AuthnService::builder(identity.clone(), factors)
        .with_clock(world.clock.clone())
        .with_key_proven_device_store(world.devices.clone())
        .build();
    let (entry, step_up, admin) = (service.clone(), service.clone(), service.clone());
    let (opening, verifying) = (service.clone(), service.clone());
    let extra = Router::new()
        .route(
            "/password/{password}",
            get(
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let outcome = entry
                        .with_audit_context(AuditContext::default())
                        .login_with_password("alice", "default", &password, &session)
                        .await;
                    format!("{outcome:?}")
                },
            ),
        )
        .route(
            "/step-up/{password}",
            get(
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let service = step_up.with_audit_context(AuditContext::default());
                    if let Err(refused) = service
                        .begin_step_up(&session, vec![FactorKind::Password])
                        .await
                    {
                        return format!("not begun: {refused:?}");
                    }
                    let credential = FactorCredential::Password(ZeroizedString::new(&password));
                    format!("{:?}", service.verify_factor(&credential, &session).await)
                },
            ),
        )
        .route(
            "/begin-step-up",
            get(move |session: AuthSession| async move {
                match opening
                    .with_audit_context(AuditContext::default())
                    .begin_step_up(&session, vec![FactorKind::Password])
                    .await
                {
                    Ok(_) => "begun".to_string(),
                    Err(refused) => format!("not begun: {refused:?}"),
                }
            }),
        )
        .route(
            "/verify/{password}",
            get(
                move |session: AuthSession, Path(password): Path<String>| async move {
                    let credential = FactorCredential::Password(ZeroizedString::new(&password));
                    let service = verifying.with_audit_context(AuditContext::default());
                    format!("{:?}", service.verify_factor(&credential, &session).await)
                },
            ),
        )
        .route(
            "/state",
            get(|session: AuthSession| async move {
                if session.is_authenticated().await {
                    "user"
                } else if session.step_up_pending().await {
                    "step-up"
                } else {
                    "guest"
                }
            }),
        )
        .route(
            "/impersonate",
            get(move |session: AuthSession| async move {
                let begun = admin
                    .with_audit_context(AuditContext::default())
                    .begin_impersonation(
                        &test_user("u1", "alice"),
                        &test_user("u2", "bob"),
                        &session,
                    )
                    .await;
                format!("{begun:?}")
            }),
        )
        .route(
            "/impersonate-across",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let begun = service
                        .with_audit_context(AuditContext::default())
                        .begin_impersonation_across_tenants(
                            &uid("u1"),
                            &test_user_in_tenant("u3", "carol", "t2"),
                            &session,
                        )
                        .await;
                    format!("{begun:?}")
                }
            }),
        )
        .route(
            "/end-impersonation",
            get({
                let service = service.clone();
                move |session: AuthSession| async move {
                    let ended = service
                        .with_audit_context(AuditContext::default())
                        .end_impersonation(&session)
                        .await;
                    format!("{ended:?}")
                }
            }),
        )
        .route(
            "/sign-in-and-impersonate",
            get({
                let (admin, clock) = (service.clone(), world.clock.clone());
                move |session: AuthSession| async move {
                    session
                        .set_authenticated(uid("u1"), tenant(), clock.now())
                        .await;
                    let begun = admin
                        .with_audit_context(AuditContext::default())
                        .begin_impersonation(
                            &test_user("u1", "alice"),
                            &test_user("u2", "bob"),
                            &session,
                        )
                        .await;
                    format!("{begun:?}")
                }
            }),
        )
        .route(
            "/who",
            get(|session: AuthSession| async move {
                let name = |id: Option<UserId>| match id {
                    Some(id) => id.to_string(),
                    None => "nobody".to_string(),
                };
                format!(
                    "{} as {}",
                    name(session.impersonator().await),
                    name(session.user_id().await)
                )
            }),
        );
    let audit = if setup.recorded {
        service.session_end_audit()
    } else {
        Arc::new(axess_core::session::UnrecordedSessionEnds)
    };
    let mut login = LoginWorld {
        world,
        identity,
        service,
        extra,
        audit,
        request_tenant: setup.request_tenant,
    };
    let sessions = login.world.sessions.clone();
    login.serve_on(&sessions);
    login
}

impl LoginWorld {
    /// Serve the application with its session layer on `sessions`.
    fn serve_on<S: SessionStore>(&mut self, sessions: &S) {
        let world = &self.world;
        let resolver = if self.request_tenant {
            resolver(&world.clock, &world.devices)
        } else {
            session_tenant_resolver(&world.clock, &world.devices)
        };
        let app = app_with(
            Wiring {
                extra: self.extra.clone(),
                audit: self.audit.clone(),
                ..Wiring::default()
            },
            &world.clock,
            sessions,
            world.keys.clone(),
            resolver,
        );
        self.world.app = app;
    }

    /// The audit rows of the sessions the layer ended because device keys
    /// are required and the session was still not bound.
    fn key_binding_endings(&self) -> Vec<axess_core::authn::event::AuthEvent> {
        self.identity
            .events()
            .into_iter()
            .filter(|event| {
                event
                    .error
                    .as_ref()
                    .is_some_and(|error| error.as_str() == "key_binding_required")
            })
            .collect()
    }

    /// The devices the store holds for `user`.
    async fn devices_of(&self, user: &str) -> Vec<Device> {
        self.world
            .devices
            .find_for_user(&tenant(), &uid(user), 100)
            .await
            .unwrap()
    }

    /// Three wrong passwords from unknown browsers, each from its own
    /// address so the throttle refuses none before the lock does.
    async fn lock_the_account(&self) {
        for n in 1..=3 {
            let from_elsewhere = self.service.with_audit_context(AuditContext {
                ip_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    203, 0, 113, n,
                ))),
                ip_source: axess_core::client_ip::Source::Peer,
                ..AuditContext::default()
            });
            let stranger = test_session();
            from_elsewhere
                .begin_login("alice", "default", &stranger)
                .await
                .unwrap();
            let wrong = FactorCredential::Password(ZeroizedString::new("wrong"));
            from_elsewhere
                .verify_factor(&wrong, &stranger)
                .await
                .unwrap();
        }
        assert_eq!(
            self.identity.failed_attempts_for("u1"),
            3,
            "the account is locked"
        );
    }
}

/// A step-up on a bound session completes on a request that proved the key
/// and leaves the binding as it was. Without the proof the request is a
/// guest's and steps nothing up.
#[tokio::test]
async fn a_step_up_leaves_a_bound_session_bound() {
    let login = login_world();
    let world = &login.world;
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let bound_to = world.get(&mut client, "/bound-device", None).await;
    let bare: &[&str] = &[SESSION, DEVICE];
    let step_up = format!("/step-up/{PASSWORD}");

    let stolen = world.get(&mut client.clone(), &step_up, Some(bare)).await;
    assert!(stolen.starts_with("not begun"), "{stolen}");

    let stepped = world.get(&mut client, &step_up, None).await;
    assert!(stepped.contains("Authenticated"), "{stepped}");
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(
        world.get(&mut client, "/bound-device", None).await,
        bound_to
    );
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "true");
    assert_eq!(
        world.get(&mut client.clone(), "/whoami", Some(bare)).await,
        "guest"
    );
}

/// An impersonation begun on a bound session leaves it bound to the
/// administrator's browser: the session becomes the target's, the binding
/// still names the administrator's device, and the session is still served
/// only to a request that proves that device's key.
#[tokio::test]
async fn an_impersonation_leaves_a_bound_session_bound_to_the_admins_browser() {
    let login = login_world();
    let world = &login.world;
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let admins_device = device_of(&client).to_string();
    assert_eq!(
        world.get(&mut client, "/bound-device", None).await,
        admins_device
    );

    assert_eq!(world.get(&mut client, "/impersonate", None).await, "Ok(())");
    assert_eq!(
        world.get(&mut client, "/who", None).await,
        format!("{} as {}", uid("u1"), uid("u2"))
    );
    assert_eq!(
        world.get(&mut client, "/bound-device", None).await,
        admins_device
    );
    let bare: &[&str] = &[SESSION, DEVICE];
    assert_eq!(
        world.get(&mut client.clone(), "/whoami", Some(bare)).await,
        "guest"
    );
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    // The device is still the administrator's, proven by its key, and the
    // target has gained none.
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");
    assert_eq!(device_of(&client).to_string(), admins_device);
    assert!(login.devices_of("u2").await.is_empty());
    assert_eq!(login.devices_of("u1").await.len(), 1);
}

/// A key registered under impersonation is the administrator's. On a
/// browser nobody has signed in on, the impersonated session's first
/// request is given a device and offered a key: the device is created as
/// the administrator's own, the key goes onto it, the session is bound to
/// it, and the target holds no device and no key.
#[tokio::test]
async fn a_key_registered_under_impersonation_is_the_administrators() {
    let login = login_world();
    let world = &login.world;
    let mut client = Client::default();
    assert_eq!(
        world
            .get(&mut client, "/sign-in-and-impersonate", None)
            .await,
        "Ok(())"
    );
    assert_eq!(
        world.get(&mut client, "/who", None).await,
        format!("{} as {}", uid("u1"), uid("u2"))
    );
    assert!(
        client.offer.is_some(),
        "the keyless device is offered a key"
    );
    let device = device_of(&client);

    assert_eq!(
        world
            .register(&mut client, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::OK
    );
    assert_eq!(
        world.get(&mut client, "/bound-device", None).await,
        device.to_string()
    );
    let admins = login.devices_of("u1").await;
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].id, device);
    assert!(
        admins[0]
            .bindings
            .iter()
            .any(|binding| matches!(binding, DeviceBinding::Key { .. })),
        "the administrator's device holds the key"
    );
    assert!(login.devices_of("u2").await.is_empty());
}

/// An impersonation begun by the request that signs the administrator in,
/// on a device of the administrator's that has a key, is bound to that
/// device at once: the owner the binding asks for is the administrator.
/// The target gains no device.
#[tokio::test]
async fn an_impersonation_on_the_administrators_keyed_device_is_bound_to_it() {
    let login = login_world();
    let world = &login.world;
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let admins_device = device_of(&client).to_string();
    assert_eq!(world.get(&mut client, "/sign-out", None).await, "out");
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");

    assert_eq!(
        world
            .get(&mut client, "/sign-in-and-impersonate", None)
            .await,
        "Ok(())"
    );
    assert_eq!(
        world.get(&mut client, "/who", None).await,
        format!("{} as {}", uid("u1"), uid("u2"))
    );
    assert_eq!(
        world.get(&mut client, "/bound-device", None).await,
        admins_device
    );
    assert_eq!(device_of(&client).to_string(), admins_device);
    assert!(login.devices_of("u2").await.is_empty());
    assert_eq!(login.devices_of("u1").await.len(), 1);
}

/// The per-account lockout through a login. With device keys required for
/// the exemption, the account's own keyed device passes a locked account
/// only on a request that proved the key: the session and device cookies
/// without the proof are locked out, the right password included.
#[tokio::test]
async fn the_lockout_exempts_a_keyed_device_only_on_a_request_that_proved_its_key() {
    let login = login_world();
    let world = &login.world;
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    world
        .devices
        .set_trust_level(
            &tenant(),
            &device_of(&client),
            DeviceTrustLevel::Seen,
            world.clock.now(),
        )
        .await
        .unwrap();
    login.lock_the_account().await;
    let entry = format!("/password/{PASSWORD}");

    let bare: &[&str] = &[SESSION, DEVICE];
    let refused = world.get(&mut client.clone(), &entry, Some(bare)).await;
    assert!(!refused.contains("Authenticated"), "{refused}");
    assert_eq!(login.identity.failed_attempts_for("u1"), 3, "still locked");

    let passed = world.get(&mut client, &entry, None).await;
    assert_eq!(passed, "Ok(Authenticated)");
    assert_eq!(login.identity.failed_attempts_for("u1"), 0);
}

/// A refresh token of a keyed device presented without its key revokes the
/// token's family, and through a cascading token store the revocation
/// reaches the device: its row is revoked, the refresh path answers that
/// the session has ended, and the bound session stops being served when
/// the proof it still holds runs out.
#[tokio::test]
async fn a_family_revoked_for_a_missing_key_reaches_the_device() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::App).await;
    let device = device_of(&client);
    let now = world.clock.now();
    let (config, rng) = (RefreshTokenConfig::default(), MockRng::new(8));
    let tokens = CascadingRefreshStore::new(
        MemoryRefreshTokenStore::new().with_clock(Arc::new(world.clock.clone())),
        world.devices.clone(),
        Arc::new(world.clock.clone()),
    );
    let (user, tenant) = (uid("u1"), tenant());
    let request = IssueRequest {
        user_id: &user,
        tenant_id: &tenant,
        device_info: None,
        family_id: None,
        device_id: Some(device),
    };
    let (token, record) = issue_refresh_token(request, &config, &tokens, &rng, now)
        .await
        .unwrap();
    // The device names the family, as an application records it when it
    // issues a token to a device.
    let row = world
        .devices
        .load_fresh(&tenant, &device)
        .await
        .unwrap()
        .unwrap();
    let mut bindings = row.bindings.clone();
    bindings.push(DeviceBinding::Refresh {
        family_id: record.family_id.expect("a family").to_string(),
        issued_at: now,
        last_used_at: now,
    });
    assert_eq!(
        world
            .devices
            .replace_bindings(&tenant, &device, &row.bindings, &bindings, now)
            .await
            .unwrap(),
        BindingsUpdate::Written
    );

    let stolen = Refresh::new(&token, &tenant, |_| async { true })
        .device_store(&world.devices)
        .device_key(&world.keys, None)
        .run(&tokens, &config, &rng, now)
        .await;
    assert!(matches!(stolen, Err(RefreshError::KeyProofInvalid)));
    let row = world
        .devices
        .load_fresh(&tenant, &device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.trust_level,
        DeviceTrustLevel::Revoked,
        "the cascade reached the device"
    );

    let identifier = client.identifier.clone().unwrap();
    let (status, body, _) =
        refresh_answer(&world, &[(draft::SESSION_ID_HEADER, identifier.as_str())]).await;
    assert_eq!(
        (status.as_u16(), body.as_str()),
        (draft::ENDED_STATUS, draft::ENDED_BODY)
    );
    world.clock.advance_secs(world.proof_lifetime());
    assert_eq!(world.get(&mut client, "/whoami", None).await, "guest");
}

/// A rotation of the session signing key reaches the proof cookie through
/// the layer. What a client holds from before the rotation is accepted by a
/// layer that names the old key as its previous one; a refresh there mints
/// the proof under the new key; and a layer that knows only the new key
/// accepts what was minted since and not a proof from before.
#[tokio::test]
async fn a_signing_key_rotation_carries_the_proof_cookie_through_the_layer() {
    let mut world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let proof_name = client
        .cookies
        .keys()
        .find(|name| name.starts_with(PROOF))
        .cloned()
        .expect("a proof cookie");
    let old_proof = client.cookies[&proof_name].clone();
    let rebuilt = |world: &World, signing_key: u8, previous_signing_key: Option<u8>| {
        app_with(
            Wiring {
                signing_key,
                previous_signing_key,
                ..Wiring::default()
            },
            &world.clock,
            &world.sessions,
            world.keys.clone(),
            resolver(&world.clock, &world.devices),
        )
    };

    let rotating = rebuilt(&world, 43, Some(42));
    world.app = rotating;
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    let challenge = client.challenge.clone().unwrap();
    assert_eq!(
        world
            .refresh(
                &mut client,
                Some(&key()),
                KeyProofShape::Browser,
                &challenge
            )
            .await,
        StatusCode::OK
    );
    assert_ne!(client.cookies[&proof_name], old_proof);

    let rotated = rebuilt(&world, 43, None);
    world.app = rotated;
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    let mut with_old_proof = client.clone();
    with_old_proof.cookies.insert(proof_name, old_proof);
    assert_eq!(
        world.get(&mut with_old_proof, "/whoami", None).await,
        "guest"
    );
}

// ── One test for each invariant of the design ───────────────────────────────

/// Whether an answer mints a proof cookie (and does not merely expire one).
fn mints_a_proof(response: &axum::response::Response) -> bool {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|cookie| cookie.starts_with(PROOF) && !cookie.contains("Max-Age=0"))
}

/// Invariant 1: the private key never reaches the server, and nothing the
/// server stores lets anyone mint a proof.
#[tokio::test]
async fn invariant_1_the_server_holds_no_private_key_and_its_rows_mint_no_proof() {
    let world = world(KeyBindingPolicy::Prefer);
    // A registration whose key carries its private half is refused, and
    // nothing of it is stored.
    let mut leaking = world.signed_in().await;
    let offer = leaking.offer.clone().unwrap();
    let url = world.config.registration_url(ORIGIN);
    let target = ProofTarget {
        method: "POST",
        url: &url,
    };
    let browser = axess_factors::key_proof::KeyProofShape::Browser;
    let (mut header, claims) = key().proof_parts(browser, target, &offer, true);
    header[draft::PROOF_KEY_MEMBER]["d"] = serde_json::json!("AAAA");
    let jws = key().sign_parts(&header, &claims);
    let refused = world
        .post(
            &mut leaking,
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, jws.as_str())],
        )
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        world
            .keys
            .key_thumbprint(&tenant(), &device_of(&leaking))
            .await
            .unwrap(),
        None
    );

    // What is stored for a registered key is its public half and a
    // challenge. Whoever reads the row whole and signs its current
    // challenge with a key of their own is refused.
    let client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let row = world
        .devices
        .load_fresh(&tenant(), &device_of(&client))
        .await
        .unwrap()
        .unwrap();
    let stored = serde_json::to_string(&row).unwrap();
    assert!(!stored.contains("\"d\""), "{stored}");
    let challenge = row
        .bindings
        .iter()
        .find_map(|binding| match binding {
            DeviceBinding::Key { challenge, .. } => Some(challenge.to_text()),
            _ => None,
        })
        .expect("the device's key");
    let reader = SoftwareKey::from_seed([9; 32]);
    assert_eq!(
        world
            .refresh(
                &mut client.clone(),
                Some(&reader),
                KeyProofShape::Browser,
                &challenge
            )
            .await,
        StatusCode::BAD_REQUEST
    );
}

/// Invariant 2: a proof cookie is minted only in the answer to a request
/// that carried a valid signature by the device's registered key over its
/// current challenge, or, at registration, by the key being registered
/// over the offer.
#[tokio::test]
async fn invariant_2_a_proof_cookie_is_minted_only_for_a_valid_signature() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.signed_in().await;
    let url = world.config.registration_url(ORIGIN);
    let browser = KeyProofShape::Browser;

    let page = Request::get("/whoami")
        .header(header::USER_AGENT, UA)
        .header(header::COOKIE, client.cookie_header(None))
        .body(Body::empty())
        .unwrap();
    assert!(!mints_a_proof(&world.send(page).await), "a page");
    let over_no_offer = World::sign(&key(), browser, &url, "v1.1.AAAA", true);
    let refused = world
        .post(
            &mut client.clone(),
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, over_no_offer.as_str())],
        )
        .await;
    assert!(!mints_a_proof(&refused), "a refused registration");
    let offer = client.offer.clone().unwrap();
    let sound = World::sign(&key(), browser, &url, &offer, true);
    let registered = world
        .post(
            &mut client,
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, sound.as_str())],
        )
        .await;
    assert!(mints_a_proof(&registered), "the registration");

    let identifier = client.identifier.clone().unwrap();
    let challenge = client.challenge.clone().unwrap();
    let refresh_url = world.config.refresh_url(ORIGIN);
    let stranger = SoftwareKey::from_seed([8; 32]);
    let attempts = [
        None,
        Some(World::sign(
            &key(),
            browser,
            &refresh_url,
            "a-stale-one",
            false,
        )),
        Some(World::sign(
            &stranger,
            browser,
            &refresh_url,
            &challenge,
            false,
        )),
    ];
    for attempt in attempts {
        let mut headers = vec![(draft::SESSION_ID_HEADER, identifier.as_str())];
        if let Some(jws) = &attempt {
            headers.push((draft::RESPONSE_HEADER, jws.as_str()));
        }
        let answer = world
            .post(&mut client.clone(), world.config.refresh_path(), &headers)
            .await;
        assert!(!mints_a_proof(&answer), "{attempt:?}");
    }
    let sound = World::sign(&key(), browser, &refresh_url, &challenge, false);
    let answer = world
        .post(
            &mut client,
            world.config.refresh_path(),
            &[
                (draft::SESSION_ID_HEADER, identifier.as_str()),
                (draft::RESPONSE_HEADER, sound.as_str()),
            ],
        )
        .await;
    assert!(mints_a_proof(&answer), "the key over the current challenge");
}

/// Invariant 3: a challenge is accepted once.
#[tokio::test]
async fn invariant_3_a_challenge_is_accepted_once() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let first = client.challenge.clone().unwrap();
    let browser = KeyProofShape::Browser;
    assert_eq!(
        world
            .refresh(&mut client, Some(&key()), browser, &first)
            .await,
        StatusCode::OK
    );
    let next = client.challenge.clone().unwrap();
    assert_ne!(next, first);
    // The same proof again: the challenge's status, and the one to sign now.
    let again = world
        .refresh(&mut client, Some(&key()), browser, &first)
        .await;
    assert_eq!(again.as_u16(), draft::CHALLENGE_STATUS);
    assert_eq!(client.challenge.as_deref(), Some(next.as_str()));
}

/// Invariant 4: under a layer that enforces keys, a device that has a key
/// is never proven by its token alone.
#[tokio::test]
async fn invariant_4_a_keyed_device_is_never_proven_by_its_token_alone() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");
    assert_eq!(world.get(&mut client, "/sign-out", None).await, "out");
    // A guest with the token and the proof is recognised, by the key; with
    // the token alone, by nothing.
    assert_eq!(world.get(&mut client.clone(), "/proven", None).await, "key");
    let token_only: &[&str] = &[DEVICE];
    assert_eq!(
        world
            .get(&mut client.clone(), "/proven", Some(token_only))
            .await,
        "unproven"
    );
    // A sign-in that holds the token alone is given another device.
    let mut copy = Client {
        cookies: client
            .cookies
            .iter()
            .filter(|(name, _)| name.as_str() == DEVICE)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        ..Client::default()
    };
    assert_eq!(world.get(&mut copy, "/sign-in", None).await, "in");
    assert_eq!(world.get(&mut copy, "/proven", None).await, "token");
    assert_ne!(device_of(&copy), device_of(&client));
}

/// Invariant 5: a layer that enforces keys serves a bound session only to a
/// request that proves the session's device and key, and a bound session
/// is never unbound: it ends. (A layer that cannot check a key and the
/// policy `Off` have tests of their own above.)
#[tokio::test]
async fn invariant_5_a_bound_session_is_served_only_with_its_key_and_never_unbound() {
    let world = world(KeyBindingPolicy::Prefer);
    let client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let bare: &[&str] = &[SESSION, DEVICE];
    let serving = &world;
    let whoami = |client: &Client| {
        let mut client = client.clone();
        async move { serving.get(&mut client, "/whoami", None).await }
    };
    assert_eq!(whoami(&client).await, "user");
    assert_eq!(
        world.get(&mut client.clone(), "/whoami", Some(bare)).await,
        "guest"
    );

    // Another device's proof, sound as it is, is no proof of this one.
    let other = world
        .bound_client(&SoftwareKey::from_seed([9; 32]), KeyProofShape::Browser)
        .await;
    let mut crossed = client.clone();
    crossed.cookies.retain(|name, _| !name.starts_with(PROOF));
    crossed.cookies.extend(
        other
            .cookies
            .iter()
            .filter(|(name, _)| name.starts_with(PROOF))
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    assert_eq!(whoami(&crossed).await, "guest");

    // The key is forgotten and the last proof runs out: the session is not
    // served as an unbound one, with every cookie the browser holds.
    assert_eq!(whoami(&client).await, "user");
    world
        .keys
        .forget_device_key(&tenant(), &device_of(&client), world.clock.now())
        .await
        .unwrap();
    world.clock.advance_secs(world.proof_lifetime());
    assert_eq!(whoami(&client).await, "guest");
}

/// Invariant 6: a key is registered only against an offer, and an offer is
/// made only to a session whose last factor verification is inside the
/// registration window, for the device that request proved by its token,
/// on one response per factor verification.
#[tokio::test]
async fn invariant_6_a_key_is_registered_only_against_its_offer() {
    let world = world(KeyBindingPolicy::Prefer);
    let browser = KeyProofShape::Browser;
    let mut client = world.signed_in().await;
    let mut late = world.signed_in().await;
    let offer = client.offer.clone().unwrap();

    // A challenge of the client's own making is no offer.
    let mut inventing = client.clone();
    inventing.offer = Some("a-challenge-of-my-own".to_string());
    assert_eq!(
        world.register(&mut inventing, &key(), browser).await,
        StatusCode::FORBIDDEN
    );
    // The offer made to this session registers nothing for another session,
    // nor for a request that holds no session.
    let mut other = world.signed_in().await;
    other.offer = Some(offer.clone());
    assert_eq!(
        world.register(&mut other, &key(), browser).await,
        StatusCode::FORBIDDEN
    );
    let mut nobody = Client {
        offer: Some(offer.clone()),
        ..Client::default()
    };
    assert_eq!(
        world.register(&mut nobody, &key(), browser).await,
        StatusCode::FORBIDDEN
    );
    // One response carried it; the next carries none.
    client.offer = None;
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(client.offer, None);
    // The session it was made to registers with it, inside the window.
    client.offer = Some(offer);
    assert_eq!(
        world.register(&mut client, &key(), browser).await,
        StatusCode::OK
    );
    // Past the window an offer is dead.
    let window = world.config.registration_window().as_secs() as i64;
    world.clock.advance_secs(window + 1);
    assert_eq!(
        world.register(&mut late, &key(), browser).await,
        StatusCode::FORBIDDEN
    );
}

/// Invariant 7: no decision about an offer, a challenge or a proof cookie
/// reads the client's clock. A request proof is the one exception: its
/// `iat` is the client's clock, held to the server's.
#[tokio::test]
async fn invariant_7_only_a_request_proof_reads_the_clients_clock() {
    let world = world_with(KeyBindingPolicy::Prefer, true);
    let mut client = world.signed_in().await;
    // A registration and a refresh whose proofs carry time claims from the
    // first second of 1970.
    let dated = |challenge: &str, url: &str, with_key: bool| {
        let target = ProofTarget {
            method: "POST",
            url,
        };
        let browser = axess_factors::key_proof::KeyProofShape::Browser;
        let (header, mut claims) = key().proof_parts(browser, target, challenge, with_key);
        for claim in ["iat", "nbf", "exp"] {
            claims[claim] = serde_json::json!(1);
        }
        key().sign_parts(&header, &claims)
    };
    let offer = client.offer.clone().unwrap();
    let jws = dated(&offer, &world.config.registration_url(ORIGIN), true);
    let registered = world
        .post(
            &mut client,
            world.config.registration_path(),
            &[(draft::RESPONSE_HEADER, jws.as_str())],
        )
        .await;
    assert_eq!(registered.status(), StatusCode::OK);
    let identifier = client.identifier.clone().unwrap();
    let challenge = client.challenge.clone().unwrap();
    let jws = dated(&challenge, &world.config.refresh_url(ORIGIN), false);
    let refreshed = world
        .post(
            &mut client,
            world.config.refresh_path(),
            &[
                (draft::SESSION_ID_HEADER, identifier.as_str()),
                (draft::RESPONSE_HEADER, jws.as_str()),
            ],
        )
        .await;
    assert_eq!(refreshed.status(), StatusCode::OK);

    // A request proof dated a day off the server's clock is refused; one
    // dated now is taken.
    let url = format!("{ORIGIN}/whoami");
    let target = ProofTarget {
        method: "GET",
        url: &url,
    };
    let now = world.clock.now().unix_seconds();
    let cookies: &[&str] = &[SESSION, DEVICE];
    let a_day_off = key().sign_request(target, now - 86_400, "t-1");
    assert_eq!(ask(&world, &client, cookies, &a_day_off).await, "guest");
    let on_time = key().sign_request(target, now, "t-2");
    assert_eq!(ask(&world, &client, cookies, &on_time).await, "user");
}

/// Invariant 8: every time comparison reads the injected clock, and every
/// random value comes from the injected generator. Two worlds built alike
/// hand out the same offer, challenges and cookies byte for byte, and a
/// proof ends when the injected clock says so.
#[tokio::test]
async fn invariant_8_time_and_randomness_are_the_injected_ones() {
    async fn script(world: &World) -> Client {
        let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
        let challenge = client.challenge.clone().unwrap();
        assert_eq!(
            world
                .refresh(
                    &mut client,
                    Some(&key()),
                    KeyProofShape::Browser,
                    &challenge
                )
                .await,
            StatusCode::OK
        );
        client
    }
    let clock = common::test_clock();
    let (first, second) = (
        world_on(clock.clone(), KeyBindingPolicy::Prefer, false),
        world_on(clock.clone(), KeyBindingPolicy::Prefer, false),
    );
    let (a, b) = (script(&first).await, script(&second).await);
    assert_eq!(a.cookies, b.cookies);
    assert_eq!(a.offer, b.offer);
    assert_eq!(a.challenge, b.challenge);
    assert_eq!(a.identifier, b.identifier);

    assert_eq!(first.get(&mut a.clone(), "/whoami", None).await, "user");
    clock.advance_secs(first.proof_lifetime());
    assert_eq!(first.get(&mut a.clone(), "/whoami", None).await, "guest");
}

// ── The registration window, the ending it makes, and the bound row ─────────

/// The barrier the next loads of a [`HeldStore`] wait at, and how many
/// loads are still to wait there.
type HeldLoads = Arc<std::sync::Mutex<Option<(Arc<tokio::sync::Barrier>, usize)>>>;

/// The session store of a test over the in-memory one. It can hold the next
/// loads at a barrier, so that requests carrying the same cookie have all
/// read the row before any of them acts on it, and it can refuse writes, so
/// that a write the layer makes does not land.
#[derive(Clone)]
struct HeldStore {
    inner: MemorySessionStore,
    held: HeldLoads,
    refusing: Arc<std::sync::atomic::AtomicBool>,
}

/// A write the [`HeldStore`] refused.
#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the session store refused the write")
    }
}

impl std::error::Error for Refused {}

impl HeldStore {
    fn over(inner: &MemorySessionStore) -> Self {
        Self {
            inner: inner.clone(),
            held: Arc::default(),
            refusing: Arc::default(),
        }
    }

    /// The next `loads` loads each wait until all of them have read.
    fn hold_loads(&self, loads: usize) {
        *self.held.lock().unwrap() = Some((Arc::new(tokio::sync::Barrier::new(loads)), loads));
    }

    fn refuse_writes(&self, refusing: bool) {
        self.refusing
            .store(refusing, std::sync::atomic::Ordering::SeqCst);
    }

    fn write(&self) -> Result<(), Refused> {
        if self.refusing.load(std::sync::atomic::Ordering::SeqCst) {
            Err(Refused)
        } else {
            Ok(())
        }
    }
}

impl SessionStore for HeldStore {
    type Error = Refused;

    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Refused> {
        let barrier = {
            let mut held = self.held.lock().unwrap();
            let barrier = held.as_ref().map(|(barrier, _)| barrier.clone());
            if let Some((_, left)) = held.as_mut() {
                *left -= 1;
                if *left == 0 {
                    *held = None;
                }
            }
            barrier
        };
        let row = self.inner.load(key).await.unwrap_or(None);
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        Ok(row)
    }

    async fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: std::time::Duration,
    ) -> Result<(), Refused> {
        self.write()?;
        self.inner
            .save(key, data, ttl)
            .await
            .map_err(|never| match never {})
    }

    async fn delete(&self, key: &SessionKey) -> Result<(), Refused> {
        self.inner.delete(key).await.map_err(|never| match never {})
    }

    async fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: std::time::Duration,
    ) -> Result<bool, Refused> {
        self.write()?;
        self.inner
            .update(key, data, ttl)
            .await
            .map_err(|never| match never {})
    }

    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: std::time::Duration,
    ) -> Result<ConditionalUpdate, Refused> {
        self.write()?;
        self.inner
            .update_if_revision(key, expected_revision, data, ttl)
            .await
            .map_err(|never| match never {})
    }

    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: std::time::Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Refused> {
        self.write()?;
        self.inner
            .cycle(old, new, data, ttl, require_old)
            .await
            .map_err(|never| match never {})
    }

    async fn cycle_if_revision(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: std::time::Duration,
        require_old: bool,
        expected_revision: u64,
    ) -> Result<CycleOutcome, Refused> {
        self.write()?;
        self.inner
            .cycle_if_revision(old, new, data, ttl, require_old, expected_revision)
            .await
            .map_err(|never| match never {})
    }

    async fn prune_expired(&self) -> Result<u64, Refused> {
        self.inner
            .prune_expired()
            .await
            .map_err(|never| match never {})
    }

    async fn find_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Refused> {
        self.inner
            .find_sessions_for_user(user_id, limit)
            .await
            .map_err(|never| match never {})
    }
}

/// Another person signs in on a bound session in one request, a login
/// begun and completed: from the moment the login begins the session is not
/// key-bound, its row is written without the first person's binding, and a
/// later request that proves the first person's key is not key-bound
/// either.
#[tokio::test]
async fn a_second_person_signing_in_on_a_bound_session_is_not_key_bound() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    assert_eq!(
        world
            .get(&mut client, "/sign-in-as-other-asking", None)
            .await,
        "true false false",
        "bound before the login, not from its start on"
    );
    let rows = stored_rows(&world, "u2").await;
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].1.key_binding.is_none(),
        "the row is written without the first person's binding"
    );
    assert!(client.proof_cookie().is_some(), "the first person's proof");
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "false");
}

/// An impersonation keeps the administrator's binding, within the
/// administrator's tenant and across tenants: the browser, its device and
/// its key are still the administrator's, so a request that proves the key
/// is key-bound, and one that does not is a guest's. The end of the
/// impersonation leaves no binding.
#[tokio::test]
async fn an_impersonation_keeps_the_administrators_binding_within_and_across_tenants() {
    for (path, target) in [("/impersonate", "u2"), ("/impersonate-across", "u3")] {
        let login = login_world();
        let world = &login.world;
        let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
        assert_eq!(world.get(&mut client, path, None).await, "Ok(())", "{path}");
        assert_eq!(
            world.get(&mut client, "/who", None).await,
            format!("{} as {}", uid("u1"), uid(target))
        );
        assert_eq!(
            world.get(&mut client, "/key-bound", None).await,
            "true",
            "{path}"
        );
        let bare: &[&str] = &[SESSION, DEVICE];
        assert_eq!(
            world.get(&mut client.clone(), "/whoami", Some(bare)).await,
            "guest",
            "{path}"
        );
        let ended = world.get(&mut client, "/end-impersonation", None).await;
        assert!(ended.starts_with("Ok"), "{path}: {ended}");
        assert_eq!(
            world.get(&mut client, "/bound", None).await,
            "unbound",
            "{path}"
        );
        assert_eq!(
            world.get(&mut client, "/key-bound", None).await,
            "false",
            "{path}"
        );
    }
}

/// Under `Require`, a session another person signed in on, whose row still
/// holds the binding made for the first person (planted here; the layer
/// writes no such row), is an unbound session of the second person: it is
/// served to the end of the registration window counted from the second
/// person's login, past the end of the first person's, and ended at the
/// next request, the first person's proof notwithstanding.
#[tokio::test]
async fn require_holds_a_second_person_to_their_own_window() {
    let world = world(KeyBindingPolicy::Require);
    let window = window_secs(&world);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let first = stored_rows(&world, "u1").await[0]
        .1
        .key_binding
        .expect("the first person's binding");
    world.clock.advance_secs(window / 2);
    assert_eq!(
        world.get(&mut client, "/sign-in-as-other", None).await,
        "in"
    );
    // The first person's binding, back on the second person's row.
    let plant = || async {
        let (row_key, mut row) = stored_rows(&world, "u2").await.remove(0);
        row.key_binding = Some(first);
        assert!(
            world
                .sessions
                .update(&row_key, &row, std::time::Duration::from_secs(3600))
                .await
                .unwrap()
        );
    };

    plant().await;
    world.clock.advance_secs(window);
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    plant().await;
    world.clock.advance_secs(1);
    assert_eq!(world.get(&mut client, "/whoami", None).await, "guest");
    assert!(
        stored_rows(&world, "u2").await.is_empty(),
        "the ended row is deleted"
    );
}

/// The person a binding was made for begins a new login on the bound
/// session, after the first login's window: while the login is open nobody
/// is signed in, the session is not bound and its row is written without
/// the binding; the request that completes the login, proving the key,
/// binds the session again inside the new login's window.
#[tokio::test]
async fn a_new_login_of_the_owner_unbinds_until_it_completes_and_binds_again() {
    let world = world(KeyBindingPolicy::Prefer);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    world.clock.advance_secs(window_secs(&world) + 10);
    assert_eq!(
        world.get(&mut client, "/log-in-again-asking", None).await,
        "true false"
    );
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "false");
    assert_eq!(
        world.get(&mut client, "/complete-login", None).await,
        "done"
    );
    assert_eq!(world.get(&mut client, "/whoami", None).await, "user");
    assert_eq!(world.get(&mut client, "/bound", None).await, "bound");
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "true");
}

/// The rows of the user's sessions the store holds.
async fn stored_rows(world: &World, user: &str) -> Vec<(SessionKey, SessionData)> {
    world
        .sessions
        .find_sessions_for_user(&uid(user), 10)
        .await
        .unwrap()
}

fn window_secs(world: &World) -> i64 {
    world.config.registration_window().as_secs() as i64
}

/// `Require` holds a session in a step-up to the window as it holds an
/// authenticated one: served to the window's end, then ended at the next
/// request, its row deleted and one audit row written through the layer's
/// sink, `SessionInvalidated` with the reason `key_binding_required`.
#[tokio::test]
async fn require_ends_an_unbound_session_in_a_step_up_after_the_window() {
    let login = required_login_world();
    let world = &login.world;
    let window = window_secs(world);
    let mut client = world.signed_in().await;
    world.clock.advance_secs(window - 30);
    assert_eq!(
        world.get(&mut client, "/begin-step-up", None).await,
        "begun"
    );

    world.clock.advance_secs(30);
    assert_eq!(
        world.get(&mut client, "/state", None).await,
        "step-up",
        "served to the window's end, not ended early"
    );
    world.clock.advance_secs(1);
    assert_eq!(world.get(&mut client, "/state", None).await, "guest");
    assert!(
        stored_rows(world, "u1").await.is_empty(),
        "the row is deleted"
    );
    let endings = login.key_binding_endings();
    assert_eq!(endings.len(), 1, "{endings:?}");
    let ending = &endings[0];
    assert_eq!(
        ending.event_type,
        axess_core::authn::event::AuthEventType::SessionInvalidated
    );
    assert_eq!(ending.user_id, Some(uid("u1")));
    assert_eq!(ending.tenant_id, Some(tenant()));
    assert_eq!(ending.actor_id, None);
    assert_eq!(
        axess_core::session::SessionEndReason::KeyBindingRequired.as_str(),
        "key_binding_required"
    );
    assert!(!axess_core::session::SessionEndReason::KeyBindingRequired.is_expiry());
}

/// The window runs from the login. A step-up finished near its end does not
/// restart it: the session ends one second past the login's window, not
/// the step-up's.
#[tokio::test]
async fn a_finished_step_up_does_not_restart_the_window() {
    let login = required_login_world();
    let world = &login.world;
    let window = window_secs(world);
    let mut client = world.signed_in().await;
    world.clock.advance_secs(window - 10);
    let stepped = world
        .get(&mut client, &format!("/step-up/{PASSWORD}"), None)
        .await;
    assert!(stepped.contains("Authenticated"), "{stepped}");

    world.clock.advance_secs(10);
    assert_eq!(world.get(&mut client, "/state", None).await, "user");
    world.clock.advance_secs(1);
    assert_eq!(world.get(&mut client, "/state", None).await, "guest");
    assert_eq!(login.key_binding_endings().len(), 1);
}

/// A session bound to its key is held to nothing more: a step-up open past
/// the window is served on the requests that prove the key, finishes, and
/// leaves the binding as it was.
#[tokio::test]
async fn a_bound_session_in_a_step_up_outlives_the_window() {
    let login = required_login_world();
    let world = &login.world;
    let window = window_secs(world);
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    assert_eq!(
        world.get(&mut client, "/begin-step-up", None).await,
        "begun"
    );
    world.clock.advance_secs(window + 60);
    assert_eq!(world.get(&mut client, "/state", None).await, "step-up");
    let verified = world
        .get(&mut client, &format!("/verify/{PASSWORD}"), None)
        .await;
    assert!(verified.contains("Authenticated"), "{verified}");
    assert_eq!(world.get(&mut client, "/key-bound", None).await, "true");
    assert!(login.key_binding_endings().is_empty());
}

/// Two requests carrying the cookie of an unbound session past its window,
/// both having read the row before either acts on it: one ending, one
/// audit row, and both requests run as guests.
#[tokio::test]
async fn two_concurrent_requests_end_an_unbound_session_once() {
    let mut login = required_login_world();
    let store = HeldStore::over(&login.world.sessions);
    login.serve_on(&store);
    let world = &login.world;
    let mut client = world.signed_in().await;
    world.clock.advance_secs(window_secs(world) + 1);

    store.hold_loads(2);
    let (mut first, mut second) = (client.clone(), client.clone());
    let (a, b) = tokio::join!(
        world.get(&mut first, "/state", None),
        world.get(&mut second, "/state", None),
    );
    assert_eq!((a.as_str(), b.as_str()), ("guest", "guest"));
    assert_eq!(login.key_binding_endings().len(), 1);
    assert!(stored_rows(world, "u1").await.is_empty());
    assert_eq!(world.get(&mut client, "/state", None).await, "guest");
    assert_eq!(login.key_binding_endings().len(), 1);
}

/// The ending of an impersonation names the administrator as its actor:
/// it is not recorded as the end of the user's own session.
#[tokio::test]
async fn the_ending_of_an_impersonation_names_the_administrator() {
    let login = required_login_world();
    let world = &login.world;
    let mut client = Client::default();
    assert_eq!(
        world
            .get(&mut client, "/sign-in-and-impersonate", None)
            .await,
        "Ok(())"
    );
    world.clock.advance_secs(window_secs(world) + 1);
    assert_eq!(world.get(&mut client, "/state", None).await, "guest");
    let endings = login.key_binding_endings();
    assert_eq!(endings.len(), 1, "{endings:?}");
    assert_eq!(endings[0].user_id, Some(uid("u2")));
    assert_eq!(endings[0].actor_id, Some(uid("u1")));
    assert!(stored_rows(world, "u2").await.is_empty());
}

/// A sink that cannot write the row leaves the session stored, its claim
/// taken back, and the request a guest's; the next request that finds the
/// sink answering ends it, with one row.
#[tokio::test]
async fn a_failing_audit_sink_keeps_the_unbound_session() {
    let login = required_login_world();
    let world = &login.world;
    let mut client = world.signed_in().await;
    world.clock.advance_secs(window_secs(world) + 1);

    login.identity.arm_record_event_failure();
    assert_eq!(world.get(&mut client, "/state", None).await, "guest");
    let rows = stored_rows(world, "u1").await;
    assert_eq!(
        rows.len(),
        1,
        "the row stays while its ending is unrecorded"
    );
    assert_eq!(rows[0].1.ending, None, "and its claim is taken back");
    assert!(login.key_binding_endings().is_empty());

    login.identity.disarm_record_event_failure();
    assert_eq!(world.get(&mut client, "/state", None).await, "guest");
    assert!(stored_rows(world, "u1").await.is_empty());
    assert_eq!(login.key_binding_endings().len(), 1);
}

/// A finished step-up is offered no registration: the offer rides on the
/// login's response, and a step-up keeps the login.
#[tokio::test]
async fn a_step_up_is_offered_no_registration() {
    let login = login_world();
    let world = &login.world;
    let mut client = world.signed_in().await;
    client.offer = None;
    world.clock.advance_secs(30);
    let stepped = world
        .get(&mut client, &format!("/step-up/{PASSWORD}"), None)
        .await;
    assert!(stepped.contains("Authenticated"), "{stepped}");
    assert_eq!(client.offer, None, "a step-up finished in one request");

    assert_eq!(
        world.get(&mut client, "/begin-step-up", None).await,
        "begun"
    );
    let verified = world
        .get(&mut client, &format!("/verify/{PASSWORD}"), None)
        .await;
    assert!(verified.contains("Authenticated"), "{verified}");
    assert_eq!(client.offer, None, "a step-up over two requests");
}

/// The bind after the handler counts the window from the login too. The
/// session stepped up late in its window; past the window it proves its
/// device by a key another session of the same browser registered, and is
/// not bound to it.
#[tokio::test]
async fn a_key_proven_past_the_window_binds_nothing() {
    let login = login_world();
    let world = &login.world;
    let window = window_secs(world);
    let mut client = world.signed_in().await;
    world.clock.advance_secs(window - 30);
    let stepped = world
        .get(&mut client, &format!("/step-up/{PASSWORD}"), None)
        .await;
    assert!(stepped.contains("Authenticated"), "{stepped}");

    // A second session on the same browser profile registers a key for the
    // device the two share.
    let mut other = Client {
        cookies: client
            .cookies
            .iter()
            .filter(|(name, _)| name.as_str() == DEVICE)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        ..Client::default()
    };
    assert_eq!(world.get(&mut other, "/sign-in", None).await, "in");
    assert!(other.offer.is_some(), "the keyless device is offered a key");
    assert_eq!(
        world
            .register(&mut other, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::OK
    );
    assert_eq!(device_of(&other), device_of(&client));

    world.clock.advance_secs(40);
    let (name, value) = other
        .cookies
        .iter()
        .find(|(name, _)| name.starts_with(PROOF))
        .map(|(name, value)| (name.clone(), value.clone()))
        .expect("the proof cookie");
    client.cookies.insert(name, value);
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");
}

/// With the stock resolver's own tenant (the session's), a step-up over two
/// requests keeps the session's device and the key's proof of it: the
/// session in the step-up is still the signed-in one. So the step-up of a
/// locked account on its own keyed device is not refused.
#[tokio::test]
async fn a_step_up_over_two_requests_keeps_the_key_proven_device() {
    let login = login_world_with(LoginSetup {
        policy: KeyBindingPolicy::Prefer,
        recorded: false,
        request_tenant: false,
    });
    let world = &login.world;
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let device = device_of(&client);
    world
        .devices
        .set_trust_level(
            &tenant(),
            &device,
            DeviceTrustLevel::Seen,
            world.clock.now(),
        )
        .await
        .unwrap();
    login.lock_the_account().await;

    assert_eq!(
        world.get(&mut client, "/begin-step-up", None).await,
        "begun"
    );
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");
    assert_eq!(
        world.get(&mut client, "/bound-device", None).await,
        device.to_string()
    );
    let verified = world
        .get(&mut client, &format!("/verify/{PASSWORD}"), None)
        .await;
    assert!(verified.contains("Authenticated"), "{verified}");
    assert_eq!(device_of(&client), device);
    assert_eq!(world.get(&mut client, "/proven", None).await, "key");
}

/// A device-key event sink that notes, for each `SessionKeyBound` row, the
/// session it names and whether the store held that session bound when the
/// row was written.
#[derive(Clone)]
struct BoundRows {
    sessions: MemorySessionStore,
    seen: Arc<std::sync::Mutex<Vec<BoundRow>>>,
}

/// The session a `SessionKeyBound` row names, and whether the store held
/// it bound when the row was written.
type BoundRow = (Option<SessionKey>, bool);

impl BoundRows {
    fn over(sessions: &MemorySessionStore) -> Self {
        Self {
            sessions: sessions.clone(),
            seen: Arc::default(),
        }
    }

    fn seen(&self) -> Vec<BoundRow> {
        self.seen.lock().unwrap().clone()
    }
}

impl axess_core::DeviceEventSink for BoundRows {
    fn emit<'a>(
        &'a self,
        event: axess_core::authn::event::AuthEvent,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if event.event_type != axess_core::authn::event::AuthEventType::SessionKeyBound {
                return;
            }
            let stored = match event.session_id {
                Some(key) => self
                    .sessions
                    .load(&key)
                    .await
                    .unwrap_or(None)
                    .is_some_and(|row| row.key_binding.is_some()),
                None => false,
            };
            self.seen.lock().unwrap().push((event.session_id, stored));
        })
    }
}

/// A world whose key service writes its rows to the [`BoundRows`] it
/// returns, served on the [`HeldStore`] it returns over its own sessions.
fn world_recording_bindings() -> (World, BoundRows, HeldStore) {
    let mut world = world(KeyBindingPolicy::Prefer);
    let (rows, store) = (
        BoundRows::over(&world.sessions),
        HeldStore::over(&world.sessions),
    );
    world.keys = world.keys.clone().with_event_sink(rows.clone());
    let resolver = resolver(&world.clock, &world.devices);
    world.app = app_with(
        Wiring::default(),
        &world.clock,
        &store,
        world.keys.clone(),
        resolver,
    );
    (world, rows, store)
}

/// The row of a binding made at the registration path is written once the
/// response's write stored the binding, and names the stored session.
#[tokio::test]
async fn the_bound_row_follows_the_write_that_stores_the_binding() {
    let (world, rows, _) = world_recording_bindings();
    let mut client = world.bound_client(&key(), KeyProofShape::Browser).await;
    let seen = rows.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].0.is_some());
    assert!(
        seen[0].1,
        "the session was stored bound when its row was written"
    );

    // And at the bind after the handler: the next sign-in on the proven key.
    assert_eq!(world.get(&mut client, "/sign-out", None).await, "out");
    assert_eq!(world.get(&mut client, "/sign-in", None).await, "in");
    assert_eq!(world.get(&mut client, "/bound", None).await, "bound");
    let seen = rows.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[1].1,
        "the session was stored bound when its row was written"
    );
}

/// A binding whose write does not land has no row. The binding is made at
/// the next request, whose write lands, and that one has its row.
#[tokio::test]
async fn a_binding_whose_write_fails_has_no_row() {
    let (world, rows, store) = world_recording_bindings();
    let mut client = world.signed_in().await;

    store.refuse_writes(true);
    assert_eq!(
        world
            .register(&mut client, &key(), KeyProofShape::Browser)
            .await,
        StatusCode::OK
    );
    assert!(rows.seen().is_empty(), "{:?}", rows.seen());
    store.refuse_writes(false);
    assert_eq!(world.get(&mut client, "/bound", None).await, "unbound");
    assert_eq!(world.get(&mut client, "/bound", None).await, "bound");
    let seen = rows.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].1);
}
