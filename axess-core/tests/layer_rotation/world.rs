//! One application for every test of the binary: a real session layer and a
//! real authentication service over one registry double, one memory store
//! and one clock, with routes that log in, step up, rotate, cut off and
//! report.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::ids::UserId;
use axess_core::authn::service::{
    Actor, AuthnService, OtherSessionsError, RequestAuthnService, require_valid_session,
};
use axess_core::authn::store::AuthMethod;
use axess_core::authn::types::AuthnScope;
use axess_core::blocking::KdfExecutor;
use axess_core::session::store::{
    MemorySessionRegistry, MemorySessionStore, SessionRegistry, SessionStore,
};
use axess_core::session::{
    LayerSessionEnded, SessionData, SessionEndAudit, SessionKey, UnknownLiveness,
    extractor::AuthSession, layer::SessionLayer,
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{MethodRouter, get},
};
use common::{password_config, password_method, test_tenant, test_user, tid, uid, user_scope};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tower::ServiceExt;

const KEY: [u8; 32] = [
    9, 2, 7, 1, 8, 2, 8, 1, 8, 2, 8, 4, 5, 9, 0, 4, 5, 2, 3, 5, 3, 6, 0, 2, 8, 7, 4, 7, 1, 3, 5, 2,
];
pub const PASSWORD: &str = "Sample2+";

pub type Service = RequestAuthnService<MockIdentityStore, MockFactorStore>;

pub fn alice() -> UserId {
    uid("u1")
}

pub fn bob() -> UserId {
    uid("u2")
}

fn password() -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(PASSWORD))
}

/// What the layer's sink was told, each with the row the store held under
/// the ended key at that moment.
#[derive(Default)]
pub struct Ends {
    store: Mutex<Option<MemorySessionStore>>,
    told: Mutex<Vec<(LayerSessionEnded, Option<SessionData>)>>,
    pub failing: AtomicBool,
}

impl Ends {
    pub fn told(&self) -> Vec<(LayerSessionEnded, Option<SessionData>)> {
        self.told.lock().unwrap().clone()
    }

    /// The reasons told so far, in order.
    pub fn reasons(&self) -> Vec<&'static str> {
        self.told()
            .iter()
            .map(|(ended, _)| ended.reason.as_str())
            .collect()
    }
}

impl SessionEndAudit for Ends {
    fn session_ended<'a>(
        &'a self,
        ended: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let store = self.store.lock().unwrap().clone();
            let row = match store {
                Some(store) => {
                    let Ok(row) = store.load(&ended.session_id).await;
                    row
                }
                None => None,
            };
            if self.failing.load(Ordering::SeqCst) {
                return Err("sink down".to_owned());
            }
            self.told.lock().unwrap().push((ended.clone(), row));
            Ok(())
        })
    }
}

/// What the registry is made to do while a test runs.
#[derive(Default)]
pub struct Faults {
    /// Every move fails.
    pub fail_moves: AtomicBool,
    /// Every session of alice is ended just before the registry answers
    /// the check this many checks from now (0: the next one).
    pub revoke_at_check: Mutex<Option<usize>>,
}

/// A handler that waits: it says it has loaded its session, then waits to
/// be let go.
#[derive(Default)]
pub struct Gate {
    pub entered: Notify,
    pub open: Notify,
}

/// How a world is built.
#[derive(Clone, Copy)]
pub struct Options {
    /// The layer is built with the registry (`SessionLayer::new`); without
    /// it, `SessionLayer::without_registry_insecure`.
    pub layer_registry: bool,
    /// The service is built with the registry.
    pub service_registry: bool,
    pub unknown: UnknownLiveness,
    pub max_sessions: Option<usize>,
    /// The absolute age cap of a signed-in session.
    pub max_age: Option<std::time::Duration>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            layer_registry: true,
            service_registry: true,
            unknown: UnknownLiveness::Reject,
            max_sessions: None,
            max_age: None,
        }
    }
}

pub struct World {
    pub clock: axess_clock::testing::MockClock,
    pub svc: Arc<Service>,
    pub identity: MockIdentityStore,
    pub registry: RegistryDouble,
    pub store: MemorySessionStore,
    pub ends: Arc<Ends>,
    pub faults: Arc<Faults>,
    pub gate: Arc<Gate>,
    pub app: Router,
}

/// A browser: the cookie it holds, and what the last response did.
#[derive(Default, Clone)]
pub struct Browser {
    pub jar: Option<String>,
    pub cookie_set: bool,
    pub status: Option<StatusCode>,
}

/// What a route is handed beside the session.
#[derive(Clone)]
struct Ctx {
    svc: Arc<Service>,
    registry: RegistryDouble,
    identity: MockIdentityStore,
    gate: Arc<Gate>,
}

impl World {
    pub fn new() -> Self {
        Self::with(Options::default())
    }

    pub fn with(options: Options) -> Self {
        let clock = common::test_clock();
        let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
        let faults = Arc::new(Faults::default());
        let hook = faults.clone();
        let registry =
            RegistryDouble::over(MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())))
                .before(move |call, inner| {
                    let fail = call.op() == RegistryOp::MoveSession
                        && hook.fail_moves.load(Ordering::SeqCst);
                    let revoke = call.op() == RegistryOp::IsValid && {
                        let mut at = hook.revoke_at_check.lock().unwrap();
                        match *at {
                            Some(0) => {
                                *at = None;
                                true
                            }
                            Some(n) => {
                                *at = Some(n - 1);
                                false
                            }
                            None => false,
                        }
                    };
                    async move {
                        if revoke {
                            inner.invalidate_user(&alice()).await.unwrap();
                        }
                        if fail {
                            Step::Fail("the registry does not answer")
                        } else {
                            Step::Forward
                        }
                    }
                });
        let ends = Arc::new(Ends::default());
        *ends.store.lock().unwrap() = Some(store.clone());
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice"))
            .with_user(test_user("u2", "bob"));
        let bobs = AuthnScope::User {
            tenant_id: tid("t1"),
            user_id: bob(),
        };
        let factors = MockFactorStore::new()
            .with_factor(user_scope(), password_config(PASSWORD))
            .with_factor(bobs.clone(), password_config(PASSWORD))
            .with_method(&alice(), password_method())
            .with_method(
                &bob(),
                AuthMethod::sequential("password", vec![FactorKind::Password], bobs),
            );
        let mut builder = AuthnService::builder(identity.clone(), factors)
            .with_clock(clock.clone())
            .with_kdf_executor(Arc::new(KdfExecutor::inline()))
            .with_session_store(store.clone());
        if options.service_registry {
            builder = builder.with_registry(registry.clone());
        }
        if let Some(max) = options.max_sessions {
            builder = builder.with_max_sessions_per_user(std::num::NonZeroUsize::new(max).unwrap());
        }
        let svc: Arc<Service> =
            Arc::new(builder.build().with_audit_context(AuditContext::default()));
        let sink: Arc<dyn SessionEndAudit> = ends.clone();
        let layer = if options.layer_registry {
            SessionLayer::new(store.clone(), KEY, registry.clone().handle(), sink)
                .with_clock(clock.clone())
        } else {
            SessionLayer::without_registry_insecure(store.clone(), KEY, sink)
                .with_clock(clock.clone())
        }
        .with_unknown_liveness(options.unknown)
        .with_max_session_age(options.max_age)
        .with_secure(false);
        let gate = Arc::new(Gate::default());
        let ctx = Ctx {
            svc: svc.clone(),
            registry: registry.clone(),
            identity: identity.clone(),
            gate: gate.clone(),
        };
        let app = routes(&ctx).layer(layer);
        Self {
            clock,
            svc,
            identity,
            registry,
            store,
            ends,
            faults,
            gate,
            app,
        }
    }

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
        browser.status = Some(resp.status());
        browser.cookie_set = false;
        if let Some(v) = resp.headers().get(header::SET_COOKIE) {
            browser.jar = Some(v.to_str().unwrap().split(';').next().unwrap().to_owned());
            browser.cookie_set = true;
        }
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The key the browser's session is stored under, read through the
    /// layer (a request that changes nothing).
    pub async fn key(&self, browser: &mut Browser) -> SessionKey {
        self.get(browser, "/key").await.parse().expect("a key")
    }

    /// The keys the registry holds for `user`, oldest first.
    pub async fn held(&self, user: &UserId) -> Vec<SessionKey> {
        self.registry.inner().active_sessions(user).await.unwrap()
    }

    /// Whether the store holds a row under `key`.
    pub async fn row(&self, key: &SessionKey) -> Option<SessionData> {
        let Ok(row) = self.store.load(key).await;
        row
    }

    /// The registry calls of `op` made so far.
    pub fn count(&self, op: RegistryOp) -> usize {
        self.registry.count(op)
    }
}

/// A route that hands the context and the session to `f`.
fn with_ctx<F, Fut>(ctx: &Ctx, f: F) -> MethodRouter
where
    F: Fn(Ctx, AuthSession) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = String> + Send + 'static,
{
    let ctx = ctx.clone();
    get(move |s: AuthSession| {
        let (ctx, f) = (ctx.clone(), f.clone());
        async move { f(ctx, s).await }
    })
}

async fn login(svc: &Service, who: &str, s: &AuthSession) -> String {
    if let Err(e) = svc.begin_login(who, "default", s).await {
        return format!("refused: {e}");
    }
    match svc.verify_factor(&password(), s).await {
        Ok(outcome) => format!("{outcome:?}"),
        Err(e) => format!("refused: {e}"),
    }
}

async fn rotate(svc: &Service, s: &AuthSession) -> String {
    match svc.rotate_session(s).await {
        Ok(()) => "rotated".to_owned(),
        Err(e) => format!("refused: {e}"),
    }
}

async fn step_up(svc: &Service, s: &AuthSession) -> String {
    if let Err(e) = svc.begin_step_up(s, vec![FactorKind::Password]).await {
        return format!("refused: {e}");
    }
    match svc.verify_factor(&password(), s).await {
        Ok(outcome) => format!("{outcome:?}"),
        Err(e) => format!("refused: {e}"),
    }
}

/// A cut-off of alice's other sessions keeping `keep`.
async fn cut(svc: &Service, keep: SessionKey) -> String {
    match svc
        .invalidate_other_sessions(&alice(), &keep, Actor::System)
        .await
    {
        Ok(()) => "kept".to_owned(),
        Err(OtherSessionsError::CallerEnded) => "caller-ended".to_owned(),
        Err(e) => format!("refused: {e}"),
    }
}

/// Rotate the session (`regenerate` behind the layer, or the service's
/// `rotate_session`), then log out, in one request. Answers the one key the
/// registry holds for alice just before the logout and the key the session
/// itself carries then, separated by a space.
async fn rotate_then_logout(c: &Ctx, s: &AuthSession, by_service: bool) -> String {
    if by_service {
        rotate(&c.svc, s).await;
    } else {
        s.regenerate().await;
    }
    let held = c.registry.inner().active_sessions(&alice()).await.unwrap();
    let [held] = held.as_slice() else {
        return format!("held {} keys", held.len());
    };
    let own = s.session_key().await;
    match c.svc.logout(s).await {
        Ok(()) => format!("{held} {own}"),
        Err(e) => format!("refused: {e}"),
    }
}

async fn whoami(s: &AuthSession) -> String {
    if s.is_authenticated().await {
        "user".to_owned()
    } else if s.snapshot().await.is_some() {
        "step-up".to_owned()
    } else {
        "guest".to_owned()
    }
}

fn routes(ctx: &Ctx) -> Router {
    let validator = ctx.svc.session_validator();
    Router::new()
        .route(
            "/valid",
            get(|| async { "valid" }).layer(require_valid_session(validator.clone())),
        )
        .route(
            "/login",
            with_ctx(ctx, |c, s| async move { login(&c.svc, "alice", &s).await }),
        )
        .route(
            "/switch-to-bob",
            with_ctx(ctx, |c, s| async move {
                // A signs out and B signs in on the same session, in one
                // request.
                s.clear().await;
                login(&c.svc, "bob", &s).await
            }),
        )
        .route(
            "/sign-out-quietly",
            get(|s: AuthSession| async move {
                // A sign-out of the adopter's own that asks the registry
                // nothing.
                s.clear().await;
                "out"
            }),
        )
        .route(
            "/login-revoked",
            with_ctx(ctx, |c, s| async move {
                let first = login(&c.svc, "alice", &s).await;
                c.registry.inner().invalidate_user(&alice()).await.unwrap();
                first
            }),
        )
        .route(
            "/rotate",
            with_ctx(ctx, |c, s| async move { rotate(&c.svc, &s).await }),
        )
        .route(
            "/rotate-revoked",
            with_ctx(ctx, |c, s| async move {
                c.registry.inner().invalidate_user(&alice()).await.unwrap();
                rotate(&c.svc, &s).await
            }),
        )
        .route(
            "/login-and-rotate",
            with_ctx(ctx, |c, s| async move {
                let first = login(&c.svc, "alice", &s).await;
                format!("{first} {}", rotate(&c.svc, &s).await)
            }),
        )
        .route(
            "/login-and-regenerate",
            with_ctx(ctx, |c, s| async move {
                let first = login(&c.svc, "alice", &s).await;
                s.regenerate().await;
                first
            }),
        )
        .route(
            "/own-sign-in",
            with_ctx(ctx, |c, s| async move {
                // A handler of the adopter's own: it registers the key the
                // session carries, then signs the session in, which rotates.
                let key = s.session_key().await;
                c.registry.inner().register(&alice(), &key).await.unwrap();
                s.set_authenticated(alice(), tid("t1"), common::start())
                    .await;
                whoami(&s).await
            }),
        )
        .route(
            "/step-up",
            with_ctx(ctx, |c, s| async move { step_up(&c.svc, &s).await }),
        )
        .route(
            "/step-up-revoked",
            with_ctx(ctx, |c, s| async move {
                if let Err(e) = c.svc.begin_step_up(&s, vec![FactorKind::Password]).await {
                    return format!("refused: {e}");
                }
                c.registry.inner().invalidate_user(&alice()).await.unwrap();
                match c.svc.verify_factor(&password(), &s).await {
                    Ok(outcome) => format!("{outcome:?}"),
                    Err(e) => format!("refused: {e}"),
                }
            }),
        )
        .route(
            "/step-up-unrecorded",
            with_ctx(ctx, |c, s| async move {
                // A step-up whose audit row cannot be written: the service
                // ends the session. Answers the outcome and whether the
                // registry still holds the entry while the request runs.
                let arrived = s.registered_key().await;
                if let Err(e) = c.svc.begin_step_up(&s, vec![FactorKind::Password]).await {
                    return format!("refused: {e}");
                }
                c.identity.arm_record_event_failure();
                let outcome = match c.svc.verify_factor(&password(), &s).await {
                    Ok(outcome) => format!("{outcome:?}"),
                    Err(_) => "refused".to_owned(),
                };
                c.identity.disarm_record_event_failure();
                let held = c.registry.inner().is_valid(&alice(), &arrived).await;
                format!("{outcome} {}", held.unwrap())
            }),
        )
        .route(
            "/regenerate-then-logout",
            with_ctx(ctx, |c, s| async move {
                s.regenerate().await;
                match c.svc.logout(&s).await {
                    Ok(()) => "out".to_owned(),
                    Err(e) => format!("refused: {e}"),
                }
            }),
        )
        .route(
            "/regenerate-then-logout-keys",
            with_ctx(ctx, |c, s| async move {
                rotate_then_logout(&c, &s, false).await
            }),
        )
        .route(
            "/rotate-then-logout-keys",
            with_ctx(
                ctx,
                |c, s| async move { rotate_then_logout(&c, &s, true).await },
            ),
        )
        .route(
            "/regenerate",
            get(|s: AuthSession| async move {
                s.regenerate().await;
                "regenerated"
            }),
        )
        .route(
            "/keys-around-regenerate",
            with_ctx(ctx, |c, s| async move {
                let held = c.registry.inner().active_sessions(&alice()).await.unwrap();
                let before = s.registered_key().await;
                s.regenerate().await;
                let after = s.registered_key().await;
                let own = s.session_key().await;
                format!("{} {} {}", held == [before], before == after, own != after)
            }),
        )
        .route(
            "/login-then-keys",
            with_ctx(ctx, |c, s| async move {
                login(&c.svc, "alice", &s).await;
                let held = c.registry.inner().active_sessions(&alice()).await.unwrap();
                let registered = s.registered_key().await;
                s.regenerate().await;
                format!(
                    "{} {}",
                    held == [registered],
                    s.registered_key().await == registered
                )
            }),
        )
        .route(
            "/regenerate-then-cut",
            with_ctx(ctx, |c, s| async move {
                s.regenerate().await;
                cut(&c.svc, s.registered_key().await).await
            }),
        )
        .route(
            "/regenerate-then-cut-own-key",
            with_ctx(ctx, |c, s| async move {
                s.regenerate().await;
                cut(&c.svc, s.session_key().await).await
            }),
        )
        .route(
            "/rotate-then-cut-earlier-key",
            with_ctx(ctx, |c, s| async move {
                let earlier = s.session_key().await;
                rotate(&c.svc, &s).await;
                cut(&c.svc, earlier).await
            }),
        )
        .route(
            "/wait-then-cut",
            with_ctx(ctx, |c, s| async move {
                let keep = s.registered_key().await;
                c.gate.entered.notify_one();
                c.gate.open.notified().await;
                cut(&c.svc, keep).await
            }),
        )
        .route("/wait-then-validate", {
            let (validator, gate) = (validator.clone(), ctx.gate.clone());
            get(move |s: AuthSession| {
                let (validator, gate) = (validator.clone(), gate.clone());
                async move {
                    gate.entered.notify_one();
                    gate.open.notified().await;
                    if validator.enforce(&s).await {
                        (StatusCode::OK, "valid")
                    } else {
                        (StatusCode::UNAUTHORIZED, "refused")
                    }
                }
            })
        })
        .route(
            "/rotate-and-check",
            with_ctx(ctx, move |c, s| {
                let validator = validator.clone();
                async move {
                    let rotated = rotate(&c.svc, &s).await;
                    let checked = c.svc.check_session(&s).await;
                    let enforced = validator.enforce(&s).await;
                    format!("{rotated} {checked} {enforced} {}", whoami(&s).await)
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move { whoami(&s).await }),
        )
        .route(
            "/key",
            get(|s: AuthSession| async move { s.session_key().await.to_string() }),
        )
}
