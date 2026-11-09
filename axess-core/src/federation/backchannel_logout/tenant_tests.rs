//! Tenant providers: a token is verified by, and ends the session of, the
//! tenant whose issuer sent it. Unsigned tokens are used throughout: the mock
//! provider skips signature verification.

use super::*;
use crate::authn::ids::testing::tenant;
use crate::federation::oauth_tenant::{
    BrokenTenantProvider, IssuerFuture, IssuerProviders, ProviderFuture, TenantOAuthProviders,
    TenantProvider,
};
use crate::session::id::SessionId;
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::{MockOAuthProvider, OAuthError};
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use axum::extract::{Form, State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const ISS_A: &str = "https://idp-a.example.com";
const ISS_B: &str = "https://idp-b.example.com";

/// A fixed set of tenant providers, or a source that always fails.
struct Source {
    providers: Vec<TenantProvider>,
    fails: bool,
}

/// A source whose issuer has providers that built and records that did not:
/// `(tenant, client id)` for each broken one.
struct PartlyBroken {
    providers: Vec<TenantProvider>,
    broken: Vec<(&'static str, &'static str)>,
}

impl TenantOAuthProviders for PartlyBroken {
    fn built_providers(&self) -> Vec<std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>> {
        self.providers.iter().map(|p| p.provider.clone()).collect()
    }

    fn provider<'a>(&'a self, _: &'a TenantId, _: &'a str) -> ProviderFuture<'a> {
        Box::pin(async { Ok(None) })
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        Box::pin(async move {
            Ok(IssuerProviders {
                providers: self
                    .providers
                    .iter()
                    .filter(|p| p.provider.issuer() == Some(issuer))
                    .cloned()
                    .collect(),
                broken: self
                    .broken
                    .iter()
                    .map(|(label, client_id)| BrokenTenantProvider {
                        tenant: tenant(label),
                        name: "sso".into(),
                        client_id: (*client_id).to_string(),
                        error: OAuthError::Config("the credential does not open".into()),
                    })
                    .collect(),
            })
        })
    }
}

fn offered(tenant_label: &str, issuer: &str, client_id: &str) -> TenantProvider {
    TenantProvider {
        tenant: tenant(tenant_label),
        name: "sso".into(),
        provider: Arc::new(
            MockOAuthProvider::new("sso")
                .with_issuer(issuer)
                .with_client_id(client_id),
        ),
    }
}

impl TenantOAuthProviders for Source {
    fn built_providers(&self) -> Vec<std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>> {
        self.providers.iter().map(|p| p.provider.clone()).collect()
    }

    fn provider<'a>(&'a self, t: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        Box::pin(async move {
            Ok(self
                .providers
                .iter()
                .find(|p| p.tenant == *t && &*p.name == name)
                .map(|p| p.provider.clone()))
        })
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        Box::pin(async move {
            if self.fails {
                return Err(OAuthError::Discovery("store down".into()));
            }
            Ok(IssuerProviders {
                providers: self
                    .providers
                    .iter()
                    .filter(|p| p.provider.issuer() == Some(issuer))
                    .cloned()
                    .collect(),
                broken: Vec::new(),
            })
        })
    }
}

fn token(iss: &str, client_id: &str, extra: serde_json::Value) -> String {
    let mut payload = serde_json::json!({
        "iss": iss,
        "aud": client_id,
        "iat": chrono::Utc::now().timestamp(),
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
    });
    payload
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    )
}

fn tenants_only(
    providers: Vec<TenantProvider>,
    registry: &MemorySessionRegistry,
    sid_map: SidMap,
) -> BackChannelLogoutHandler {
    BackChannelLogoutHandler::for_tenants(
        Arc::new(Source {
            providers,
            fails: false,
        }),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map,
        Arc::new(SystemClock),
    )
}

async fn post(h: &BackChannelLogoutHandler, t: String) -> Result<StatusCode, StatusCode> {
    BackChannelLogoutHandler::handle_outcome(
        State(h.clone()),
        Form(LogoutParams { logout_token: t }),
    )
    .await
}

/// One live session per `(issuer, sid)`, mapped as a login would.
async fn login(
    registry: &MemorySessionRegistry,
    sid_map: &SidMap,
    rng: &MockRng,
    user: &str,
    tenant_label: &str,
    iss: &str,
    sid: &str,
) -> (crate::authn::ids::UserId, SessionId) {
    let user = axess_identity::testing::user(user);
    let session = SessionId::new(rng);
    registry.register(&user, &session).await.unwrap();
    sid_map.insert_displacing(
        (iss.to_string(), sid.to_string()),
        "idp-sub",
        Some(tenant(tenant_label)),
        user,
        session,
        chrono::Utc::now(),
    );
    (user, session)
}

/// The back-channel logout token of tenant B's issuer ends tenant B's session
/// and no other, though both tenants call their provider `sso` and both
/// sessions carry the same `sid`.
#[tokio::test]
async fn a_token_from_tenant_bs_issuer_ends_only_tenant_bs_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = tenants_only(
        vec![
            offered("acme", ISS_A, "client-a"),
            offered("beta", ISS_B, "client-b"),
        ],
        &registry,
        sid_map.clone(),
    );
    let rng = MockRng::new(21);
    let (ua, sa) = login(
        &registry, &sid_map, &rng, "alice", "acme", ISS_A, "same-sid",
    )
    .await;
    let (ub, sb) = login(&registry, &sid_map, &rng, "bob", "beta", ISS_B, "same-sid").await;

    let t = token(
        ISS_B,
        "client-b",
        serde_json::json!({ "sid": "same-sid", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Ok(StatusCode::OK));

    assert!(
        !registry.is_valid(&ub, &sb).await.unwrap(),
        "B's session ended"
    );
    assert!(
        registry.is_valid(&ua, &sa).await.unwrap(),
        "A's session stands"
    );

    // A token for B's issuer addressed to A's client id is not B's to verify.
    let t = token(
        ISS_B,
        "client-a",
        serde_json::json!({ "sid": "same-sid", "jti": "j2" }),
    );
    assert_eq!(post(&h, t).await, Err(StatusCode::BAD_REQUEST));
    assert!(registry.is_valid(&ua, &sa).await.unwrap());
}

/// Tenants on one issuer with different client ids are told apart by `aud`.
#[tokio::test]
async fn tenants_on_one_issuer_are_told_apart_by_the_client_id() {
    let registry = MemorySessionRegistry::new();
    let h = tenants_only(
        vec![
            offered("acme", ISS_A, "client-a"),
            offered("beta", ISS_A, "client-b"),
        ],
        &registry,
        SidMap::new(),
    );
    let claims = serde_json::json!({ "aud": "client-b" });
    let chosen = h
        .entry_for(ISS_A, &claims)
        .await
        .expect("one match")
        .expect("a provider");
    assert_eq!(chosen.provider.client_id(), Some("client-b"));
    assert_eq!(chosen.tenant, Some(tenant("beta")));
}

/// Two tenants with one issuer and one client id cannot be told apart: the
/// token is refused with the named error and no session ends.
#[tokio::test]
async fn an_issuer_and_client_id_shared_by_two_tenants_is_refused_not_guessed() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = tenants_only(
        vec![
            offered("acme", ISS_A, "client-x"),
            offered("beta", ISS_A, "client-x"),
        ],
        &registry,
        sid_map.clone(),
    );
    let rng = MockRng::new(22);
    let (user, session) = login(&registry, &sid_map, &rng, "alice", "acme", ISS_A, "s1").await;

    let claims = serde_json::json!({ "aud": "client-x" });
    match h.entry_for(ISS_A, &claims).await {
        Err(LogoutProviderError::Ambiguous { global, tenants }) => {
            assert!(!global);
            assert_eq!(tenants.len(), 2);
        }
        other => panic!("expected Ambiguous, got {:?}", other.map(|p| p.is_some())),
    }
    let t = token(
        ISS_A,
        "client-x",
        serde_json::json!({ "sid": "s1", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Err(StatusCode::BAD_REQUEST));
    assert!(
        registry.is_valid(&user, &session).await.unwrap(),
        "nothing ended"
    );
}

/// A tenant provider that matches a global one's issuer and client id does
/// not shadow it: the global registration is the operator's, so it decides,
/// and a record a tenant wrote cannot make its tokens ambiguous.
#[tokio::test]
async fn a_tenant_matching_the_global_registration_does_not_shadow_it() {
    let registry = MemorySessionRegistry::new();
    let global: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("sso")
            .with_issuer(ISS_A)
            .with_client_id("client-x"),
    )];
    let h = BackChannelLogoutHandler::new(
        &global,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        SidMap::new(),
        Arc::new(SystemClock),
    )
    .expect("handler")
    .with_tenant_providers(Arc::new(PartlyBroken {
        providers: vec![offered("acme", ISS_A, "client-x")],
        broken: vec![("beta", "client-x")],
    }));
    let claims = serde_json::json!({ "aud": "client-x" });

    let entry = h
        .entry_for(ISS_A, &claims)
        .await
        .expect("the global registration decides")
        .expect("and is found");

    assert_eq!(entry.tenant, None, "the global registration is unscoped");
}

/// Without any tenant source the handler is what it was: the global map
/// decides, and a token of an unknown issuer is refused.
#[tokio::test]
async fn global_providers_resolve_beside_a_tenant_source() {
    let registry = MemorySessionRegistry::new();
    let global: Vec<Arc<dyn OAuthProvider>> = vec![Arc::new(
        MockOAuthProvider::new("corp")
            .with_issuer(ISS_A)
            .with_client_id("client-g"),
    )];
    let h = BackChannelLogoutHandler::new(
        &global,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        SidMap::new(),
        Arc::new(SystemClock),
    )
    .expect("handler")
    .with_tenant_providers(Arc::new(Source {
        providers: vec![offered("beta", ISS_B, "client-b")],
        fails: false,
    }));
    for (iss, aud, jti) in [(ISS_A, "client-g", "g1"), (ISS_B, "client-b", "b1")] {
        let t = token(iss, aud, serde_json::json!({ "sid": "s", "jti": jti }));
        assert_eq!(post(&h, t).await, Ok(StatusCode::OK), "{iss}");
    }
    let t = token(
        "https://other.example.com",
        "client-g",
        serde_json::json!({ "sid": "s", "jti": "o1" }),
    );
    assert_eq!(post(&h, t).await, Err(StatusCode::BAD_REQUEST));
}

/// A tenant source that fails answers a retryable 503, not a refusal.
#[tokio::test]
async fn a_failing_tenant_source_is_a_retryable_503() {
    let registry = MemorySessionRegistry::new();
    let h = BackChannelLogoutHandler::for_tenants(
        Arc::new(Source {
            providers: vec![],
            fails: true,
        }),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        SidMap::new(),
        Arc::new(SystemClock),
    );
    let t = token(
        ISS_A,
        "client-a",
        serde_json::json!({ "sid": "s", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Err(StatusCode::SERVICE_UNAVAILABLE));
}

fn partly_broken(
    providers: Vec<TenantProvider>,
    broken: Vec<(&'static str, &'static str)>,
    registry: &MemorySessionRegistry,
    sid_map: SidMap,
) -> BackChannelLogoutHandler {
    BackChannelLogoutHandler::for_tenants(
        Arc::new(PartlyBroken { providers, broken }),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map,
        Arc::new(SystemClock),
    )
}

/// A tenant whose provider does not build leaves the other tenants of the
/// issuer working: a token addressed to another client id verifies and ends
/// its session.
#[tokio::test]
async fn a_broken_tenant_provider_does_not_stop_the_other_tenants_of_its_issuer() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = partly_broken(
        vec![offered("acme", ISS_A, "client-a")],
        vec![("beta", "client-b")],
        &registry,
        sid_map.clone(),
    );
    let rng = MockRng::new(23);
    let (user, session) = login(&registry, &sid_map, &rng, "alice", "acme", ISS_A, "s1").await;

    let t = token(
        ISS_A,
        "client-a",
        serde_json::json!({ "sid": "s1", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Ok(StatusCode::OK));
    assert!(!registry.is_valid(&user, &session).await.unwrap());
}

/// A token addressed to the broken provider is refused as retryable: the
/// IdP resends it once the configuration is fixed.
#[tokio::test]
async fn a_token_addressed_to_a_broken_tenant_provider_is_a_retryable_503() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = partly_broken(
        vec![offered("acme", ISS_A, "client-a")],
        vec![("beta", "client-b")],
        &registry,
        sid_map.clone(),
    );
    let rng = MockRng::new(24);
    let (user, session) = login(&registry, &sid_map, &rng, "bob", "beta", ISS_A, "s2").await;

    let claims = serde_json::json!({ "aud": "client-b" });
    assert!(matches!(
        h.entry_for(ISS_A, &claims).await,
        Err(LogoutProviderError::Unavailable { .. })
    ));
    let t = token(
        ISS_A,
        "client-b",
        serde_json::json!({ "sid": "s2", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Err(StatusCode::SERVICE_UNAVAILABLE));
    assert!(
        registry.is_valid(&user, &session).await.unwrap(),
        "nothing ended"
    );
}

/// A broken provider that shares the issuer and client id with a working one
/// keeps the token ambiguous: it is not attributed to the one that built.
#[tokio::test]
async fn a_broken_provider_sharing_the_client_id_keeps_the_token_ambiguous() {
    let registry = MemorySessionRegistry::new();
    let h = partly_broken(
        vec![offered("acme", ISS_A, "client-x")],
        vec![("beta", "client-x")],
        &registry,
        SidMap::new(),
    );
    let claims = serde_json::json!({ "aud": "client-x" });
    match h.entry_for(ISS_A, &claims).await {
        Err(LogoutProviderError::Ambiguous { global, tenants }) => {
            assert!(!global);
            assert_eq!(tenants, vec![tenant("acme"), tenant("beta")]);
        }
        other => panic!("expected Ambiguous, got {:?}", other.map(|e| e.is_some())),
    }
}

/// The refusal reads as one sentence in a log line.
#[test]
fn the_ambiguity_message_has_no_run_of_spaces() {
    let e = LogoutProviderError::Ambiguous {
        global: true,
        tenants: vec![tenant("acme")],
    };
    let text = e.to_string();
    assert!(!text.contains("  "), "{text}");
    assert!(text.contains("token (global registration: true"), "{text}");
}

/// A login of `user` through the issuer, registered the way the login path
/// does: in the subject registry, and under a `sid`.
async fn login_with_subject(
    registry: &MemorySessionRegistry,
    sid_map: &SidMap,
    rng: &MockRng,
    user: &str,
    tenant_label: &str,
    sid: &str,
) -> (crate::authn::ids::UserId, SessionId) {
    let user = axess_identity::testing::user(user);
    let session = SessionId::new(rng);
    registry.register(&user, &session).await.unwrap();
    let tenant = Some(tenant(tenant_label));
    sid_map.register_subject_session(ISS_A, "idp-sub", tenant, user, session);
    sid_map.insert_displacing(
        (ISS_A.to_string(), sid.to_string()),
        "idp-sub",
        tenant,
        user,
        session,
        chrono::Utc::now(),
    );
    (user, session)
}

/// Two tenants share an issuer and a subject. A token for tenant A's client
/// that names only the `sub` ends tenant A's session; tenant B's stays.
#[tokio::test]
async fn a_sub_logout_ends_only_the_verifying_tenants_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = tenants_only(
        vec![
            offered("acme", ISS_A, "client-a"),
            offered("beta", ISS_A, "client-b"),
        ],
        &registry,
        sid_map.clone(),
    );
    let rng = MockRng::new(23);
    let (ua, sa) = login_with_subject(&registry, &sid_map, &rng, "alice", "acme", "sid-a").await;
    let (ub, sb) = login_with_subject(&registry, &sid_map, &rng, "bob", "beta", "sid-b").await;

    let t = token(
        ISS_A,
        "client-a",
        serde_json::json!({ "sub": "idp-sub", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Ok(StatusCode::OK));

    assert!(
        !registry.is_valid(&ua, &sa).await.unwrap(),
        "A's session ended"
    );
    assert!(
        registry.is_valid(&ub, &sb).await.unwrap(),
        "B's session belongs to a tenant whose provider did not verify the token"
    );
}

/// A `sid` that maps to tenant B's session, in a token tenant A's provider
/// verified, ends nothing.
#[tokio::test]
async fn a_sid_logout_does_not_reach_another_tenants_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = tenants_only(
        vec![
            offered("acme", ISS_A, "client-a"),
            offered("beta", ISS_A, "client-b"),
        ],
        &registry,
        sid_map.clone(),
    );
    let rng = MockRng::new(24);
    let (ub, sb) = login_with_subject(&registry, &sid_map, &rng, "bob", "beta", "sid-b").await;

    let t = token(
        ISS_A,
        "client-a",
        serde_json::json!({ "sid": "sid-b", "jti": "j1" }),
    );
    assert_eq!(post(&h, t).await, Ok(StatusCode::OK));

    assert!(
        registry.is_valid(&ub, &sb).await.unwrap(),
        "a token verified for tenant A does not end tenant B's session"
    );
}

/// Counts how often the tenant source is asked about an issuer.
struct Counting(std::sync::atomic::AtomicUsize);

impl TenantOAuthProviders for Counting {
    fn built_providers(&self) -> Vec<std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>> {
        Vec::new()
    }

    fn provider<'a>(&'a self, _: &'a TenantId, _: &'a str) -> ProviderFuture<'a> {
        Box::pin(async { Ok(None) })
    }

    fn providers_for_issuer<'a>(&'a self, _: &'a str) -> IssuerFuture<'a> {
        Box::pin(async move {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(IssuerProviders {
                providers: Vec::new(),
                broken: Vec::new(),
            })
        })
    }
}

/// An issuer nobody configured is looked up once per short interval, not once
/// per unauthenticated request.
#[tokio::test]
async fn an_unknown_issuer_is_not_looked_up_on_every_request() {
    use std::sync::atomic::Ordering;
    let clock = axess_clock::testing::MockClock::now();
    let source = Arc::new(Counting(Default::default()));
    let h = BackChannelLogoutHandler::for_tenants(
        source.clone(),
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
        SidMap::new(),
        Arc::new(clock.clone()),
    );
    for n in 0..5 {
        let t = token(
            "https://nobody.example",
            "client-a",
            serde_json::json!({ "sub": "s", "jti": format!("j{n}") }),
        );
        assert_eq!(post(&h, t).await, Err(StatusCode::BAD_REQUEST));
    }
    assert_eq!(
        source.0.load(Ordering::SeqCst),
        1,
        "one store read, not five"
    );

    clock.advance_secs(3600);
    let t = token(
        "https://nobody.example",
        "client-a",
        serde_json::json!({ "sub": "s", "jti": "later" }),
    );
    assert_eq!(post(&h, t).await, Err(StatusCode::BAD_REQUEST));
    assert_eq!(
        source.0.load(Ordering::SeqCst),
        2,
        "the answer is not remembered for ever"
    );
}

/// With the memory turned off every request asks the source.
#[tokio::test]
async fn a_zero_unknown_issuer_memory_asks_the_source_every_time() {
    use std::sync::atomic::Ordering;
    let source = Arc::new(Counting(Default::default()));
    let h = BackChannelLogoutHandler::for_tenants(
        source.clone(),
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
        SidMap::new(),
        Arc::new(SystemClock),
    )
    .with_unknown_issuer_memory(std::time::Duration::ZERO);
    for n in 0..3 {
        let t = token(
            "https://nobody.example",
            "client-a",
            serde_json::json!({ "sub": "s", "jti": format!("j{n}") }),
        );
        assert_eq!(post(&h, t).await, Err(StatusCode::BAD_REQUEST));
    }
    assert_eq!(source.0.load(Ordering::SeqCst), 3);
}

/// A tenant provider installed in the live registry after a token for its
/// issuer was refused is found by the next token, though the refusal is
/// remembered: the registry's generation moved.
#[tokio::test]
async fn a_provider_added_to_the_live_registry_is_found_despite_a_remembered_miss() {
    use crate::federation::oauth_tenant::LiveTenantOAuthProviders;
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let registry = MemorySessionRegistry::new();
    let sid_map = SidMap::new();
    let h = BackChannelLogoutHandler::for_tenants(
        live.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map.clone(),
        Arc::new(SystemClock),
    );
    let rng = MockRng::new(25);
    let (user, session) = login(&registry, &sid_map, &rng, "alice", "acme", ISS_A, "s1").await;

    let t = |jti: &str| {
        token(
            ISS_A,
            "client-a",
            serde_json::json!({ "sid": "s1", "jti": jti }),
        )
    };
    assert_eq!(post(&h, t("j1")).await, Err(StatusCode::BAD_REQUEST));

    live.set(
        tenant("acme"),
        "sso".into(),
        Arc::new(
            MockOAuthProvider::new("sso")
                .with_issuer(ISS_A)
                .with_client_id("client-a"),
        ),
    );
    assert_eq!(post(&h, t("j2")).await, Ok(StatusCode::OK));
    assert!(!registry.is_valid(&user, &session).await.unwrap());
}

/// A memory interval an operator set to an extreme value (zero, the largest
/// duration chrono holds, `Duration::MAX`) is a setting, not a way to abort
/// the unauthenticated request that reads it.
#[tokio::test]
async fn an_extreme_unknown_issuer_memory_never_panics_the_request() {
    for extreme in axess_testing::durations::extreme_durations() {
        let h = BackChannelLogoutHandler::for_tenants(
            Arc::new(Counting(Default::default())),
            Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
            SidMap::new(),
            Arc::new(SystemClock),
        )
        .with_unknown_issuer_memory(extreme.value);
        let t = token(
            "https://nobody.example",
            "client-a",
            serde_json::json!({ "sub": "s", "jti": "extreme" }),
        );
        assert_eq!(
            post(&h, t).await,
            Err(StatusCode::BAD_REQUEST),
            "memory of {}",
            extreme.name
        );
    }
}
