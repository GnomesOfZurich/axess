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
    iss: &str,
    sid: &str,
) -> (crate::authn::ids::UserId, SessionId) {
    let user = axess_identity::testing::user(user);
    let session = SessionId::new(rng);
    registry.register(&user, &session).await.unwrap();
    sid_map.insert(
        (iss.to_string(), sid.to_string()),
        "idp-sub",
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
    let (ua, sa) = login(&registry, &sid_map, &rng, "alice", ISS_A, "same-sid").await;
    let (ub, sb) = login(&registry, &sid_map, &rng, "bob", ISS_B, "same-sid").await;

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
    let (user, session) = login(&registry, &sid_map, &rng, "alice", ISS_A, "s1").await;

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

/// A tenant provider that matches a global one's issuer and client id is the
/// same ambiguity.
#[tokio::test]
async fn a_tenant_matching_the_global_registration_is_ambiguous_too() {
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
    .with_tenant_providers(Arc::new(Source {
        providers: vec![offered("acme", ISS_A, "client-x")],
        fails: false,
    }));
    let claims = serde_json::json!({ "aud": "client-x" });
    assert!(matches!(
        h.entry_for(ISS_A, &claims).await,
        Err(LogoutProviderError::Ambiguous { global: true, .. })
    ));
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
    let (user, session) = login(&registry, &sid_map, &rng, "alice", ISS_A, "s1").await;

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
    let (user, session) = login(&registry, &sid_map, &rng, "bob", ISS_A, "s2").await;

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
