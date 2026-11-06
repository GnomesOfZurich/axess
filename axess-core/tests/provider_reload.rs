//! Live provider reload: a refused reload leaves the previous provider
//! serving, an accepted one decides the next login, a removal refuses by
//! name, one tenant's reload leaves another's alone, a login in flight across
//! a swap finishes only against the same issuer, and a coordinated follower
//! converges on its source.
//!
//! Every IdP is a wiremock server on localhost.
//!
//! Run with: `cargo test -p axess-core --features testing-oauth,jwt-aws-lc,fido2,ldap --test provider_reload`

#![cfg(feature = "testing-oauth")]

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{
    AuthnService, BuiltProvider, ProviderChangeKind, ProviderEntry, ProviderKey,
    ProviderReloadError, ProviderSource, ProviderSourceError, ReadCause,
};
use axess_core::federation::oauth_tenant::LiveTenantOAuthProviders;
use axess_core::metrics::MetricSinks;
use axess_core::reload::{InProcessCoordinator, ReloadCoordinator, ReloadFuture};
use axess_core::testing::{
    RecordingMetrics,
    mock_authn::{MockFactorStore, MockIdentityStore},
    oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints},
    test_session,
};
use axess_factors::oauth::{
    OAuthError, OAuthLoginOptions, OAuthProviderBuilder, OAuthProviderConfig,
};
use common::{test_tenant, test_user, tid};
use serde_json::json;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const REDIRECT: &str = "http://localhost:3000/callback";

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

/// One key pair for every IdP of the file: generating RSA keys is the slow
/// part of a test, and the IdPs differ by issuer, not by key.
fn keys() -> &'static (Vec<u8>, serde_json::Value, String) {
    static KEYS: OnceLock<(Vec<u8>, serde_json::Value, String)> = OnceLock::new();
    KEYS.get_or_init(oauth_generate_rsa_keypair)
}

async fn idp() -> MockServer {
    let server = MockServer::start().await;
    oauth_mount_oidc_endpoints(&server, &keys().1).await;
    server
}

/// What `OAuthProviderConfig::discover(..).build()` yields, as a candidate.
async fn candidate(
    name: &str,
    server_uri: &str,
    client_id: &str,
) -> Result<axess_factors::oauth::OAuthProviderConfig, OAuthError> {
    OAuthProviderConfig::discover(name, server_uri, client_id, "secret", REDIRECT)
        .await
        .and_then(OAuthProviderBuilder::build)
}

fn service_with(recorder: &Arc<RecordingMetrics>, providers: Vec<OAuthProviderConfig>) -> Service {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let mut builder = AuthnService::builder(identity, MockFactorStore::new())
        .with_metrics(MetricSinks::all(recorder.clone()));
    for provider in providers {
        builder = builder.with_oauth_provider(provider);
    }
    builder.build()
}

fn recorder() -> Arc<RecordingMetrics> {
    Arc::new(RecordingMetrics::default())
}

/// The authorization URL the next login of `name` starts with.
async fn authorize_url(service: &Service, name: &str) -> Result<url::Url, OAuthError> {
    service
        .with_audit_context(AuditContext::default())
        .begin_oauth_login(name, &OAuthLoginOptions::default(), &test_session())
        .await
        .map(|(url, _)| url)
}

fn client_id_of(url: &url::Url) -> String {
    url.query_pairs()
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned())
        .expect("an authorization URL names its client")
}

async fn eventually(what: &str, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..200 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not happen within 2s: {what}");
}

// ── Refusal ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_reload_with_an_unreachable_discovery_document_is_refused_and_logins_keep_working() {
    let live = idp().await;
    // A loopback port nothing listens on: bind, note the port, close.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let gone_uri = format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);

    let metrics = recorder();
    let service = service_with(
        &metrics,
        vec![candidate("sso", &live.uri(), "old").await.unwrap()],
    );

    let refused = service
        .reload_oauth_provider("sso", candidate("sso", &gone_uri, "new"))
        .await
        .expect_err("a discovery document that cannot be fetched is refused");
    assert!(
        matches!(refused, ProviderReloadError::Build { .. }),
        "{refused}"
    );

    let url = authorize_url(&service, "sso")
        .await
        .expect("the old provider serves");
    assert!(url.as_str().starts_with(&live.uri()));
    assert_eq!(client_id_of(&url), "old");
    assert_eq!(metrics.count("provider_reload_refused:oauth"), 1);
    assert_eq!(metrics.count("provider_reloaded"), 0);
}

#[tokio::test]
async fn a_candidate_named_otherwise_is_refused() {
    let idp = idp().await;
    let service = service_with(
        &recorder(),
        vec![candidate("sso", &idp.uri(), "old").await.unwrap()],
    );

    let refused = service
        .reload_oauth_provider("sso", candidate("other", &idp.uri(), "new"))
        .await
        .expect_err("a provider swapped in under another name is refused");
    assert!(
        matches!(refused, ProviderReloadError::NameMismatch { .. }),
        "{refused}"
    );
    assert_eq!(
        client_id_of(&authorize_url(&service, "sso").await.unwrap()),
        "old"
    );
}

#[tokio::test]
async fn a_candidate_that_does_not_finish_in_time_is_refused() {
    let idp = idp().await;
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_provider_validation_timeout(Duration::from_millis(50))
        .with_oauth_provider(candidate("sso", &idp.uri(), "old").await.unwrap())
        .build();

    let refused = service
        .reload_oauth_provider("sso", async {
            std::future::pending::<()>().await;
            candidate("sso", &idp.uri(), "never").await
        })
        .await
        .expect_err("a candidate past the deadline is refused");
    assert!(
        matches!(refused, ProviderReloadError::TimedOut { .. }),
        "{refused}"
    );
    assert_eq!(
        client_id_of(&authorize_url(&service, "sso").await.unwrap()),
        "old"
    );
}

// ── Acceptance and removal ───────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_reload_changes_the_next_authorize_url() {
    let first = idp().await;
    let second = idp().await;
    let metrics = recorder();
    let service = service_with(
        &metrics,
        vec![candidate("sso", &first.uri(), "old").await.unwrap()],
    );
    assert!(
        authorize_url(&service, "sso")
            .await
            .unwrap()
            .as_str()
            .starts_with(&first.uri())
    );

    let change = service
        .reload_oauth_provider("sso", candidate("sso", &second.uri(), "new"))
        .await
        .expect("a reachable, consistent provider is accepted");
    assert_eq!(change.kind, ProviderChangeKind::Replaced);

    let url = authorize_url(&service, "sso").await.unwrap();
    assert!(url.as_str().starts_with(&second.uri()), "{url}");
    assert_eq!(client_id_of(&url), "new");
    assert_eq!(service.oauth_providers().provider_count(), 1);
    assert_eq!(metrics.count("provider_reloaded:oauth"), 1);

    let added = service
        .reload_oauth_provider("extra", candidate("extra", &first.uri(), "x"))
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    assert_eq!(service.oauth_providers().provider_count(), 2);
}

#[tokio::test]
async fn a_removed_provider_refuses_by_name() {
    let idp = idp().await;
    let metrics = recorder();
    let service = service_with(
        &metrics,
        vec![candidate("sso", &idp.uri(), "c").await.unwrap()],
    );

    let removed = service.remove_oauth_provider("sso").await.unwrap();
    assert_eq!(removed.kind, ProviderChangeKind::Removed);

    let refused = authorize_url(&service, "sso")
        .await
        .expect_err("the route refuses");
    assert!(matches!(refused, OAuthError::UnknownProvider(name) if name == "sso"));
    assert!(!service.has_oauth_providers());
    assert_eq!(metrics.count("provider_removed:oauth"), 1);

    let again = service
        .remove_oauth_provider("sso")
        .await
        .expect_err("nothing to remove");
    assert!(
        matches!(again, ProviderReloadError::NotFound { .. }),
        "{again}"
    );
}

// ── Tenants ──────────────────────────────────────────────────────────────────

fn tenant_service(live: &Arc<LiveTenantOAuthProviders>) -> Service {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    AuthnService::builder(identity, MockFactorStore::new())
        .with_live_tenant_oauth_providers(live.clone())
        .build()
}

async fn tenant_url(
    service: &Service,
    tenant: &TenantId,
    name: &str,
) -> Result<url::Url, OAuthError> {
    service
        .with_audit_context(AuditContext::default())
        .begin_oauth_login_with_tenant_provider(
            name,
            &OAuthLoginOptions::default(),
            tenant,
            &test_session(),
        )
        .await
        .map(|(url, _)| url)
}

#[tokio::test]
async fn a_tenants_reload_leaves_another_tenants_provider_untouched() {
    let (a, b, c) = (idp().await, idp().await, idp().await);
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = tenant_service(&live);
    let (acme, globex) = (tid("acme"), tid("globex"));

    service
        .reload_tenant_oauth_provider(&acme, "sso", candidate("sso", &a.uri(), "acme-1"))
        .await
        .unwrap();
    service
        .reload_tenant_oauth_provider(&globex, "sso", candidate("sso", &b.uri(), "globex-1"))
        .await
        .unwrap();
    let globex_before = live.get(&globex, "sso").expect("globex has one");

    service
        .reload_tenant_oauth_provider(&acme, "sso", candidate("sso", &c.uri(), "acme-2"))
        .await
        .unwrap();

    let acme_url = tenant_url(&service, &acme, "sso").await.unwrap();
    assert!(acme_url.as_str().starts_with(&c.uri()), "{acme_url}");
    let globex_url = tenant_url(&service, &globex, "sso").await.unwrap();
    assert!(globex_url.as_str().starts_with(&b.uri()), "{globex_url}");
    assert!(
        Arc::ptr_eq(&globex_before, &live.get(&globex, "sso").unwrap()),
        "globex's provider is the same object, not rebuilt"
    );

    service
        .remove_tenant_oauth_provider(&acme, "sso")
        .await
        .unwrap();
    assert!(tenant_url(&service, &acme, "sso").await.is_err());
    assert!(tenant_url(&service, &globex, "sso").await.is_ok());
    assert_eq!(live.len(), 1);
}

#[tokio::test]
async fn a_tenant_reload_without_a_live_registry_is_refused_by_name() {
    let idp = idp().await;
    let service = service_with(&recorder(), vec![]);
    let refused = service
        .reload_tenant_oauth_provider(&tid("acme"), "sso", candidate("sso", &idp.uri(), "c"))
        .await
        .expect_err("no registry to put it in");
    assert!(
        matches!(refused, ProviderReloadError::NoTenantRegistry),
        "{refused}"
    );
}

// ── A login in flight across a swap ──────────────────────────────────────────

fn id_token(issuer: &str, client_id: &str, nonce: &str) -> String {
    let (der, _, kid) = keys();
    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.clone());
    axess_factors::jwt::ensure_crypto_provider();
    jsonwebtoken::encode(
        &header,
        &json!({
            "iss": issuer, "sub": "alice-subject", "aud": client_id,
            "exp": now + 3600, "iat": now, "nonce": nonce,
            "email": "alice@example.com", "email_verified": true,
        }),
        &jsonwebtoken::EncodingKey::from_rsa_der(der),
    )
    .expect("JWT encode")
}

async fn mount_token_endpoint(server: &MockServer, client_id: &str, nonce: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access", "token_type": "Bearer", "expires_in": 3600,
            "id_token": id_token(&server.uri(), client_id, nonce),
        })))
        .mount(server)
        .await;
}

async fn begin_and_read(
    service: &Service,
    session: &axess_core::session::extractor::AuthSession,
) -> (String, String) {
    service
        .with_audit_context(AuditContext::default())
        .begin_oauth_login("sso", &OAuthLoginOptions::default(), session)
        .await
        .expect("begin");
    let get = async |key: &str| {
        session
            .get_custom(key)
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .expect("stashed")
    };
    (
        get("axess.oauth.csrf_state").await,
        get("axess.oauth.nonce").await,
    )
}

#[tokio::test]
async fn a_login_in_flight_across_a_swap_to_the_same_issuer_finishes() {
    let idp = idp().await;
    let service = service_with(
        &recorder(),
        vec![candidate("sso", &idp.uri(), "client-v1").await.unwrap()],
    );
    let session = test_session();
    let (state, nonce) = begin_and_read(&service, &session).await;

    // The client credential rotated while the user was at the IdP.
    service
        .reload_oauth_provider("sso", candidate("sso", &idp.uri(), "client-v2"))
        .await
        .unwrap();
    mount_token_endpoint(&idp, "client-v2", &nonce).await;

    let claims = service
        .with_audit_context(AuditContext::default())
        .finish_oauth_login("code", &state, &session)
        .await
        .expect("the same issuer honours the ceremony");
    assert_eq!(claims.subject.as_str(), "alice-subject");
}

#[tokio::test]
async fn a_login_in_flight_across_a_swap_to_another_issuer_is_refused() {
    let (old, new) = (idp().await, idp().await);
    let service = service_with(
        &recorder(),
        vec![candidate("sso", &old.uri(), "c").await.unwrap()],
    );
    let session = test_session();
    let (state, nonce) = begin_and_read(&service, &session).await;

    service
        .reload_oauth_provider("sso", candidate("sso", &new.uri(), "c"))
        .await
        .unwrap();
    mount_token_endpoint(&new, "c", &nonce).await;

    let refused = service
        .with_audit_context(AuditContext::default())
        .finish_oauth_login("code", &state, &session)
        .await
        .expect_err("a code from the old issuer is not taken to the new one");
    assert!(matches!(refused, OAuthError::CsrfMismatch), "{refused:?}");
}

// ── Across instances ─────────────────────────────────────────────────────────

/// A source whose entries and the IdP each entry points at the test sets.
struct TestSource {
    entries: Mutex<Vec<ProviderEntry>>,
    uris: Mutex<HashMap<ProviderKey, String>>,
    desired_calls: AtomicUsize,
}

impl TestSource {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(Vec::new()),
            uris: Mutex::new(HashMap::new()),
            desired_calls: AtomicUsize::new(0),
        })
    }

    fn set_oauth(&self, name: &str, uri: &str, revision: &str) {
        let key = ProviderKey::OAuth {
            tenant: None,
            name: Arc::from(name),
        };
        self.uris
            .lock()
            .unwrap()
            .insert(key.clone(), uri.to_string());
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.key != key);
        entries.push(ProviderEntry {
            key,
            revision: revision.to_string(),
        });
    }

    #[cfg(feature = "fido2")]
    fn set_fido2(&self, revision: &str) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.key != ProviderKey::Fido2);
        entries.push(ProviderEntry {
            key: ProviderKey::Fido2,
            revision: revision.to_string(),
        });
    }

    fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

impl ProviderSource for TestSource {
    fn desired(&self) -> ReloadFuture<'_, Result<Vec<ProviderEntry>, ProviderSourceError>> {
        self.desired_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(self.entries.lock().unwrap().clone()) })
    }

    fn build<'a>(
        &'a self,
        key: &'a ProviderKey,
    ) -> ReloadFuture<'a, Result<BuiltProvider, ProviderSourceError>> {
        Box::pin(async move {
            #[cfg(feature = "fido2")]
            if *key == ProviderKey::Fido2 {
                return Ok(BuiltProvider::Fido2(Arc::new(
                    axess_factors::fido2::MockFido2Provider::new(),
                )));
            }
            let uri = self
                .uris
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| ProviderSourceError("unknown key".into()))?;
            let ProviderKey::OAuth { name, .. } = key else {
                return Err(ProviderSourceError("not an OAuth key".into()));
            };
            let provider = candidate(name, &uri, "followed")
                .await
                .map_err(|e| ProviderSourceError(e.to_string()))?;
            Ok(BuiltProvider::OAuth(Arc::new(provider)))
        })
    }
}

fn follower_service(bus: Arc<dyn ReloadCoordinator>) -> Service {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    AuthnService::builder(identity, MockFactorStore::new())
        .with_provider_coordinator(bus)
        .build()
}

fn bus(capacity: usize) -> Arc<InProcessCoordinator> {
    Arc::new(InProcessCoordinator::new(
        NonZeroUsize::new(capacity).unwrap(),
    ))
}

#[tokio::test]
async fn the_coordinator_delivers_a_change_to_a_second_service() {
    let (first, second) = (idp().await, idp().await);
    let bus = bus(16);
    let a = follower_service(bus.clone());
    let b = follower_service(bus.clone());
    let source = TestSource::new();
    // An hour away: only a notice can make the follower read again.
    let _follower = b
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    eventually("the follower read the source at start", async || {
        source.desired_calls.load(Ordering::SeqCst) >= 1
    })
    .await;

    // The adopter updates the source, then reloads one instance.
    source.set_oauth("sso", &second.uri(), "r1");
    let change = a
        .reload_oauth_provider("sso", candidate("sso", &second.uri(), "local"))
        .await
        .unwrap();
    assert!(change.announced);

    eventually("B follows A", async || b.has_oauth_providers()).await;
    let url = authorize_url(&b, "sso").await.unwrap();
    assert!(url.as_str().starts_with(&second.uri()), "{url}");
    assert_eq!(
        client_id_of(&url),
        "followed",
        "B built it from its source, not from A"
    );

    // The source stops listing it: the follower removes what it installed.
    source.clear();
    bus.announce("oauth:-:sso").await.unwrap();
    eventually("B drops it", async || !b.has_oauth_providers()).await;
    drop(first);
}

#[tokio::test]
async fn a_notice_cannot_install_a_provider_the_source_does_not_hold() {
    let bus = bus(16);
    let b = follower_service(bus.clone());
    let source = TestSource::new();
    let _follower = b
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    eventually("start read", async || {
        source.desired_calls.load(Ordering::SeqCst) >= 1
    })
    .await;
    let reads = source.desired_calls.load(Ordering::SeqCst);

    bus.announce("oauth:-:evil").await.unwrap();
    eventually("the notice made it re-read", async || {
        source.desired_calls.load(Ordering::SeqCst) > reads
    })
    .await;
    assert!(!b.has_oauth_providers());
}

#[tokio::test]
async fn a_lagging_follower_converges_on_the_source() {
    let idp = idp().await;
    // Capacity 2 on a single-threaded runtime: the follower does not run
    // between the announcements below, so its receiver must lag.
    let bus = bus(2);
    let b = follower_service(bus.clone());
    let source = TestSource::new();
    let follower = b
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    eventually("start read", async || {
        source.desired_calls.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(follower.reads(ReadCause::Start), 1);
    assert_eq!(follower.reads(ReadCause::Lagged), 0);

    let mut probe = bus.subscribe().await.unwrap();
    source.set_oauth("sso", &idp.uri(), "r1");
    for i in 0..8 {
        bus.announce(&format!("notice-{i}")).await.unwrap();
    }
    assert!(
        matches!(
            probe.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
        ),
        "eight notices into a channel of two must lag a reader that is behind"
    );

    eventually("the lagged follower converges", async || {
        b.has_oauth_providers()
    })
    .await;
    // The read that converged it was the lag arm's: the follower names why
    // it read, so a lag arm that is gone leaves this at zero.
    assert!(
        follower.reads(ReadCause::Lagged) >= 1,
        "the lagged receiver re-read as Lagged"
    );
    assert_eq!(
        follower.reads(ReadCause::Poll),
        0,
        "the hour-long poll did not fire"
    );
}

#[tokio::test]
async fn following_without_a_coordinator_or_with_a_zero_poll_is_refused_by_name() {
    let none = service_with(&recorder(), vec![]);
    assert!(
        none.follow_provider_reloads(TestSource::new(), Duration::from_secs(1))
            .await
            .is_err()
    );
    let some = follower_service(bus(4));
    assert!(
        some.follow_provider_reloads(TestSource::new(), Duration::ZERO)
            .await
            .is_err()
    );
}

// ── FIDO2 and LDAP ───────────────────────────────────────────────────────────

#[cfg(feature = "fido2")]
#[tokio::test]
async fn a_fido2_reload_refuses_a_candidate_that_does_not_build_and_accepts_one_that_does() {
    use axess_factors::fido2::MockFido2Provider;
    let metrics = recorder();
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_metrics(MetricSinks::all(metrics.clone()))
        .with_fido2(MockFido2Provider::new())
        .build();

    let refused = service
        .reload_fido2(async { Err::<MockFido2Provider, _>("relying party id is not a domain") })
        .await
        .expect_err("a relying party that does not parse is refused");
    assert!(
        matches!(refused, ProviderReloadError::Build { .. }),
        "{refused}"
    );
    assert!(service.has_fido2());
    assert_eq!(metrics.count("provider_reload_refused:fido2"), 1);

    let ok = service
        .reload_fido2(async { Ok::<_, String>(MockFido2Provider::new()) })
        .await
        .unwrap();
    assert_eq!(ok.kind, ProviderChangeKind::Replaced);
    assert_eq!(metrics.count("provider_reloaded:fido2"), 1);
}

#[cfg(feature = "ldap")]
#[tokio::test]
async fn an_ldap_reload_refuses_an_unreachable_directory_and_accepts_a_reachable_one() {
    use axess_factors::ldap::{LdapProviderConfig, MockLdapProvider};
    let metrics = recorder();
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_metrics(MetricSinks::all(metrics.clone()))
        .with_ldap(MockLdapProvider::new("{user}@corp"))
        .build();

    // Nothing listens on port 1 of the loopback address.
    let unreachable = LdapProviderConfig::new("ldap://127.0.0.1:1", "{user}@corp")
        .with_timeout(Duration::from_secs(2));
    let refused = service
        .reload_ldap(async { Ok::<_, String>(unreachable) })
        .await
        .expect_err("a directory that does not answer is refused");
    assert!(
        matches!(refused, ProviderReloadError::Unreachable { .. }),
        "{refused}"
    );
    assert!(service.has_ldap());
    assert_eq!(metrics.count("provider_reload_refused:ldap"), 1);

    let ok = service
        .reload_ldap(async { Ok::<_, String>(MockLdapProvider::new("{user}@new")) })
        .await
        .unwrap();
    assert_eq!(ok.kind, ProviderChangeKind::Replaced);
}

#[cfg(feature = "fido2")]
#[tokio::test]
async fn a_source_that_drops_fido2_removes_what_the_follower_installed_and_only_that() {
    use axess_factors::fido2::MockFido2Provider;
    let bus = bus(16);
    let source = TestSource::new();

    // Installed by the follower: withdrawn when the source stops listing it.
    let follower_built = follower_service(bus.clone());
    let _follower = follower_built
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    source.set_fido2("r1");
    bus.announce("fido2").await.unwrap();
    eventually("the follower installs FIDO2", async || {
        follower_built.has_fido2()
    })
    .await;
    source.clear();
    bus.announce("fido2").await.unwrap();
    eventually("the follower withdraws FIDO2", async || {
        !follower_built.has_fido2()
    })
    .await;

    // Registered at construction and never named by the source: left alone.
    let other_bus = self::bus(16);
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let constructed = AuthnService::builder(identity, MockFactorStore::new())
        .with_provider_coordinator(other_bus.clone())
        .with_fido2(MockFido2Provider::new())
        .build();
    let empty = TestSource::new();
    let _second = constructed
        .follow_provider_reloads(empty.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    let reads = empty.desired_calls.load(Ordering::SeqCst);
    other_bus.announce("fido2").await.unwrap();
    eventually("the second follower read its source", async || {
        empty.desired_calls.load(Ordering::SeqCst) > reads
    })
    .await;
    assert!(
        constructed.has_fido2(),
        "a provider the follower never installed stays in force"
    );
}
