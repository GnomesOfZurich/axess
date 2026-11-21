//! Live provider reload: a refused reload leaves the previous provider
//! serving, an accepted one decides the next login, a removal refuses by
//! name, one tenant's reload leaves another's alone, a login in flight across
//! a swap finishes only against the same issuer, and a coordinated follower
//! converges on its source.
//!
//! Every IdP is a wiremock server on localhost.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc,fido2,ldap --test provider_reload`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::service::OAuthCallbackRoute;

use axess_core::authn::AuditContext;
use axess_core::authn::factor::FederatedProvider;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{
    AuthnService, BuiltProvider, ProviderChangeError, ProviderChangeKind, ProviderEntry,
    ProviderKey, ProviderReloadError, ProviderSource, ProviderSourceError, ReadCause,
};
use axess_core::federation::oauth_tenant::LiveTenantOAuthProviders;
use axess_core::metrics::MetricSinks;
use axess_core::reload::{InProcessCoordinator, ReloadCoordinator, ReloadFuture};
use axess_core::testing::{
    RecordingMetrics,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::oauth::{
    OAuthError, OAuthLoginOptions, OAuthProviderBuilder, OAuthProviderConfig,
};
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use common::{provider_admin, reload_refusal, test_tenant, test_user, tid, uid};
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

/// What `OAuthProviderConfig::discover_screened(.., axess_factors::egress::EgressPolicy::screened_allowing_loopback_http()).build()` yields, as a candidate.
async fn candidate(
    clock: &MockClock,
    name: &str,
    server_uri: &str,
    client_id: &str,
) -> Result<axess_factors::oauth::OAuthProviderConfig, OAuthError> {
    OAuthProviderConfig::discover_screened(
        name,
        server_uri,
        client_id,
        "secret",
        REDIRECT,
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .map(|b| b.with_clock(std::sync::Arc::new(clock.clone())))
    .and_then(OAuthProviderBuilder::build)
}

fn service_with(
    clock: &MockClock,
    recorder: &Arc<RecordingMetrics>,
    providers: Vec<OAuthProviderConfig>,
) -> Service {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let mut builder = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
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
    let clock = common::test_clock();
    let live = idp().await;
    // A loopback port nothing listens on: bind, note the port, close.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let gone_uri = format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);

    let metrics = recorder();
    let service = service_with(
        &clock,
        &metrics,
        vec![candidate(&clock, "sso", &live.uri(), "old").await.unwrap()],
    );

    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &gone_uri, "new"),
        )
        .await
        .map_err(reload_refusal)
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

/// A provider's name may be its tenant's text: the line that records a
/// refused reload carries it escaped.
#[tokio::test]
async fn a_refused_reloads_provider_name_is_logged_escaped() {
    let clock = common::test_clock();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let gone_uri = format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let service = service_with(&clock, &recorder(), vec![]);
    let forged = "sso\nWARN forged\u{202E}";
    let capture = axess_testing::mock_tracing::TracingCapture::install();

    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            forged,
            FederatedProvider::Custom(forged.into()),
            candidate(&clock, forged, &gone_uri, "new"),
        )
        .await;
    assert!(refused.is_err());

    let events = capture.events();
    let line = events
        .iter()
        .find(|e| e.message.contains("provider reload refused"))
        .unwrap_or_else(|| panic!("no line for the refusal among {events:?}"));
    assert!(
        !line.message.chars().any(axess_identity::log_text::escapes),
        "{:?}",
        line.message
    );
    assert!(line.message.contains("WARN forged"), "{:?}", line.message);
}

#[tokio::test]
async fn a_candidate_named_otherwise_is_refused() {
    let clock = common::test_clock();
    let idp = idp().await;
    let service = service_with(
        &clock,
        &recorder(),
        vec![candidate(&clock, "sso", &idp.uri(), "old").await.unwrap()],
    );

    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "other", &idp.uri(), "new"),
        )
        .await
        .map_err(reload_refusal)
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
    let clock = common::test_clock();
    let idp = idp().await;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_provider_validation_timeout(Duration::from_millis(50))
        .with_oauth_provider(candidate(&clock, "sso", &idp.uri(), "old").await.unwrap())
        .build();

    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            async {
                std::future::pending::<()>().await;
                candidate(&clock, "sso", &idp.uri(), "never").await
            },
        )
        .await
        .map_err(reload_refusal)
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
    let clock = common::test_clock();
    let first = idp().await;
    let second = idp().await;
    let metrics = recorder();
    let service = service_with(
        &clock,
        &metrics,
        vec![candidate(&clock, "sso", &first.uri(), "old").await.unwrap()],
    );
    assert!(
        authorize_url(&service, "sso")
            .await
            .unwrap()
            .as_str()
            .starts_with(&first.uri())
    );

    let change = service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &second.uri(), "new"),
        )
        .await
        .expect("a reachable, consistent provider is accepted");
    assert_eq!(change.kind, ProviderChangeKind::Replaced);

    let url = authorize_url(&service, "sso").await.unwrap();
    assert!(url.as_str().starts_with(&second.uri()), "{url}");
    assert_eq!(client_id_of(&url), "new");
    assert_eq!(service.oauth_providers().provider_count(), 1);
    assert_eq!(metrics.count("provider_reloaded:oauth"), 1);

    let added = service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "extra",
            FederatedProvider::Custom("extra".into()),
            candidate(&clock, "extra", &first.uri(), "x"),
        )
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    assert_eq!(service.oauth_providers().provider_count(), 2);
}

#[tokio::test]
async fn a_removed_provider_refuses_by_name() {
    let clock = common::test_clock();
    let idp = idp().await;
    let metrics = recorder();
    let service = service_with(
        &clock,
        &metrics,
        vec![candidate(&clock, "sso", &idp.uri(), "c").await.unwrap()],
    );

    let removed = service
        .with_audit_context(AuditContext::default())
        .remove_oauth_provider_as(&provider_admin(), "sso")
        .await
        .unwrap();
    assert_eq!(removed.kind, ProviderChangeKind::Removed);

    let refused = authorize_url(&service, "sso")
        .await
        .expect_err("the route refuses");
    assert!(matches!(refused, OAuthError::UnknownProvider(name) if name == "sso"));
    assert!(!service.has_oauth_providers());
    assert_eq!(metrics.count("provider_removed:oauth"), 1);

    let again = service
        .with_audit_context(AuditContext::default())
        .remove_oauth_provider_as(&provider_admin(), "sso")
        .await
        .map_err(reload_refusal)
        .expect_err("nothing to remove");
    assert!(
        matches!(again, ProviderReloadError::NotFound { .. }),
        "{again}"
    );
}

// ── Tenants ──────────────────────────────────────────────────────────────────

fn tenant_service(clock: &MockClock, live: &Arc<LiveTenantOAuthProviders>) -> Service {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
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
    let clock = common::test_clock();
    let (a, b, c) = (idp().await, idp().await, idp().await);
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = tenant_service(&clock, &live);
    let (acme, globex) = (tid("acme"), tid("globex"));

    service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &provider_admin(),
            &acme,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &a.uri(), "acme-1"),
        )
        .await
        .unwrap();
    service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &provider_admin(),
            &globex,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &b.uri(), "globex-1"),
        )
        .await
        .unwrap();
    let globex_before = live.get(&globex, "sso").expect("globex has one");

    service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &provider_admin(),
            &acme,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &c.uri(), "acme-2"),
        )
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
        .with_audit_context(AuditContext::default())
        .remove_tenant_oauth_provider_as(&provider_admin(), &acme, "sso")
        .await
        .unwrap();
    assert!(tenant_url(&service, &acme, "sso").await.is_err());
    assert!(tenant_url(&service, &globex, "sso").await.is_ok());
    assert_eq!(live.len(), 1);
}

/// A tenant's provider changed by an administrator is accounted for: the
/// reload writes one `MethodEnabled` row and the removal one `MethodDisabled`
/// row, each naming the administrator, the tenant and the provider, and
/// nothing else is written.
#[tokio::test]
async fn a_tenant_provider_change_by_an_administrator_writes_one_audit_row_naming_them() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    use axess_core::authn::factor::FactorKind;
    let clock = common::test_clock();
    let idp = idp().await;
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_live_tenant_oauth_providers(live.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let (acme, admin) = (tid("acme"), uid("admin-1"));

    let added = request
        .reload_tenant_oauth_provider_as(
            &admin,
            &acme,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &idp.uri(), "acme-1"),
        )
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    let removed = request
        .remove_tenant_oauth_provider_as(&admin, &acme, "sso")
        .await
        .unwrap();
    assert_eq!(removed.kind, ProviderChangeKind::Removed);
    assert!(live.get(&acme, "sso").is_none());

    let rows = identity.events();
    assert_eq!(rows.len(), 2, "one row per change: {rows:?}");
    for (row, event_type) in rows
        .iter()
        .zip([AuthEventType::MethodEnabled, AuthEventType::MethodDisabled])
    {
        assert_eq!(row.event_type, event_type);
        assert_eq!(row.event_status, AuthEventStatus::Success);
        assert_eq!(row.actor_id, Some(admin), "the administrator is the actor");
        assert_eq!(row.tenant_id, Some(acme), "the row is the tenant's");
        assert_eq!(
            row.factor_kind,
            Some(FactorKind::Federated(FederatedProvider::Custom(
                "sso".into()
            )))
        );
        assert!(
            row.user_id.is_none(),
            "the subject is the provider, not a user"
        );
    }
}

/// A refused change is accounted for too, as a failure row with the refusal.
#[tokio::test]
async fn a_refused_provider_change_writes_a_failure_row() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_live_tenant_oauth_providers(live.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());

    let refused = request
        .remove_tenant_oauth_provider_as(&uid("admin-1"), &tid("acme"), "sso")
        .await
        .expect_err("nothing to remove");
    assert!(
        matches!(
            refused,
            ProviderChangeError::Refused(ProviderReloadError::NotFound { .. })
        ),
        "{refused}"
    );

    let rows = identity.events();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_type, AuthEventType::MethodDisabled);
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(rows[0].actor_id, Some(uid("admin-1")));
    assert!(
        rows[0]
            .error
            .as_ref()
            .is_some_and(|e| e.as_str().contains("no such provider")),
        "{:?}",
        rows[0].error
    );
}

/// A change whose audit row cannot be written does not stand: the removal
/// and the reload are undone and refused by name, and the provider in force
/// before them keeps serving.
#[tokio::test]
async fn a_provider_change_whose_audit_row_cannot_be_written_is_undone() {
    let clock = common::test_clock();
    let (a, b) = (idp().await, idp().await);
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_live_tenant_oauth_providers(live.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let (acme, admin) = (tid("acme"), uid("admin-1"));
    request
        .reload_tenant_oauth_provider_as(
            &admin,
            &acme,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &a.uri(), "acme-1"),
        )
        .await
        .unwrap();
    let in_force = live.get(&acme, "sso").expect("installed");

    identity.arm_record_event_failure();
    let refused = request
        .remove_tenant_oauth_provider_as(&admin, &acme, "sso")
        .await
        .expect_err("a removal nobody can account for does not stand");
    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
    let still = live.get(&acme, "sso").expect("the removal was undone");
    assert!(Arc::ptr_eq(&in_force, &still), "the same provider serves");

    let refused = request
        .reload_tenant_oauth_provider_as(
            &admin,
            &acme,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &b.uri(), "acme-2"),
        )
        .await
        .expect_err("a reload nobody can account for does not stand");
    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
    let still = live.get(&acme, "sso").expect("the reload was undone");
    assert!(Arc::ptr_eq(&in_force, &still), "the same provider serves");
    let url = tenant_url(&service, &acme, "sso").await.unwrap();
    assert!(url.as_str().starts_with(&a.uri()), "{url}");
}

#[tokio::test]
async fn a_tenant_reload_without_a_live_registry_is_refused_by_name() {
    let clock = common::test_clock();
    let idp = idp().await;
    let service = service_with(&clock, &recorder(), vec![]);
    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &provider_admin(),
            &tid("acme"),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &idp.uri(), "c"),
        )
        .await
        .map_err(reload_refusal)
        .expect_err("no registry to put it in");
    assert!(
        matches!(refused, ProviderReloadError::NoTenantRegistry),
        "{refused}"
    );
}

// ── A login in flight across a swap ──────────────────────────────────────────

fn id_token(issuer: &str, client_id: &str, nonce: &str) -> String {
    let (der, _, kid) = keys();
    let now = common::start().unix_seconds();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.clone());
    axess_factors::jwt::encode(
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
    let clock = common::test_clock();
    let idp = idp().await;
    let service = service_with(
        &clock,
        &recorder(),
        vec![
            candidate(&clock, "sso", &idp.uri(), "client-v1")
                .await
                .unwrap(),
        ],
    );
    let session = test_session();
    let (state, nonce) = begin_and_read(&service, &session).await;

    // The client credential rotated while the user was at the IdP.
    service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &idp.uri(), "client-v2"),
        )
        .await
        .unwrap();
    mount_token_endpoint(&idp, "client-v2", &nonce).await;

    let claims = service
        .with_audit_context(AuditContext::default())
        .finish_oauth_login(
            OAuthCallbackRoute::global("sso"),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect("the same issuer honours the ceremony");
    assert_eq!(claims.subject.as_str(), "alice-subject");
}

#[tokio::test]
async fn a_login_in_flight_across_a_swap_to_another_issuer_is_refused() {
    let clock = common::test_clock();
    let (old, new) = (idp().await, idp().await);
    let service = service_with(
        &clock,
        &recorder(),
        vec![candidate(&clock, "sso", &old.uri(), "c").await.unwrap()],
    );
    let session = test_session();
    let (state, nonce) = begin_and_read(&service, &session).await;

    service
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &new.uri(), "c"),
        )
        .await
        .unwrap();
    mount_token_endpoint(&new, "c", &nonce).await;

    let refused = service
        .with_audit_context(AuditContext::default())
        .finish_oauth_login(
            OAuthCallbackRoute::global("sso"),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect_err("a code from the old issuer is not taken to the new one");
    assert!(matches!(refused, OAuthError::CsrfMismatch), "{refused:?}");
}

// ── Across instances ─────────────────────────────────────────────────────────

/// A source whose entries and the IdP each entry points at the test sets.
/// It builds what it lists on the clock of the test's world.
struct TestSource {
    clock: MockClock,
    entries: Mutex<Vec<ProviderEntry>>,
    uris: Mutex<HashMap<ProviderKey, String>>,
    desired_calls: AtomicUsize,
}

impl TestSource {
    fn new(clock: &MockClock) -> Arc<Self> {
        Arc::new(Self {
            clock: clock.clone(),
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
            let name = match key {
                ProviderKey::OAuth { name, .. } => name,
                // The other keys exist only with their features on.
                #[cfg(any(feature = "fido2", feature = "ldap"))]
                _ => return Err(ProviderSourceError("not an OAuth key".into())),
            };
            let provider = candidate(&self.clock, name, &uri, "followed")
                .await
                .map_err(|e| ProviderSourceError(e.to_string()))?;
            Ok(BuiltProvider::OAuth {
                provider: Arc::new(provider),
                kind: FederatedProvider::Custom(name.to_string()),
            })
        })
    }
}

fn follower_service(clock: &MockClock, bus: Arc<dyn ReloadCoordinator>) -> Service {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
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
    let clock = common::test_clock();
    let (first, second) = (idp().await, idp().await);
    let bus = bus(16);
    let a = follower_service(&clock, bus.clone());
    let b = follower_service(&clock, bus.clone());
    let source = TestSource::new(&clock);
    // An hour away: only a notice can make the follower read again.
    let follower = b
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
        .with_audit_context(AuditContext::default())
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &second.uri(), "local"),
        )
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
    drop(follower);
}

#[tokio::test]
async fn a_notice_cannot_install_a_provider_the_source_does_not_hold() {
    let clock = common::test_clock();
    let bus = bus(16);
    let b = follower_service(&clock, bus.clone());
    let source = TestSource::new(&clock);
    let follower = b
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
    drop(follower);
}

#[tokio::test]
async fn a_lagging_follower_converges_on_the_source() {
    let clock = common::test_clock();
    let idp = idp().await;
    // Capacity 2 on a single-threaded runtime: the follower does not run
    // between the announcements below, so its receiver must lag.
    let bus = bus(2);
    let b = follower_service(&clock, bus.clone());
    let source = TestSource::new(&clock);
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
    let clock = common::test_clock();
    let none = service_with(&clock, &recorder(), vec![]);
    assert!(
        none.follow_provider_reloads(TestSource::new(&clock), Duration::from_secs(1))
            .await
            .is_err()
    );
    let some = follower_service(&clock, bus(4));
    assert!(
        some.follow_provider_reloads(TestSource::new(&clock), Duration::ZERO)
            .await
            .is_err()
    );
}

// ── FIDO2 and LDAP ───────────────────────────────────────────────────────────

#[cfg(feature = "fido2")]
#[tokio::test]
async fn a_fido2_reload_refuses_a_candidate_that_does_not_build_and_accepts_one_that_does() {
    use axess_factors::fido2::MockFido2Provider;
    let clock = common::test_clock();
    let metrics = recorder();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_metrics(MetricSinks::all(metrics.clone()))
        .with_fido2(MockFido2Provider::new())
        .build();

    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_fido2_as(&provider_admin(), async {
            Err::<MockFido2Provider, _>("relying party id is not a domain")
        })
        .await
        .map_err(reload_refusal)
        .expect_err("a relying party that does not parse is refused");
    assert!(
        matches!(refused, ProviderReloadError::Build { .. }),
        "{refused}"
    );
    assert!(service.has_fido2());
    assert_eq!(metrics.count("provider_reload_refused:fido2"), 1);

    let ok = service
        .with_audit_context(AuditContext::default())
        .reload_fido2_as(&provider_admin(), async {
            Ok::<_, String>(MockFido2Provider::new())
        })
        .await
        .unwrap();
    assert_eq!(ok.kind, ProviderChangeKind::Replaced);
    assert_eq!(metrics.count("provider_reloaded:fido2"), 1);
}

#[cfg(feature = "ldap")]
#[tokio::test]
async fn an_ldap_reload_refuses_an_unreachable_directory_and_accepts_a_reachable_one() {
    use axess_factors::ldap::{LdapProviderConfig, MockLdapProvider};
    let clock = common::test_clock();
    let metrics = recorder();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_metrics(MetricSinks::all(metrics.clone()))
        .with_ldap(MockLdapProvider::new("{user}@corp"))
        .build();

    // Nothing listens on port 1 of the loopback address.
    let unreachable = LdapProviderConfig::new("ldap://127.0.0.1:1", "{user}@corp")
        .with_timeout(Duration::from_secs(2));
    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_ldap_as(&provider_admin(), async { Ok::<_, String>(unreachable) })
        .await
        .map_err(reload_refusal)
        .expect_err("a directory that does not answer is refused");
    assert!(
        matches!(refused, ProviderReloadError::Unreachable { .. }),
        "{refused}"
    );
    assert!(service.has_ldap());
    assert_eq!(metrics.count("provider_reload_refused:ldap"), 1);

    let ok = service
        .with_audit_context(AuditContext::default())
        .reload_ldap_as(&provider_admin(), async {
            Ok::<_, String>(MockLdapProvider::new("{user}@new"))
        })
        .await
        .unwrap();
    assert_eq!(ok.kind, ProviderChangeKind::Replaced);
}

#[cfg(feature = "fido2")]
#[tokio::test]
async fn a_source_that_drops_fido2_removes_what_the_follower_installed_and_only_that() {
    use axess_factors::fido2::MockFido2Provider;
    let clock = common::test_clock();
    let bus = bus(16);
    let source = TestSource::new(&clock);

    // Installed by the follower: withdrawn when the source stops listing it.
    let follower_built = follower_service(&clock, bus.clone());
    let follower = follower_built
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
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let constructed = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_provider_coordinator(other_bus.clone())
        .with_fido2(MockFido2Provider::new())
        .build();
    let empty = TestSource::new(&clock);
    let second = constructed
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
    drop(follower);
    drop(second);
}
