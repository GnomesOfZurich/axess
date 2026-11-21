//! The kind a reload names is the kind of the provider it installs: every
//! way a provider arrives, at construction, by an administrator's reload of
//! a global or a tenant's provider, or from the source a follower reads,
//! configures the `FederatedProvider` the logins through it record and the
//! audit rows of the change name. A removal's row names the kind of the
//! provider it took out, and an undone change puts the kind back with the
//! provider.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test provider_reload_kind`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType, AuthFailureReason};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::service::{
    AuthnService, BuiltProvider, OAuthCallbackRoute, PROVIDER_SOURCE_REASON, ProviderChangeError,
    ProviderEntry, ProviderKey, ProviderSource, ProviderSourceError,
};
use axess_core::federation::oauth_tenant::{LiveTenantOAuthProviders, TenantOAuthProviders};
use axess_core::reload::{InProcessCoordinator, ReloadCoordinator, ReloadFuture};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::oauth::{
    OAuthError, OAuthLoginOptions, OAuthProviderBuilder, OAuthProviderConfig,
};
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use common::{provider_admin, test_tenant, test_user, tid};
use serde_json::json;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "client";

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

fn keys() -> &'static (Vec<u8>, serde_json::Value, String) {
    static KEYS: OnceLock<(Vec<u8>, serde_json::Value, String)> = OnceLock::new();
    KEYS.get_or_init(oauth_generate_rsa_keypair)
}

async fn idp() -> MockServer {
    let server = MockServer::start().await;
    oauth_mount_oidc_endpoints(&server, &keys().1).await;
    server
}

async fn candidate(
    clock: &MockClock,
    name: &str,
    server: &MockServer,
) -> Result<OAuthProviderConfig, OAuthError> {
    OAuthProviderConfig::discover_screened(
        name,
        &server.uri(),
        CLIENT_ID,
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .map(|b| b.with_clock(Arc::new(clock.clone())))
    .and_then(OAuthProviderBuilder::build)
}

fn identity(clock: &MockClock) -> MockIdentityStore {
    MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
}

fn federated(kind: FederatedProvider) -> Option<FactorKind> {
    Some(FactorKind::Federated(kind))
}

/// The `MethodEnabled` and `MethodDisabled` rows, in the order written.
fn change_rows(identity: &MockIdentityStore) -> Vec<AuthEvent> {
    identity
        .events()
        .into_iter()
        .filter(|row| {
            matches!(
                row.event_type,
                AuthEventType::MethodEnabled | AuthEventType::MethodDisabled
            )
        })
        .collect()
}

fn id_token(issuer: &str, nonce: &str) -> String {
    let (der, _, kid) = keys();
    let now = common::start().unix_seconds();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.clone());
    axess_factors::jwt::encode(
        &header,
        &json!({
            "iss": issuer, "sub": "alice-subject", "aud": CLIENT_ID,
            "exp": now + 3600, "iat": now, "nonce": nonce,
        }),
        &jsonwebtoken::EncodingKey::from_rsa_der(der),
    )
    .expect("JWT encode")
}

/// A whole login through the global provider `sso`; the kind the session's
/// assurance records.
async fn global_login_kind(service: &Service, server: &MockServer) -> FactorKind {
    let request = service.with_audit_context(AuditContext::default());
    let session = test_session();
    request
        .begin_oauth_login("sso", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let read = async |key: &str| {
        session
            .get_custom(key)
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .expect("stashed")
    };
    let (state, nonce) = (
        read("axess.oauth.csrf_state").await,
        read("axess.oauth.nonce").await,
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access", "token_type": "Bearer", "expires_in": 3600,
            "id_token": id_token(&server.uri(), &nonce),
        })))
        .mount(server)
        .await;
    let claims = request
        .finish_oauth_login(
            OAuthCallbackRoute::global("sso"),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect("finish");
    request
        .complete_oauth_login(&test_user("u1", "alice"), &claims, &session)
        .await
        .expect("complete");
    let assurance = session.assurance().await;
    assert_eq!(assurance.len(), 1, "{assurance:?}");
    assurance[0].kind.clone()
}

/// A global provider added by a reload records the kind the reload named,
/// in the reload's row and in the session of a login through it; a second
/// reload names it anew, and the removal's row names the kind of the
/// provider it took out.
#[tokio::test]
async fn a_global_reload_configures_the_kind_its_logins_and_rows_record() {
    let clock = common::test_clock();
    let server = idp().await;
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());

    request
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Google,
            candidate(&clock, "sso", &server),
        )
        .await
        .expect("added");
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Google
    );
    assert_eq!(
        global_login_kind(&service, &server).await,
        FactorKind::Federated(FederatedProvider::Google)
    );

    request
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Microsoft,
            candidate(&clock, "sso", &server),
        )
        .await
        .expect("replaced");
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Microsoft
    );
    request
        .remove_oauth_provider_as(&provider_admin(), "sso")
        .await
        .expect("removed");
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Custom("sso".into()),
        "the kind went with the provider"
    );

    let rows = change_rows(&identity);
    let kinds: Vec<_> = rows
        .iter()
        .map(|row| (row.event_type.clone(), row.factor_kind.clone()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (
                AuthEventType::MethodEnabled,
                federated(FederatedProvider::Google)
            ),
            (
                AuthEventType::MethodEnabled,
                federated(FederatedProvider::Microsoft)
            ),
            (
                AuthEventType::MethodDisabled,
                federated(FederatedProvider::Microsoft)
            ),
        ]
    );
}

/// A provider configured with a kind at construction and reloaded with
/// another has the reload's; a refused reload's failure row names the kind
/// it would have configured and changes nothing; a removal of a name with
/// no provider names `Custom(name)`.
#[tokio::test]
async fn a_reload_names_the_kind_and_a_refused_one_changes_nothing() {
    let clock = common::test_clock();
    let server = idp().await;
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider_of_kind(
            candidate(&clock, "sso", &server).await.unwrap(),
            FederatedProvider::Github,
        )
        .build();
    let request = service.with_audit_context(AuditContext::default());

    request
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "other", &server),
        )
        .await
        .expect_err("a candidate named otherwise");
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Github,
        "a refused reload leaves the kind in force"
    );
    request
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, "sso", &server),
        )
        .await
        .expect("replaced");
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Custom("sso".into())
    );
    request
        .remove_oauth_provider_as(&provider_admin(), "nothing")
        .await
        .expect_err("nothing to remove");

    let rows = change_rows(&identity);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(
        rows[0].factor_kind,
        federated(FederatedProvider::Custom("sso".into()))
    );
    assert_eq!(rows[1].event_status, AuthEventStatus::Success);
    assert_eq!(
        rows[1].factor_kind,
        federated(FederatedProvider::Custom("sso".into()))
    );
    assert_eq!(rows[2].event_type, AuthEventType::MethodDisabled);
    assert_eq!(rows[2].event_status, AuthEventStatus::Failure);
    assert_eq!(
        rows[2].factor_kind,
        federated(FederatedProvider::Custom("nothing".into()))
    );
}

/// A reload or a removal whose row cannot be written is undone, and the
/// kind is put back with the provider.
#[tokio::test]
async fn an_undone_change_puts_the_kind_back_with_the_provider() {
    let clock = common::test_clock();
    let server = idp().await;
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider_of_kind(
            candidate(&clock, "sso", &server).await.unwrap(),
            FederatedProvider::Github,
        )
        .build();
    let request = service.with_audit_context(AuditContext::default());

    identity.arm_record_event_failure();
    let refused = request
        .reload_oauth_provider_as(
            &provider_admin(),
            "sso",
            FederatedProvider::Google,
            candidate(&clock, "sso", &server),
        )
        .await
        .expect_err("no row, no change");
    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Github
    );

    identity.arm_record_event_failure();
    request
        .remove_oauth_provider_as(&provider_admin(), "sso")
        .await
        .expect_err("no row, no removal");
    assert!(service.has_oauth_providers(), "the removal was undone");
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Github
    );
}

/// A tenant's provider added to the live registry by a reload records the
/// reload's kind: in the registry, in the reload's row and the removal's,
/// both of the tenant, and on the row of a refused callback through it.
#[tokio::test]
async fn a_tenant_reload_configures_the_kind_its_logins_and_rows_record() {
    let clock = common::test_clock();
    let server = idp().await;
    let identity = identity(&clock);
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_live_tenant_oauth_providers(live.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let acme = tid("acme");

    request
        .reload_tenant_oauth_provider_as(
            &provider_admin(),
            &acme,
            "sso",
            FederatedProvider::Microsoft,
            candidate(&clock, "sso", &server),
        )
        .await
        .expect("added");
    assert_eq!(
        live.provider_kind(&acme, "sso").await,
        FederatedProvider::Microsoft
    );

    let session = test_session();
    request
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &acme,
            &session,
        )
        .await
        .expect("begin");
    request
        .finish_oauth_login(
            OAuthCallbackRoute::of_tenant(&acme, "sso"),
            "code",
            "not-the-state",
            None,
            &session,
        )
        .await
        .expect_err("the state does not match");
    let refused: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|row| row.error == Some(AuthFailureReason::CsrfMismatch))
        .collect();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(
        refused[0].factor_kind,
        federated(FederatedProvider::Microsoft)
    );

    request
        .remove_tenant_oauth_provider_as(&provider_admin(), &acme, "sso")
        .await
        .expect("removed");
    assert_eq!(
        live.provider_kind(&acme, "sso").await,
        FederatedProvider::Custom("sso".into())
    );
    let rows = change_rows(&identity);
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in &rows {
        assert_eq!(row.tenant_id, Some(acme));
        assert_eq!(row.factor_kind, federated(FederatedProvider::Microsoft));
    }
}

/// A source that names one global OAuth provider, built with a kind.
struct KindSource {
    clock: MockClock,
    server_uri: String,
    entries: Mutex<Vec<ProviderEntry>>,
}

fn sso_key() -> ProviderKey {
    ProviderKey::OAuth {
        tenant: None,
        name: Arc::from("sso"),
    }
}

impl ProviderSource for KindSource {
    fn desired(&self) -> ReloadFuture<'_, Result<Vec<ProviderEntry>, ProviderSourceError>> {
        Box::pin(async move { Ok(self.entries.lock().unwrap().clone()) })
    }

    fn build<'a>(
        &'a self,
        _: &'a ProviderKey,
    ) -> ReloadFuture<'a, Result<BuiltProvider, ProviderSourceError>> {
        Box::pin(async move {
            let provider = OAuthProviderConfig::discover_screened(
                "sso",
                &self.server_uri,
                CLIENT_ID,
                "secret",
                "http://localhost:3000/callback",
                axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
            )
            .await
            .map(|b| b.with_clock(Arc::new(self.clock.clone())))
            .and_then(OAuthProviderBuilder::build)
            .map_err(|e| ProviderSourceError(e.to_string()))?;
            Ok(BuiltProvider::OAuth {
                provider: Arc::new(provider),
                kind: FederatedProvider::Google,
            })
        })
    }
}

/// A provider a follower installs from its source has the kind the source
/// built it with, and the follower's rows, the install's and the
/// withdrawal's, name it.
#[tokio::test]
async fn a_followed_provider_has_the_kind_its_source_built_it_with() {
    let clock = common::test_clock();
    let server = idp().await;
    let identity = identity(&clock);
    let bus: Arc<dyn ReloadCoordinator> = Arc::new(InProcessCoordinator::new(
        NonZeroUsize::new(16).expect("non-zero"),
    ));
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_provider_coordinator(bus.clone())
        .build();
    let source = Arc::new(KindSource {
        clock: clock.clone(),
        server_uri: server.uri(),
        entries: Mutex::new(vec![ProviderEntry {
            key: sso_key(),
            revision: "r1".into(),
        }]),
    });
    let follower = service
        .follow_provider_reloads(source.clone(), Duration::from_millis(20))
        .await
        .expect("following");

    wait_for("the follower installs the provider", || {
        service.has_oauth_providers()
    })
    .await;
    assert_eq!(
        service.oauth_providers().provider_kind("sso"),
        FederatedProvider::Google
    );
    source.entries.lock().unwrap().clear();
    wait_for("the follower withdraws the provider", || {
        !service.has_oauth_providers()
    })
    .await;
    drop(follower);

    let rows = change_rows(&identity);
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in &rows {
        assert_eq!(row.factor_kind, federated(FederatedProvider::Google));
        assert_eq!(
            row.error,
            Some(AuthFailureReason::from(PROVIDER_SOURCE_REASON)),
            "a follower's row names no administrator"
        );
    }
}

async fn wait_for(what: &str, check: impl Fn() -> bool) {
    for _ in 0..300 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not happen within 3s: {what}");
}
