//! A tenant registers an `(issuer, client_id)` pair only with a proof that
//! it owns the client: a confidential client proves itself to its identity
//! provider, and a public client needs an operator's attestation, which is
//! an audit row naming the operator, the tenant and the pair. A tenant that
//! tries to take another's pair without the proof is refused, and the owner
//! registers it after.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_ownership`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{
    AuthnService, CLIENT_OWNERSHIP_ATTESTED_REASON, ProviderChangeError,
};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, OperatorAttestation, OwnershipProofs, OwnershipPurpose,
    StoredTenantOAuthProviders, TenantClientCredential, TenantDpop, TenantOAuthProviderRecord,
    TenantOAuthProviderStore, TokenEndpointProbe,
};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::FactorSecret;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::OAuthError;
use axess_testing::oauth_wiremock::oauth_discovery_document;
use common::{test_tenant, test_user_in_tenant, uid};
use std::sync::Arc;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OWNERS_CLIENT: &str = "owners-client";
/// `owners-client:owners-secret`, base64.
const OWNERS_BASIC: &str = "Basic b3duZXJzLWNsaWVudDpvd25lcnMtc2VjcmV0";

fn tenant(label: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(label)
}

fn record(
    tenant_label: &str,
    issuer: &str,
    client_id: &str,
    secret: &str,
) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(tenant_label),
        name: "sso".into(),
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
        redirect_url: "https://rp.example/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain(secret.into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

type Directory = StoredTenantOAuthProviders<Arc<MemoryTenantOAuthProviderStore>>;

fn directory(clock: &MockClock, proofs: OwnershipProofs) -> Directory {
    directory_over(
        clock,
        Arc::new(MemoryTenantOAuthProviderStore::new()),
        proofs,
    )
}

/// A directory over `store`, which the caller keeps to write past it.
fn directory_over(
    clock: &MockClock,
    store: Arc<MemoryTenantOAuthProviderStore>,
    proofs: OwnershipProofs,
) -> Directory {
    StoredTenantOAuthProviders::new_unencrypted(store, proofs)
        .with_clock(std::sync::Arc::new(clock.clone()))
        .with_egress_policy(EgressPolicy::screened_allowing_loopback_http())
}

/// An identity store that knows the deployment's operator, a user of the
/// operator tenant [`TenantId::SYSTEM`], which attests for other tenants.
fn identity(clock: &MockClock) -> MockIdentityStore {
    let mut operator = test_user_in_tenant("operator-1", "operator", "unused");
    operator.tenant_id = TenantId::SYSTEM;
    MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(operator)
}

fn probe_or_attestation() -> OwnershipProofs {
    OwnershipProofs::accept(TokenEndpointProbe::new()).or_accept(OperatorAttestation)
}

/// An identity provider that authenticates `owners-client` with its secret
/// only: anything else is `invalid_client`.
async fn idp() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(oauth_discovery_document(&server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", OWNERS_BASIC))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "invalid_client" })),
        )
        .mount(&server)
        .await;
    server
}

fn refusal<T>(result: Result<T, OAuthError>) -> String {
    match result {
        Err(OAuthError::Config(text)) => text,
        Err(other) => panic!("expected a refusal by name, got {other:?}"),
        Ok(_) => panic!("the record was stored"),
    }
}

/// Tenant B registers the owner's issuer and client id with a secret of its
/// own: the provider does not authenticate it, so the record is refused and
/// the pair stays free. The owner registers it with its own secret, and B,
/// trying again, meets the owner's record as well.
#[tokio::test]
async fn a_tenant_that_registers_anothers_pair_without_proof_is_refused() {
    let clock = common::test_clock();
    let server = idp().await;
    let issuer = server.uri();
    let directory = directory(&clock, probe_or_attestation());

    let text = refusal(
        directory
            .upsert(record("squatter", &issuer, OWNERS_CLIENT, "guessed"))
            .await,
    );
    assert!(text.contains("not proven"), "{text}");
    assert_eq!(
        directory.holder_of(&issuer, OWNERS_CLIENT).await.unwrap(),
        None
    );

    directory
        .upsert(record("owner", &issuer, OWNERS_CLIENT, "owners-secret"))
        .await
        .expect("the owner proves its client");
    assert_eq!(
        directory.holder_of(&issuer, OWNERS_CLIENT).await.unwrap(),
        Some((tenant("owner"), "sso".to_string()))
    );

    let text = refusal(
        directory
            .upsert(record("squatter", &issuer, OWNERS_CLIENT, ""))
            .await,
    );
    assert!(
        text.contains("already registered by another record"),
        "{text}"
    );
    assert_eq!(
        directory.holder_of(&issuer, OWNERS_CLIENT).await.unwrap(),
        Some((tenant("owner"), "sso".to_string())),
        "the owner keeps its pair"
    );
}

/// A pair the owner holds is refused before the squatter's credential goes
/// anywhere: no request reaches the identity provider, so a tenant can
/// neither guess the owner's secret against it nor spend the owner's client
/// against its limits, however often it tries.
#[tokio::test]
async fn a_held_pair_is_refused_without_a_request_to_the_identity_provider() {
    let clock = common::test_clock();
    let server = idp().await;
    let issuer = server.uri();
    let directory = directory(&clock, probe_or_attestation());
    directory
        .upsert(record("owner", &issuer, OWNERS_CLIENT, "owners-secret"))
        .await
        .expect("the owner proves its client");
    let before = server.received_requests().await.unwrap_or_default().len();

    for guess in ["guessed", "owners-secret"] {
        let text = refusal(
            directory
                .upsert(record("squatter", &issuer, OWNERS_CLIENT, guess))
                .await,
        );
        assert!(
            text.contains("already registered by another record"),
            "{text}"
        );
    }

    let after = server.received_requests().await.unwrap_or_default().len();
    assert_eq!(after, before, "no request reached the identity provider");
}

/// An attestation is written to the audit trail before it exists: a
/// `MethodEnabled` row naming the operator, the tenant, the provider and,
/// in its reason, the issuer and the client id.
#[tokio::test]
async fn an_attestation_is_an_audit_row_naming_the_operator_the_tenant_and_the_pair() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());

    let attestation = request
        .attest_tenant_oauth_client_as(
            &uid("operator-1"),
            &record("acme", "https://idp.example", "public-app", ""),
            OwnershipPurpose::Register,
        )
        .await
        .expect("the row is written");

    assert_eq!(attestation.operator(), &uid("operator-1"));
    let rows = identity.events();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.event_type, AuthEventType::MethodEnabled);
    assert_eq!(row.event_status, AuthEventStatus::Success);
    assert_eq!(row.actor_id, Some(uid("operator-1")));
    assert_eq!(row.tenant_id, Some(tenant("acme")));
    assert_eq!(
        row.factor_kind,
        Some(FactorKind::Federated(FederatedProvider::Custom(
            "sso".into()
        )))
    );
    let reason = row
        .error
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert_eq!(
        reason,
        format!(
            "{CLIENT_OWNERSHIP_ATTESTED_REASON} purpose=register \
             issuer=\"https://idp.example\" client_id=\"public-app\""
        )
    );
}

/// An attestation whose row cannot be written does not exist: one nobody
/// can account for proves nothing.
#[tokio::test]
async fn an_attestation_whose_row_cannot_be_written_is_refused() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    identity.arm_record_event_failure();

    let refused = request
        .attest_tenant_oauth_client_as(
            &uid("operator-1"),
            &record("acme", "https://idp.example", "public-app", ""),
            OwnershipPurpose::Register,
        )
        .await
        .expect_err("no row, no attestation");

    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
}

/// A public client is refused without an attestation, and stored with one
/// that names its tenant, provider and pair; one that names another tenant
/// does not stand in for it.
#[tokio::test]
async fn a_public_client_needs_an_operators_attestation() {
    let clock = common::test_clock();
    let server = idp().await;
    let issuer = server.uri();
    let directory = directory(&clock, probe_or_attestation());
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let public = record("acme", &issuer, "public-app", "");

    let text = refusal(directory.upsert(public.clone()).await);
    assert!(text.contains("public client"), "{text}");
    assert!(text.contains("no operator attestation"), "{text}");

    let elsewhere = request
        .attest_tenant_oauth_client_as(
            &uid("operator-1"),
            &record("other", &issuer, "public-app", ""),
            OwnershipPurpose::Register,
        )
        .await
        .unwrap();
    let text = refusal(directory.upsert_attested(public.clone(), elsewhere).await);
    assert!(text.contains("no operator attestation"), "{text}");

    let attestation = request
        .attest_tenant_oauth_client_as(&uid("operator-1"), &public, OwnershipPurpose::Register)
        .await
        .unwrap();
    directory
        .upsert_attested(public, attestation)
        .await
        .expect("the attested public client is stored");
    assert_eq!(
        directory.holder_of(&issuer, "public-app").await.unwrap(),
        Some((tenant("acme"), "sso".to_string()))
    );
}

/// A tenant named in the policy accepts only the proofs named for it: here
/// an attestation, so even a client the provider authenticates is refused
/// without one.
#[tokio::test]
async fn a_tenant_with_its_own_proofs_accepts_only_those() {
    let clock = common::test_clock();
    let server = idp().await;
    let issuer = server.uri();
    let directory = directory(
        &clock,
        OwnershipProofs::accept(TokenEndpointProbe::new())
            .for_tenant(tenant("owner"), OperatorAttestation),
    );

    let text = refusal(
        directory
            .upsert(record("owner", &issuer, OWNERS_CLIENT, "owners-secret"))
            .await,
    );

    assert!(text.contains("no operator attestation"), "{text}");
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the probe was not asked"
    );
}

/// The operator's hand-over needs the owner's proof as any write does: a
/// record that does not prove its client is refused and the holder keeps
/// the pair.
#[tokio::test]
async fn a_hand_over_needs_the_owners_proof() {
    let clock = common::test_clock();
    let server = idp().await;
    let issuer = server.uri();
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone(), probe_or_attestation());
    let service = AuthnService::builder(identity(&clock), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    // Written past the directory, as a record from before it asked for proof.
    store
        .put(record("squatter", &issuer, OWNERS_CLIENT, "guessed"))
        .await
        .unwrap();

    let refused = request
        .reassign_tenant_oauth_pair_as(
            &uid("operator-1"),
            &directory,
            record("owner", &issuer, OWNERS_CLIENT, "wrong"),
            None,
        )
        .await
        .expect_err("the owner's record does not prove its client");
    let ProviderChangeError::HandOver(refused) = refused else {
        panic!("expected the directory's refusal, got {refused}");
    };
    let text = refusal::<()>(Err(refused));
    assert!(text.contains("not proven"), "{text}");
    assert_eq!(
        directory.holder_of(&issuer, OWNERS_CLIENT).await.unwrap(),
        Some((tenant("squatter"), "sso".to_string()))
    );

    let handed = request
        .reassign_tenant_oauth_pair_as(
            &uid("operator-1"),
            &directory,
            record("owner", &issuer, OWNERS_CLIENT, "owners-secret"),
            None,
        )
        .await
        .expect("the owner proves its client");
    let removed: Vec<_> = handed
        .removed
        .iter()
        .map(|record| (record.tenant_id, record.name.clone()))
        .collect();
    assert_eq!(removed, vec![(tenant("squatter"), "sso".to_string())]);
}
