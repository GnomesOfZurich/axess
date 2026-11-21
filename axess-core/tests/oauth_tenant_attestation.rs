//! Who may attest that a tenant owns a client, and what an attestation is
//! good for. The attester is a deployment operator, never a user of the
//! tenant being attested, so a tenant's own administrator cannot vouch for a
//! client the tenant took. An attestation names one tenant, provider name,
//! issuer, client id and write, and stands in for no other. An operator's
//! hand-over writes a row for each record it removes, and a record stored
//! before the directory asked for proof is checked without being written.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_attestation`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::ids::{TenantId, UserId};
use axess_core::authn::service::{
    AuthnService, CLIENT_PAIR_HAND_OVER_REQUESTED_REASON, CLIENT_PAIR_HANDED_OVER_REASON,
    ProviderChangeError,
};
use axess_core::authn::types::{EntityState, StatusCause, StatusDetail, User};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, OperatorAttestation, OwnershipAttestation, OwnershipProofs,
    OwnershipPurpose, OwnershipRefused, Reproved, StoredTenantOAuthProviders,
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TenantOAuthProviderStore,
};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::FactorSecret;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::OAuthError;
use common::{test_tenant, test_user_in_tenant, tid, uid};
use std::sync::Arc;

const ISSUER: &str = "https://idp.example";

fn record(
    tenant_label: &str,
    name: &str,
    issuer: &str,
    client_id: &str,
) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tid(tenant_label),
        name: name.into(),
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
        redirect_url: "https://rp.example/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain(String::new().into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

type Directory = StoredTenantOAuthProviders<Arc<MemoryTenantOAuthProviderStore>>;

fn directory(clock: &MockClock) -> Directory {
    directory_over(clock, Arc::new(MemoryTenantOAuthProviderStore::new()))
}

/// A directory over `store`, which the caller keeps to write past it.
fn directory_over(clock: &MockClock, store: Arc<MemoryTenantOAuthProviderStore>) -> Directory {
    StoredTenantOAuthProviders::new_unencrypted(store, OwnershipProofs::accept(OperatorAttestation))
        .with_clock(std::sync::Arc::new(clock.clone()))
        .with_egress_policy(EgressPolicy::screened_allowing_loopback_http())
}

/// A user of the deployment's operator tenant, [`TenantId::SYSTEM`], in
/// `status`.
fn operator(label: &str, status: EntityState) -> User {
    let mut user = test_user_in_tenant(label, label, "unused");
    user.tenant_id = TenantId::SYSTEM;
    user.status = status;
    user
}

/// An identity store with the deployment's operator (an active user of
/// [`TenantId::SYSTEM`]), a suspended and a pending one, an administrator
/// of `acme` and one of `beta`, a third tenant.
fn identity(clock: &MockClock) -> MockIdentityStore {
    let detail = |cause| StatusDetail {
        cause,
        reason: "".into(),
        since: axess_clock::Timestamp::UNIX_EPOCH,
        until: None,
    };
    MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(operator("operator-1", EntityState::Active))
        .with_user(operator(
            "suspended-operator",
            EntityState::Suspended(detail(StatusCause::Administrative)),
        ))
        .with_user(operator(
            "pending-operator",
            EntityState::Pending(detail(StatusCause::Verification)),
        ))
        .with_user(test_user_in_tenant("acme-admin", "admin@acme", "acme"))
        .with_user(test_user_in_tenant("beta-admin", "admin@beta", "beta"))
}

fn refusal<T>(result: Result<T, OAuthError>) -> String {
    match result {
        Err(OAuthError::Config(text)) => text,
        Err(other) => panic!("expected a refusal by name, got {other:?}"),
        Ok(_) => panic!("the record was stored"),
    }
}

async fn attest(
    clock: &MockClock,
    identity: &MockIdentityStore,
    actor: &UserId,
    tenant: &TenantId,
) -> Result<OwnershipAttestation, ProviderChangeError> {
    attest_for(clock, identity, actor, tenant, OwnershipPurpose::Register).await
}

async fn attest_for(
    clock: &MockClock,
    identity: &MockIdentityStore,
    actor: &UserId,
    tenant: &TenantId,
    purpose: OwnershipPurpose,
) -> Result<OwnershipAttestation, ProviderChangeError> {
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    service
        .with_audit_context(AuditContext::default())
        .attest_tenant_oauth_client_as(
            actor,
            &TenantOAuthProviderRecord {
                tenant_id: *tenant,
                ..record("acme", "sso", ISSUER, "public-app")
            },
            purpose,
        )
        .await
}

/// The reason an audit row carries.
fn reason(row: &axess_core::authn::event::AuthEvent) -> String {
    row.error
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
}

/// A user of the tenant being attested cannot attest it: a tenant's own
/// administrator would otherwise vouch for a client the tenant took. The
/// refusal is by name, a failure row records it, and there is no
/// attestation.
#[tokio::test]
async fn the_tenants_own_administrator_cannot_attest_it() {
    let clock = common::test_clock();
    let identity = identity(&clock);

    let refused = attest(&clock, &identity, &uid("acme-admin"), &tid("acme"))
        .await
        .expect_err("a tenant does not attest itself");

    assert!(
        refused
            .to_string()
            .contains("acts for the tenant it would attest"),
        "{refused}"
    );
    let rows = identity.events();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(rows[0].event_type, AuthEventType::MethodEnabled);
    assert_eq!(rows[0].actor_id, Some(uid("acme-admin")));
}

/// An attester the identity store does not know is refused: nothing says
/// whose side it is on.
#[tokio::test]
async fn an_attester_nobody_knows_is_refused() {
    let clock = common::test_clock();
    let identity = identity(&clock);

    let refused = attest(&clock, &identity, &uid("nobody"), &tid("acme"))
        .await
        .expect_err("an unknown attester");

    assert!(
        refused.to_string().contains("not a known user"),
        "{refused}"
    );
}

/// A deployment operator, an active user of [`TenantId::SYSTEM`], attests
/// for another tenant, never for the operator tenant itself.
#[tokio::test]
async fn a_deployment_operator_attests() {
    let clock = common::test_clock();
    let identity = identity(&clock);

    attest(&clock, &identity, &uid("operator-1"), &tid("acme"))
        .await
        .expect("an operator of the deployment");
    let refused = attest(&clock, &identity, &uid("operator-1"), &TenantId::SYSTEM)
        .await
        .expect_err("an operator acts for the operator tenant");
    assert!(
        matches!(refused, ProviderChangeError::OperatorActsForTenant),
        "{refused}"
    );
}

/// Attest as `actor` for `acme`, and hand acme's pair over as `actor`:
/// both are refused, each with a failure row, and the squatter keeps the
/// pair. Returns the two refusals.
async fn refused_both_ways(actor: &UserId) -> [ProviderChangeError; 2] {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone());
    store
        .put(record("squatter", "sso", ISSUER, "public-app"))
        .await
        .unwrap();

    let attested = attest_for(
        &clock,
        &identity,
        actor,
        &tid("acme"),
        OwnershipPurpose::HandOver,
    )
    .await
    .expect_err("no attestation");
    let handed = service
        .with_audit_context(AuditContext::default())
        .reassign_tenant_oauth_pair_as(
            actor,
            &directory,
            record("acme", "sso", ISSUER, "public-app"),
            None,
        )
        .await
        .expect_err("no hand-over");

    let rows = identity.events();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter()
            .all(|row| row.event_status == AuthEventStatus::Failure
                && row.actor_id == Some(*actor)),
        "{rows:?}"
    );
    assert_eq!(
        directory.holder_of(ISSUER, "public-app").await.unwrap(),
        Some((tid("squatter"), "sso".to_string()))
    );
    [attested, handed]
}

/// An active administrator of a third tenant, neither the one attested nor
/// the one that holds the pair, is not a deployment operator: it can
/// neither attest nor hand a pair over, so a party with two tenants cannot
/// use one to take another tenant's client for the second.
#[tokio::test]
async fn a_third_tenants_administrator_neither_attests_nor_hands_over() {
    for refused in refused_both_ways(&uid("beta-admin")).await {
        assert!(
            matches!(refused, ProviderChangeError::NotADeploymentOperator),
            "{refused}"
        );
    }
}

/// The reserved system user names nobody who checked ownership, so it
/// neither attests nor hands a pair over.
#[tokio::test]
async fn the_system_user_neither_attests_nor_hands_over() {
    for refused in refused_both_ways(&UserId::SYSTEM).await {
        assert!(
            matches!(refused, ProviderChangeError::OperatorIsSystemUser),
            "{refused}"
        );
    }
}

/// A user of the operator tenant whose account is not active (suspended,
/// or not yet verified) neither attests nor hands a pair over.
#[tokio::test]
async fn an_operator_not_active_neither_attests_nor_hands_over() {
    for actor in ["suspended-operator", "pending-operator"] {
        for refused in refused_both_ways(&uid(actor)).await {
            assert!(
                matches!(refused, ProviderChangeError::OperatorNotActive),
                "{actor}: {refused}"
            );
        }
    }
}

/// An attestation stands in for its own tenant, provider name, issuer and
/// client id only: a record that differs in any one of them is refused.
#[tokio::test]
async fn an_attestation_names_one_tenant_provider_issuer_and_client() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let other_issuer = "https://other.example";
    let cases = [
        (
            "another tenant",
            record("beta", "sso", ISSUER, "public-app"),
        ),
        (
            "another name",
            record("acme", "sso-2", ISSUER, "public-app"),
        ),
        (
            "another issuer",
            record("acme", "sso", other_issuer, "public-app"),
        ),
        (
            "another client id",
            record("acme", "sso", ISSUER, "other-app"),
        ),
    ];
    for (named, record) in cases {
        let directory = directory(&clock);
        let attestation = attest(&clock, &identity, &uid("operator-1"), &tid("acme"))
            .await
            .unwrap();

        let text = refusal(directory.upsert_attested(record, attestation).await);

        assert!(text.contains("no operator attestation"), "{named}: {text}");
    }
}

/// An attestation made for a registration does not hand a pair over, and
/// one made for a hand-over does not register: each is refused by name,
/// and the purpose is on the attestation's audit row.
#[tokio::test]
async fn an_attestation_is_good_for_the_write_it_names() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone());
    store
        .put(record("squatter", "sso", ISSUER, "public-app"))
        .await
        .unwrap();

    let for_register = attest(&clock, &identity, &uid("operator-1"), &tid("acme"))
        .await
        .unwrap();
    let refused = request
        .reassign_tenant_oauth_pair_as(
            &uid("operator-1"),
            &directory,
            record("acme", "sso", ISSUER, "public-app"),
            Some(for_register),
        )
        .await
        .expect_err("a registration's attestation does not hand a pair over");
    assert!(
        refused
            .to_string()
            .contains("attested this client for a register write, not for a hand_over write"),
        "{refused}"
    );

    let for_hand_over = attest_for(
        &clock,
        &identity,
        &uid("operator-1"),
        &tid("acme"),
        OwnershipPurpose::HandOver,
    )
    .await
    .unwrap();
    assert!(
        identity
            .events()
            .iter()
            .any(|row| reason(row).contains("purpose=hand_over")),
        "the purpose is on the attestation's row"
    );
    let text = refusal(
        self::directory(&clock)
            .upsert_attested(record("acme", "sso", ISSUER, "public-app"), for_hand_over)
            .await,
    );
    assert!(text.contains("not for a register write"), "{text}");
}

/// A hand-over writes its request before anything changes, then a row for
/// the record it stored and one `MethodDisabled` row for each record it
/// removed, attributed to that record's tenant and naming its provider.
#[tokio::test]
async fn a_hand_over_writes_a_row_for_each_record_it_removes() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext {
        request_id: Some("hand-over-1".into()),
        ..AuditContext::default()
    });
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone());
    store
        .put(record("squatter", "borrowed", ISSUER, "public-app"))
        .await
        .unwrap();
    let attestation = attest_for(
        &clock,
        &identity,
        &uid("operator-1"),
        &tid("acme"),
        OwnershipPurpose::HandOver,
    )
    .await
    .unwrap();
    let before = identity.events().len();

    let handed = request
        .reassign_tenant_oauth_pair_as(
            &uid("operator-1"),
            &directory,
            record("acme", "sso", ISSUER, "public-app"),
            Some(attestation),
        )
        .await
        .expect("the attested hand-over");

    let removed: Vec<_> = handed
        .removed
        .iter()
        .map(|record| (record.tenant_id, record.name.clone()))
        .collect();
    assert_eq!(removed, [(tid("squatter"), "borrowed".to_string())]);
    let rows = identity.events().split_off(before);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(
        rows[0].event_status,
        AuthEventStatus::Failure,
        "the request row is pending until its outcome row"
    );
    assert!(
        rows.iter()
            .all(|row| row.request_id.as_deref() == Some("hand-over-1")),
        "the outcome rows follow the request under its request id: {rows:?}"
    );
    assert!(
        reason(&rows[0]).starts_with(CLIENT_PAIR_HAND_OVER_REQUESTED_REASON),
        "{rows:?}"
    );
    assert_eq!(rows[0].tenant_id, Some(tid("acme")));
    assert_eq!(rows[1].event_type, AuthEventType::MethodEnabled);
    assert_eq!(rows[1].event_status, AuthEventStatus::Success);
    let removed = &rows[2];
    assert_eq!(removed.event_type, AuthEventType::MethodDisabled);
    assert_eq!(removed.event_status, AuthEventStatus::Success);
    assert_eq!(removed.actor_id, Some(uid("operator-1")));
    assert_eq!(removed.tenant_id, Some(tid("squatter")));
    assert_eq!(
        removed.factor_kind,
        Some(FactorKind::Federated(FederatedProvider::Custom(
            "borrowed".into()
        )))
    );
    assert!(
        reason(removed).starts_with(CLIENT_PAIR_HANDED_OVER_REASON),
        "{removed:?}"
    );
    assert!(reason(removed).contains("public-app"), "{removed:?}");
}

/// A user of the tenant the pair would go to cannot hand it over: the
/// request is refused before anything is written to the store.
#[tokio::test]
async fn the_receiving_tenants_administrator_cannot_hand_a_pair_over() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone());
    store
        .put(record("squatter", "sso", ISSUER, "public-app"))
        .await
        .unwrap();

    let refused = service
        .with_audit_context(AuditContext::default())
        .reassign_tenant_oauth_pair_as(
            &uid("acme-admin"),
            &directory,
            record("acme", "sso", ISSUER, "public-app"),
            None,
        )
        .await
        .expect_err("a tenant does not take a pair for itself");

    assert!(
        matches!(refused, ProviderChangeError::OperatorActsForTenant),
        "{refused}"
    );
    assert_eq!(
        directory.holder_of(ISSUER, "public-app").await.unwrap(),
        Some((tid("squatter"), "sso".to_string()))
    );
}

/// A record stored before the directory asked for proof is checked as a
/// registration would be, and nothing is written: here the deployment
/// accepts only an attestation, which a stored record never carries, so it
/// is refused, and a missing record is reported as one.
#[tokio::test]
async fn reprove_checks_a_stored_record_and_writes_nothing() {
    let clock = common::test_clock();
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone());
    let stored = store
        .put(record("squatter", "sso", ISSUER, "public-app"))
        .await
        .unwrap();

    let verdict = directory.reprove(&tid("squatter"), "sso").await.unwrap();

    assert_eq!(verdict, Reproved::Refused(OwnershipRefused::NotAttested));
    assert_eq!(
        store
            .get(&tid("squatter"), "sso")
            .await
            .unwrap()
            .map(|record| record.revision),
        Some(stored.revision),
        "nothing was written"
    );
    assert_eq!(
        directory.reprove(&tid("nobody"), "sso").await.unwrap(),
        Reproved::NoRecord
    );
    let assumed = StoredTenantOAuthProviders::new_unencrypted(
        store.clone(),
        axess_core::testing::oauth_tenant::ownership_assumed(),
    )
    .with_clock(std::sync::Arc::new(clock.clone()));
    assert!(matches!(
        assumed.reprove(&tid("squatter"), "sso").await.unwrap(),
        Reproved::Proven(_)
    ));
}
