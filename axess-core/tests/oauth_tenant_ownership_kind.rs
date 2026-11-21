//! The audit rows of an operator's acts on a client's ownership name each
//! record's provider by the kind the record is configured with: the
//! attestation's row, a refused operator's row, and a hand-over's request,
//! outcome and removal rows. A record that names no kind is
//! `Custom(name)`, as before. The kind is not part of the binding a sealed
//! credential opens under: a credential sealed before the record named a
//! kind still opens once it does.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_ownership_kind`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::factor_secret::FactorSecretCipher;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{AuthnService, ProviderChangeError};
use axess_core::authn::types::{EntityState, User};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, OperatorAttestation, OwnershipProofs, OwnershipPurpose,
    StoredTenantOAuthProviders, TenantClientCredential, TenantDpop, TenantOAuthProviderRecord,
    TenantOAuthProviderStore, TenantOAuthProviders,
};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::FactorSecret;
use axess_factors::egress::EgressPolicy;
use common::{test_tenant, test_user_in_tenant, tid, uid};
use std::sync::Arc;

const ISSUER: &str = "https://idp.example";

fn record(
    tenant_label: &str,
    name: &str,
    client_id: &str,
    kind: Option<FederatedProvider>,
) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tid(tenant_label),
        name: name.into(),
        issuer: ISSUER.to_string(),
        client_id: client_id.to_string(),
        redirect_url: "https://rp.example/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain(String::new().into())),
        dpop: TenantDpop::Advertised,
        kind,
        revision: 0,
    }
}

type Directory = StoredTenantOAuthProviders<Arc<MemoryTenantOAuthProviderStore>>;

fn directory_over(clock: &MockClock, store: Arc<MemoryTenantOAuthProviderStore>) -> Directory {
    StoredTenantOAuthProviders::new_unencrypted(store, OwnershipProofs::accept(OperatorAttestation))
        .with_clock(Arc::new(clock.clone()))
        .with_egress_policy(EgressPolicy::screened_allowing_loopback_http())
}

fn operator(label: &str) -> User {
    let mut user = test_user_in_tenant(label, label, "unused");
    user.tenant_id = TenantId::SYSTEM;
    user.status = EntityState::Active;
    user
}

fn identity(clock: &MockClock) -> MockIdentityStore {
    MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(operator("operator-1"))
        .with_user(test_user_in_tenant("acme-admin", "admin@acme", "acme"))
}

fn federated(kind: FederatedProvider) -> Option<FactorKind> {
    Some(FactorKind::Federated(kind))
}

/// An attestation's row names the attested record's kind, and the refusal
/// row of an operator who may not attest names it too; a record with no
/// kind is `Custom(name)`.
#[tokio::test]
async fn an_attestation_row_names_the_records_kind() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());

    let google = record("acme", "sso", "public-app", Some(FederatedProvider::Google));
    request
        .attest_tenant_oauth_client_as(&uid("operator-1"), &google, OwnershipPurpose::Register)
        .await
        .expect("a deployment operator attests");
    let refused = request
        .attest_tenant_oauth_client_as(&uid("acme-admin"), &google, OwnershipPurpose::Register)
        .await
        .expect_err("the tenant's own administrator");
    assert!(
        matches!(refused, ProviderChangeError::OperatorActsForTenant),
        "{refused}"
    );
    request
        .attest_tenant_oauth_client_as(
            &uid("operator-1"),
            &record("acme", "corp", "corp-app", None),
            OwnershipPurpose::Register,
        )
        .await
        .expect("a record that names no kind");

    let rows = identity.events();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Success);
    assert_eq!(rows[0].factor_kind, federated(FederatedProvider::Google));
    assert_eq!(rows[1].event_status, AuthEventStatus::Failure);
    assert_eq!(rows[1].factor_kind, federated(FederatedProvider::Google));
    assert_eq!(
        rows[2].factor_kind,
        federated(FederatedProvider::Custom("corp".into()))
    );
}

/// A hand-over's request and outcome rows name the kind of the record the
/// pair goes to, and each removal row the kind of the record it removed.
#[tokio::test]
async fn a_hand_overs_rows_name_each_records_kind() {
    let clock = common::test_clock();
    let identity = identity(&clock);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory_over(&clock, store.clone());
    store
        .put(record(
            "squatter",
            "borrowed",
            "public-app",
            Some(FederatedProvider::Github),
        ))
        .await
        .unwrap();
    let owner = record(
        "acme",
        "sso",
        "public-app",
        Some(FederatedProvider::Microsoft),
    );
    let attestation = request
        .attest_tenant_oauth_client_as(&uid("operator-1"), &owner, OwnershipPurpose::HandOver)
        .await
        .expect("attested");
    let before = identity.events().len();

    let handed = request
        .reassign_tenant_oauth_pair_as(&uid("operator-1"), &directory, owner, Some(attestation))
        .await
        .expect("the attested hand-over");
    assert_eq!(handed.removed.len(), 1);
    assert_eq!(
        handed.removed[0].kind,
        Some(FederatedProvider::Github),
        "the removed record as it was stored"
    );

    let rows = identity.events().split_off(before);
    let kinds: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                row.event_type.clone(),
                row.event_status.clone(),
                row.factor_kind.clone(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (
                AuthEventType::MethodEnabled,
                AuthEventStatus::Failure,
                federated(FederatedProvider::Microsoft)
            ),
            (
                AuthEventType::MethodEnabled,
                AuthEventStatus::Success,
                federated(FederatedProvider::Microsoft)
            ),
            (
                AuthEventType::MethodDisabled,
                AuthEventStatus::Success,
                federated(FederatedProvider::Github)
            ),
        ]
    );
    assert_eq!(rows[2].tenant_id, Some(tid("squatter")));
}

/// A record in the stored form records had before they named a kind: no
/// `kind` key, and its client secret sealed with [`KEY`] under the binding
/// of tenant `acme` and provider `sso`. It is kept as bytes, not sealed
/// here, so a change to the binding that would leave credentials already
/// stored unopenable fails this test.
const SEALED_BEFORE_KINDS: &str =
    include_str!("fixtures/tenant-oauth-record-sealed-before-kinds.json");

/// The key [`SEALED_BEFORE_KINDS`] was sealed with.
const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";

/// A credential sealed before the record named a kind opens with the kind
/// set: the kind is not part of the binding, so configuring one moves no
/// sealed credential, and the directory serves the provider with the
/// record's kind.
#[tokio::test]
async fn a_credential_sealed_before_the_record_named_a_kind_still_opens() {
    let stored: TenantOAuthProviderRecord =
        serde_json::from_str(SEALED_BEFORE_KINDS).expect("the stored form reads");
    assert_eq!(stored.kind, None, "the fixture names no kind");
    assert!(
        matches!(
            stored.credential,
            TenantClientCredential::Secret(FactorSecret::Sealed(_))
        ),
        "the fixture's secret is sealed: {:?}",
        stored.credential
    );
    let clock = common::test_clock();
    let cipher = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    assert_eq!(
        &*stored.open_secret(Some(&cipher)).expect("opens as stored"),
        "s3cret"
    );

    for kind in [
        FederatedProvider::Google,
        FederatedProvider::Microsoft,
        FederatedProvider::Github,
        FederatedProvider::Custom("other-name".into()),
    ] {
        let mut configured = stored.clone();
        configured.kind = Some(kind.clone());
        assert_eq!(
            &*configured
                .open_secret(Some(&cipher))
                .unwrap_or_else(|e| panic!("{kind:?}: {e}")),
            "s3cret",
            "{kind:?}"
        );
    }

    // Through the directory: the record with a kind added in the store
    // answers that kind, and the start-up pass over the stored records
    // finds nothing to move to another binding.
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let mut configured = stored.clone();
    configured.kind = Some(FederatedProvider::Google);
    store.put(configured).await.unwrap();
    let directory = StoredTenantOAuthProviders::new(
        store.clone(),
        Arc::new(cipher),
        OwnershipProofs::accept(OperatorAttestation),
    )
    .with_clock(Arc::new(clock.clone()))
    .with_egress_policy(EgressPolicy::screened_allowing_loopback_http());
    let acme = tid("acme");
    assert_eq!(
        directory.provider_kind(&acme, "sso").await,
        FederatedProvider::Google
    );
    let report = directory
        .reseal_earlier_bindings()
        .await
        .expect("the pass reads every record");
    assert_eq!(report.moved, 0, "{report:?}");
    assert_eq!(report.not_moved, 0, "{report:?}");
    let held = store
        .get(&acme, "sso")
        .await
        .unwrap()
        .expect("the record is still stored");
    assert_eq!(
        serde_json::to_value(&held.credential).unwrap(),
        serde_json::to_value(&stored.credential).unwrap(),
        "the sealed credential is stored as it was"
    );
}
