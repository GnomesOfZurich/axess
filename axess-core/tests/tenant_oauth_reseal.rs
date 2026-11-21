#![cfg(all(feature = "oauth", feature = "testing"))]
//! The start-up pass moves every tenant OAuth credential still sealed under
//! the earlier binding (the issuer and client id only) to the current one,
//! once, and a directory that cannot move one does not start; a record the
//! pass never reached is refused at use, and the refusal logged by name,
//! when the earlier binding is refused. A directory that was not started
//! runs the pass before its first resolution, and resolves nothing while
//! the pass fails.

use axess_clock::testing::MockClock;
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::factor_secret::{FactorSecretBinding, FactorSecretCipher};
use axess_core::authn::ids::testing::tenant;
use axess_core::authn::types::AuthnScope;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, ResealReport, StoredTenantOAuthProviders,
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TenantOAuthProviderStore,
    TenantOAuthProviders,
};
use axess_core::session::legacy_blobs::LegacyBlobs;
use axess_core::testing::oauth_tenant::ownership_assumed;
use axess_factors::FactorSecret;
use std::sync::Arc;

const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";

fn record(tenant_label: &str, client_id: &str) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(tenant_label),
        name: "sso".into(),
        issuer: "https://idp.example".into(),
        client_id: client_id.into(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec!["openid".into()],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

/// `record` with its credential sealed as 0.15 to 0.19 sealed it: bound to
/// the tenant and name with the issuer and client id as the only context.
fn in_the_earlier_binding(
    cipher: &FactorSecretCipher,
    mut record: TenantOAuthProviderRecord,
) -> TenantOAuthProviderRecord {
    let scope = AuthnScope::Tenant(record.tenant_id);
    let kind = FactorKind::Federated(FederatedProvider::Custom(record.name.clone()));
    let context = [record.issuer.as_str(), record.client_id.as_str()];
    let sealed = cipher
        .seal(
            "s3cret",
            FactorSecretBinding::new(&scope, &kind).with_context(&context),
        )
        .expect("seal");
    record.credential = TenantClientCredential::Secret(FactorSecret::Sealed(sealed));
    record
}

/// A cipher that refuses the earlier binding, as the directory's will.
fn refusing(clock: &MockClock) -> FactorSecretCipher {
    FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_earlier_tenant_binding(LegacyBlobs::Reject)
}

#[tokio::test]
async fn the_pass_moves_every_earlier_binding_once() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let cipher = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    let store = MemoryTenantOAuthProviderStore::new();
    store
        .put(in_the_earlier_binding(&cipher, record("t1", "c1")))
        .await
        .unwrap();
    store
        .put(in_the_earlier_binding(&cipher, record("t2", "c2")))
        .await
        .unwrap();
    let mut current = record("t3", "c3");
    current.seal(&cipher).unwrap();
    store.put(current).await.unwrap();

    let directory =
        StoredTenantOAuthProviders::new(store, Arc::new(refusing(&clock)), ownership_assumed())
            .with_clock(Arc::new(clock.clone()));
    assert_eq!(
        directory.reseal_earlier_bindings().await.unwrap(),
        ResealReport {
            moved: 2,
            not_moved: 0
        }
    );

    let after = directory.store().list_all().await.unwrap();
    for stored in &after {
        let (text, due) = stored
            .open_credential(Some(&refusing(&clock)))
            .expect("every credential opens with the earlier binding refused");
        assert_eq!(&*text, "s3cret");
        assert!(!due, "{}: still due a re-seal", stored.client_id);
    }

    assert_eq!(
        directory.reseal_earlier_bindings().await.unwrap(),
        ResealReport::default(),
        "a second pass moves nothing"
    );
    let again = directory.store().list_all().await.unwrap();
    let revisions = |records: &[TenantOAuthProviderRecord]| -> Vec<u64> {
        records.iter().map(|r| r.revision).collect()
    };
    assert_eq!(
        revisions(&again),
        revisions(&after),
        "a second pass writes nothing"
    );
}

#[tokio::test]
async fn a_directory_whose_record_cannot_be_moved_does_not_start_and_names_it() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let other_key = FactorSecretCipher::new(*b"another key, another deployment!")
        .with_clock(Arc::new(clock.clone()));
    let store = MemoryTenantOAuthProviderStore::new();
    let mut foreign = record("t1", "c1");
    foreign.name = "broken-sso".into();
    foreign.seal(&other_key).unwrap();
    store.put(foreign).await.unwrap();

    let started =
        StoredTenantOAuthProviders::new(store, Arc::new(refusing(&clock)), ownership_assumed())
            .with_clock(Arc::new(clock.clone()))
            .started()
            .await;
    let Err(error) = started else {
        panic!("a directory with a credential it cannot open started");
    };
    let text = format!("{error}");
    assert!(
        text.contains("broken-sso"),
        "the record is not named: {text}"
    );
    assert!(
        text.contains(&tenant("t1").to_string()),
        "the tenant is not named: {text}"
    );
}

#[tokio::test]
async fn under_reject_a_record_the_pass_did_not_reach_is_refused_by_name() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let cipher = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = StoredTenantOAuthProviders::new(
        store.clone(),
        Arc::new(refusing(&clock)),
        ownership_assumed(),
    )
    .with_clock(Arc::new(clock.clone()))
    .started()
    .await
    .unwrap();
    // Written after the pass, past the directory, as a 0.19.0 node still
    // writing during a rolling upgrade would.
    store
        .put(in_the_earlier_binding(&cipher, record("t1", "c1")))
        .await
        .unwrap();

    let capture = axess_testing::mock_tracing::TracingCapture::install();
    let refused = directory.provider(&tenant("t1"), "sso").await;
    assert!(
        refused.is_err(),
        "a credential in the earlier binding was used under Reject"
    );
    let named = format!("tenant {} provider \"sso\"", tenant("t1"));
    assert!(
        capture.contains(&named),
        "the refusal is not logged naming the record: {:?}",
        capture.events()
    );
}

/// The default cipher refuses the earlier binding at use; `Accept` is the
/// named opt-in for a rolling upgrade.
#[test]
fn the_earlier_binding_is_refused_by_default_and_accepted_by_name() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let cipher = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    let earlier = in_the_earlier_binding(&cipher, record("t1", "c1"));
    assert!(!cipher.earlier_tenant_binding_readable());
    assert!(
        earlier.open_credential(Some(&cipher)).is_err(),
        "the default opened a credential in the earlier binding"
    );
    let rolling = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_earlier_tenant_binding(LegacyBlobs::Accept);
    let (text, due) = earlier.open_credential(Some(&rolling)).unwrap();
    assert_eq!(&*text, "s3cret");
    assert!(due, "a credential opened under the opt-in is due a re-seal");
}

/// A directory built with `new` and never started still moves the earlier
/// binding before it resolves anything, so an adopter who upgrades without
/// calling `started` is not served refusals for every stored credential.
#[tokio::test]
async fn a_directory_that_was_not_started_moves_the_earlier_binding_before_it_resolves() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let cipher = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    let store = MemoryTenantOAuthProviderStore::new();
    // An issuer the egress screen refuses before any connection, so the
    // build ends without the network once the credential has opened.
    let mut local = record("t1", "c1");
    local.issuer = "https://127.0.0.1:9".into();
    store
        .put(in_the_earlier_binding(&cipher, local))
        .await
        .unwrap();
    let directory =
        StoredTenantOAuthProviders::new(store, Arc::new(refusing(&clock)), ownership_assumed())
            .with_clock(Arc::new(clock.clone()));

    let capture = axess_testing::mock_tracing::TracingCapture::install();
    let _ = directory.provider(&tenant("t1"), "sso").await;
    assert!(
        !capture.contains("does not open"),
        "the credential was refused at use instead of moved first: {:?}",
        capture.events()
    );
    for stored in directory.store().list_all().await.unwrap() {
        let (_, due) = stored
            .open_credential(Some(&refusing(&clock)))
            .expect("the credential opens with the earlier binding refused");
        assert!(!due, "{}: still due a re-seal", stored.client_id);
    }
}

/// While the pass cannot move a record, a directory that was not started
/// resolves nothing, and says which record stops it; once the record is
/// gone the next resolution runs the pass again and goes through.
#[tokio::test]
async fn a_directory_that_was_not_started_resolves_nothing_while_its_pass_fails() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let other_key = FactorSecretCipher::new(*b"another key, another deployment!")
        .with_clock(Arc::new(clock.clone()));
    let store = MemoryTenantOAuthProviderStore::new();
    let mut foreign = record("t1", "c1");
    foreign.name = "broken-sso".into();
    foreign.seal(&other_key).unwrap();
    store.put(foreign).await.unwrap();
    let directory =
        StoredTenantOAuthProviders::new(store, Arc::new(refusing(&clock)), ownership_assumed())
            .with_clock(Arc::new(clock.clone()));

    let Err(error) = directory.provider(&tenant("t2"), "sso").await else {
        panic!("a directory whose pass fails resolved a provider");
    };
    assert!(
        format!("{error}").contains("broken-sso"),
        "the refusal does not name the record: {error}"
    );
    let Err(_) = directory.providers_for_issuer("https://idp.example").await else {
        panic!("a directory whose pass fails listed an issuer's providers");
    };

    directory.remove(&tenant("t1"), "broken-sso").await.unwrap();
    let resolved = directory.provider(&tenant("t2"), "sso").await.unwrap();
    assert!(resolved.is_none(), "no record, no provider");
}
