//! One `(issuer, client id)` pair belongs to one record: registrations that
//! collide or do not, the global registration's pairs, registrations racing
//! for one pair, and the operator's override for a pair a tenant took first.

use super::directory_tests::{
    SHARED_ISSUER, directory, idp, record, refused_text, secret, unloadable_key,
};
use super::*;
use crate::authn::ids::testing::tenant;

/// A second tenant cannot register the issuer and client id a first one holds:
/// the pair would make every logout token addressed to that client ambiguous
/// and refused.
#[tokio::test]
async fn a_tenant_cannot_register_a_pair_another_tenant_holds() {
    let directory = directory();
    directory
        .upsert(record("acme", SHARED_ISSUER, "client-x", secret()))
        .await
        .unwrap();

    let text = refused_text(
        directory
            .upsert(record("beta", SHARED_ISSUER, "client-x", secret()))
            .await,
    );

    assert!(
        text.contains("already registered by another record"),
        "{text}"
    );
    assert!(!text.contains("acme"), "the holder is not named: {text}");
    assert!(
        !text.contains(SHARED_ISSUER),
        "the issuer is not echoed: {text}"
    );
    assert!(
        directory
            .raw_store()
            .get(&tenant("beta"), "sso")
            .await
            .unwrap()
            .is_none(),
        "nothing was written"
    );
}

/// What stays allowed: a tenant updating its own record, one issuer with
/// different client ids, one client id at different issuers.
#[tokio::test]
async fn the_pairs_that_do_not_collide_are_registered() {
    let directory = directory();
    directory
        .upsert(record("acme", SHARED_ISSUER, "client-x", secret()))
        .await
        .unwrap();

    directory
        .upsert(record("acme", SHARED_ISSUER, "client-x", secret()))
        .await
        .expect("a tenant updates its own record");
    directory
        .upsert(record("beta", SHARED_ISSUER, "client-y", secret()))
        .await
        .expect("another client id at the same issuer");
    directory
        .upsert(record(
            "gamma",
            "https://idp.other.example",
            "client-x",
            secret(),
        ))
        .await
        .expect("the same client id at another issuer");
}

/// A broken record counts as holding its pair, so a tenant cannot take the
/// pair of a record that does not build.
#[tokio::test]
async fn a_record_that_does_not_build_still_holds_its_pair() {
    let directory = directory();
    directory
        .upsert(record("acme", SHARED_ISSUER, "client-x", unloadable_key()))
        .await
        .unwrap();

    let text = refused_text(
        directory
            .upsert(record("beta", SHARED_ISSUER, "client-x", secret()))
            .await,
    );

    assert!(
        text.contains("already registered by another record"),
        "{text}"
    );
}

/// The global registration's pair is not a tenant's to take, whichever tenant
/// asks.
#[tokio::test]
async fn a_tenant_cannot_register_the_pair_of_the_global_provider() {
    let directory = directory().with_global_registration(SHARED_ISSUER, "client-x");

    let text = refused_text(
        directory
            .upsert(record("acme", SHARED_ISSUER, "client-x", secret()))
            .await,
    );

    assert!(
        text.contains("already registered by the global provider"),
        "{text}"
    );
    directory
        .upsert(record("acme", SHARED_ISSUER, "client-y", secret()))
        .await
        .expect("another client id at the same issuer");
}

/// Registrations in one process are serialised: of two tenants racing for one
/// pair, one wins and one is refused.
#[tokio::test]
async fn two_tenants_racing_for_one_pair_do_not_both_win() {
    let directory = Arc::new(directory());
    let mut set = tokio::task::JoinSet::new();
    for label in ["acme", "beta", "gamma", "delta"] {
        let directory = directory.clone();
        set.spawn(async move {
            directory
                .upsert(record(label, SHARED_ISSUER, "client-x", secret()))
                .await
                .is_ok()
        });
    }
    let mut won = 0;
    while let Some(done) = set.join_next().await {
        won += usize::from(done.unwrap());
    }
    assert_eq!(won, 1);
}

/// The operator's way out of a squatted pair: the record that registered
/// another tenant's issuer and client id first is found by the pair, and the
/// owner's record takes the pair in the same step that removes it.
#[tokio::test]
async fn an_operator_hands_a_squatted_pair_to_the_tenant_that_owns_it() {
    let (server, issuer) = idp().await;
    let directory = directory();
    let (squatter, owner) = (tenant("squatter"), tenant("owner"));
    let mut taken = record("squatter", &issuer, "owners-client", secret());
    taken.name = "borrowed".into();
    directory.upsert(taken.clone()).await.unwrap();
    assert!(
        directory
            .upsert(record("owner", &issuer, "owners-client", secret()))
            .await
            .is_err(),
        "the pair is held"
    );
    assert_eq!(
        directory.holder_of(&issuer, "owners-client").await.unwrap(),
        Some((squatter, "borrowed".to_string()))
    );
    let generation = directory.generation();

    let reassigned = directory
        .hand_over(record("owner", &issuer, "owners-client", secret()), None)
        .await
        .unwrap();

    let removed: Vec<_> = reassigned
        .removed
        .iter()
        .map(|record| (record.tenant_id, record.name.clone()))
        .collect();
    assert_eq!(removed, [(squatter, "borrowed".to_string())]);
    assert_eq!(
        (reassigned.stored.tenant_id, reassigned.stored.revision),
        (owner, 1)
    );
    assert!(
        directory.generation() > generation,
        "the change is announced"
    );
    assert!(
        directory
            .provider(&squatter, "borrowed")
            .await
            .unwrap()
            .is_none(),
        "the squatting record no longer resolves"
    );
    assert_eq!(
        directory.holder_of(&issuer, "owners-client").await.unwrap(),
        Some((owner, "sso".to_string()))
    );
    let text = refused_text(directory.upsert(taken).await);
    assert!(
        text.contains("already registered by another record"),
        "the squatter cannot take it back: {text}"
    );

    let free = directory
        .hand_over(record("owner", &issuer, "another-client", secret()), None)
        .await
        .unwrap();
    assert!(free.removed.is_empty(), "a free pair removes nothing");
    drop(server);
}

/// The global registration's pair is not handed to a tenant, even by the
/// operator's override.
#[tokio::test]
async fn the_global_providers_pair_is_never_reassigned_to_a_tenant() {
    let directory = directory().with_global_registration(SHARED_ISSUER, "client-x");

    let refused = directory
        .hand_over(record("acme", SHARED_ISSUER, "client-x", secret()), None)
        .await
        .map(|r| r.stored);

    assert!(
        refused_text(refused).contains("already registered by the global provider"),
        "refused by name"
    );
    assert!(
        directory
            .raw_store()
            .get(&tenant("acme"), "sso")
            .await
            .unwrap()
            .is_none()
    );
}

/// A store whose writer in another process tries the squatter's record again
/// right after each removal it is asked for: straight into the store, where
/// only the store's own constraint decides.
struct SquatterWritesBetween {
    inner: MemoryTenantOAuthProviderStore,
    squatter: TenantOAuthProviderRecord,
    /// Whether each of the squatter's writes was taken.
    taken: std::sync::Mutex<Vec<bool>>,
}

impl SquatterWritesBetween {
    async fn squatter_writes(&self) {
        let taken = self.inner.put(self.squatter.clone()).await.is_ok();
        self.taken.lock().unwrap().push(taken);
    }
}

impl TenantOAuthProviderStore for SquatterWritesBetween {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.get(tenant, name).await
    }
    async fn put(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        self.inner.put(record).await
    }
    async fn put_if_revision(
        &self,
        record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.put_if_revision(record, expected).await
    }
    async fn reassign_pair(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
        let reassigned = self.inner.reassign_pair(record).await;
        self.squatter_writes().await;
        reassigned
    }
    async fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<bool, TenantOAuthProviderStoreError> {
        let deleted = self.inner.delete(tenant, name).await;
        self.squatter_writes().await;
        deleted
    }
    async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list_by_issuer(issuer).await
    }
    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list(tenant).await
    }
    async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list_all().await
    }
}

/// The squatter's writer runs straight after the removal and before anything
/// else: a removal followed by the owner's own registration would hand it
/// the pair again, and the owner's registration would be refused. The pair
/// goes to the owner in the same write that removes the squatter, so the
/// squatter's write is refused and the owner holds the pair.
#[tokio::test]
async fn a_squatter_writing_straight_after_the_removal_does_not_take_the_pair_back() {
    let mut squatter = record("squatter", SHARED_ISSUER, "owners-client", secret());
    squatter.name = "borrowed".into();
    let inner = MemoryTenantOAuthProviderStore::new();
    inner.put(squatter.clone()).await.unwrap();
    let directory = StoredTenantOAuthProviders::new_unencrypted(
        SquatterWritesBetween {
            inner,
            squatter,
            taken: std::sync::Mutex::new(Vec::new()),
        },
        crate::testing::oauth_tenant::ownership_assumed(),
    );

    directory
        .hand_over(
            record("owner", SHARED_ISSUER, "owners-client", secret()),
            None,
        )
        .await
        .expect("the owner's record takes the pair");

    assert_eq!(
        *directory.raw_store().taken.lock().unwrap(),
        [false],
        "the squatter's write after the removal was refused"
    );
    assert_eq!(
        directory
            .holder_of(SHARED_ISSUER, "owners-client")
            .await
            .unwrap(),
        Some((tenant("owner"), "sso".to_string()))
    );
}

/// A store whose every write is refused as a held pair, as one shared with
/// another process refuses the loser of a race the other process won.
struct HeldElsewhere(MemoryTenantOAuthProviderStore);

impl TenantOAuthProviderStore for HeldElsewhere {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.get(tenant, name).await
    }
    async fn put(
        &self,
        _: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        Err(TenantOAuthProviderStoreError::pair_held())
    }
    async fn put_if_revision(
        &self,
        _: TenantOAuthProviderRecord,
        _: u64,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Err(TenantOAuthProviderStoreError::pair_held())
    }
    async fn reassign_pair(
        &self,
        _: TenantOAuthProviderRecord,
    ) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
        Err(TenantOAuthProviderStoreError::pair_held())
    }
    async fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<bool, TenantOAuthProviderStoreError> {
        self.0.delete(tenant, name).await
    }
    async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.list_by_issuer(issuer).await
    }
    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.list(tenant).await
    }
    async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.list_all().await
    }
}

/// A write the store refuses changes nothing a reader can see, so the
/// generation stays where it was: a remembered miss for the issuer is not
/// voided by a record that was never stored.
#[tokio::test]
async fn a_write_the_store_refuses_leaves_the_generation_where_it_was() {
    let directory = StoredTenantOAuthProviders::new_unencrypted(
        HeldElsewhere(MemoryTenantOAuthProviderStore::new()),
        crate::testing::oauth_tenant::ownership_assumed(),
    );
    let before = directory.generation();

    let text = refused_text(
        directory
            .upsert(record("acme", SHARED_ISSUER, "client-x", secret()))
            .await,
    );

    assert!(
        text.contains("already registered by another record"),
        "{text}"
    );
    assert_eq!(directory.generation(), before);
}

/// A credential moved to the current binding is not written over a record
/// that changed since it was read, even one at the same revision: a record
/// removed and registered again starts at revision 1, as the one it replaced
/// may have, and the stale write would bring back the old record's pair.
#[tokio::test]
async fn a_reseal_does_not_write_over_a_record_registered_again_at_its_revision() {
    use crate::authn::factor_secret::FactorSecretCipher;
    let cipher = Arc::new(FactorSecretCipher::new(
        *b"0123456789abcdef0123456789abcdeF",
    ));
    let directory = StoredTenantOAuthProviders::new(
        MemoryTenantOAuthProviderStore::new(),
        cipher,
        crate::testing::oauth_tenant::ownership_assumed(),
    );
    let squatter = tenant("squatter");
    let read = directory
        .raw_store()
        .put(record("squatter", SHARED_ISSUER, "client-x", secret()))
        .await
        .unwrap();
    directory
        .raw_store()
        .delete(&squatter, "sso")
        .await
        .unwrap();
    let again = directory
        .raw_store()
        .put(record("squatter", SHARED_ISSUER, "client-y", secret()))
        .await
        .unwrap();
    assert_eq!(again.revision, read.revision, "the revision restarted");

    directory.move_to_current_binding(&read, "s3cret").await;

    let stored = directory
        .raw_store()
        .get(&squatter, "sso")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_id, "client-y", "the stale record came back");
    assert_eq!(stored.revision, again.revision);
}
