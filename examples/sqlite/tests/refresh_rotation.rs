//! Refresh-token rotation against the real SQL path: one parent rotates
//! once. The second rotation of the same parent finds it revoked, stores
//! nothing and answers `ParentAlreadyRevoked`, which the session layer
//! treats as a reuse. Before the conditional UPDATE both rotations
//! succeeded and two live children existed for one presented token.

use axess::authn::{DeviceId, TenantId, UserId};
use axess::session::{
    DeviceTokenRevocation, RefreshToken, RefreshTokenId, RefreshTokenStore, RevocationReason,
    RotationOutcome,
};
use axess::{Clock, SystemClock};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const TENANT: &str = "00000000-0000-0000-0000-000000000001";

async fn backend() -> OurBackend {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("in-memory url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    seed(&SystemClock, &pool).await.expect("seed");
    OurBackend::new(pool)
}

fn token(suffix: &str) -> RefreshToken {
    let now = SystemClock.now();
    RefreshToken {
        id: RefreshTokenId::try_new(format!("00000000-0000-0000-0000-0000000000{suffix}"))
            .expect("token id"),
        user_id: UserId::try_new(ALICE).expect("user id"),
        tenant_id: TenantId::try_new(TENANT).expect("tenant id"),
        token_hash: format!("hash-{suffix}"),
        issued_at: now,
        expires_at: now + chrono::Duration::days(30),
        revoked: false,
        device_info: None,
        family_id: None,
        device_id: None,
        authn_time: None,
        revoked_reason: None,
        revoked_at: None,
    }
}

#[tokio::test]
async fn a_parent_rotates_once_and_a_second_rotation_is_a_lost_race() {
    let store = backend().await;
    let parent = token("a0");
    store.store_token(&parent).await.expect("store parent");

    let first = store
        .rotate_token(&parent.id, &token("a1"))
        .await
        .expect("first rotation");
    assert_eq!(first, RotationOutcome::Rotated);

    let second = store
        .rotate_token(&parent.id, &token("a2"))
        .await
        .expect("second rotation runs");
    assert_eq!(
        second,
        RotationOutcome::ParentAlreadyRevoked,
        "the parent was already revoked"
    );

    let active = store
        .active_tokens(&parent.user_id)
        .await
        .expect("active tokens");
    let ids: Vec<String> = active.iter().map(|t| t.id.to_string()).collect();
    assert_eq!(
        ids,
        vec![token("a1").id.to_string()],
        "exactly the first child is live: {ids:?}"
    );
}

/// Each way of revoking a token records its own reason, and a later sweep
/// never rewrites it: only a `Rotated` token's reuse is a theft signal.
#[tokio::test]
async fn revocation_reasons_are_persisted_and_not_overwritten() {
    use axess::session::RevocationReason;
    let store = backend().await;
    let user = UserId::try_new(ALICE).expect("user id");

    let rotated = token("b0");
    store.store_token(&rotated).await.expect("store");
    let mut child = token("b1");
    child.family_id = rotated.family_id;
    assert_eq!(
        store
            .rotate_token(&rotated.id, &child)
            .await
            .expect("rotate"),
        RotationOutcome::Rotated
    );
    let logged_out = token("b2");
    store.store_token(&logged_out).await.expect("store");
    store.revoke_token(&logged_out.id).await.expect("revoke");

    let family = axess::session::TokenFamilyId::try_new("00000000-0000-0000-0000-0000000000f1")
        .expect("family id");
    let mut swept = token("b3");
    swept.family_id = Some(family);
    store.store_token(&swept).await.expect("store");
    store.revoke_family(&user, &family).await.expect("family");
    store.revoke_user_tokens(&user).await.expect("all");

    let reason = |hash: &str| {
        let hash = hash.to_string();
        let store = &store;
        async move {
            store
                .find_token(&hash)
                .await
                .expect("find")
                .expect("row")
                .revoked_reason
        }
    };
    assert_eq!(reason("hash-b0").await, Some(RevocationReason::Rotated));
    assert_eq!(reason("hash-b2").await, Some(RevocationReason::Explicit));
    assert_eq!(reason("hash-b3").await, Some(RevocationReason::Compromise));
    assert!(
        store
            .find_token("hash-b0")
            .await
            .expect("find")
            .expect("row")
            .revoked_at
            .is_some()
    );
}

/// Revoking a device's tokens records why and when, so a later presentation
/// of one of them is refused as revoked and not read as theft.
#[tokio::test]
async fn revoking_a_device_records_the_reason_and_the_time() {
    let store = backend().await;
    let device = DeviceId::try_new("00000000-0000-0000-0000-0000000000d1").expect("device id");
    let mut parent = token("b0");
    parent.device_id = Some(device);
    store.store_token(&parent).await.expect("store");

    let done = store
        .revoke_device_tokens(&parent.tenant_id, &device)
        .await
        .expect("revoke by device");
    assert_eq!(done, DeviceTokenRevocation::Revoked { tokens: 1 });

    let row = store
        .find_token(&parent.token_hash)
        .await
        .expect("find")
        .expect("row");
    assert!(row.revoked);
    assert_eq!(row.revoked_reason, Some(RevocationReason::Device));
    assert!(row.revoked_at.is_some(), "the revocation time is recorded");
}

mod compromise_revokes_the_familys_devices {
    //! Reuse of a rotated-out token is a compromise signal: the family is
    //! revoked, and every device the family ran on must end `Revoked`. The
    //! backend's `on_token_compromise` is the trait default, which only
    //! logs, so the store is wrapped in `CascadingRefreshStore` with the
    //! sqlite device store; the test shows the device row after reuse.

    use super::*;
    use axess::backends::sqlite::DeviceStore as SqliteDeviceStore;
    use axess::device::{
        CascadingRefreshStore, Device, DeviceStore, DeviceTrustLevel, FingerprintHash,
    };
    use axess::session::{
        IssueRequest, Refresh, RefreshError, RefreshTokenConfig, SessionCrypto, issue_refresh_token,
    };
    use axess::{SystemRng, authn::DeviceId};
    use std::sync::Arc;

    async fn device_store(backend: &OurBackend) -> SqliteDeviceStore {
        let devices = SqliteDeviceStore::new(backend.pool().clone(), SessionCrypto::new([7u8; 32]));
        devices.init_schema().await.expect("device schema");
        devices
    }

    async fn trusted_device(devices: &SqliteDeviceStore) -> (TenantId, DeviceId) {
        let tenant = TenantId::try_new(TENANT).expect("tenant id");
        let id = DeviceId::try_new("00000000-0000-0000-0000-0000000000d1").expect("device id");
        let now = SystemClock.now();
        devices
            .save(
                &Device {
                    id,
                    tenant_id: tenant,
                    user_id: Some(UserId::try_new(ALICE).expect("user id")),
                    trust_level: DeviceTrustLevel::Trusted,
                    fingerprint_hash: FingerprintHash::from_bytes([0xd1; 32]),
                    first_seen_at: now,
                    last_seen_at: now,
                    revoked_at: None,
                    demoted_at: None,
                    bindings: Vec::new(),
                },
                now,
            )
            .await
            .expect("device saved");
        (tenant, id)
    }

    /// Issue a token on `device`, rotate it once, present it again, and
    /// return the device's trust level afterwards.
    async fn reuse_on<S: axess::session::RefreshTokenStore>(
        store: &S,
        devices: &SqliteDeviceStore,
        (tenant, device): (TenantId, DeviceId),
    ) -> DeviceTrustLevel {
        let config = RefreshTokenConfig::default();
        let now = SystemClock.now();
        let user = UserId::try_new(ALICE).expect("user id");
        let (v1, _) = issue_refresh_token(
            IssueRequest {
                user_id: &user,
                tenant_id: &tenant,
                device_info: None,
                family_id: None,
                device_id: Some(device),
            },
            &config,
            store,
            &SystemRng,
            now,
        )
        .await
        .expect("issued");
        Refresh::new(&v1, |_| async { true })
            .run(store, &config, &SystemRng, now)
            .await
            .expect("first refresh rotates");
        let reuse = Refresh::new(&v1, |_| async { true })
            .run(store, &config, &SystemRng, now)
            .await;
        assert!(
            matches!(reuse, Err(RefreshError::Revoked)),
            "reuse of the rotated-out token is refused"
        );
        devices
            .load(&tenant, &device)
            .await
            .expect("device read")
            .expect("device row")
            .trust_level
    }

    #[tokio::test]
    async fn reuse_of_a_rotated_out_token_leaves_the_familys_devices_revoked() {
        let backend = backend().await;
        let devices = device_store(&backend).await;
        let target = trusted_device(&devices).await;
        let store = CascadingRefreshStore::new(backend, devices.clone(), Arc::new(SystemClock));
        let level = reuse_on(&store, &devices, target).await;
        assert_eq!(
            level,
            DeviceTrustLevel::Revoked,
            "every device linked to the compromised family must be revoked"
        );
    }

    #[tokio::test]
    async fn the_bare_backend_only_logs_the_compromise() {
        // The contrast the wrapper exists for: a refresh store holds no
        // device store, so the trait default can revoke nothing. An
        // application that hands out refresh tokens wraps its store.
        let backend = backend().await;
        let devices = device_store(&backend).await;
        let target = trusted_device(&devices).await;
        let level = reuse_on(&backend, &devices, target).await;
        assert_eq!(level, DeviceTrustLevel::Trusted);
    }
}
