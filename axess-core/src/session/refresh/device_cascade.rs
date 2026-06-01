//! Device cascade tests: verify the (tenant, device) target
//! collection in `collect_family_device_targets` produces the right
//! input for `cascade_revoke_devices`, and that running the cascade
//! against a memory device store transitions the linked devices to
//! `Revoked`.

use super::test_support::{fixture_tenant, fixture_user, now, test_config};
use super::*;
use crate::authn::ids::DeviceId;
use crate::device::{
    Device, DeviceStore, DeviceTrustLevel, FingerprintHash, MemoryDeviceStore,
    cascade_revoke_devices,
};
use crate::testing::{MemoryRefreshTokenStore, mock_random::MockRng};

fn make_device_id(name: &str) -> DeviceId {
    axess_identity::testing::device(name)
}

fn build_trusted_device(tenant: &TenantId, id: &DeviceId, fp: u8, now: DateTime<Utc>) -> Device {
    Device {
        id: *id,
        tenant_id: *tenant,
        user_id: Some(fixture_user()),
        trust_level: DeviceTrustLevel::Trusted,
        fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
        first_seen_at: now,
        last_seen_at: now,
        revoked_at: None,
        bindings: Vec::new(),
    }
}

/// End-to-end: issue v1 with a device link, rotate to v2 (which
/// inherits the device link), reuse v1 → family revocation +
/// `on_token_compromise` fires with `[(tenant, device)]`. The
/// production override would call `cascade_revoke_devices` here;
/// the default just logs, so we drive the cascade explicitly to
/// prove the device store reflects the revocation.
#[tokio::test]
async fn refresh_compromise_to_device_revocation_full_cascade() {
    let refresh_store = MemoryRefreshTokenStore::new();
    let device_store = MemoryDeviceStore::new();
    let config = test_config();
    let rng = MockRng::new(201);
    let ts = now();

    let tenant = fixture_tenant();
    let device_id = make_device_id("dev-cascade");
    device_store
        .save(&build_trusted_device(&tenant, &device_id, 0xc0, ts))
        .await
        .unwrap();

    // Issue v1 carrying device_id.
    let (plaintext_v1, _v1) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: Some(device_id),
        },
        &config,
        &refresh_store,
        &rng,
        ts,
    )
    .await
    .unwrap();

    // Rotate v1 → v2; v2 must inherit the device link.
    let (session, new_token) =
        refresh_session(&plaintext_v1, &refresh_store, &config, &rng, ts, None)
            .await
            .unwrap();
    assert_eq!(
        session.device_id,
        Some(device_id),
        "rotated session must carry the device_id from the parent token"
    );
    let (_plaintext_v2, v2_record) = new_token.unwrap();
    assert_eq!(
        v2_record.device_id,
        Some(device_id),
        "rotated token must inherit device_id"
    );

    // Reuse v1 → triggers family revocation. The default
    // on_token_compromise just logs; we replicate the cascade
    // step a production override would perform by collecting
    // family targets and driving the primitive directly.
    let err = refresh_session(&plaintext_v1, &refresh_store, &config, &rng, ts, None).await;
    assert!(matches!(err, Err(RefreshError::Revoked)));

    // Drive the cascade with the same target set the trait hook
    // would receive. Even though the family is now revoked, the
    // tenant + device pair is what we cascade on; independent
    // of refresh-side state.
    let targets = vec![(tenant, device_id)];
    let revoked = cascade_revoke_devices(&device_store, &targets, ts).await;
    assert_eq!(revoked, 1);

    // Device row reflects the revocation.
    let after = device_store
        .load(&tenant, &device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(after.revoked_at, Some(ts));
}

/// `collect_family_device_targets` deduplicates the seen-record
/// device entry against the active-siblings list, so a token
/// family with N members all bound to the same device produces
/// a single (tenant, device) target rather than N copies. Pins
/// the dedup invariant: without it, the cascade primitive
/// would be called once per family member and emit duplicate
/// audit events.
#[tokio::test]
async fn collect_family_targets_deduplicates_same_device_across_family() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(7);
    let ts = now();

    let tenant = fixture_tenant();
    let device_id = make_device_id("dev-dedup");

    // Issue v1, rotate to v2; both share the same device_id and
    // family_id (rotation inherits both). v2 is currently active;
    // v1 is the seen-record once it's been consumed.
    let (plaintext_v1, v1) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: Some(device_id),
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();
    let (_session, _) = refresh_session(&plaintext_v1, &store, &config, &rng, ts, None)
        .await
        .unwrap();

    // Reload the (now-revoked) v1 record so we can call the
    // private collector directly with it.
    let v1_token_hash = hash_token(&plaintext_v1, config.hash_pepper.as_deref());
    let v1_after = store.find_token(&v1_token_hash).await.unwrap().unwrap();
    assert!(v1_after.revoked, "v1 must be revoked after rotation");

    let family_id = v1.family_id.as_ref().expect("family must be assigned");
    let targets = collect_family_device_targets(&store, family_id, &v1_after).await;
    assert_eq!(
        targets.len(),
        1,
        "family of 2 tokens sharing the same device must collapse to 1 target"
    );
    assert_eq!(targets[0], (tenant, device_id));
}

/// `collect_family_device_targets` must INCLUDE tokens
/// whose `family_id` matches the cascade family and EXCLUDE tokens
/// from any other family for the same user. Pins the `!= → ==`
/// mutation on the family-id guard: with the mutation the function
/// would skip the matching family's tokens and instead drag in the
/// stranger-family's device, contaminating the cascade target set
/// and revoking a device that was never in the compromised chain.
///
/// Setup: same user holds two refresh tokens in two DIFFERENT
/// families, each bound to a different device.
///   - Family A → device DA (the compromised family)
///   - Family B → device DB (a sibling, unrelated family)
///
/// Expected (original): targets == `[(tenant, DA)]`.
/// With `!= → ==` mutation: family-A's active record is skipped;
/// family-B's record is included, so the result contains DB and
/// (via the seen-record line that runs before the loop) DA: the
/// total length flips from 1 to 2 and the contents include DB.
#[tokio::test]
async fn collect_family_targets_excludes_other_families_for_same_user() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(28);
    let ts = now();

    let tenant = fixture_tenant();
    let device_a = make_device_id("dev-family-a");
    let device_b = make_device_id("dev-family-b");

    // Issue token in family A bound to device A.
    let (plaintext_a, record_a) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: Some(device_a),
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();

    // Issue token in family B bound to device B (`family_id: None`
    // mints a fresh family per `issue_refresh_token`'s contract).
    issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: Some(device_b),
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();

    let family_a = record_a
        .family_id
        .as_ref()
        .expect("family must be assigned");

    // Reload record_a as the seen-record (mirrors how the cascade
    // hook invokes the collector after a token reuse is detected).
    let token_a_hash = hash_token(&plaintext_a, config.hash_pepper.as_deref());
    let seen_a = store.find_token(&token_a_hash).await.unwrap().unwrap();

    let targets = collect_family_device_targets(&store, family_a, &seen_a).await;

    // Family A's device must be present; family B's device must NOT.
    assert!(
        targets.contains(&(tenant, device_a)),
        "family-A's device must be in the cascade targets"
    );
    assert!(
        !targets.contains(&(tenant, device_b)),
        "family-B's device must NOT be in family-A's cascade; \
         mutating `!= → ==` would let it leak in"
    );
    assert_eq!(
        targets.len(),
        1,
        "only family-A's single device belongs in the target set"
    );
}
