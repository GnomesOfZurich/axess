//! The SQLite store against the shared contract, and the races the
//! single-connection test pool exposes.

use super::*;
use crate::device::store::consistency as shared;
use crate::device::types::DeviceBinding;

#[tokio::test]
async fn shared_contract() {
    shared::ties_are_broken_by_the_smaller_id(fresh_store().await).await;
    shared::a_shared_fingerprint_stays_findable_while_any_device_carries_it(fresh_store().await)
        .await;
    shared::a_sighting_never_rewinds_and_skips_a_revoked_row(fresh_store().await).await;
    shared::a_save_never_un_revokes(fresh_store().await).await;
    shared::a_revoked_save_without_a_time_is_stamped_and_purged(fresh_store().await).await;
    shared::sweep_decisions_agree_to_the_second(
        fresh_store()
            .await
            .with_sweep_config(shared::tight_config()),
    )
    .await;
}

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: now_at(10, 0),
        last_used_at: now_at(10, 0),
    }
}

/// Two bindings swaps that read the same bindings: the loser's write
/// matches no row, and on a one-connection pool its re-read must not wait
/// for the connection its own transaction holds.
#[tokio::test]
async fn a_losing_bindings_swap_reports_a_conflict_on_a_one_connection_pool() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteDeviceStore::plaintext(pool);
    store.init_schema().await.unwrap();
    let (t, u, d) = ids();
    let before = vec![refresh("fam-a")];
    store
        .save(
            &build_device(&t, Some(&u), &d, 7, before.clone()),
            now_at(10, 0),
        )
        .await
        .unwrap();

    let (to_b, to_c) = ([refresh("fam-b")], [refresh("fam-c")]);
    let (first, second) = tokio::join!(
        store.replace_bindings(&t, &d, &before, &to_b, now_at(10, 1)),
        store.replace_bindings(&t, &d, &before, &to_c, now_at(10, 1)),
    );
    let mut outcomes = vec![first.unwrap(), second.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        outcomes,
        vec![BindingsUpdate::Conflict, BindingsUpdate::Written]
    );
}

/// A revoked row without a revocation time, as an older version could save
/// it, is stamped by a sweep and purged by a later one.
#[tokio::test]
async fn a_legacy_revoked_row_without_a_time_ages_out() {
    let store = fresh_store().await;
    let (t, u, d) = ids();
    let now = now_at(10, 0);
    let mut revoked = build_device(&t, Some(&u), &d, 8, Vec::new());
    revoked.trust_level = DeviceTrustLevel::Revoked;
    store.save(&revoked, now).await.unwrap();
    sqlx::query("UPDATE devices SET revoked_at = NULL")
        .execute(&store.pool)
        .await
        .unwrap();

    store.sweep(&t, now).await.unwrap();
    let stamped = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(stamped.revoked_at, Some(now));
    let grace = SweepConfig::default().revoked_grace;
    let counts = store
        .sweep(&t, now + grace + chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
}
