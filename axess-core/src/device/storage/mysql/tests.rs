//! The MySQL device store against a real server, ignored by default
//! (`MYSQL_URL=mysql://root:mysql@localhost:3306/axess_test`). Every test works on a schema of its own, so the
//! tests can run in parallel and be repeated against the same server.

use super::*;
use crate::authn::ids::testing;
use crate::device::storage::sql_common::FAMILY_INSERT_CHUNK;
use crate::device::store::consistency::{self as shared, at, dev_id, device, tenant, user};
use crate::device::store::sql_contract as contract;
use crate::testing::sql_live;

async fn store(connections: u32) -> MysqlDeviceStore {
    let store = MysqlDeviceStore::plaintext(sql_live::mysql_pool(connections).await);
    store.init_schema().await.expect("init_schema");
    store
}

macro_rules! live_contract {
    ($($name:ident),+ $(,)?) => {$(
        #[tokio::test]
        #[ignore = "requires a running MySQL (MYSQL_URL)"]
        async fn $name() {
            contract::$name(store(4).await).await;
        }
    )+};
}

live_contract!(
    records_round_trip,
    save_upserts_and_lookups_are_tenant_scoped,
    revoked_devices_never_use_up_the_active_limit,
    a_duplicated_refresh_family_does_not_poison_later_saves,
    writes_to_a_missing_device_are_errors,
    trust_changes_stamp_and_clear_the_times,
    a_conditional_change_never_overwrites_a_revocation,
    bindings_swaps_are_conditional,
    races_have_one_winner,
    the_sweep_follows_the_ladder,
    the_sweep_moves_one_level_and_counts_from_the_demotion,
);

#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn shared_contract() {
    shared::ties_are_broken_by_the_smaller_id(store(4).await).await;
    shared::a_sighting_never_rewinds_and_skips_a_revoked_row(store(4).await).await;
    shared::a_save_never_un_revokes(store(4).await).await;
    shared::a_revoked_save_without_a_time_is_stamped_and_purged(store(4).await).await;
    shared::sweep_decisions_agree_to_the_second(
        store(4).await.with_sweep_config(shared::tight_config()),
    )
    .await;
}

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: at(0),
        last_used_at: at(0),
    }
}

/// A losing bindings swap re-reads after its transaction has ended, so on a
/// pool of one connection it does not wait for the connection it holds.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn a_losing_bindings_swap_reports_a_conflict_on_a_one_connection_pool() {
    let pool = sql_live::mysql_pool(1).await;
    let store = MysqlDeviceStore::plaintext(pool);
    store.init_schema().await.unwrap();
    let (t, id) = (tenant(), dev_id("one-conn"));
    let before = vec![refresh("fam-a")];
    let mut d = device("one-conn", 7, DeviceTrustLevel::Seen, at(10));
    d.bindings = before.clone();
    store.save(&d, at(10)).await.unwrap();

    let (to_b, to_c) = ([refresh("fam-b")], [refresh("fam-c")]);
    let both = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(
            store.replace_bindings(&t, &id, &before, &to_b, at(11)),
            store.replace_bindings(&t, &id, &before, &to_c, at(11)),
        )
    })
    .await
    .expect("the losing swap must not wait on its own connection");
    let mut outcomes = vec![both.0.unwrap(), both.1.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        outcomes,
        vec![BindingsUpdate::Conflict, BindingsUpdate::Written]
    );
}

/// A revoked row without a revocation time, as an older version could save
/// it, is stamped by a sweep and purged by a later one.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn a_legacy_revoked_row_without_a_time_ages_out() {
    let store = store(4).await;
    let (t, id) = (tenant(), dev_id("legacy"));
    let now = at(1_000);
    store
        .save(&device("legacy", 8, DeviceTrustLevel::Revoked, now), now)
        .await
        .unwrap();
    sqlx::query("UPDATE devices SET revoked_at = NULL")
        .execute(&store.pool)
        .await
        .unwrap();

    store.sweep(&t, now).await.unwrap();
    let stamped = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(stamped.revoked_at, Some(now));
    let grace = SweepConfig::default().revoked_grace;
    let counts = store
        .sweep(&t, now + grace + chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
}

/// A purge removes the family index rows with the device, and a device with
/// more families than one insert batch is indexed completely, once.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn the_family_index_follows_the_device() {
    let store = store(4).await;
    let t = tenant();
    let count = FAMILY_INSERT_CHUNK * 2 + 200;
    let mut many = device("many", 1, DeviceTrustLevel::Seen, at(10));
    many.bindings = (0..count).map(|i| refresh(&format!("fam-{i}"))).collect();
    store.save(&many, at(10)).await.unwrap();
    for i in [0, FAMILY_INSERT_CHUNK - 1, FAMILY_INSERT_CHUNK, count - 1] {
        let found = store
            .find_by_refresh_family(&t, &format!("fam-{i}"))
            .await
            .unwrap();
        assert_eq!(found.len(), 1, "fam-{i}");
    }
    store.save(&many, at(11)).await.unwrap();
    let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_bindings_refresh")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(rows, count as i64, "a second save rewrites, not duplicates");

    let now = at(5_000_000);
    let mut gone = device("gone", 2, DeviceTrustLevel::Revoked, now);
    gone.revoked_at = Some(now - chrono::Duration::days(8));
    gone.bindings = vec![refresh("gone-fam")];
    store.save(&gone, now).await.unwrap();
    let counts = store.sweep(&t, now).await.unwrap();
    assert_eq!(counts.revoked_purged, 1);
    assert!(store.load(&t, &gone.id).await.unwrap().is_none());
    let (left,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM device_bindings_refresh WHERE family_id = 'gone-fam'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(left, 0, "the cascade removes the index rows on purge");
}

/// The bindings column on disk is not plaintext, and the row reads back
/// whole.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn an_encrypted_store_seals_the_bindings_column() {
    let pool = sql_live::mysql_pool(4).await;
    let store = MysqlDeviceStore::new(pool, SessionCrypto::new([0x42; 32]));
    store.init_schema().await.unwrap();
    let mut d = device("sealed", 3, DeviceTrustLevel::Seen, at(10));
    d.bindings = vec![refresh("fam-secret")];
    store.save(&d, at(10)).await.unwrap();

    let (raw,): (String,) = sqlx::query_as("SELECT bindings FROM devices")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(
        !raw.contains("fam-secret"),
        "bindings must not be plaintext"
    );
    assert_eq!(store.load(&tenant(), &d.id).await.unwrap().unwrap(), d);
}

/// A save that has read a live row and then waits behind a revocation does
/// not undo it: the write itself carries the rule, not only the read before it.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn a_save_that_waits_behind_a_revocation_does_not_undo_it() {
    let store = store(4).await;
    let (t, id) = (tenant(), dev_id("waiter"));
    let live = device("waiter", 5, DeviceTrustLevel::Trusted, at(10));
    store.save(&live, at(10)).await.unwrap();

    // Hold the row, as a concurrent revocation does until it commits.
    let mut holder = store.pool.begin().await.unwrap();
    sqlx::query("SELECT trust_level FROM devices WHERE tenant_id = ? AND id = ? FOR UPDATE")
        .bind(t.to_string())
        .bind(id.to_string())
        .fetch_one(&mut *holder)
        .await
        .unwrap();

    let saver = store.clone();
    let mut changed = live.clone();
    changed.user_id = Some(testing::user("someone-else"));
    changed.last_seen_at = at(50);
    let waiting = tokio::spawn(async move { saver.save(&changed, at(50)).await });
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;

    sqlx::query(
        "UPDATE devices SET trust_level = 'Revoked', revoked_at = ? WHERE tenant_id = ? AND id = ?",
    )
    .bind(at(20).timestamp())
    .bind(t.to_string())
    .bind(id.to_string())
    .execute(&mut *holder)
    .await
    .unwrap();
    holder.commit().await.unwrap();
    waiting.await.unwrap().unwrap();

    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.revoked_at, Some(at(20)));
    assert_eq!(row.user_id, Some(user()), "no other column was written");
    assert_eq!(row.last_seen_at, at(10));
}

/// The index insert is idempotent on its own, independent of the
/// de-duplication in front of it: the same family twice must not fail.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn the_family_index_insert_is_idempotent() {
    let store = store(2).await;
    let d = device("idem", 1, DeviceTrustLevel::Seen, at(10));
    store.save(&d, at(10)).await.unwrap();
    let mut tx = store.pool.begin().await.unwrap();
    rewrite_family_index(
        &mut tx,
        &tenant().to_string(),
        &d.id.to_string(),
        &["f".to_string(), "f".to_string()],
    )
    .await
    .expect("duplicate family ids in one rewrite");
    tx.commit().await.unwrap();
    assert_eq!(
        store
            .find_by_refresh_family(&tenant(), "f")
            .await
            .unwrap()
            .len(),
        1
    );
}
