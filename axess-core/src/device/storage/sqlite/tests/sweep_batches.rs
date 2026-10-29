//! The sweep changes at most a batch of rows per statement and repeats until
//! it is done, with the same totals as one unbounded statement.

use super::*;
use crate::device::storage::sql_common::SweepCutoffs;
use crate::device::storage::sqlite::sweep::run_in_batches;
use crate::device::store::SweepConfig;

async fn save_idle_trusted(store: &SqliteDeviceStore, t: &TenantId, n: usize, now: DateTime<Utc>) {
    for i in 0..n {
        let d = crate::authn::ids::testing::device(&format!("batch-{i}"));
        let mut device = build_device(t, None, &d, 0x30, vec![]);
        device.trust_level = DeviceTrustLevel::Trusted;
        device.last_seen_at = now - chrono::Duration::days(200);
        device.first_seen_at = device.last_seen_at;
        store
            .save(&device, crate::device::test_now())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_stage_runs_in_bounded_statements_and_sums_to_the_whole() {
    let store = fresh_store().await;
    let (t, _, _) = ids();
    let now = now_at(20, 0);
    save_idle_trusted(&store, &t, 10, now).await;
    let cutoffs = SweepCutoffs::new(&SweepConfig::default(), now);

    let (counts, statements) = run_in_batches(&store.pool, &t.to_string(), &cutoffs, 3)
        .await
        .unwrap();

    assert_eq!(counts.trusted_to_seen, 10, "every row is demoted");
    assert_eq!(counts.seen_to_revoked, 0);
    // Stage 1 needs ceil(10 / 3) + 0 statements: three full batches and one
    // short one; the other three stages find nothing and run once each.
    assert_eq!(statements, 4 + 3);
    let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE trust_level = 'Seen'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(seen, 10);
}

/// A stage whose rows fill the last batch exactly ends on an empty statement.
#[tokio::test]
async fn a_stage_that_ends_on_a_full_batch_runs_once_more() {
    let store = fresh_store().await;
    let (t, _, _) = ids();
    let now = now_at(20, 0);
    save_idle_trusted(&store, &t, 6, now).await;
    let cutoffs = SweepCutoffs::new(&SweepConfig::default(), now);

    let (counts, statements) = run_in_batches(&store.pool, &t.to_string(), &cutoffs, 3)
        .await
        .unwrap();

    assert_eq!(counts.trusted_to_seen, 6);
    assert_eq!(statements, 3 + 3);
}

/// With the production batch size one statement per stage is enough for a
/// small table, so the sweep's cost for it is unchanged.
#[tokio::test]
async fn a_small_table_costs_one_statement_per_stage() {
    let store = fresh_store().await;
    let (t, _, _) = ids();
    let now = now_at(20, 0);
    save_idle_trusted(&store, &t, 4, now).await;
    let cutoffs = SweepCutoffs::new(&SweepConfig::default(), now);

    let (counts, statements) = run_in_batches(
        &store.pool,
        &t.to_string(),
        &cutoffs,
        crate::device::storage::sweep_batches::SWEEP_BATCH,
    )
    .await
    .unwrap();
    assert_eq!(counts.trusted_to_seen, 4);
    assert_eq!(statements, 4);
}
