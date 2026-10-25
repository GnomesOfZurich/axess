//! `find_by_fingerprint_for_user` finds the caller's own device and is served
//! by its index.

use super::*;

fn owned(t: &TenantId, u: &UserId, id: &str, fp: u8, seen: DateTime<Utc>) -> Device {
    let mut d = build_device(
        t,
        Some(u),
        &crate::authn::ids::testing::device(id),
        fp,
        vec![],
    );
    d.last_seen_at = seen;
    d
}

#[tokio::test]
async fn returns_only_the_callers_device_newest_first() {
    let store = fresh_store().await;
    let (t, u, _) = ids();
    let other = crate::authn::ids::testing::user("user-2");
    store
        .save(&owned(&t, &u, "old", 5, now_at(9, 0)), now_at(9, 0))
        .await
        .unwrap();
    store
        .save(&owned(&t, &u, "new", 5, now_at(11, 0)), now_at(11, 0))
        .await
        .unwrap();
    store
        .save(
            &owned(&t, &other, "theirs", 5, now_at(12, 0)),
            now_at(12, 0),
        )
        .await
        .unwrap();
    store
        .save(&owned(&t, &u, "elsewhere", 6, now_at(12, 0)), now_at(12, 0))
        .await
        .unwrap();

    let got = store
        .find_by_fingerprint_for_user(&t, &u, &fingerprint(5))
        .await
        .unwrap()
        .expect("found");
    assert_eq!(got.id, crate::authn::ids::testing::device("new"));
    assert!(
        store
            .find_by_fingerprint_for_user(&t, &u, &fingerprint(7))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_lookup_uses_the_user_fingerprint_index() {
    let store = fresh_store().await;
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN SELECT tenant_id FROM devices \
         WHERE tenant_id = ?1 AND user_id = ?2 AND fingerprint_hash = ?3 \
         ORDER BY last_seen_at DESC LIMIT 1",
    )
    .bind("t")
    .bind("u")
    .bind(vec![0u8; 32])
    .fetch_all(&store.pool)
    .await
    .unwrap();
    let detail = plan
        .iter()
        .map(|r| r.3.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        detail.contains("idx_devices_user_fingerprint"),
        "plan: {detail}"
    );
}
