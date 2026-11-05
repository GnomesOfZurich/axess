//! The named lock a create takes, against a real MySQL server, ignored by
//! default (`MYSQL_URL`): it is held until the create has committed, and a
//! create that is cancelled does not leave it on a pooled connection.

use super::*;
use crate::device::storage::sql_common::create_lock_name;
use crate::device::store::consistency::{at, device};
use crate::testing::sql_live;
use std::time::Duration;

/// The named lock is still taken by some session.
async fn lock_is_held(observer: &sqlx::MySqlPool, name: &str) -> bool {
    let free: Option<i64> = sqlx::query_scalar("SELECT IS_FREE_LOCK(?)")
        .bind(name)
        .fetch_one(observer)
        .await
        .unwrap();
    free == Some(0)
}

/// A pool on the test server, a session of its own for looking at locks.
async fn observer() -> sqlx::MySqlPool {
    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect_with(
            std::env::var("MYSQL_URL")
                .expect("MYSQL_URL")
                .parse::<sqlx::mysql::MySqlConnectOptions>()
                .expect("MYSQL_URL parses")
                .ssl_mode(sqlx::mysql::MySqlSslMode::Required),
        )
        .await
        .expect("observer connects")
}

/// A create that is dropped part-way, on a pool of one connection (so the
/// connection it used is the one the pool hands out next), must not leave
/// its lock on that connection: the lock belongs to the session, and the
/// next create of the same key, or any other session, would wait on it.
///
/// The create is held after it has taken its lock by a write lock another
/// session puts on the devices table, and is aborted there.
#[tokio::test]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn a_cancelled_create_does_not_leave_its_lock_on_a_pooled_connection() {
    let store = MysqlDeviceStore::plaintext(sql_live::mysql_pool(1).await);
    store.init_schema().await.unwrap();
    let observer = observer().await;
    let d = device("cancelled", 240, DeviceTrustLevel::Seen, at(10));
    let name = create_lock_name(&d);
    let schema: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    // `LOCK TABLES` is not available through prepared statements.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "LOCK TABLES `{schema}`.devices WRITE"
    )))
    .execute(&observer)
    .await
    .unwrap();

    let create = tokio::spawn({
        let store = store.clone();
        let d = d.clone();
        async move { store.create_or_find(&d, at(10)).await }
    });
    let mut waited = 0;
    while !lock_is_held(&observer, &name).await {
        assert!(waited < 500, "the create never took its lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += 1;
    }
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    sqlx::raw_sql("UNLOCK TABLES")
        .execute(&observer)
        .await
        .unwrap();

    // Give a close or a rollback that the drop started time to land.
    let mut waited = 0;
    while lock_is_held(&observer, &name).await && waited < 200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += 1;
    }
    assert!(
        !lock_is_held(&observer, &name).await,
        "a create cancelled while holding its lock left it on a pooled connection"
    );
}

/// Two creates of one key run one after the other: the second must find the
/// first one's device. With the lock given up before the commit, it can read
/// before the insert is visible and insert a second live device.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires a running MySQL (MYSQL_URL)"]
async fn concurrent_creates_of_one_key_leave_one_live_device() {
    let store = MysqlDeviceStore::plaintext(sql_live::mysql_pool(24).await);
    store.init_schema().await.unwrap();
    for round in 0..120u8 {
        let creators = (0..16u8).map(|n| {
            let store = store.clone();
            // One create key (tenant, fingerprint, owner), eight device ids.
            let d = device(
                &format!("race-{round}-{n}"),
                100 + round,
                DeviceTrustLevel::Seen,
                at(10),
            );
            tokio::spawn(async move { store.create_or_find(&d, at(10)).await.unwrap().id })
        });
        let mut ids = Vec::new();
        for c in creators {
            ids.push(c.await.unwrap());
        }
        ids.sort_by_key(ToString::to_string);
        ids.dedup();
        assert_eq!(
            ids.len(),
            1,
            "round {round}: concurrent creates of one key made {} devices",
            ids.len()
        );
    }
}
