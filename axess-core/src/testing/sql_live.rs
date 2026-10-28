//! Pools for the live-server tests of the Postgres and MySQL stores.
//!
//! Each call hands back a pool on a schema (Postgres) or database (MySQL)
//! that nothing else uses, so tests that run in parallel, and runs that
//! repeat against the same server, never see each other's rows. The tests
//! that use these are `#[ignore]`d; when they are run on purpose a missing
//! URL or an unreachable server is a failure, never a skip.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A name no other test, process or earlier run has used.
fn unique_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("axt_{}_{nanos}_{n}", std::process::id())
}

fn url_from(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        panic!("{var} is not set: these tests need a live server and run only with --ignored")
    })
}

/// A Postgres pool whose connections all use a fresh, empty schema.
#[cfg(feature = "postgres")]
pub(crate) async fn postgres_pool(max_connections: u32) -> sqlx::PgPool {
    use sqlx::postgres::PgPoolOptions;

    let url = url_from("POSTGRES_URL");
    let schema = unique_name();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap_or_else(|e| panic!("POSTGRES_URL is set but the server is unreachable: {e}"));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .expect("create the test schema");
    admin.close().await;

    PgPoolOptions::new()
        .max_connections(max_connections)
        .after_connect(move |conn, _meta| {
            let set = format!("SET search_path TO {schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(set))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect to the test schema")
}

/// A MySQL pool on a fresh, empty database.
#[cfg(feature = "mysql")]
pub(crate) async fn mysql_pool(max_connections: u32) -> sqlx::MySqlPool {
    use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
    use std::str::FromStr;

    let url = url_from("MYSQL_URL");
    let database = unique_name();
    // `caching_sha2_password` needs a secure channel; the container's
    // certificate is self-signed, so it is required but not verified.
    let options = MySqlConnectOptions::from_str(&url)
        .expect("MYSQL_URL parses")
        .ssl_mode(sqlx::mysql::MySqlSslMode::Required);
    let admin = MySqlPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|e| panic!("MYSQL_URL is set but the server is unreachable: {e}"));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .expect("create the test database");
    admin.close().await;

    MySqlPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options.database(&database))
        .await
        .expect("connect to the test database")
}
