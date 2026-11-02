//! Pools for the live-server tests of the Postgres and MySQL stores.
//!
//! Each call hands back a pool on a schema (Postgres) or database (MySQL)
//! that nothing else uses, so tests that run in parallel, and runs that
//! repeat against the same server, never see each other's rows. The tests
//! that use these are `#[ignore]`d; when they are run on purpose a missing
//! URL or an unreachable server is a failure, never a skip.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Every name [`unique_name`] makes starts with this.
const PREFIX: &str = "axt_";

/// How old a test schema or database must be before a later run drops it.
/// Far longer than any live run, so a run going on in parallel keeps its own.
const STALE_AFTER_NANOS: u128 = 60 * 60 * 1_000_000_000;

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A name no other test, process or earlier run has used.
fn unique_name() -> String {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{PREFIX}{}_{}_{n}", std::process::id(), now_nanos())
}

/// Whether `name` is one [`unique_name`] made more than [`STALE_AFTER_NANOS`]
/// before `now`. A name of any other shape is never stale, so the sweep
/// cannot drop a schema or database these helpers did not create.
fn is_stale(name: &str, now: u128) -> bool {
    let Some(rest) = name.strip_prefix(PREFIX) else {
        return false;
    };
    let mut parts = rest.split('_');
    let (Some(pid), Some(made), Some(n), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !(digits(pid) && digits(n)) {
        return false;
    }
    made.parse::<u128>()
        .is_ok_and(|made| now.saturating_sub(made) > STALE_AFTER_NANOS)
}

/// Drop what an earlier run left behind: list the `axt%` schemas (Postgres)
/// or databases (MySQL) with `list_sql`, and drop every one [`is_stale`]
/// accepts with the statement `drop_sql` builds for it. Once per process for
/// each server (`swept`), through [`sweep_stale_once`].
#[cfg(any(feature = "postgres", feature = "mysql"))]
async fn sweep_stale<DB>(
    swept: &'static tokio::sync::OnceCell<()>,
    admin: &sqlx::Pool<DB>,
    list_sql: &'static str,
    drop_sql: impl Fn(&str) -> String,
) where
    DB: sqlx::Database,
    DB::Arguments: sqlx::IntoArguments<DB>,
    for<'c> &'c sqlx::Pool<DB>: sqlx::Executor<'c, Database = DB>,
    String: sqlx::Type<DB> + for<'r> sqlx::Decode<'r, DB>,
    usize: sqlx::ColumnIndex<DB::Row>,
{
    sweep_stale_once(
        swept,
        sqlx::query_scalar(list_sql).fetch_all(admin),
        |stale| {
            let statement = drop_sql(&stale);
            async move {
                sqlx::query(sqlx::AssertSqlSafe(statement))
                    .execute(admin)
                    .await
                    .map(drop)
            }
        },
    )
    .await;
}

/// The sweep's decisions, apart from any server: the stale names `list`
/// returns (see [`is_stale`]), each dropped with `drop`. Once per process
/// for each `swept` cell, so test processes running in parallel do not all
/// race to drop the same schema, and a failed list or drop (Postgres can
/// answer "tuple concurrently deleted" when another process got there
/// first) is logged, not a panic that fails an unrelated test: the sweep is
/// housekeeping.
#[cfg(any(feature = "postgres", feature = "mysql"))]
async fn sweep_stale_once<L, D, DF>(swept: &'static tokio::sync::OnceCell<()>, list: L, drop: D)
where
    L: std::future::Future<Output = Result<Vec<String>, sqlx::Error>>,
    D: Fn(String) -> DF,
    DF: std::future::Future<Output = Result<(), sqlx::Error>>,
{
    swept
        .get_or_init(|| async {
            let names = match list.await {
                Ok(names) => names,
                Err(e) => {
                    tracing::warn!(error = %e, "live-test sweep: could not list earlier schemas");
                    return;
                }
            };
            let now = now_nanos();
            for stale in names.into_iter().filter(|n| is_stale(n, now)) {
                if let Err(e) = drop(stale.clone()).await {
                    tracing::warn!(%stale, error = %e, "live-test sweep: could not drop");
                }
            }
        })
        .await;
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
    static SWEPT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    sweep_stale(
        &SWEPT,
        &admin,
        "SELECT schema_name::text FROM information_schema.schemata WHERE schema_name LIKE 'axt%'",
        |stale| format!("DROP SCHEMA IF EXISTS {stale} CASCADE"),
    )
    .await;
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
    static SWEPT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    sweep_stale(
        &SWEPT,
        &admin,
        "SELECT CAST(schema_name AS CHAR) FROM information_schema.schemata WHERE schema_name LIKE 'axt%'",
        |stale| format!("DROP DATABASE IF EXISTS {stale}"),
    )
    .await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_helpers_names_older_than_the_cutoff_are_stale() {
        let now = 10 * STALE_AFTER_NANOS;
        let made = |at: u128| format!("axt_4242_{at}_0");
        assert!(
            is_stale(&made(now - 2 * STALE_AFTER_NANOS), now),
            "an earlier run's name"
        );
        assert!(
            !is_stale(&made(now - STALE_AFTER_NANOS / 2), now),
            "a run going on now"
        );
        assert!(
            !is_stale(&made(now + STALE_AFTER_NANOS), now),
            "a name from a clock ahead"
        );
        for other in [
            "axess_test",
            "axt_",
            "axt_4242_1",
            "axt_4242_1_0_9",
            "axt_x_1_0",
            "axt_4242_1_y",
            "axt_4242_notanumber_0",
            "public",
        ] {
            assert!(!is_stale(other, now), "{other} is not one of ours");
        }
    }

    #[test]
    fn a_fresh_name_is_not_stale_and_has_the_swept_shape() {
        let name = unique_name();
        assert!(!is_stale(&name, now_nanos()));
        assert!(is_stale(&name, now_nanos() + 2 * STALE_AFTER_NANOS));
    }

    /// A drop that fails (another process dropped the schema first) is
    /// logged, not a panic, and the sweep runs once per process.
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    #[tokio::test]
    async fn the_sweep_runs_once_and_survives_a_failed_drop() {
        static SWEPT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        let stale = format!("axt_1_{}_0", now_nanos() - 2 * STALE_AFTER_NANOS);
        let tried = std::sync::atomic::AtomicUsize::new(0);
        sweep_stale_once(&SWEPT, async { Ok(vec![stale.clone()]) }, |_| {
            tried.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(sqlx::Error::RowNotFound) }
        })
        .await;
        assert_eq!(tried.load(std::sync::atomic::Ordering::SeqCst), 1);
        sweep_stale_once(
            &SWEPT,
            async { panic!("the sweep ran a second time") },
            |_| async { Ok(()) },
        )
        .await;
    }
}
