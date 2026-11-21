//! The swap that makes a TOTP step, an HOTP counter and a recovery code
//! single-use is one guarded `UPDATE`, so of two requests holding one code
//! one wins and the other is answered `false`, never an error.
//!
//! The store runs the check a store outside this repository runs, opened
//! the way `main` opens it: a database file in WAL mode behind a pool of
//! five connections. That matters. A pool of one connection, or an
//! in-memory database, serialises every statement and would pass a store
//! that reads the row and then writes it in a transaction of its own, which
//! is the store that answers "database is locked" when two logins meet.
//!
//! The swap decides "is the row still what the caller loaded" on the
//! configuration as a value, and guards its write with the row's version.
//! The second group holds it to both: a row whose text is not what this
//! build would write is swapped all the same, and every write of a
//! configuration moves its version.

use axess::authn::{AuthnScope, FactorConfig, FactorKind, FactorStore, TenantId, UserId};
use axess_clock::testing::MockClock;
use axess_core::testing::store_contract::assert_compare_and_save_factor_contract;
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::str::FromStr;
use std::sync::Arc;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const ALICE: &str = "00000000-0000-0000-0000-000000000010";

/// A seeded database file of its own, opened as the application opens its
/// database, and the directory to remove afterwards.
async fn backend_on_a_file() -> (OurBackend, sqlx::SqlitePool, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("axess-factor-swap-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let opts =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", dir.join("factors.db").display()))
            .expect("database url")
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect to the database file");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    let clock = MockClock::at_reference();
    seed(
        &clock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF")
            .with_clock(Arc::new(clock.clone())),
    )
    .await
    .expect("seed");
    let backend = OurBackend::new(pool.clone()).with_clock(Arc::new(clock));
    (backend, pool, dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_meets_the_compare_and_save_contract() {
    let (backend, pool, dir) = backend_on_a_file().await;

    assert_compare_and_save_factor_contract(
        Arc::new(backend),
        &TenantId::try_new(TENANT).expect("tenant"),
        &UserId::try_new(ALICE).expect("user"),
    )
    .await;

    pool.close().await;
    std::fs::remove_dir_all(&dir).expect("remove the scratch dir");
}

fn alice() -> AuthnScope {
    AuthnScope::User {
        tenant_id: TenantId::try_new(TENANT).expect("tenant"),
        user_id: UserId::try_new(ALICE).expect("user"),
    }
}

/// An HOTP row as a release wrote it before the attempt count, the attempt
/// limit and the lock existed: all of them have a default when read today.
const HOTP_IN_AN_OLDER_SHAPE: &str = r#"{"Hotp":{"secret":"JBSWY3DPEHPK3PXP","digits":6,"algorithm":"Sha1","counter":7,"lookahead_window":10}}"#;

/// A recovery-code set from before `under_previous_pepper`, written by a
/// tool that also orders its keys and spaces its text differently.
const CODES_IN_AN_OLDER_SHAPE: &str = r#"{ "RecoveryCodes": { "codes": [
    { "used_at": null, "hash": "hmac-sha256:00000000000000000000000000000000000000000000000000000000000000aa" },
    { "used_at": null, "hash": "hmac-sha256:00000000000000000000000000000000000000000000000000000000000000bb" }
] } }"#;

/// The configuration with one JSON member replaced: how these tests move a
/// counter on or spend a code without naming every field of the kind.
fn with(config: &FactorConfig, pointer: &str, value: serde_json::Value) -> FactorConfig {
    let mut json = serde_json::to_value(config).expect("a configuration serialises");
    *json.pointer_mut(pointer).expect("the member exists") = value;
    serde_json::from_value(json).expect("the changed configuration reads")
}

async fn put_text(pool: &sqlx::SqlitePool, kind: &FactorKind, text: &str) {
    let done = sqlx::query(
        "UPDATE factor_configs SET config_json = ?1 WHERE user_id = ?2 AND tenant_id = ?3 AND kind = ?4",
    )
    .bind(text)
    .bind(ALICE)
    .bind(TENANT)
    .bind(kind.as_str())
    .execute(pool)
    .await
    .expect("write the row's text");
    assert_eq!(done.rows_affected(), 1, "the row exists");
}

async fn version(pool: &sqlx::SqlitePool, kind: &FactorKind) -> i64 {
    sqlx::query_scalar(
        "SELECT version FROM factor_configs WHERE user_id = ?1 AND tenant_id = ?2 AND kind = ?3",
    )
    .bind(ALICE)
    .bind(TENANT)
    .bind(kind.as_str())
    .fetch_one(pool)
    .await
    .expect("the row's version")
}

/// The case the comparison by value exists for. A stored row whose text is
/// not what this build serialises the same configuration to (a field that
/// has a default since, other key order, other spacing) is still the row
/// the caller loaded: the swap answers true. A comparison of text answers
/// false for it on every attempt, and the service reads that as a replay:
/// the right HOTP code, or an unspent recovery code, never gets its user in.
#[tokio::test]
async fn a_row_in_an_older_shape_is_swapped_and_not_read_as_a_replay() {
    let (backend, pool, dir) = backend_on_a_file().await;
    let scope = alice();
    let cases = [
        (
            FactorKind::Hotp,
            HOTP_IN_AN_OLDER_SHAPE,
            "/Hotp/counter",
            serde_json::json!(8),
        ),
        (
            FactorKind::RecoveryCode,
            CODES_IN_AN_OLDER_SHAPE,
            "/RecoveryCodes/codes/0/used_at",
            serde_json::json!("2027-01-15T08:00:00Z"),
        ),
    ];
    for (kind, older, spent, value) in cases {
        let name = kind.as_str().to_string();
        let parsed: FactorConfig = serde_json::from_str(older).expect("the older shape reads");
        backend.save_factor(&scope, parsed).await.expect("save");
        put_text(&pool, &kind, older).await;

        let loaded = backend
            .load_factor(&scope, kind.clone())
            .await
            .expect("load")
            .expect("the row");
        assert_ne!(
            serde_json::to_string(&loaded).expect("serialises"),
            older,
            "{name}: the case under test is a row whose text differs from what is written today"
        );

        let next = with(&loaded, spent, value.clone());
        assert!(
            backend
                .compare_and_save_factor(&scope, &loaded, next)
                .await
                .expect("swap"),
            "{name}: a row in an older shape that nobody changed must be swapped"
        );
        assert!(
            !backend
                .compare_and_save_factor(&scope, &loaded, with(&loaded, spent, value))
                .await
                .expect("swap"),
            "{name}: the same swap again is the replay"
        );
    }

    pool.close().await;
    std::fs::remove_dir_all(&dir).expect("remove the scratch dir");
}

/// The swap's write is guarded by the version it read, which is sound only
/// if nothing replaces a configuration without moving the version: the
/// store's own statements, and one typed by hand.
#[tokio::test]
async fn every_write_of_a_configuration_moves_its_version() {
    let (backend, pool, dir) = backend_on_a_file().await;
    let scope = alice();
    let kind = FactorKind::Hotp;
    let config: FactorConfig =
        serde_json::from_str(HOTP_IN_AN_OLDER_SHAPE).expect("the older shape reads");

    backend
        .save_factor(&scope, config.clone())
        .await
        .expect("the first save inserts");
    let start = version(&pool, &kind).await;

    backend
        .save_factor(&scope, with(&config, "/Hotp/counter", serde_json::json!(8)))
        .await
        .expect("the second save replaces");
    assert_eq!(version(&pool, &kind).await, start + 1, "a save over a row");

    put_text(&pool, &kind, HOTP_IN_AN_OLDER_SHAPE).await;
    assert_eq!(
        version(&pool, &kind).await,
        start + 2,
        "a statement typed by hand"
    );

    let loaded = backend
        .load_factor(&scope, kind.clone())
        .await
        .expect("load")
        .expect("the row");
    let next = with(&loaded, "/Hotp/counter", serde_json::json!(9));
    assert!(
        backend
            .compare_and_save_factor(&scope, &loaded, next.clone())
            .await
            .expect("swap")
    );
    assert_eq!(version(&pool, &kind).await, start + 3, "a swap that wrote");

    assert!(
        !backend
            .compare_and_save_factor(&scope, &loaded, next)
            .await
            .expect("swap")
    );
    assert_eq!(
        version(&pool, &kind).await,
        start + 3,
        "a swap that answered false wrote nothing"
    );

    pool.close().await;
    std::fs::remove_dir_all(&dir).expect("remove the scratch dir");
}

/// A swap never succeeds on a factor the store would no longer load. The
/// loads hand out enabled rows only, and disabling a row does not move its
/// version, so the swap's guard names `enabled` itself: a factor disabled
/// between a caller's load and its swap answers false and is not written.
#[tokio::test]
async fn a_factor_disabled_since_it_was_loaded_is_not_swapped() {
    let (backend, pool, dir) = backend_on_a_file().await;
    let scope = alice();
    let kind = FactorKind::Hotp;
    let config: FactorConfig =
        serde_json::from_str(HOTP_IN_AN_OLDER_SHAPE).expect("the older shape reads");
    backend.save_factor(&scope, config).await.expect("save");

    let loaded = backend
        .load_factor(&scope, kind.clone())
        .await
        .expect("load")
        .expect("the row, while it is enabled");
    let text_before: String = sqlx::query_scalar(
        "SELECT config_json FROM factor_configs WHERE user_id = ?1 AND tenant_id = ?2 AND kind = ?3",
    )
    .bind(ALICE)
    .bind(TENANT)
    .bind(kind.as_str())
    .fetch_one(&pool)
    .await
    .expect("the row's text");
    let version_before = version(&pool, &kind).await;

    let disabled = sqlx::query(
        "UPDATE factor_configs SET enabled = 0 WHERE user_id = ?1 AND tenant_id = ?2 AND kind = ?3",
    )
    .bind(ALICE)
    .bind(TENANT)
    .bind(kind.as_str())
    .execute(&pool)
    .await
    .expect("disable the factor");
    assert_eq!(disabled.rows_affected(), 1);
    assert!(
        backend
            .load_factor(&scope, kind.clone())
            .await
            .expect("load")
            .is_none(),
        "a disabled factor is not loaded"
    );

    let next = with(&loaded, "/Hotp/counter", serde_json::json!(8));
    assert!(
        !backend
            .compare_and_save_factor(&scope, &loaded, next.clone())
            .await
            .expect("swap"),
        "a factor disabled since it was loaded must not be swapped"
    );
    let text_after: String = sqlx::query_scalar(
        "SELECT config_json FROM factor_configs WHERE user_id = ?1 AND tenant_id = ?2 AND kind = ?3",
    )
    .bind(ALICE)
    .bind(TENANT)
    .bind(kind.as_str())
    .fetch_one(&pool)
    .await
    .expect("the row's text");
    assert_eq!(text_after, text_before, "a refused swap writes nothing");
    assert_eq!(version(&pool, &kind).await, version_before);

    // Enabled again, the same row is the one the caller loaded, and is
    // swapped: the refusal was for the flag and nothing else.
    sqlx::query(
        "UPDATE factor_configs SET enabled = 1 WHERE user_id = ?1 AND tenant_id = ?2 AND kind = ?3",
    )
    .bind(ALICE)
    .bind(TENANT)
    .bind(kind.as_str())
    .execute(&pool)
    .await
    .expect("enable the factor");
    assert!(
        backend
            .compare_and_save_factor(&scope, &loaded, next)
            .await
            .expect("swap")
    );

    pool.close().await;
    std::fs::remove_dir_all(&dir).expect("remove the scratch dir");
}
