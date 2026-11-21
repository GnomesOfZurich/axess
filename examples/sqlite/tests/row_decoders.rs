//! The user, tenant and audit row decoders against corrupted rows: a value
//! the schema's CHECK constraints did not catch is an integrity error the
//! lookup reports, never a panic and never a user read as unlocked, and an
//! audit row that cannot be read is counted by reason, never returned, and
//! does not fail the query.

use axess::authn::{IdentityLookup, TenantId, UserId};
use axess_clock::testing::MockClock;
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const TENANT: &str = "00000000-0000-0000-0000-000000000001";

async fn pool(clock: &MockClock) -> sqlx::SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("in-memory url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    seed(
        clock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF")
            .with_clock(std::sync::Arc::new(clock.clone())),
    )
    .await
    .expect("seed");
    pool
}

#[tokio::test]
async fn a_user_row_with_a_bad_id_column_is_an_error_not_a_panic() {
    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    let backend = OurBackend::new(pool.clone()).with_clock(std::sync::Arc::new(clock.clone()));
    let alice = UserId::try_new(ALICE).expect("user id");
    assert!(
        backend.get_user(&alice).await.expect("lookup").is_some(),
        "the seeded row reads"
    );

    sqlx::query("UPDATE users SET created_by = 'not a user id' WHERE id = ?1")
        .bind(ALICE)
        .execute(&pool)
        .await
        .expect("corrupt the row");
    let err = backend
        .get_user(&alice)
        .await
        .expect_err("a malformed id column is an integrity error");
    assert!(err.to_string().contains("created_by"), "{err}");
}

#[tokio::test]
async fn an_unparseable_locked_until_never_reads_as_unlocked() {
    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    let backend = OurBackend::new(pool.clone()).with_clock(std::sync::Arc::new(clock.clone()));
    let alice = UserId::try_new(ALICE).expect("user id");
    assert_eq!(
        backend.account_status(&alice).await.expect("status"),
        axess::authn::EntityState::Active,
        "the seeded row is active"
    );

    sqlx::query("UPDATE users SET locked_until = 'garbage' WHERE id = ?1")
        .bind(ALICE)
        .execute(&pool)
        .await
        .expect("corrupt the row");
    let status = backend.account_status(&alice).await;
    assert!(
        !matches!(status, Ok(axess::authn::EntityState::Active)),
        "garbage in locked_until must not read as unlocked: {status:?}"
    );
    assert!(
        status.is_err(),
        "an unparseable locked_until is an error: {status:?}"
    );
    let full = backend.get_user(&alice).await;
    assert!(full.is_err(), "the full row read reports it too: {full:?}");
}

#[tokio::test]
async fn a_tenant_row_with_a_bad_id_column_is_an_error_not_a_panic() {
    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    let backend = OurBackend::new(pool.clone()).with_clock(std::sync::Arc::new(clock.clone()));
    let tenant = TenantId::try_new(TENANT).expect("tenant id");
    assert!(backend.get_tenant(&tenant).await.expect("lookup").is_some());

    sqlx::query("UPDATE tenants SET updated_by = 'x' WHERE id = ?1")
        .bind(TENANT)
        .execute(&pool)
        .await
        .expect("corrupt the row");
    let err = backend
        .get_tenant(&tenant)
        .await
        .expect_err("a malformed id column is an integrity error");
    assert!(err.to_string().contains("updated_by"), "{err}");
}

/// Write one audit row the way an earlier release did: the session column
/// holds `session`, whatever text that is.
async fn plant_event(pool: &sqlx::SqlitePool, id: &str, session: &str) {
    sqlx::query(
        "INSERT INTO auth_events
         (id, user_id, tenant_id, session_id, event_type, event_status, event_time, ip_source)
         VALUES (?1, ?2, ?3, ?4, 'authenticated', 'success', '2026-01-01T00:00:00+00:00', 'unknown')",
    )
    .bind(id)
    .bind(ALICE)
    .bind(TENANT)
    .bind(session)
    .execute(pool)
    .await
    .expect("plant the row");
}

#[tokio::test]
async fn an_audit_row_names_its_session_by_the_key_and_reads_an_older_row_as_its_key() {
    use axess::authn::IdentityAuthnLog;
    use axess::authn::{AuditQuery, AuthEventBuilder, AuthEventType, EventQueryFilter};
    use axess::{SessionId, SessionKey};

    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    let backend = OurBackend::new(pool.clone()).with_clock(std::sync::Arc::new(clock.clone()));
    let (alice, tenant) = (
        UserId::try_new(ALICE).expect("user id"),
        TenantId::try_new(TENANT).expect("tenant id"),
    );
    let written = SessionKey::from_bytes([0x5a; 32]);
    backend
        .record_event(
            AuthEventBuilder::success(AuthEventType::Authenticated)
                .attributed_to(&alice, &tenant)
                .with_session(written)
                .build_at(
                    axess_clock::Timestamp::from_unix_seconds(1_800_000_000).expect("in range"),
                ),
        )
        .await
        .expect("record the event");
    let stored: String = sqlx::query_scalar("SELECT session_id FROM auth_events")
        .fetch_one(&pool)
        .await
        .expect("the row");
    assert_eq!(
        stored,
        written.to_string(),
        "the column holds the key's 64 characters"
    );

    let older = SessionId::from_bytes([0x17; 16]);
    plant_event(&pool, "older", &older.to_string()).await;
    let read = backend
        .query_events(&tenant, &EventQueryFilter::default())
        .await
        .expect("query")
        .events;
    let mut sessions: Vec<Option<SessionKey>> = read.iter().map(|e| e.session_id).collect();
    sessions.sort();
    let mut expected = vec![Some(written), Some(SessionKey::of(&older))];
    expected.sort();
    assert_eq!(
        sessions, expected,
        "a row of this release reads as its key, a row holding a session id as the key of that id"
    );

    plant_event(&pool, "corrupt", "not a session").await;
    let trail = backend
        .query_events(&tenant, &EventQueryFilter::default())
        .await
        .expect("query");
    assert_eq!(
        trail.unreadable.session, 1,
        "a row whose session column names no session is counted under its reason"
    );
    let read = trail.events;
    assert_eq!(
        read.len(),
        2,
        "a row whose session column names no session is not read: {read:?}"
    );
    assert!(
        read.iter().all(|e| e.session_id.is_some()),
        "no row is read as an event of no session: {read:?}"
    );
}

/// Write one audit row with the given text in the columns a reader parses.
async fn plant_row(
    pool: &sqlx::SqlitePool,
    id: &str,
    session: Option<&str>,
    event_type: &str,
    event_status: &str,
    event_time: &str,
) {
    sqlx::query(
        "INSERT INTO auth_events
         (id, user_id, tenant_id, session_id, event_type, event_status, event_time, ip_source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'unknown')",
    )
    .bind(id)
    .bind(ALICE)
    .bind(TENANT)
    .bind(session)
    .bind(event_type)
    .bind(event_status)
    .bind(event_time)
    .execute(pool)
    .await
    .expect("plant the row");
}

#[tokio::test]
async fn an_audit_query_answers_the_rows_it_read_and_counts_those_it_could_not_by_reason() {
    use axess::SessionKey;
    use axess::authn::{AuditQuery, EventQueryFilter, UnreadableRows};
    use axess_testing::mock_tracing::LineCapture;

    const AT: &str = "2026-01-01T00:00:00+00:00";
    let unreadable_texts = [
        "session-text-of-no-session",
        "event-type-text-of-no-type",
        "status-text-of-no-status",
        "time-text-of-no-time",
    ];
    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    let backend = OurBackend::new(pool.clone()).with_clock(std::sync::Arc::new(clock.clone()));
    let tenant = TenantId::try_new(TENANT).expect("tenant id");
    let good = SessionKey::from_bytes([0x5a; 32]);
    plant_row(
        &pool,
        "good",
        Some(&good.to_string()),
        "authenticated",
        "success",
        AT,
    )
    .await;
    plant_row(
        &pool,
        "no-session",
        Some(unreadable_texts[0]),
        "authenticated",
        "success",
        AT,
    )
    .await;
    plant_row(&pool, "no-type", None, unreadable_texts[1], "success", AT).await;
    plant_row(
        &pool,
        "no-status",
        None,
        "authenticated",
        unreadable_texts[2],
        AT,
    )
    .await;
    plant_row(
        &pool,
        "no-time",
        None,
        "authenticated",
        "success",
        unreadable_texts[3],
    )
    .await;

    // The capture keeps a second dispatcher registered and asks every
    // callsite again once it is live: a plain default subscriber lost the
    // warning whenever a sibling test, with no subscriber, hit its callsite
    // first and the callsite cached that it is never wanted.
    let capture = LineCapture::install();
    let trail = backend
        .query_events(&tenant, &EventQueryFilter::default())
        .await
        .expect("a row that cannot be read does not fail the query");
    let logged = capture.text();
    drop(capture);

    let sessions: Vec<_> = trail.events.iter().map(|e| e.session_id).collect();
    assert_eq!(
        sessions,
        vec![Some(good)],
        "the good row is read, and only it"
    );
    assert_eq!(
        trail.unreadable,
        UnreadableRows {
            session: 1,
            event_type: 1,
            other: 2,
        },
        "each row that could not be read is counted under its reason"
    );
    assert_eq!(trail.unreadable.total(), 4);

    let returned = format!("{trail:?}");
    assert!(
        logged.contains("rows that could not be read"),
        "the count reaches the log: {logged}"
    );
    for text in unreadable_texts {
        assert!(!returned.contains(text), "{text} is returned: {returned}");
        assert!(!logged.contains(text), "{text} is logged: {logged}");
    }
}

/// The audit query meets the store kit's rule for rows it cannot read: one
/// readable row and one of each kind that cannot be read, and the query
/// answers the first and counts the others, each once, under its reason.
#[tokio::test]
async fn the_audit_query_meets_the_unreadable_rows_contract() {
    use axess::SessionKey;
    use axess::authn::{AuthEventBuilder, AuthEventType, IdentityAuthnLog};

    let clock = MockClock::at_reference();
    let pool = pool(&clock).await;
    let backend = OurBackend::new(pool.clone()).with_clock(std::sync::Arc::new(clock.clone()));
    let (alice, tenant) = (
        UserId::try_new(ALICE).expect("user id"),
        TenantId::try_new(TENANT).expect("tenant id"),
    );
    let readable = AuthEventBuilder::success(AuthEventType::Authenticated)
        .attributed_to(&alice, &tenant)
        .with_session(SessionKey::from_bytes([0x5a; 32]))
        .build_at(axess_clock::Timestamp::from_unix_seconds(1_800_000_000).expect("in range"));
    backend
        .record_event(readable.clone())
        .await
        .expect("record the readable event");
    const AT: &str = "2026-01-01T00:00:00+00:00";
    plant_row(
        &pool,
        "no-session",
        Some("not a session"),
        "authenticated",
        "success",
        AT,
    )
    .await;
    plant_row(&pool, "no-type", None, "not an event type", "success", AT).await;
    plant_row(
        &pool,
        "no-status",
        None,
        "authenticated",
        "not a status",
        AT,
    )
    .await;

    axess_core::testing::store_contract::assert_unreadable_rows_contract(
        &backend, &tenant, &readable,
    )
    .await;
}
