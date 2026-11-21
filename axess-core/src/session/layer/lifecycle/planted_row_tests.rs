//! Rows no release writes, planted in a real SQLite table as raw MessagePack
//! and presented with a cookie that verifies: a row below the current
//! schema version is no session of this release, whatever it holds and
//! wherever it lies. The request runs as a guest, the row is left as it
//! lies, and nothing is told to the audit sink or asked of the registry.

use super::*;
use crate::authn::ids::testing as ids;
use crate::metrics::MetricSinks;
use crate::session::crypto::{BoundFormat, SessionCrypto};
use crate::session::data::{SESSION_DATA_VERSION, SessionData};
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::UnknownLiveness;
use crate::session::layer::audit::LayerSessionEnded;
use crate::session::storage::sqlite::SqliteSessionStore;
use crate::session::store::{MemorySessionRegistry, SessionRegistryHandle};
use crate::testing::RecordingMetrics;
use crate::testing::mock_random::MockRng;
use axess_clock::testing::MockClock;
use axess_testing::mock_tracing::TracingCapture;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A sink that counts what it is told.
#[derive(Default)]
struct Counted(AtomicUsize);

impl SessionEndAudit for Counted {
    fn session_ended<'a>(
        &'a self,
        _: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

/// A row in the shape this release writes: `data` as MessagePack of its JSON
/// form, with its `version` member set to `version`.
fn tagged(data: &SessionData, version: u8) -> serde_json::Value {
    let mut row = serde_json::to_value(data).expect("a session serialises");
    row["version"] = serde_json::json!(version);
    row
}

fn signed_in_now() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state.set_authenticated(
        ids::user("u"),
        ids::tenant("t"),
        MockClock::reference_time(),
    );
    data
}

/// A pending step-up as the release before the flow marker stored it:
/// version 2, the step-up label as its method, and no `flow` member.
fn pending_under_the_label(version: Option<u8>) -> serde_json::Value {
    let at = MockClock::reference_time();
    let mut row = serde_json::json!({
        "auth_state": {
            "kind": "Authenticating",
            "user_id": ids::user("u"),
            "tenant_id": ids::tenant("t"),
            "method_name": "step-up",
            "remaining": [{ "Required": "Totp" }],
            "completed": [["Password", at]],
            "attempt_count": 0,
            "last_attempt": null,
        },
        "fingerprint": null,
        "device_id": null,
        "custom": { "cart": ["item"] },
        "revision": 4,
        "touched_at": at,
    });
    if let Some(version) = version {
        row["version"] = serde_json::json!(version);
    }
    row
}

/// Every row below the version these tests plant, by what it is.
fn rows_below_the_version() -> Vec<(&'static str, serde_json::Value)> {
    let at = MockClock::reference_time();
    vec![
        (
            "a pending step-up of version 2 with no flow",
            pending_under_the_label(Some(2)),
        ),
        (
            "a signed-in row of version 1",
            serde_json::json!({
                "version": 1,
                "auth_state": {
                    "kind": "Authenticated",
                    "user_id": ids::user("u"),
                    "tenant_id": ids::tenant("t"),
                    "authn_time": at,
                    "factors_completed": ["Password"],
                },
                "fingerprint": null,
                "custom": {},
            }),
        ),
        (
            "a row with no version member",
            serde_json::json!({
                "auth_state": { "kind": "Guest" },
                "fingerprint": null,
                "custom": { "cart": ["item"] },
            }),
        ),
        (
            "a guest in the current shape tagged 2",
            tagged(
                &SessionData {
                    custom: serde_json::json!({ "cart": ["item"] }),
                    ..SessionData::default()
                },
                2,
            ),
        ),
        (
            "a signed-in session in the current shape tagged 2",
            tagged(&signed_in_now(), 2),
        ),
    ]
}

fn packed(row: &serde_json::Value) -> Vec<u8> {
    rmp_serde::to_vec_named(row).expect("a row encodes")
}

/// An in-process SQLite table behind a store, and a second handle on the
/// same connection to plant and read rows with.
async fn table(crypto: Option<SessionCrypto>) -> (SqliteSessionStore, SqlitePool) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = match crypto {
        Some(crypto) => SqliteSessionStore::new(pool.clone(), crypto),
        None => SqliteSessionStore::plaintext_insecure(pool.clone()),
    }
    .with_clock(Arc::new(MockClock::at_reference()));
    store.init_schema().await.unwrap();
    (store, pool)
}

async fn plant(pool: &SqlitePool, name: &str, bytes: &[u8]) {
    sqlx::query("INSERT INTO sessions (id, data, data_bin, expires_at) VALUES (?1, '', ?2, ?3)")
        .bind(name)
        .bind(bytes)
        .bind(i64::MAX)
        .execute(pool)
        .await
        .unwrap();
}

async fn bytes_under(pool: &SqlitePool, name: &str) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT data_bin FROM sessions WHERE id = ?1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// What a request carrying a cookie for `id` met, and what it left behind.
struct Presented {
    outcome: LoadOutcome,
    refused: u64,
    told: usize,
    held: bool,
    warned: Vec<String>,
}

/// Present a cookie for `id` to `store`, with a registry that holds `id`
/// for the user of the planted rows and metrics that count.
async fn present(store: &SqliteSessionStore, id: SessionId) -> Presented {
    let clock = MockClock::at_reference();
    let registry: Arc<dyn SessionRegistryHandle> = MemorySessionRegistry::new()
        .with_clock(Arc::new(clock.clone()))
        .handle();
    assert!(
        registry
            .register(&ids::user("u"), &SessionKey::of(&id))
            .await
    );
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::default();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            cfg.cookie_name.as_ref(),
            keys.sign_cookie(&CookieSession::of_id(id))
        ))
        .unwrap(),
    );
    let recorder = Arc::new(RecordingMetrics::default());
    let metrics = MetricSinks::noop().with_session(recorder.clone());
    let sink = Arc::new(Counted::default());
    let audit: Arc<dyn SessionEndAudit> = sink.clone();
    let capture = TracingCapture::install();
    let outcome = load_session(
        store,
        &keys,
        &cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy {
            registry: Some(registry.as_ref()),
            unknown: UnknownLiveness::Reject,
            clock: &clock,
            metrics: Some(&metrics),
            audit: &audit,
        },
    )
    .await;
    let warned = capture
        .events()
        .into_iter()
        .filter(|event| event.level == tracing::Level::WARN)
        .map(|event| event.message)
        .collect();
    Presented {
        outcome,
        refused: recorder.count("session_row_refused"),
        told: sink.0.load(Ordering::SeqCst),
        held: registry
            .held_sessions(&ids::user("u"))
            .await
            .unwrap()
            .contains(&SessionKey::of(&id)),
        warned,
    }
}

/// The row of the planted bytes in the current version is served: what
/// refuses the rows below is their version, not their bytes or the way they
/// were planted.
#[tokio::test]
async fn the_same_row_at_the_current_version_is_served() {
    let (store, pool) = table(None).await;
    let id = SessionId::new(&MockRng::new(51));
    let key = SessionKey::of(&id).to_string();
    plant(
        &pool,
        &key,
        &packed(&tagged(&signed_in_now(), SESSION_DATA_VERSION)),
    )
    .await;
    let seen = present(&store, id).await;
    assert!(seen.outcome.stored);
    assert_eq!(*seen.outcome.session.key(), SessionKey::of(&id));
    assert!(seen.outcome.data.auth_state.is_authenticated());
    assert_eq!(seen.refused, 0);
}

/// A row below the version under the session's key is not served, not
/// migrated, not ended and not re-sealed: the request is a guest under a
/// fresh session, the row is counted once and logged by the key's log form
/// with its version, and its bytes, the audit sink and the registry are as
/// they were.
#[tokio::test]
async fn a_row_below_the_version_under_the_key_is_counted_and_left_as_it_lies() {
    for (what, row) in rows_below_the_version() {
        let (store, pool) = table(None).await;
        let id = SessionId::new(&MockRng::new(52));
        let key = SessionKey::of(&id);
        let bytes = packed(&row);
        plant(&pool, &key.to_string(), &bytes).await;

        let seen = present(&store, id).await;

        assert!(!seen.outcome.stored, "{what} was served");
        assert_ne!(*seen.outcome.session.key(), SessionKey::of(&id), "{what}");
        assert!(seen.outcome.data.auth_state.is_guest(), "{what}");
        assert_eq!(seen.outcome.data.custom, serde_json::Value::Null, "{what}");
        assert!(!seen.outcome.session_ended, "{what}");
        assert_eq!(seen.refused, 1, "{what} is counted once");
        let version = row["version"].as_u64().unwrap_or(1);
        let line = seen
            .warned
            .iter()
            .find(|line| line.contains("below the current schema version"))
            .unwrap_or_else(|| panic!("{what} is logged: {:?}", seen.warned));
        assert!(
            line.contains(&format!("session={}", key.prefix())),
            "{line}"
        );
        assert!(line.contains(&format!("version={version}")), "{line}");
        assert!(
            line.contains(&format!("current={SESSION_DATA_VERSION}")),
            "{line}"
        );
        assert!(!line.contains(&id.to_string()), "{line}");
        assert!(!line.contains(&key.to_string()), "{line}");
        assert_eq!(
            bytes_under(&pool, &key.to_string()).await,
            Some(bytes),
            "{what} is left as it lies"
        );
        assert_eq!(seen.told, 0, "{what} is no ending");
        assert!(seen.held, "{what}: the registry was not asked");
    }
}

/// The same rows under the id's own text, where the release before keyed
/// its rows: no store looks there, so nothing is found, counted or told.
#[tokio::test]
async fn a_row_below_the_version_under_the_ids_text_is_not_found() {
    for (what, row) in rows_below_the_version() {
        let (store, pool) = table(None).await;
        let id = SessionId::new(&MockRng::new(53));
        let bytes = packed(&row);
        plant(&pool, &id.to_string(), &bytes).await;

        let seen = present(&store, id).await;

        assert!(!seen.outcome.stored, "{what} was served");
        assert!(seen.outcome.data.auth_state.is_guest(), "{what}");
        assert_eq!(
            seen.refused, 0,
            "{what}: the store holds no row under the key"
        );
        assert_eq!(
            bytes_under(&pool, &id.to_string()).await,
            Some(bytes),
            "{what}"
        );
        assert_eq!(seen.told, 0, "{what}");
        assert!(seen.held, "{what}");
    }
}

/// A sealed row below the version that only the previous key opens is not
/// re-sealed under the current one: a row below the version is never
/// written back by a store.
#[tokio::test]
async fn a_sealed_row_below_the_version_is_not_resealed() {
    let previous = crate::testing::test_key(8);
    let (store, pool) = table(Some(
        SessionCrypto::new(crate::testing::test_key(9)).with_previous_key(previous),
    ))
    .await;
    let id = SessionId::new(&MockRng::new(54));
    let key = SessionKey::of(&id);
    let sealed = SessionCrypto::new(previous)
        .seal_bound(
            BoundFormat::SESSION,
            key.as_bytes(),
            &packed(&tagged(&signed_in_now(), 2)),
        )
        .unwrap();
    plant(&pool, &key.to_string(), &sealed).await;

    let seen = present(&store, id).await;

    assert!(!seen.outcome.stored);
    assert_eq!(seen.refused, 1);
    assert_eq!(
        bytes_under(&pool, &key.to_string()).await,
        Some(sealed),
        "the row is not re-sealed"
    );
}

// ── one shape is read ──────────────────────────────────────────────────────

/// `row`, at the current version, with `member` of its state removed or
/// replaced.
fn current_without(
    data: &SessionData,
    member: &str,
    with: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut row = tagged(data, SESSION_DATA_VERSION);
    let state = row["auth_state"]
        .as_object_mut()
        .expect("a state is an object");
    assert!(state.remove(member).is_some(), "the state writes {member}");
    if let Some(value) = with {
        state.insert(member.to_owned(), value);
    }
    row
}

fn stepping_up() -> SessionData {
    let mut data = signed_in_now();
    assert!(
        data.auth_state
            .begin_step_up(vec![crate::authn::factor::FactorStep::Required(
                crate::authn::factor::FactorKind::Totp
            )])
    );
    data
}

fn logging_in() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state.begin_authenticating(
        ids::user("u"),
        ids::tenant("t"),
        "password+totp".into(),
        vec![crate::authn::factor::FactorStep::Required(
            crate::authn::factor::FactorKind::Password,
        )],
    );
    data
}

/// A row at the current version in a shape this release does not write is
/// not a session: the store refuses it as undecodable, the request is a
/// guest, and the row is left as it lies. Among them the pending step-up
/// a node of the release before wrote back, still tagged 3, under the
/// step-up label and with no flow: read as a login it would be served as
/// one, outside every check a signed-in session is held to.
#[tokio::test]
async fn a_row_at_the_version_in_another_shape_is_not_a_session() {
    let rows = [
        (
            "a pending step-up with no flow",
            pending_under_the_label(Some(SESSION_DATA_VERSION)),
        ),
        (
            "a pending state with no flow",
            current_without(&logging_in(), "flow", None),
        ),
        (
            "a signed-in state with no login time",
            current_without(&signed_in_now(), "signed_in_at", None),
        ),
        (
            "a signed-in state with a plain list of factors",
            current_without(
                &signed_in_now(),
                "factors_completed",
                Some(serde_json::json!(["Password"])),
            ),
        ),
    ];
    for (what, row) in rows {
        let (store, pool) = table(None).await;
        let id = SessionId::new(&MockRng::new(55));
        let key = SessionKey::of(&id);
        let bytes = packed(&row);
        plant(&pool, &key.to_string(), &bytes).await;

        let refused = store.load(&key).await;
        assert!(
            matches!(
                refused,
                Err(crate::session::storage::session_codec::SqlStoreError::Decode(_))
            ),
            "{what} was read: {refused:?}"
        );
        let seen = present(&store, id).await;
        assert!(!seen.outcome.stored, "{what} was served");
        assert!(seen.outcome.data.auth_state.is_guest(), "{what}");
        assert_eq!(seen.told, 0, "{what}");
        assert_eq!(
            bytes_under(&pool, &key.to_string()).await,
            Some(bytes),
            "{what} is left as it lies"
        );
    }
}

/// What this release writes it reads: a step-up and a login in progress
/// each round-trip with their flow in the stored bytes, the login's as
/// `login`; and a row of a higher version in the current shape is served
/// as it was stored.
#[tokio::test]
async fn what_this_release_writes_is_read_and_a_higher_version_is_served() {
    let (store, pool) = table(None).await;
    for (what, data, flow) in [
        ("a step-up", stepping_up(), &b"step_up"[..]),
        ("a login in progress", logging_in(), &b"login"[..]),
    ] {
        let key = SessionKey::of(&SessionId::new(&MockRng::new(56)));
        store
            .save(&key, &data, std::time::Duration::from_secs(60))
            .await
            .unwrap();
        let bytes = bytes_under(&pool, &key.to_string()).await.expect("written");
        assert!(
            bytes.windows(4).any(|w| w == b"flow"),
            "{what} is stored with its flow"
        );
        assert!(bytes.windows(flow.len()).any(|w| w == flow), "{what}");
        let back = store.load(&key).await.unwrap().expect("the row loads");
        assert_eq!(back.auth_state, data.auth_state, "{what}");
        store.delete(&key).await.unwrap();
    }

    let id = SessionId::new(&MockRng::new(57));
    let key = SessionKey::of(&id).to_string();
    let above = SESSION_DATA_VERSION + 1;
    plant(&pool, &key, &packed(&tagged(&signed_in_now(), above))).await;
    let seen = present(&store, id).await;
    assert!(seen.outcome.stored, "a row of a higher version is served");
    assert_eq!(*seen.outcome.session.key(), SessionKey::of(&id));
    assert_eq!(seen.outcome.data.version, above);
    assert_eq!(seen.outcome.data.auth_state, signed_in_now().auth_state);
    assert_eq!(seen.refused, 0);
}
