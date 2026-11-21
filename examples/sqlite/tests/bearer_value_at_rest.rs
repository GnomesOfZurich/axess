//! No column of any table the example keeps holds a session id.
//!
//! A session's id is what its cookie carries. Alice signs in, opens her
//! dashboard and signs out; every value of every column of every table of
//! the example's schema, the audit table and the sessions table among them,
//! is then searched for every form of every id the run's cookies carried.
//! The positive half (the sessions table and the audit table name her
//! session by its key) keeps a search of the wrong database from passing.

use std::collections::BTreeMap;
use std::str::FromStr;

use axess::{SessionId, SessionKey};
use axess_clock::testing::MockClock;
use axess_example_sqlite::models::backend::{SEED_PASSWORD, seed};
use axess_example_sqlite::web::app::build_router_on;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Column as _, Row as _};
use tower::ServiceExt;

async fn app() -> (axum::Router, sqlx::SqlitePool) {
    let clock = MockClock::at_reference();
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    seed(
        &clock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF")
            .with_clock(std::sync::Arc::new(clock.clone())),
    )
    .await
    .expect("seed");
    let router = build_router_on(pool.clone(), std::sync::Arc::new(clock))
        .await
        .0;
    (router, pool)
}

/// A browser's cookies, and the bearer value of every session cookie it was
/// handed.
#[derive(Default)]
struct Browser {
    cookies: BTreeMap<String, String>,
    bearers: Vec<SessionId>,
}

impl Browser {
    async fn send(
        &mut self,
        router: &axum::Router,
        request: axum::http::request::Builder,
        body: Body,
    ) -> String {
        let jar = self
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut request = if jar.is_empty() {
            request
        } else {
            request.header(header::COOKIE, jar)
        }
        .body(body)
        .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "192.0.2.7:50000".parse::<std::net::SocketAddr>().unwrap(),
        ));
        let response = router.clone().oneshot(request).await.unwrap();
        for set in response.headers().get_all(header::SET_COOKIE) {
            let text = set.to_str().unwrap();
            let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if name.ends_with("axess.sid") && !value.is_empty() {
                let (id, _) = value.split_once('.').expect("id.mac");
                let bytes: [u8; 16] = URL_SAFE_NO_PAD.decode(id).unwrap().try_into().unwrap();
                self.bearers.push(SessionId::from_bytes(bytes));
            }
            if attributes.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The CSRF token a page's form carries.
    fn csrf(page: &str) -> String {
        let marker = r#"name="_csrf" value=""#;
        let start = page.find(marker).expect("a CSRF input") + marker.len();
        page[start..].split('"').next().unwrap().to_owned()
    }

    async fn post_form(
        &mut self,
        router: &axum::Router,
        uri: &str,
        form: &[(&str, &str)],
    ) -> String {
        let body = serde_urlencoded::to_string(form).unwrap();
        self.send(
            router,
            Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
            Body::from(body),
        )
        .await
    }
}

/// Every value of every column of every table, as bytes, with where it is.
async fn every_value(pool: &sqlx::SqlitePool) -> Vec<(String, Vec<u8>)> {
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
            .fetch_all(pool)
            .await
            .unwrap();
    assert!(tables.iter().any(|t| t == "auth_events"), "{tables:?}");
    assert!(tables.iter().any(|t| t == "sessions"), "{tables:?}");
    let mut values = Vec::new();
    for table in tables {
        // The name comes from the database's own catalogue, quoted.
        // Every column is read as its bytes: text as its UTF-8, a blob as
        // itself, a number as its text.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM \"{table}\"")))
            .fetch_all(pool)
            .await
            .unwrap();
        for row in rows {
            for (n, column) in row.columns().iter().enumerate() {
                let value: Option<Vec<u8>> = row
                    .try_get::<Option<Vec<u8>>, _>(n)
                    .or_else(|_| {
                        row.try_get::<Option<String>, _>(n)
                            .map(|v| v.map(String::into_bytes))
                    })
                    .or_else(|_| {
                        row.try_get::<Option<i64>, _>(n)
                            .map(|v| v.map(|i| i.to_string().into_bytes()))
                    })
                    .or_else(|_| {
                        row.try_get::<Option<f64>, _>(n)
                            .map(|v| v.map(|f| f.to_string().into_bytes()))
                    })
                    .unwrap_or_else(|e| panic!("{table}.{}: {e}", column.name()));
                if let Some(value) = value {
                    values.push((format!("{table}.{}", column.name()), value));
                }
            }
        }
    }
    values
}

/// Every form a bearer value could take in a column: the hyphenated text in
/// either case, the 32 digits in either case, the cookie's base64, the 16
/// raw bytes, and the first eight digits with three dots.
fn forms(id: &SessionId) -> Vec<Vec<u8>> {
    let hyphenated = id.to_string();
    let simple = hyphenated.replace('-', "");
    vec![
        hyphenated.clone().into_bytes(),
        hyphenated.to_uppercase().into_bytes(),
        simple.clone().into_bytes(),
        simple.to_uppercase().into_bytes(),
        URL_SAFE_NO_PAD.encode(id.as_bytes()).into_bytes(),
        format!("{}...", &simple[..8]).into_bytes(),
        id.as_bytes().to_vec(),
    ]
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn assert_no_id(values: &[(String, Vec<u8>)], bearers: &[SessionId]) {
    for id in bearers {
        for form in forms(id) {
            for (place, value) in values {
                assert!(
                    !holds(value, &form),
                    "{place} holds the bearer value {id}: {}",
                    String::from_utf8_lossy(value)
                );
            }
        }
    }
}

fn names_key(values: &[(String, Vec<u8>)], table: &str, key: &SessionKey) -> bool {
    let text = key.to_string();
    values
        .iter()
        .any(|(place, value)| place.starts_with(table) && holds(value, text.as_bytes()))
}

#[tokio::test]
async fn no_column_of_the_example_holds_a_session_id() {
    let (router, pool) = app().await;
    let mut browser = Browser::default();
    let login = browser
        .send(&router, Request::get("/login"), Body::empty())
        .await;
    let token = Browser::csrf(&login);
    browser
        .post_form(
            &router,
            "/login",
            &[
                ("identifier", "alice"),
                ("password", SEED_PASSWORD),
                ("_csrf", &token),
            ],
        )
        .await;
    let dashboard = browser
        .send(&router, Request::get("/dashboard"), Body::empty())
        .await;
    let signed_in = *browser.bearers.last().expect("a session cookie");
    let key = SessionKey::of(&signed_in);

    let values = every_value(&pool).await;
    assert_no_id(&values, &browser.bearers);
    assert!(
        names_key(&values, "sessions.id", &key),
        "the row is stored under the key"
    );
    assert!(
        names_key(&values, "auth_events.session_id", &key),
        "the login's row names the key"
    );

    let token = Browser::csrf(&dashboard);
    browser
        .post_form(&router, "/logout", &[("_csrf", &token)])
        .await;
    let values = every_value(&pool).await;
    assert_no_id(&values, &browser.bearers);
    assert!(
        browser.bearers.len() >= 2,
        "a guest and a signed-in session"
    );
}
