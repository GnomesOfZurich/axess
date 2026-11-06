//! The second-factor and signup flows end to end, driven through the router
//! the way a browser drives it: cookies carried between requests, a CSRF
//! token read from each form.
//!
//! Alice enrolls TOTP and is shown her recovery codes once. From then on
//! her login asks for TOTP or a recovery code; a code gets her in once and
//! is refused the second time.

use axess::SystemClock;
use axess_example_sqlite::{
    models::backend::{SEED_PASSWORD, seed},
    web::app::build_router,
};
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{collections::BTreeMap, net::SocketAddr, str::FromStr};
use tower::ServiceExt;

/// A browser: a cookie jar, and the address it connects from. The auth
/// routes allow ten requests a minute per address, so each sign-in round
/// in a test uses its own.
struct Browser {
    router: Router,
    pool: sqlx::SqlitePool,
    cookies: BTreeMap<String, String>,
    peer: SocketAddr,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Browser {
    async fn new() -> Self {
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
            &SystemClock,
            &pool,
            &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
        )
        .await
        .expect("seed");
        let (router, _store) = build_router(pool.clone()).await;
        Self {
            router,
            pool,
            cookies: BTreeMap::new(),
            peer: "192.0.2.1:50000".parse().expect("address"),
        }
    }

    fn move_to(&mut self, address: &str) {
        self.peer = format!("{address}:50000").parse().expect("address");
    }

    async fn send(&mut self, method: &str, uri: &str, form: Option<Vec<(&str, &str)>>) -> Page {
        let cookie = self
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut req = Request::builder().method(method).uri(uri);
        if !cookie.is_empty() {
            req = req.header(header::COOKIE, cookie);
        }
        let body = match form {
            Some(fields) => {
                req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                Body::from(serde_urlencoded::to_string(fields).expect("form encodes"))
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).expect("request");
        req.extensions_mut().insert(ConnectInfo(self.peer));

        let res = self.router.clone().oneshot(req).await.expect("infallible");
        for set in res.headers().get_all(header::SET_COOKIE) {
            let pair = set
                .to_str()
                .expect("ascii cookie")
                .split(';')
                .next()
                .expect("pair");
            let (name, value) = pair.split_once('=').expect("name=value");
            self.cookies.insert(name.to_owned(), value.to_owned());
        }
        let status = res.status();
        let location = res
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().expect("ascii location").to_owned());
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .expect("body");
        Page {
            status,
            location,
            body: String::from_utf8(body.to_vec()).expect("utf8"),
        }
    }

    /// Load `uri` and return the CSRF token from its first form.
    async fn token_from(&mut self, uri: &str) -> String {
        let page = self.send("GET", uri, None).await;
        assert_eq!(page.status, StatusCode::OK, "GET {uri}: {}", page.body);
        attribute(&page.body, r#"name="_csrf" value=""#)
    }

    async fn post(&mut self, form_page: &str, action: &str, fields: Vec<(&str, &str)>) -> Page {
        let token = self.token_from(form_page).await;
        let mut fields = fields;
        fields.push(("_csrf", &token));
        self.send("POST", action, Some(fields)).await
    }

    async fn log_in(&mut self) -> Page {
        let fields = vec![("identifier", "alice"), ("password", SEED_PASSWORD)];
        self.post("/login", "/login", fields).await
    }

    async fn log_out(&mut self) {
        let page = self.post("/dashboard", "/logout", vec![]).await;
        assert!(page.status.is_redirection(), "logout: {}", page.status);
    }
}

/// The value after `prefix`, up to the next `"`.
fn attribute(html: &str, prefix: &str) -> String {
    let start = html
        .find(prefix)
        .unwrap_or_else(|| panic!("{prefix} in {html}"))
        + prefix.len();
    let end = html[start..].find('"').expect("closing quote");
    html[start..start + end].to_owned()
}

/// The secret the enrolment page shows for typing in by hand.
fn shown_secret(html: &str) -> String {
    let start = html.find(r#"id="totp-secret""#).expect("secret shown");
    let rest = &html[start..];
    let open = rest.find('>').expect("tag end") + 1;
    let close = rest[open..].find('<').expect("closing tag");
    rest[open..open + close].to_owned()
}

/// The current code for a base32 TOTP secret, as an authenticator shows it.
fn totp_code(secret: &str) -> String {
    let secret = totp_rs::Secret::try_from_base32(secret).expect("base32 secret");
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(secret)
        .build()
        .expect("valid totp")
        .generate_current()
        .to_string()
}

/// Every `<code>` on the page that looks like a recovery code.
fn recovery_codes(html: &str) -> Vec<String> {
    html.split("<code>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</code>").map(|(code, _)| code.to_owned()))
        .filter(|code| code.len() == 11 && code.as_bytes()[5] == b'-')
        .collect()
}

#[tokio::test]
async fn a_recovery_code_stands_in_for_totp_once() {
    let mut browser = Browser::new().await;

    // Enroll TOTP; the recovery codes are shown on the confirmation page.
    let page = browser.log_in().await;
    assert_eq!(page.location.as_deref(), Some("/dashboard"));
    let setup = browser.send("GET", "/setup-totp", None).await;
    let secret = shown_secret(&setup.body);
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);
    let code = totp_code(&secret);
    let fields = vec![
        ("code", code.as_str()),
        ("current_password", SEED_PASSWORD),
        ("_csrf", token.as_str()),
    ];
    let enrolled = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert_eq!(enrolled.status, StatusCode::OK, "{}", enrolled.body);
    let codes = recovery_codes(&enrolled.body);
    assert_eq!(codes.len(), axess::RECOVERY_CODE_COUNT, "{}", enrolled.body);
    browser.log_out().await;

    // The password now leads to the second step, where a recovery code,
    // typed carelessly, is accepted in place of the TOTP code.
    browser.move_to("192.0.2.2");
    let page = browser.log_in().await;
    assert_eq!(page.location.as_deref(), Some("/totp"));
    let sloppy = codes[0].replace('-', " ").to_lowercase();
    let page = browser
        .post("/totp", "/recovery-code", vec![("code", &sloppy)])
        .await;
    assert_eq!(
        page.location.as_deref(),
        Some("/dashboard"),
        "{}",
        page.body
    );
    browser.log_out().await;

    // The same code a second time is refused; another one still works.
    browser.move_to("192.0.2.3");
    browser.log_in().await;
    let page = browser
        .post("/totp", "/recovery-code", vec![("code", &codes[0])])
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Wrong code"), "{}", page.body);
    // The wrong guess earned this browser a second's delay: a code typed
    // straight away is refused unread, and runs once the second has passed.
    let page = browser
        .post("/totp", "/recovery-code", vec![("code", &codes[1])])
        .await;
    assert!(page.body.contains("Too many wrong codes"), "{}", page.body);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let page = browser
        .post("/totp", "/recovery-code", vec![("code", &codes[1])])
        .await;
    assert_eq!(
        page.location.as_deref(),
        Some("/dashboard"),
        "{}",
        page.body
    );
}

/// The stored TOTP row for alice, as the database holds it.
async fn stored_totp(pool: &sqlx::SqlitePool) -> (String, String) {
    let config: String = sqlx::query_scalar(
        "SELECT config_json FROM factor_configs
          WHERE kind = 'totp' AND user_id = '00000000-0000-0000-0000-000000000010'",
    )
    .fetch_one(pool)
    .await
    .expect("one totp row");
    let methods: String = sqlx::query_scalar(
        "SELECT group_concat(steps_json) FROM auth_methods WHERE name = 'password+totp'",
    )
    .fetch_one(pool)
    .await
    .expect("method row");
    (config, methods)
}

#[tokio::test]
async fn an_enrolled_totp_factor_is_not_replaced_from_the_session() {
    let mut browser = Browser::new().await;
    browser.log_in().await;

    let setup = browser.send("GET", "/setup-totp", None).await;
    let secret = shown_secret(&setup.body);
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);
    let code = totp_code(&secret);
    let fields = vec![
        ("code", code.as_str()),
        ("current_password", SEED_PASSWORD),
        ("_csrf", token.as_str()),
    ];
    let enrolled = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert_eq!(enrolled.status, StatusCode::OK, "{}", enrolled.body);
    let before = stored_totp(&browser.pool).await;
    assert!(
        before.0.contains("last_step\":") && !before.0.contains("last_step\":null"),
        "enrolment must record the verified step: {}",
        before.0
    );

    // A hijacked session posts its own secret and a valid code for it.
    let attacker = axess::generate_totp_secret(&axess::SystemRng);
    let attacker_code = totp_code(&attacker);
    let token = browser.token_from("/dashboard").await;
    let fields = vec![
        ("secret", attacker.as_str()),
        ("current_password", SEED_PASSWORD),
        ("code", attacker_code.as_str()),
        ("_csrf", token.as_str()),
    ];
    let page = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert_eq!(
        page.status,
        StatusCode::CONFLICT,
        "a replace must be refused and say so, got {}",
        page.body
    );
    assert!(recovery_codes(&page.body).is_empty());
    assert_eq!(
        stored_totp(&browser.pool).await,
        before,
        "the stored factor, recovery codes and method must be unchanged"
    );
}

/// Two enrolments posted together with a valid code: the first to write wins
/// and the other is turned away without recovery codes, so the secret that
/// was confirmed is the one that is kept.
#[tokio::test]
async fn concurrent_totp_enrolments_do_not_overwrite_each_other() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    let setup = browser.send("GET", "/setup-totp", None).await;
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);
    let secret = shown_secret(&setup.body);

    let cookie = browser
        .cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let enrol = || {
        let code = totp_code(&secret);
        let form = serde_urlencoded::to_string(vec![
            ("code", code.as_str()),
            ("current_password", SEED_PASSWORD),
            ("_csrf", token.as_str()),
        ])
        .expect("form encodes");
        let mut req = Request::builder()
            .method("POST")
            .uri("/setup-totp")
            .header(header::COOKIE, cookie.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .expect("request");
        req.extensions_mut().insert(ConnectInfo(browser.peer));
        let router = browser.router.clone();
        async move {
            let res = router.oneshot(req).await.expect("infallible");
            let body = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .expect("body");
            String::from_utf8(body.to_vec()).expect("utf8")
        }
    };
    let (first, second) = tokio::join!(enrol(), enrol());

    let winners = [first, second]
        .iter()
        .filter(|body| !recovery_codes(body).is_empty())
        .count();
    assert_eq!(winners, 1, "enrolments that were told they won");
}

/// The store, not the handler's earlier check, decides between two
/// enrolments: the second insert for a user reports it lost and the first
/// secret stays. Run in order, so it fails whenever the insert is not
/// conditional, which the concurrent test above can pass without.
#[tokio::test]
async fn the_second_totp_insert_for_a_user_loses_and_the_first_stays() {
    use axess::authn::{
        AuthnScope, FactorConfig, FactorStore, TenantId, TotpConfig, UserId, ZeroizedString,
    };
    let browser = Browser::new().await;
    let backend = axess_example_sqlite::models::backend::OurBackend::new(browser.pool.clone());
    let scope = AuthnScope::User {
        tenant_id: TenantId::try_new("00000000-0000-0000-0000-000000000001").expect("tenant"),
        user_id: UserId::try_new("00000000-0000-0000-0000-000000000010").expect("user"),
    };
    let totp = |secret: &str| {
        FactorConfig::Totp(TotpConfig {
            secret: ZeroizedString::new(secret).into(),
            ..TotpConfig::default()
        })
    };
    assert!(
        backend
            .insert_factor_if_absent(&scope, totp("FIRSTSECRET"))
            .await
            .expect("first insert")
    );
    assert!(
        !backend
            .insert_factor_if_absent(&scope, totp("SECONDSECRET"))
            .await
            .expect("second insert"),
        "the second enrolment must lose"
    );
    let (stored, _) = stored_totp(&browser.pool).await;
    assert!(stored.contains("FIRSTSECRET") && !stored.contains("SECONDSECRET"));
}

/// Enrolment is all or nothing: when the method upgrade finds no row to
/// upgrade, no TOTP factor and no recovery codes stay behind, so a login
/// that still asks for the password only is never paired with a stored
/// second factor, and the dashboard still offers to enrol.
#[tokio::test]
async fn a_failed_method_upgrade_leaves_no_second_factor_stored() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    let setup = browser.send("GET", "/setup-totp", None).await;
    let secret = shown_secret(&setup.body);
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);

    sqlx::query("DELETE FROM auth_methods WHERE user_id = '00000000-0000-0000-0000-000000000010'")
        .execute(&browser.pool)
        .await
        .expect("remove alice's method");

    let code = totp_code(&secret);
    let fields = vec![
        ("code", code.as_str()),
        ("current_password", SEED_PASSWORD),
        ("_csrf", token.as_str()),
    ];
    let page = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert!(
        recovery_codes(&page.body).is_empty(),
        "a failed enrolment must show no recovery codes: {}",
        page.body
    );
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factor_configs
          WHERE kind IN ('totp', 'recovery_code')
            AND user_id = '00000000-0000-0000-0000-000000000010'",
    )
    .fetch_one(&browser.pool)
    .await
    .expect("count");
    assert_eq!(stored, 0, "the enrolment must leave no factor rows behind");
}

/// The secret that is enrolled is the one the page issued, held in the
/// session: a secret the client posts, with a valid code for it, is ignored.
#[tokio::test]
async fn the_client_cannot_choose_the_secret_it_enrols() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    let setup = browser.send("GET", "/setup-totp", None).await;
    assert!(
        !setup.body.contains(r#"name="secret""#),
        "the secret must not travel in a form field: {}",
        setup.body
    );
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);

    let chosen = axess::generate_totp_secret(&axess::SystemRng);
    let chosen_code = totp_code(&chosen);
    let fields = vec![
        ("secret", chosen.as_str()),
        ("current_password", SEED_PASSWORD),
        ("code", chosen_code.as_str()),
        ("_csrf", token.as_str()),
    ];
    let page = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert!(
        recovery_codes(&page.body).is_empty(),
        "a client-chosen secret must not enrol: {}",
        page.body
    );
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factor_configs
          WHERE kind = 'totp' AND user_id = '00000000-0000-0000-0000-000000000010'",
    )
    .fetch_one(&browser.pool)
    .await
    .expect("count");
    assert_eq!(
        stored, 0,
        "nothing may be stored for a secret the server did not issue"
    );
}

/// Enrolling a second factor needs the account's current password: a session
/// alone, with a valid code for the issued secret, enrols nothing.
#[tokio::test]
async fn enrolling_totp_needs_the_current_password() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    let setup = browser.send("GET", "/setup-totp", None).await;
    let secret = shown_secret(&setup.body);
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);
    let code = totp_code(&secret);

    let fields = vec![
        ("code", code.as_str()),
        ("current_password", "not the password"),
        ("_csrf", token.as_str()),
    ];
    let page = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert!(
        recovery_codes(&page.body).is_empty(),
        "a wrong current password must not enrol: {}",
        page.body
    );
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factor_configs
          WHERE kind = 'totp' AND user_id = '00000000-0000-0000-0000-000000000010'",
    )
    .fetch_one(&browser.pool)
    .await
    .expect("count");
    assert_eq!(stored, 0, "no factor may be stored without the password");

    let fields = vec![
        ("code", code.as_str()),
        ("current_password", SEED_PASSWORD),
        ("_csrf", token.as_str()),
    ];
    let page = browser.send("POST", "/setup-totp", Some(fields)).await;
    assert_eq!(recovery_codes(&page.body).len(), axess::RECOVERY_CODE_COUNT);
}

/// `/setup-totp` checks a password, so it answers to the same rate limit as
/// the login routes: a run of guesses is cut off.
#[tokio::test]
async fn setup_totp_is_rate_limited() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    let setup = browser.send("GET", "/setup-totp", None).await;
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);

    let mut statuses = Vec::new();
    for _ in 0..15 {
        let fields = vec![
            ("code", "000000"),
            ("current_password", "guess"),
            ("_csrf", token.as_str()),
        ];
        statuses.push(
            browser
                .send("POST", "/setup-totp", Some(fields))
                .await
                .status,
        );
    }
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "fifteen guesses in a row were never limited: {statuses:?}"
    );
}

#[tokio::test]
async fn setup_totp_turns_a_guest_away() {
    let mut browser = Browser::new().await;
    let page = browser.send("GET", "/setup-totp", None).await;
    assert!(page.status.is_redirection(), "{}", page.status);
    assert!(page.location.as_deref().unwrap_or("").starts_with("/login"));
}

/// Captures what the app logs on the `dev_mail` target, where the example
/// writes the mail it would send.
#[derive(Clone, Default)]
struct MailLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for MailLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MailLog {
    type Writer = MailLog;
    fn make_writer(&'a self) -> MailLog {
        self.clone()
    }
}

impl MailLog {
    /// Start capturing on this thread (the test runs on one thread).
    fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        let log = Self::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_env_filter(tracing_subscriber::EnvFilter::new("dev_mail=debug"))
            .with_ansi(false)
            .finish();
        (log, tracing::subscriber::set_default(subscriber))
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("log lock").clone()).expect("utf8 log")
    }

    /// The path of the verification link in the log.
    fn verification_link(&self) -> String {
        let text = self.text();
        let start = text
            .find("/verify-email?token=")
            .unwrap_or_else(|| panic!("no verification link in the log: {text}"));
        text[start..]
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '"')
            .collect()
    }
}

impl Browser {
    async fn sign_up(&mut self, username: &str) -> Page {
        let fields = vec![
            ("username", username),
            ("fullname", "Carol Example"),
            ("email", "carol@example.com"),
            ("password", "Gnomes2+LongEnough"),
        ];
        self.post("/signup", "/signup", fields).await
    }
}

async fn user_status(pool: &sqlx::SqlitePool, username: &str) -> Option<String> {
    sqlx::query_scalar("SELECT status FROM users WHERE identifier = ?1")
        .bind(username)
        .fetch_optional(pool)
        .await
        .expect("status")
}

/// A signup does not activate the account or sign anyone in: that waits for
/// the link mailed to the address, opened in the browser that signed up.
#[tokio::test]
async fn a_signup_is_completed_by_the_emailed_link() {
    let (log, _guard) = MailLog::capture();
    let mut browser = Browser::new().await;

    let page = browser.sign_up("carol").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("Check your email"), "{}", page.body);
    assert_eq!(
        user_status(&browser.pool, "carol").await.as_deref(),
        Some("candidate")
    );
    let dashboard = browser.send("GET", "/dashboard", None).await;
    assert!(
        dashboard.status.is_redirection(),
        "signed in before verifying"
    );

    let link = log.verification_link();
    let page = browser.send("GET", &link, None).await;
    assert_eq!(
        page.location.as_deref(),
        Some("/dashboard"),
        "{}",
        page.body
    );
    assert_eq!(
        user_status(&browser.pool, "carol").await.as_deref(),
        Some("active")
    );
    let dashboard = browser.send("GET", "/dashboard", None).await;
    assert_eq!(dashboard.status, StatusCode::OK);
}

#[tokio::test]
async fn a_wrong_or_foreign_verification_link_completes_nothing() {
    let (log, _guard) = MailLog::capture();
    let mut browser = Browser::new().await;
    browser.sign_up("carol").await;
    let link = log.verification_link();

    let wrong = browser.send("GET", "/verify-email?token=nope", None).await;
    assert!(wrong.location.is_none(), "{}", wrong.body);

    // The right token, from a browser that never began the signup.
    let mut stranger = Browser::new().await;
    stranger.router = browser.router.clone();
    let page = stranger.send("GET", &link, None).await;
    assert!(page.location.is_none(), "{}", page.body);
    assert_eq!(
        user_status(&browser.pool, "carol").await.as_deref(),
        Some("candidate")
    );
}

/// A signup for a taken username takes about as long as one for a free name,
/// and answers the same page: the form is not an oracle for who has an
/// account.
#[tokio::test]
async fn a_taken_username_costs_the_same_work_as_a_free_one() {
    let mut browser = Browser::new().await;
    let timed = |username: &'static str| {
        let fields = vec![
            ("username", username),
            ("fullname", "Carol Example"),
            ("email", "carol@example.com"),
            ("password", "Gnomes2+LongEnough"),
        ];
        (username, fields)
    };
    let (_, free_fields) = timed("carol");
    let (_, taken_fields) = timed("alice");

    let token = browser.token_from("/signup").await;
    let mut fields = free_fields;
    fields.push(("_csrf", &token));
    let start = std::time::Instant::now();
    let free = browser.send("POST", "/signup", Some(fields)).await;
    let free_took = start.elapsed();

    // Another visitor, with a session of their own, asks for the same name.
    let mut visitor = Browser::new().await;
    visitor.router = browser.router.clone();
    let token = visitor.token_from("/signup").await;
    let mut fields = taken_fields;
    fields.push(("_csrf", &token));
    let start = std::time::Instant::now();
    let taken = visitor.send("POST", "/signup", Some(fields)).await;
    let taken_took = start.elapsed();

    assert_eq!(free.body, taken.body, "the two answers differ");
    assert!(
        taken_took * 2 >= free_took,
        "the taken path answered in {taken_took:?}, the free one in {free_took:?}"
    );
}

/// Pages that carry account state are not cached, framed or allowed to load
/// anything: the TOTP page shows the secret, so it most of all.
#[tokio::test]
async fn pages_are_not_cached_or_framed_and_carry_a_csp() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    for uri in ["/setup-totp", "/login", "/dashboard"] {
        let mut req = Request::builder().uri(uri);
        let cookie = browser
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        req = req.header(header::COOKIE, cookie);
        let mut req = req.body(Body::empty()).expect("request");
        req.extensions_mut().insert(ConnectInfo(browser.peer));
        let res = browser
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("infallible");
        let headers = res.headers();
        assert_eq!(
            headers.get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
            Some(&b"no-store"[..]),
            "{uri}"
        );
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS).map(|v| v.as_bytes()),
            Some(&b"DENY"[..]),
            "{uri}"
        );
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap_or_else(|| panic!("{uri} has no CSP"))
            .to_str()
            .expect("ascii");
        assert!(csp.contains("frame-ancestors 'none'"), "{uri}: {csp}");
    }
}

/// Reading a form is not an attempt: only submissions count against the
/// limit, so a person who reloads the login page is never turned away.
#[tokio::test]
async fn reading_the_login_page_is_not_limited() {
    let mut browser = Browser::new().await;
    for _ in 0..15 {
        let page = browser.send("GET", "/login", None).await;
        assert_eq!(page.status, StatusCode::OK);
    }
}

/// Login and forgot-password have a bucket each: a run of failed logins from
/// one address does not stop that address asking for a reset, and the other
/// way round.
#[tokio::test]
async fn login_and_forgot_password_do_not_share_a_limit() {
    let mut browser = Browser::new().await;
    let mut limited = false;
    for _ in 0..15 {
        let fields = vec![("identifier", "nobody"), ("password", "wrong password")];
        let page = browser.post("/login", "/login", fields).await;
        limited |= page.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "fifteen failed logins in a row were never limited");

    let fields = vec![("identifier", "alice")];
    let page = browser
        .post("/forgot-password", "/forgot-password", fields)
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

/// Asking twice for the same account's reset inside the cooldown mints one
/// token, so the form cannot be used to flood an inbox.
#[tokio::test]
async fn a_second_reset_request_inside_the_cooldown_mints_no_token() {
    let (log, _guard) = MailLog::capture();
    let mut browser = Browser::new().await;
    for _ in 0..2 {
        let fields = vec![("identifier", "alice")];
        browser
            .post("/forgot-password", "/forgot-password", fields)
            .await;
    }
    let links = log.text().matches("password reset link").count();
    assert_eq!(links, 1, "{}", log.text());
}
