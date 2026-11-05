//! The second-factor flow end to end, driven through the router the way a
//! browser drives it: cookies carried between requests, a CSRF token read
//! from each form.
//!
//! Alice enrolls TOTP and is shown her recovery codes once. From then on
//! her login asks for TOTP or a recovery code; a code gets her in once and
//! is refused the second time.

use axess::SystemClock;
use axess_example_sqlite::{models::backend::seed, web::app::build_router};
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
            &axess::authn::FactorSecretCipher::new([7; 32]),
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
        let fields = vec![("identifier", "alice"), ("password", "Gnomes2+")];
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
    let secret = attribute(&setup.body, r#"name="secret" value=""#);
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);
    let code = totp_code(&secret);
    let fields = vec![
        ("secret", secret.as_str()),
        ("code", &code),
        ("_csrf", &token),
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
    let secret = attribute(&setup.body, r#"name="secret" value=""#);
    let token = attribute(&setup.body, r#"name="_csrf" value=""#);
    let code = totp_code(&secret);
    let fields = vec![
        ("secret", secret.as_str()),
        ("code", &code),
        ("_csrf", &token),
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
        ("code", &attacker_code),
        ("_csrf", &token),
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

/// Two enrolments posted together, each with its own secret and a valid code
/// for it: the first to write wins and the other is turned away without
/// recovery codes, so the secret that was confirmed is the one that is kept.
#[tokio::test]
async fn concurrent_totp_enrolments_do_not_overwrite_each_other() {
    let mut browser = Browser::new().await;
    browser.log_in().await;
    let token = browser.token_from("/setup-totp").await;

    let cookie = browser
        .cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let enrol = |secret: String| {
        let code = totp_code(&secret);
        let form = serde_urlencoded::to_string(vec![
            ("secret", secret.as_str()),
            ("code", code.as_str()),
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
    let (first, second) = tokio::join!(
        enrol(axess::generate_totp_secret(&axess::SystemRng)),
        enrol(axess::generate_totp_secret(&axess::SystemRng)),
    );

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
