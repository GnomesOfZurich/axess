//! Callback and UserInfo checks that need only the mock provider: the provider
//! the callback arrived at, the RFC 9207 `iss` parameter and the UserInfo
//! `sub` binding.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth --test oauth_callback_checks`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType, AuthFailureReason};
use axess_core::authn::service::OAuthCallbackRoute;
use axess_core::{
    authn::service::AuthnService,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use axess_factors::oauth::{MockOAuthProvider, OAuthError, OAuthLoginOptions};
use axess_testing::mock_tracing::{LineCapture, TracingCapture};
use common::test_tenant;

type Svc = axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn service(clock: &MockClock, mock: MockOAuthProvider) -> Svc {
    service_with(
        clock,
        MockIdentityStore::new().with_clock(clock.clone()),
        vec![mock],
    )
}

fn service_with(
    clock: &MockClock,
    identity: MockIdentityStore,
    mocks: Vec<MockOAuthProvider>,
) -> Svc {
    let mut builder =
        AuthnService::builder(identity.with_tenant(test_tenant()), MockFactorStore::new())
            .with_clock(clock.clone());
    for mock in mocks {
        builder = builder.with_oauth_provider(mock);
    }
    builder.build().with_audit_context(AuditContext::default())
}

async fn begun(svc: &Svc, name: &str) -> (axess_core::session::extractor::AuthSession, String) {
    let session = test_session();
    svc.begin_oauth_login(name, &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let state = session
        .get_custom("axess.oauth.csrf_state")
        .await
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("state");
    (session, state)
}

fn idp(clock: &MockClock, name: &str) -> MockOAuthProvider {
    MockOAuthProvider::new(name)
        .with_clock(std::sync::Arc::new(clock.clone()))
        .with_user("alice", "a@example.com", vec![], vec![])
}

/// The classic mix-up: the login began at one authorization server, which
/// sent the browser on to an honest one that sends no `iss`, and the honest
/// server's code came back on its own redirect URI. The callback names a
/// provider other than the ceremony's, so it is refused before any code is
/// exchanged (the ceremony's provider would fail the exchange, and does not
/// get to), the failure is recorded as a provider mismatch, and the ceremony
/// is cleared. The same callback on the ceremony's own route finishes.
#[tokio::test]
async fn a_callback_at_another_provider_than_the_login_began_with_is_refused() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new().with_clock(clock.clone());
    let svc = service_with(
        &clock,
        identity.clone(),
        vec![
            idp(&clock, "attacker").with_failure("the code must never be exchanged here"),
            idp(&clock, "honest"),
        ],
    );

    let (session, state) = begun(&svc, "attacker").await;
    let err = svc
        .finish_oauth_login(
            OAuthCallbackRoute::global("honest"),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect_err("a callback on another provider's redirect URI is a mix-up");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");
    assert!(
        session.get_custom("axess.oauth.csrf_state").await.is_none(),
        "the ceremony is cleared"
    );
    let mismatches: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::LoginAttempt
                && e.event_status == AuthEventStatus::Failure
                && e.error == Some(AuthFailureReason::ProviderMismatch)
        })
        .collect();
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(
        matches!(&mismatches[0].factor_kind, Some(kind) if kind.to_string().contains("attacker")),
        "the row names the ceremony's provider: {:?}",
        mismatches[0].factor_kind
    );

    let (session, state) = begun(&svc, "honest").await;
    svc.finish_oauth_login(
        OAuthCallbackRoute::global("honest"),
        "code",
        &state,
        None,
        &session,
    )
    .await
    .expect("the ceremony's own route finishes the login");
}

/// The provider a refused callback names is the request's own text (the
/// `{provider}` of the route, passed on by the application), so the line
/// that records the refusal carries it with control characters and the line
/// separators escaped, and cut short: one request cannot forge a second log
/// line, write to the terminal that reads the log, or fill the line.
#[tokio::test]
async fn the_provider_a_refused_callback_names_is_logged_escaped_and_cut() {
    let clock = common::test_clock();
    let capture = TracingCapture::install();
    let svc = service(&clock, idp(&clock, "honest"));
    let (session, state) = begun(&svc, "honest").await;
    let named = format!("x\r\nWARN forged line\u{1b}[2J\u{2028}{}", "a".repeat(2048));

    let err = svc
        .finish_oauth_login(
            OAuthCallbackRoute::global(&named),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect_err("a callback on a route of another name is refused");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");

    let events = capture.events();
    let line = events
        .iter()
        .find(|e| e.message.contains("another registration's redirect URI"))
        .unwrap_or_else(|| panic!("no line for the refusal among {events:?}"));
    assert!(
        !line.message.chars().any(char::is_control),
        "a control character reached the log line raw: {:?}",
        line.message
    );
    assert!(
        !line.message.contains('\u{2028}'),
        "a line separator reached the log line raw: {:?}",
        line.message
    );
    assert!(
        line.message.contains("forged line"),
        "the name is kept, escaped: {:?}",
        line.message
    );
    assert!(
        line.message.len() < 512,
        "the name is cut: the line is {} bytes",
        line.message.len()
    );
}

/// The ceremony's provider may be a tenant's, named by its tenant: the line
/// that refuses a callback on another route carries the ceremony's name
/// escaped too, not only the route's.
#[tokio::test]
async fn the_ceremonys_provider_name_is_logged_escaped() {
    let clock = common::test_clock();
    let forged = "sso\nWARN forged\u{202E}";
    let svc = service(
        &clock,
        idp(&clock, forged).with_issuer("https://idp.example.org"),
    );
    let (session, state) = begun(&svc, forged).await;
    let capture = TracingCapture::install();

    let err = svc
        .finish_oauth_login(
            OAuthCallbackRoute::global("other"),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect_err("a callback on another route is refused");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");

    let events = capture.events();
    let line = events
        .iter()
        .find(|e| e.message.contains("another registration's redirect URI"))
        .unwrap_or_else(|| panic!("no line for the refusal among {events:?}"));
    assert!(
        !line.message.chars().any(axess_identity::log_text::escapes),
        "{:?}",
        line.message
    );
    assert!(line.message.contains("WARN forged"), "{:?}", line.message);
}

/// A span's fields are printed with every line written inside the span, and
/// by themselves where spans are exported, so a provider name the request
/// gave is escaped and cut there as it is in the refusal's own line. Each
/// entry point that takes a provider by name is called with a long hostile
/// one; no line a stock formatter writes carries it raw or whole.
#[tokio::test]
async fn a_span_carries_the_provider_name_it_was_called_with_escaped_and_cut() {
    let clock = common::test_clock();
    // No colours and none of the formatter's own cleaning of control
    // characters: the lines read here are what the name was made into before
    // the formatter saw it.
    let printed = LineCapture::install();

    let svc = service(&clock, idp(&clock, "honest"));
    let (session, state) = begun(&svc, "honest").await;
    let named = format!("x\r\nWARN forged line\u{1b}[2J\u{2028}{}", "a".repeat(2048));
    let options = OAuthLoginOptions::default();

    svc.finish_oauth_login(
        OAuthCallbackRoute::global(&named),
        "code",
        &state,
        None,
        &session,
    )
    .await
    .expect_err("a callback on a route of another name is refused");
    let fresh = test_session();
    svc.begin_oauth_login(&named, &options, &fresh)
        .await
        .expect_err("no provider has that name");
    svc.begin_oauth_login_with_tenant_provider(&named, &options, &test_tenant().id, &fresh)
        .await
        .expect_err("no tenant provider has that name");
    svc.oauth_global()
        .refresh_oauth_token(&named, "refresh", "alice", None, None)
        .await
        .expect_err("no provider has that name");
    svc.oauth_global()
        .fetch_userinfo(&named, "token", "alice", None)
        .await
        .expect_err("no provider has that name");

    let text = printed.text();
    for span in [
        "finish_oauth_login",
        "begin_oauth_login",
        "begin_oauth_login_with_tenant_provider",
        "refresh_oauth_token",
        "fetch_userinfo",
    ] {
        let opened = format!(" {span}{{");
        assert!(
            text.split('\n')
                .any(|line| line.contains(&opened) && line.contains("forged line")),
            "{span}: no line for its span keeps the name, escaped"
        );
    }
    for line in text.split('\n') {
        let head: String = line.chars().take(160).collect();
        assert!(
            !line.chars().any(char::is_control),
            "a control character reached a line raw: {head:?}"
        );
        assert!(
            !line.contains('\u{2028}'),
            "a line separator reached a line raw: {head:?}"
        );
        assert!(
            line.len() < 1024,
            "the name is cut: a line is {} bytes: {head:?}",
            line.len()
        );
    }
}

/// A callback whose `iss` is another server\'s is refused as a mix-up, before
/// the code is exchanged; the provider\'s own issuer passes.
#[tokio::test]
async fn a_callback_iss_that_is_not_the_providers_is_refused() {
    let clock = common::test_clock();
    let svc = service(&clock, idp(&clock, "idp"));

    let (session, state) = begun(&svc, "idp").await;
    let err = svc
        .finish_oauth_login(
            OAuthCallbackRoute::global("idp"),
            "code",
            &state,
            Some("https://evil.example.com"),
            &session,
        )
        .await
        .expect_err("a different issuer is a mix-up");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");

    let (session, state) = begun(&svc, "idp").await;
    svc.finish_oauth_login(
        OAuthCallbackRoute::global("idp"),
        "code",
        &state,
        Some("https://idp.example.com"),
        &session,
    )
    .await
    .expect("the provider\'s own issuer is accepted");
}

/// A missing `iss` is refused when the IdP advertises that it sends one, and
/// accepted when it does not.
#[tokio::test]
async fn a_missing_iss_is_refused_only_when_the_idp_advertises_it() {
    let clock = common::test_clock();
    let svc = service(&clock, idp(&clock, "strict").with_iss_parameter_required());
    let (session, state) = begun(&svc, "strict").await;
    let err = svc
        .finish_oauth_login(
            OAuthCallbackRoute::global("strict"),
            "code",
            &state,
            None,
            &session,
        )
        .await
        .expect_err("the IdP sends iss, so its absence is refused");
    assert!(matches!(err, OAuthError::CsrfMismatch), "got {err:?}");

    let svc = service(&clock, idp(&clock, "lax"));
    let (session, state) = begun(&svc, "lax").await;
    svc.finish_oauth_login(
        OAuthCallbackRoute::global("lax"),
        "code",
        &state,
        None,
        &session,
    )
    .await
    .expect("an IdP that does not advertise it need not send it");
}

/// A UserInfo response for another subject is refused and returns no claims.
#[tokio::test]
async fn userinfo_for_another_subject_is_refused() {
    let clock = common::test_clock();
    let svc = AuthnService::builder(
        MockIdentityStore::new().with_clock(clock.clone()),
        MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .with_oauth_provider(
        MockOAuthProvider::new("ui")
            .with_clock(std::sync::Arc::new(clock.clone()))
            .with_user("bob", "b@example.com", vec![], vec![]),
    )
    .build()
    .with_audit_context(AuditContext::default());

    let err = svc
        .oauth_global()
        .fetch_userinfo("ui", "token", "alice", None)
        .await
        .expect_err("sub=bob is not alice");
    assert!(matches!(err, OAuthError::SubjectMismatch), "got {err:?}");
    assert!(!err.to_string().contains("bob") && !err.to_string().contains("alice"));

    let claims = svc
        .oauth_global()
        .fetch_userinfo("ui", "token", "bob", None)
        .await
        .unwrap();
    assert_eq!(claims.sub, "bob");
}
