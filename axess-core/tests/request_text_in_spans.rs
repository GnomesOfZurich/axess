#![cfg(feature = "testing")]
//! The tenant identifier a login, a signup or a password reset is called
//! with is the request's own text, and the entry point's span carries it on
//! every line written inside the span. It is escaped and cut there, so one
//! request cannot forge a log line, rewrite a terminal or fill a line.

use axess_core::testing::fixtures as common;

use axess_core::testing::{mock_authn::make_password_service_on, test_session};
use axess_testing::mock_tracing::LineCapture;
use common::test_user;

/// A tenant identifier with a line break, a forged line, a terminal escape,
/// a Unicode line separator and two kilobytes after them.
fn hostile() -> String {
    format!("x\r\nWARN forged line\u{1b}[2J\u{2028}{}", "a".repeat(2048))
}

/// Every printed line is free of raw control characters and line
/// separators, and shorter than the hostile text.
fn assert_clean(text: &str) {
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
            "the tenant identifier is cut: a line is {} bytes: {head:?}",
            line.len()
        );
    }
}

#[tokio::test]
async fn the_entry_points_spans_carry_the_tenant_identifier_escaped_and_cut() {
    let printed = LineCapture::install();
    let svc = make_password_service_on(
        std::sync::Arc::new(common::test_clock()),
        "u1",
        "alice",
        "hunter2",
    );
    let tenant = hostile();

    let _ = svc.begin_login("alice", &tenant, &test_session()).await;
    let _ = svc
        .login_with_password("alice", &tenant, "hunter2", &test_session())
        .await;
    let _ = svc
        .begin_signup(test_user("u2", "bob"), &tenant, &test_session())
        .await;
    let _ = svc
        .begin_password_reset("alice", &tenant, std::time::Duration::from_secs(300))
        .await;

    let text = printed.text();
    for span in [
        "begin_login",
        "login_with_password",
        "begin_signup",
        "begin_password_reset",
    ] {
        let opened = format!(" {span}{{");
        assert!(
            text.split('\n')
                .any(|line| line.contains(&opened) && line.contains("forged line")),
            "{span}: no line for its span keeps the tenant identifier, escaped"
        );
    }
    assert_clean(&text);
}
