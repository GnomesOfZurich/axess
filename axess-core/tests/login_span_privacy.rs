#![cfg(feature = "testing")]
//! The login identifier is not recorded on a tracing span. Its own test
//! binary: span callsite interest is cached, so a subscriber installed
//! after other tests ran can miss the spans.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::AuthnService;
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_testing::mock_tracing::PrintedLines;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::time::Duration;

// ── D22: the identifier is not recorded on a tracing span ───────────────────

#[tokio::test]
async fn spans_do_not_record_the_login_identifier() {
    let clock = common::test_clock();
    use tracing_subscriber::fmt::format::FmtSpan;
    let buf = PrintedLines::new();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(buf.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    let secret = "secret.person@example.com";
    let _ = svc.begin_login(secret, "default", &test_session()).await;
    let _ = svc
        .begin_password_reset(secret, "default", Duration::from_secs(300))
        .await;

    let out = buf.text();
    assert!(
        out.contains("begin_login"),
        "the spans were captured: {out}"
    );
    assert!(
        !out.contains(secret),
        "identifier leaked into a span: {out}"
    );
    drop(guard);
}
