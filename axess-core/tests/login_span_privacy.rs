#![cfg(feature = "testing")]
//! The login identifier is not recorded on a tracing span. Its own test
//! binary: span callsite interest is cached, so a subscriber installed
//! after other tests ran can miss the spans.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::AuthnService;
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::time::Duration;

// ── D22: the identifier is not recorded on a tracing span ───────────────────

#[derive(Clone, Default)]
struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

#[tokio::test]
async fn spans_do_not_record_the_login_identifier() {
    use tracing_subscriber::fmt::format::FmtSpan;
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(buf.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity, factors)
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    let secret = "secret.person@example.com";
    let _ = svc.begin_login(secret, "default", &test_session()).await;
    let _ = svc
        .begin_password_reset(secret, "default", Duration::from_secs(300))
        .await;

    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        out.contains("begin_login"),
        "the spans were captured: {out}"
    );
    assert!(
        !out.contains(secret),
        "identifier leaked into a span: {out}"
    );
}
