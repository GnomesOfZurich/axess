#![cfg(all(feature = "testing", feature = "memory"))]
//! Building an authentication service without a session registry says what
//! that costs. Its own test binary: the subscriber must be installed before
//! the warning's callsite is first reached, which other tests in a shared
//! binary would otherwise decide first.

mod common;

use axess_core::authn::service::AuthnService;
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;

fn identity_and_factors() -> (MockIdentityStore, MockFactorStore) {
    (
        MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice")),
        MockFactorStore::new()
            .with_factor(user_scope(), password_config("Gnomes2+"))
            .with_method(&uid("u1"), password_method()),
    )
}

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

/// Building a service with no registry says what that costs.
#[test]
fn building_without_a_registry_warns_and_building_with_one_does_not() {
    let build = |with_registry: bool| {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (identity, factors) = identity_and_factors();
            let builder = AuthnService::builder(identity, factors);
            let _ = if with_registry {
                builder.with_registry(MemorySessionRegistry::new()).build()
            } else {
                builder.build()
            };
        });
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
    };
    assert!(build(false).contains("without a session registry"));
    assert!(!build(true).contains("without a session registry"));
}
