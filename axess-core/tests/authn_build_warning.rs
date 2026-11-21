#![cfg(all(feature = "testing", feature = "memory"))]
//! Building an authentication service without a session registry says what
//! that costs. Its own test binary: the subscriber must be installed before
//! the warning's callsite is first reached, which other tests in a shared
//! binary would otherwise decide first.

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::service::AuthnService;
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_testing::mock_tracing::PrintedLines;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};

fn identity_and_factors(clock: &MockClock) -> (MockIdentityStore, MockFactorStore) {
    (
        MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice")),
        MockFactorStore::new()
            .with_factor(user_scope(), password_config("Sample2+"))
            .with_method(&uid("u1"), password_method()),
    )
}

/// Building a service with no registry says what that costs.
#[test]
fn building_without_a_registry_warns_and_building_with_one_does_not() {
    let clock = common::test_clock();
    let build = |with_registry: bool| {
        let buf = PrintedLines::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (identity, factors) = identity_and_factors(&clock);
            let builder = AuthnService::builder(identity, factors).with_clock(clock.clone());
            let _ = if with_registry {
                builder
                    .with_registry(
                        MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone())),
                    )
                    .build()
            } else {
                builder.build()
            };
        });
        buf.text()
    };
    assert!(build(false).contains("without a session registry"));
    assert!(!build(true).contains("without a session registry"));
}
