//! The fixture's factor store with nothing armed is the store under it, and
//! keeps the rules of the factor swap: every implementor of `FactorStore`
//! in this repository runs the check an adopter's store runs.

use std::sync::Arc;

use axess_core::authn::types::AuthnScope;
use axess_core::testing::store_contract::assert_compare_and_save_factor_contract;

use crate::fixture::fixture;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fixture_store_with_nothing_armed_meets_the_compare_and_save_contract() {
    let f = fixture();
    let AuthnScope::User { tenant_id, user_id } = f.scope.clone() else {
        panic!("the fixture's scope is a user's");
    };

    assert_compare_and_save_factor_contract(Arc::new(f.factors.clone()), &tenant_id, &user_id)
        .await;
}
