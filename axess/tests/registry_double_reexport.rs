//! The facade names the registry double under `axess::testing`, so an
//! adopter's tests build it from the crate they depend on.

#![cfg(feature = "testing")]

use axess::SessionKey;
use axess::SessionRegistry;
use axess::testing::MockRng;
use axess::testing::registry_double::{RegistryCall, RegistryDouble, RegistryOp, Step};

#[tokio::test]
async fn the_facade_builds_the_registry_double_and_reads_its_calls() {
    let user = axess::testing::user("u1");
    let session = SessionKey::of(&axess::SessionId::new(&MockRng::new(3)));
    let registry = RegistryDouble::new().before(|_, _| async { Step::Forward });

    registry.register(&user, &session).await.unwrap();

    assert_eq!(
        registry.calls(),
        vec![RegistryCall::Register { user, session }]
    );
    assert_eq!(registry.count(RegistryOp::Register), 1);
    assert!(registry.is_valid(&user, &session).await.unwrap());
}
