//! The entity index is emptied without losing a concurrent writer's member.

use super::index_ops::drain_index;
use crate::testing::valkey_fake::FakeValkey;

const INDEX: &str = "p:authz-entities-uid:Folder::\"f\"";

/// Another pod loads a child document between two commands of the
/// invalidation: its member must be deleted with its entry, or stay in the
/// index, never be cached with no index naming it.
#[tokio::test]
async fn a_write_racing_the_invalidation_stays_indexed_or_is_gone() {
    let fake = FakeValkey::default();
    fake.sadd_now(INDEX, "p:entity:d1");
    fake.set_now("p:entity:d1", "v1");
    fake.after_next("SPOP", |other| {
        other.sadd_now(INDEX, "p:entity:d2");
        other.set_now("p:entity:d2", "v2");
    });

    drain_index(&fake, INDEX).await.expect("drain");

    let indexed = fake.is_member(INDEX, "p:entity:d2");
    let cached = fake.exists("p:entity:d2");
    assert!(
        indexed || !cached,
        "d2 is cached with no index; commands: {:?}",
        fake.commands()
    );
    assert!(!fake.exists("p:entity:d1"), "d1 outlived the invalidation");
}

/// A write that lands after the last read is indexed, so the next
/// invalidation finds it.
#[tokio::test]
async fn a_write_after_the_invalidation_is_indexed_for_the_next_one() {
    let fake = FakeValkey::default();
    fake.sadd_now(INDEX, "p:entity:d1");
    fake.set_now("p:entity:d1", "v1");
    drain_index(&fake, INDEX).await.expect("drain");

    fake.sadd_now(INDEX, "p:entity:d2");
    fake.set_now("p:entity:d2", "v2");
    drain_index(&fake, INDEX).await.expect("drain again");

    assert!(!fake.exists("p:entity:d2"));
}

/// More members than one read returns are all deleted, and the index is empty.
#[tokio::test]
async fn an_index_larger_than_one_batch_is_drained_whole() {
    let fake = FakeValkey::default();
    for n in 0..600 {
        let key = format!("p:entity:d{n}");
        fake.sadd_now(INDEX, &key);
        fake.set_now(&key, "v");
    }

    drain_index(&fake, INDEX).await.expect("drain");

    assert!((0..600).all(|n| !fake.exists(&format!("p:entity:d{n}"))));
    assert!(!fake.is_member(INDEX, "p:entity:d0"));
}
