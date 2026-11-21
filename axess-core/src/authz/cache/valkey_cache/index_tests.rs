//! The entity index is emptied without losing a concurrent writer's member,
//! and a writer racing the emptying leaves its entry indexed or unstored.

use super::index_ops::{drain_index, store_indexed};
use crate::testing::valkey_fake::FakeValkey;

const INDEX: &str = "p:authz-entities-uid:Folder::\"f\"";

/// Another pod invalidates the folder between the index write and the entry
/// write of a load: the member is popped and the entry's key deleted before
/// the entry exists. When the load is done its entry must be indexed, so the
/// next invalidation finds it, or not be stored at all.
#[tokio::test]
async fn a_drain_between_the_index_write_and_the_entry_write_leaves_the_entry_indexed() {
    let fake = FakeValkey::default();
    fake.sadd_now(INDEX, "p:entity:d1");
    fake.set_now("p:entity:d1", "v1");
    fake.after_next("SADD", |other| other.drain_now(INDEX));

    store_indexed(&fake, &[INDEX.to_owned()], "p:entity:d2", "v2", 60_000)
        .await
        .expect("store");

    let indexed = fake.is_member(INDEX, "p:entity:d2");
    let cached = fake.exists("p:entity:d2");
    assert!(
        indexed || !cached,
        "d2 is cached with no index; commands: {:?}",
        fake.commands()
    );
    assert!(!fake.exists("p:entity:d1"), "d1 outlived the invalidation");
}

/// A load names its entry in every index it belongs to, under the folder as
/// under the document, before the entry is written.
#[tokio::test]
async fn a_stored_entry_is_named_in_every_index_before_it_exists() {
    let fake = FakeValkey::default();
    fake.after_next("SET", |other| {
        assert!(
            other.is_member(INDEX, "p:entity:d"),
            "indexed under the folder first"
        );
        assert!(
            other.is_member(&doc_index(), "p:entity:d"),
            "indexed under the document first"
        );
    });

    store_indexed(
        &fake,
        &[INDEX.to_owned(), doc_index()],
        "p:entity:d",
        "v",
        60_000,
    )
    .await
    .expect("store");

    assert!(fake.exists("p:entity:d"));
    assert!(fake.is_member(INDEX, "p:entity:d") && fake.is_member(&doc_index(), "p:entity:d"));
}

fn doc_index() -> String {
    "p:authz-entities-uid:Doc::\"d\"".to_owned()
}

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

/// Another pod invalidates the folder between the two index writes of a
/// load, and the second index write fails: the entry was written in between
/// and nothing names it any more, so it is taken back before the error is
/// returned.
#[tokio::test]
async fn a_failed_second_index_write_after_a_drain_takes_the_entry_back() {
    let fake = FakeValkey::default();
    fake.after_next("SADD", |other| other.drain_now(INDEX));
    fake.fail_call("SADD", 1);

    let stored = store_indexed(&fake, &[INDEX.to_owned()], "p:entity:d", "v", 60_000).await;

    assert!(stored.is_err(), "the failed index write is reported");
    let indexed = fake.is_member(INDEX, "p:entity:d");
    let cached = fake.exists("p:entity:d");
    assert!(
        indexed || !cached,
        "the entry is cached with no index; commands: {:?}",
        fake.commands()
    );
}

/// When the delete that takes the entry back fails as well, the error says
/// so: the caller is not told the entry is unstored.
#[tokio::test]
async fn a_failed_take_back_is_the_error_returned() {
    let fake = FakeValkey::default();
    fake.fail_call("SADD", 1);
    fake.fail_call("DEL", 0);

    let stored = store_indexed(&fake, &[INDEX.to_owned()], "p:entity:d", "v", 60_000).await;

    assert!(stored.is_err());
    assert_eq!(
        fake.commands().last().map(String::as_str),
        Some("DEL failed"),
        "{:?}",
        fake.commands()
    );
}

/// A first index write that fails stores nothing.
#[tokio::test]
async fn a_failed_first_index_write_stores_nothing() {
    let fake = FakeValkey::default();
    fake.fail_call("SADD", 0);

    let stored = store_indexed(&fake, &[INDEX.to_owned()], "p:entity:d", "v", 60_000).await;

    assert!(stored.is_err());
    assert!(!fake.exists("p:entity:d"));
}
