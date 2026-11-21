//! The directory's register and records surface: an incomplete record is
//! refused by name and nothing is written, the read-only records view reads
//! what the store holds, and a remove answers whether there was a record.

use super::directory_tests::{directory, record, refused_text, secret};
use crate::authn::ids::testing::tenant;

const ISSUER: &str = "https://idp.example";

/// A record with no name, no issuer or no client id is refused as one that
/// needs all three, each on its own, and the store is left empty.
#[tokio::test]
async fn a_record_missing_any_one_of_name_issuer_or_client_id_is_refused() {
    let directory = directory();
    let mut no_name = record("acme", ISSUER, "client-1", secret());
    no_name.name = String::new();
    let no_issuer = record("acme", "", "client-1", secret());
    let no_client_id = record("acme", ISSUER, "", secret());

    for (what, incomplete) in [
        ("name", no_name),
        ("issuer", no_issuer),
        ("client id", no_client_id),
    ] {
        let text = refused_text(directory.upsert(incomplete).await);
        assert!(
            text.contains("needs a name, an issuer and a client id"),
            "no {what}: {text}"
        );
    }
    assert!(
        directory.store().list_all().await.expect("list").is_empty(),
        "an incomplete record was written"
    );
}

/// The records view reads each record, a tenant's records, an issuer's and
/// all of them, as the store holds them, and names itself when printed.
#[tokio::test]
async fn the_records_view_reads_what_the_store_holds() {
    let directory = directory();
    directory
        .upsert(record("acme", ISSUER, "client-1", secret()))
        .await
        .expect("acme sso");
    let mut corp = record("acme", "https://other.example", "client-2", secret());
    corp.name = "corp".into();
    directory.upsert(corp).await.expect("acme corp");
    directory
        .upsert(record("beta", ISSUER, "client-3", secret()))
        .await
        .expect("beta sso");

    let records = directory.store();
    let got = records
        .get(&tenant("acme"), "sso")
        .await
        .expect("get")
        .expect("acme's sso is stored");
    assert_eq!(got.client_id, "client-1");
    assert!(
        records
            .get(&tenant("acme"), "absent")
            .await
            .expect("get")
            .is_none()
    );

    let mut acme: Vec<String> = records
        .list(&tenant("acme"))
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.name)
        .collect();
    acme.sort();
    assert_eq!(acme, ["corp", "sso"]);

    let mut at_issuer: Vec<String> = records
        .list_by_issuer(ISSUER)
        .await
        .expect("list_by_issuer")
        .into_iter()
        .map(|r| r.client_id)
        .collect();
    at_issuer.sort();
    assert_eq!(at_issuer, ["client-1", "client-3"]);

    assert_eq!(records.list_all().await.expect("list_all").len(), 3);
    let copied = records;
    assert_eq!(copied.list_all().await.expect("list_all").len(), 3);
    let cloned = clone_of(&records);
    assert_eq!(cloned.list(&tenant("beta")).await.expect("list").len(), 1);
    assert!(
        format!("{records:?}").contains("TenantOAuthRecords"),
        "{records:?}"
    );
}

/// `value.clone()` through the `Clone` bound alone, so a test proves a type
/// is `Clone` as well as `Copy` without calling `clone` on a known `Copy`.
fn clone_of<T: Clone>(value: &T) -> T {
    value.clone()
}

/// A remove answers `true` when there was a record and `false` when there
/// was none.
#[tokio::test]
async fn a_remove_answers_whether_there_was_a_record() {
    let directory = directory();
    directory
        .upsert(record("acme", ISSUER, "client-1", secret()))
        .await
        .expect("upsert");

    assert!(
        directory
            .remove(&tenant("acme"), "sso")
            .await
            .expect("remove")
    );
    assert!(
        !directory
            .remove(&tenant("acme"), "sso")
            .await
            .expect("remove")
    );
    assert!(
        directory
            .store()
            .get(&tenant("acme"), "sso")
            .await
            .expect("get")
            .is_none()
    );
}
