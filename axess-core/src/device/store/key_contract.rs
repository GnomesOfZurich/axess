//! What a device store owes a device key, checked against every backend:
//! the `Key` binding comes back as it was written, and replacing its
//! challenge is one compare-and-swap, which is what makes a challenge
//! single-use.
//!
//! Each function takes a store that holds nothing and uses only the
//! [`DeviceStore`] interface. Times are whole seconds because the SQL stores
//! keep seconds.

use std::fmt::Debug;

use super::consistency::{at, dev_id, device, tenant};
use super::{BindingsUpdate, DeviceStore};
use crate::device::types::{DeviceBinding, DeviceTrustLevel};
use crate::device_key::{KeyChallenge, KeyProofShape, KeyThumbprint, P256PublicKey};

/// A `Key` binding whose challenge is `challenge`, issued at `at(issued)`.
pub(crate) fn key_binding(challenge: u8, issued: i64) -> DeviceBinding {
    DeviceBinding::Key {
        thumbprint: KeyThumbprint::from_bytes([0x11; 32]),
        public_key: P256PublicKey {
            x: [0x22; 32],
            y: [0x33; 32],
        },
        shape: KeyProofShape::Browser,
        bound_at: at(1),
        proven_at: at(issued),
        challenge: KeyChallenge::from_bytes([challenge; 32]),
        challenge_issued_at: at(issued),
    }
}

fn cookie() -> DeviceBinding {
    DeviceBinding::Cookie {
        token_hash: crate::device::types::FingerprintHash::from_bytes([0x44; 32]),
        issued_at: at(0),
        last_used_at: at(0),
    }
}

async fn bindings<S>(store: &S, label: &str) -> Vec<DeviceBinding>
where
    S: DeviceStore,
    S::Error: Debug,
{
    store
        .load_fresh(&tenant(), &dev_id(label))
        .await
        .unwrap()
        .expect("the device")
        .bindings
}

/// A key written beside a cookie binding reads back equal, through `load`
/// and through `load_fresh`, in the order it was written.
pub(crate) async fn a_key_binding_round_trips<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let mut row = device("keyed", 1, DeviceTrustLevel::Seen, at(0));
    row.bindings = vec![cookie(), key_binding(7, 2)];
    store.save(&row, at(2)).await.unwrap();

    assert_eq!(bindings(&store, "keyed").await, row.bindings);
    let cached = store
        .load(&tenant(), &dev_id("keyed"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cached.bindings, row.bindings);
}

/// Replacing the challenge writes when the bindings are the ones read and
/// conflicts when they moved. Of two replacements made from one read exactly
/// one writes, so one proof cannot be accepted twice. A revoked row takes
/// nothing, and a missing one says so.
pub(crate) async fn a_challenge_is_replaced_by_one_compare_and_swap<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("swap"));
    let mut row = device("swap", 2, DeviceTrustLevel::Seen, at(0));
    let read = vec![cookie(), key_binding(1, 1)];
    row.bindings = read.clone();
    store.save(&row, at(1)).await.unwrap();

    // Two writers read the same bindings and each mint a next challenge.
    let first = vec![cookie(), key_binding(2, 2)];
    let second = vec![cookie(), key_binding(3, 2)];
    assert_eq!(
        store
            .replace_bindings(&t, &id, &read, &first, at(2))
            .await
            .unwrap(),
        BindingsUpdate::Written
    );
    assert_eq!(
        store
            .replace_bindings(&t, &id, &read, &second, at(2))
            .await
            .unwrap(),
        BindingsUpdate::Conflict,
        "the second writer's read is stale: its proof is not accepted"
    );
    assert_eq!(bindings(&store, "swap").await, first);

    // The loser reads again and its write lands.
    assert_eq!(
        store
            .replace_bindings(&t, &id, &first, &second, at(3))
            .await
            .unwrap(),
        BindingsUpdate::Written
    );
    assert_eq!(bindings(&store, "swap").await, second);

    // A key added to a keyless device is the same swap: a second
    // registration from the same read conflicts.
    let mut plain = device("register", 3, DeviceTrustLevel::Unknown, at(0));
    plain.bindings = vec![cookie()];
    store.save(&plain, at(1)).await.unwrap();
    let keyless = vec![cookie()];
    let registered = vec![cookie(), key_binding(5, 2)];
    assert_eq!(
        store
            .replace_bindings(&t, &dev_id("register"), &keyless, &registered, at(2))
            .await
            .unwrap(),
        BindingsUpdate::Written
    );
    assert_eq!(
        store
            .replace_bindings(
                &t,
                &dev_id("register"),
                &keyless,
                &[cookie(), key_binding(6, 2)],
                at(2)
            )
            .await
            .unwrap(),
        BindingsUpdate::Conflict,
        "a device takes one key"
    );

    // A revoked device gains nothing, a missing one is reported.
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, at(4))
        .await
        .unwrap();
    assert_eq!(
        store
            .replace_bindings(&t, &id, &second, &first, at(5))
            .await
            .unwrap(),
        BindingsUpdate::Revoked
    );
    assert_eq!(bindings(&store, "swap").await, second);
    assert_eq!(
        store
            .replace_bindings(&t, &dev_id("absent"), &read, &first, at(5))
            .await
            .unwrap(),
        BindingsUpdate::Missing
    );
}

/// A registration and a sighting of one device lose neither write. The
/// sighting moves `last_seen_at` and no binding, so one that lands between
/// a registration's read and its write does not make that write a conflict;
/// the registration replaces the bindings and nothing else, so it does not
/// move the sighting. Made at once, both land.
pub(crate) async fn a_registration_beside_a_sighting_loses_neither<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("sighted"));
    let mut row = device("sighted", 4, DeviceTrustLevel::Seen, at(0));
    let keyless = vec![cookie()];
    row.bindings = keyless.clone();
    store.save(&row, at(1)).await.unwrap();

    // The registration read the bindings; a sighting lands; it writes.
    assert_eq!(
        store.record_sighting(&t, &id, at(600)).await.unwrap(),
        DeviceTrustLevel::Seen
    );
    let registered = vec![cookie(), key_binding(5, 2)];
    assert_eq!(
        store
            .replace_bindings(&t, &id, &keyless, &registered, at(601))
            .await
            .unwrap(),
        BindingsUpdate::Written,
        "a sighting is no change to the bindings"
    );
    let after = store
        .load_fresh(&t, &id)
        .await
        .unwrap()
        .expect("the device");
    assert_eq!(after.bindings, registered);
    assert_eq!(after.last_seen_at, at(600), "the sighting stands");

    // Both at once, from one read of the row.
    let next = vec![cookie(), key_binding(6, 3)];
    let (sighted, swapped) = tokio::join!(
        store.record_sighting(&t, &id, at(1200)),
        store.replace_bindings(&t, &id, &registered, &next, at(1200)),
    );
    assert_eq!(sighted.unwrap(), DeviceTrustLevel::Seen);
    assert_eq!(swapped.unwrap(), BindingsUpdate::Written);
    let after = store
        .load_fresh(&t, &id)
        .await
        .unwrap()
        .expect("the device");
    assert_eq!(after.bindings, next, "the key write is not lost");
    assert_eq!(after.last_seen_at, at(1200), "nor is the sighting");
}
