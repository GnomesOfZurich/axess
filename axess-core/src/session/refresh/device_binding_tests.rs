//! The device string a token carries is stored as a keyed digest bound to the
//! token's device id, and rotation checks it.

use super::device_binding::{bind, verify};
use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::authn::ids::DeviceId;
use crate::testing::mock_random::MockRng;

fn device(label: &str) -> DeviceId {
    axess_identity::testing::device(label)
}

async fn issue(
    store: &crate::testing::MemoryRefreshTokenStore,
    config: &RefreshTokenConfig,
    info: Option<&str>,
    device_id: Option<DeviceId>,
) -> (String, RefreshToken) {
    issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: info.map(str::to_owned),
            family_id: None,
            device_id,
        },
        config,
        store,
        &MockRng::new(5),
        now(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn the_record_holds_a_keyed_digest_and_not_the_client_string() {
    let store = store();
    let (_, record) = issue(
        &store,
        &test_config(),
        Some("Mozilla/5.0 (secret UA)"),
        None,
    )
    .await;
    let stored = record.device_info.expect("a binding");
    assert!(stored.starts_with("hb1:"), "{stored}");
    assert!(!stored.contains("Mozilla"), "{stored}");
}

#[tokio::test]
async fn rotation_checks_the_digest_and_the_child_keeps_it() {
    let store = store();
    let config = test_config();
    let (plaintext, record) = issue(&store, &config, Some("fp-hex"), Some(device("d1"))).await;

    let wrong = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &MockRng::new(6),
        now(),
        Some("other"),
        |_| async { true },
    )
    .await;
    assert!(matches!(wrong, Err(RefreshError::DeviceMismatch)));
    let none = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &MockRng::new(6),
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(none, Err(RefreshError::DeviceMismatch)));

    let (_, child) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &MockRng::new(6),
        now(),
        Some("fp-hex"),
        |_| async { true },
    )
    .await
    .unwrap();
    let (_, child) = child.expect("rotated");
    assert_eq!(
        child.device_info, record.device_info,
        "binding is inherited unchanged"
    );
    assert_eq!(child.device_id, Some(device("d1")));
}

/// The stored value is for the device id on the row: the same string
/// presented for a row that names another device does not match.
#[test]
fn the_digest_is_bound_to_the_device_id() {
    let pepper = Some(&b"pepper-pepper-pepper-pepper-1234"[..]);
    let for_d1 = bind("fp", Some(&device("d1")), pepper);
    assert_ne!(for_d1, bind("fp", Some(&device("d2")), pepper));
    assert_ne!(for_d1, bind("fp", None, pepper));

    let mut row = row_with(Some(for_d1.clone()), Some(device("d1")));
    assert_eq!(verify(&row, Some("fp"), pepper), Ok(Some(for_d1)));
    row.device_id = Some(device("d2"));
    assert_eq!(verify(&row, Some("fp"), pepper), Err(()));
}

#[test]
fn a_different_pepper_is_a_different_digest() {
    let d = device("d1");
    assert_ne!(
        bind(
            "fp",
            Some(&d),
            Some(&b"pepper-one-pepper-one-pepper-123"[..])
        ),
        bind(
            "fp",
            Some(&d),
            Some(&b"pepper-two-pepper-two-pepper-123"[..])
        ),
    );
}

fn row_with(info: Option<String>, device_id: Option<DeviceId>) -> RefreshToken {
    RefreshToken {
        id: RefreshTokenId::try_new("5b0f6f0e-2c5b-4d7e-9a53-0d4bb1a6a001").unwrap(),
        user_id: fixture_user(),
        tenant_id: fixture_tenant(),
        token_hash: "h".into(),
        issued_at: now(),
        expires_at: now() + Duration::days(1),
        revoked: false,
        device_info: info,
        family_id: None,
        device_id,
        authn_time: None,
        revoked_reason: None,
        revoked_at: None,
    }
}

/// A token an earlier release stored with the raw string still refreshes, and
/// the token that replaces it carries the keyed digest.
#[test]
fn a_raw_string_from_an_earlier_release_is_honoured_and_upgraded() {
    let d = device("d1");
    let row = row_with(Some("iPhone/16".to_string()), Some(d));
    let upgraded = verify(&row, Some("iPhone/16"), None).unwrap().unwrap();
    assert_eq!(upgraded, bind("iPhone/16", Some(&d), None));
    assert_eq!(verify(&row, Some("Android/15"), None), Err(()));
    assert_eq!(verify(&row, None, None), Err(()));
}

#[test]
fn an_unbound_token_needs_nothing_and_stays_unbound() {
    let row = row_with(None, None);
    assert_eq!(verify(&row, Some("anything"), None), Ok(None));
    assert_eq!(verify(&row, None, None), Ok(None));
}
