//! The bytes every stored or sent timestamp is written as, and what of the
//! stored forms still reads back.
//!
//! A session row, a device row, a status detail or an audit filter written by
//! one release is read by the next, so a timestamp keeps its exact text: an
//! RFC 3339 instant in UTC with a `Z`, whole seconds with no fraction, and a
//! fraction of three, six or nine digits, the fewest that hold the value. A
//! value from outside the years 0 to 9999 (the clamp of a lifetime set to
//! "for ever") is written with a sign. Each case below writes a value and
//! compares the text with the pinned one, then reads that text back and
//! writes it again; the reading cases also take the other forms an earlier
//! release accepted, and rows from before a field existed.
//!
//! No case names a time type: an instant comes from the reference clock or
//! from a stored row, so the cases read the same whatever type holds it.

use axess_clock::Until;
use axess_clock::testing::MockClock;
use axess_core::authn::assurance::{CredentialBinding, FactorAssurance};
use axess_core::authn::event::{AuthEventBuilder, AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{FactorKind, FactorStep};
#[cfg(feature = "device")]
use axess_core::authn::ids::DeviceId;
use axess_core::authn::ids::{TenantId, UserId};
use axess_core::authn::store::EventQueryFilter;
use axess_core::authn::types::{EntityState, StatusCause, StatusDetail, Tenant, User};
#[cfg(feature = "device")]
use axess_core::device::types::{
    AttestationClass, Device, DeviceBinding, DeviceTrustLevel, FingerprintHash,
};
use axess_core::session::SessionEndReason;
use axess_core::session::data::{
    AuthFlow, AuthState, EndingClaim, Impersonation, SessionData, WorkflowKind, WorkflowState,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;

const ADMIN: &str = "01010101-0101-0101-0101-010101010101";
const USER: &str = "02020202-0202-0202-0202-020202020202";
const TENANT: &str = "03030303-0303-0303-0303-030303030303";
#[cfg(feature = "device")]
const DEVICE: &str = "04040404-0404-0404-0404-040404040404";
#[cfg(feature = "device")]
const HASH: &str = "0505050505050505050505050505050505050505050505050505050505050505";

/// The instant a stored row names, read the way the row reads it.
macro_rules! at {
    ($text:expr) => {
        serde_json::from_str::<Impersonation>(&format!(
            r#"{{"admin":"{ADMIN}","since":"{}"}}"#,
            $text
        ))
        .expect("an instant the row form reads")
        .since
    };
}

fn admin() -> UserId {
    UserId::from_bytes([1; 16])
}

fn user() -> UserId {
    UserId::from_bytes([2; 16])
}

fn tenant() -> TenantId {
    TenantId::from_bytes([3; 16])
}

/// The JSON text of `value`, compared with the pinned text.
fn writes_as<T: Serialize>(value: &T, pinned: &str) {
    let text = serde_json::to_string(value).expect("serialises");
    assert_eq!(text, pinned, "the written text changed");
}

/// The pinned text reads, and the value read writes the same text again.
fn reads_back<T: Serialize + DeserializeOwned>(pinned: &str) -> T {
    let value: T = serde_json::from_str(pinned).expect("the pinned text reads");
    writes_as(&value, pinned);
    value
}

#[test]
fn an_instant_is_written_in_utc_with_the_fewest_fraction_digits_that_hold_it() {
    let cases = [
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ("2026-01-01T00:00:00.500Z", "2026-01-01T00:00:00.500Z"),
        ("2026-01-01T00:00:00.120Z", "2026-01-01T00:00:00.120Z"),
        ("2026-01-01T00:00:00.001Z", "2026-01-01T00:00:00.001Z"),
        ("2026-01-01T00:00:00.123456Z", "2026-01-01T00:00:00.123456Z"),
        ("2026-01-01T00:00:00.000001Z", "2026-01-01T00:00:00.000001Z"),
        (
            "2026-01-01T00:00:00.123456789Z",
            "2026-01-01T00:00:00.123456789Z",
        ),
        (
            "2026-01-01T00:00:00.100000001Z",
            "2026-01-01T00:00:00.100000001Z",
        ),
        ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
        (
            "1969-12-31T23:59:59.999999999Z",
            "1969-12-31T23:59:59.999999999Z",
        ),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"),
        (
            "9999-12-31T23:59:59.999999999Z",
            "9999-12-31T23:59:59.999999999Z",
        ),
    ];
    for (stored, written) in cases {
        let since = at!(stored);
        writes_as(
            &Impersonation {
                admin: admin(),
                since,
            },
            &format!(r#"{{"admin":"{ADMIN}","since":"{written}"}}"#),
        );
    }
}

#[test]
fn an_instant_outside_the_four_digit_years_is_written_with_a_sign() {
    // The latest and earliest instants an earlier release stored for a
    // lifetime that does not fit ("for ever"), and a year just past 9999.
    for stored in [
        "+262142-12-31T23:59:59.999999999Z",
        "-262143-01-01T00:00:00Z",
        "+10000-01-01T00:00:00Z",
        "-0001-12-31T23:59:59Z",
    ] {
        reads_back::<Impersonation>(&format!(r#"{{"admin":"{ADMIN}","since":"{stored}"}}"#));
    }
}

#[test]
fn the_reference_clock_writes_the_reference_instant() {
    writes_as(
        &Impersonation {
            admin: admin(),
            since: MockClock::reference_time(),
        },
        &format!(r#"{{"admin":"{ADMIN}","since":"2026-01-01T00:00:00Z"}}"#),
    );
    assert_eq!(at!("2026-01-01T00:00:00Z"), MockClock::reference_time());
}

#[test]
fn the_other_forms_an_earlier_release_read_still_read_as_the_same_instant() {
    let reference = MockClock::reference_time();
    for stored in [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T01:00:00+01:00",
        "2025-12-31T19:30:00-04:30",
        "2026-01-01t00:00:00z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00:00.000000000000Z",
        "2026-01-01T00:00:00+0000",
        "2026-01-01T00:00:00 UTC",
        "2026-01-01T00:00:00 +00:00",
    ] {
        assert_eq!(at!(stored), reference, "{stored}");
    }
    // Digits past the ninth are dropped, not rounded.
    let late = at!("2026-01-01T00:00:00.1234567899Z");
    writes_as(
        &Impersonation {
            admin: admin(),
            since: late,
        },
        &format!(r#"{{"admin":"{ADMIN}","since":"2026-01-01T00:00:00.123456789Z"}}"#),
    );
}

#[test]
fn a_text_that_is_no_instant_is_refused() {
    for stored in [
        "",
        "2026-01-01",
        "2026-01-01T00:00:00",
        "2026-13-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T00:00:00Zjunk",
        "1767225600",
    ] {
        let json = format!(r#"{{"admin":"{ADMIN}","since":"{stored}"}}"#);
        assert!(
            serde_json::from_str::<Impersonation>(&json).is_err(),
            "{stored:?} read as an instant"
        );
    }
    let json = format!(r#"{{"admin":"{ADMIN}","since":1767225600}}"#);
    assert!(serde_json::from_str::<Impersonation>(&json).is_err());
}

#[test]
fn a_status_detail_keeps_its_since_and_until() {
    let detail = StatusDetail {
        cause: StatusCause::Lockout,
        reason: "too many attempts".into(),
        since: MockClock::reference_time(),
        until: Some(Until::At(at!("2026-01-01T00:15:00.250Z"))),
    };
    let pinned = r#"{"cause":"Lockout","reason":"too many attempts","since":"2026-01-01T00:00:00Z","until":"2026-01-01T00:15:00.250Z"}"#;
    writes_as(&detail, pinned);
    assert_eq!(reads_back::<StatusDetail>(pinned), detail);

    let open = r#"{"cause":"Lockout","reason":"r","since":"2026-01-01T00:00:00Z","until":null}"#;
    assert_eq!(reads_back::<StatusDetail>(open).until, None);
    // A row with no `until` at all reads as an open-ended state.
    let missing: StatusDetail =
        serde_json::from_str(r#"{"cause":"Lockout","reason":"r","since":"2026-01-01T00:00:00Z"}"#)
            .expect("a row without until reads");
    assert_eq!(missing.until, None);
    // The clamp of a lockout "for ever".
    reads_back::<StatusDetail>(
        r#"{"cause":"Lockout","reason":"r","since":"2026-01-01T00:00:00Z","until":"+262142-12-31T23:59:59.999999999Z"}"#,
    );
}

#[test]
fn a_user_and_a_tenant_keep_their_stamps() {
    let state = EntityState::Suspended(StatusDetail {
        cause: StatusCause::Administrative,
        reason: "review".into(),
        since: at!("2026-01-01T00:00:01.5Z"),
        until: None,
    });
    let user = User {
        id: user(),
        tenant_id: tenant(),
        identifier: Arc::from("alice@example.com"),
        display_name: Arc::from("Alice"),
        status: state.clone(),
        webauthn_id: None,
        created_by: admin(),
        created_at: MockClock::reference_time(),
        updated_by: admin(),
        updated_at: at!("2026-01-02T03:04:05.000006Z"),
    };
    let pinned = format!(
        r#"{{"id":"{USER}","tenant_id":"{TENANT}","identifier":"alice@example.com","display_name":"Alice","status":{{"Suspended":{{"cause":"Administrative","reason":"review","since":"2026-01-01T00:00:01.500Z","until":null}}}},"created_by":"{ADMIN}","created_at":"2026-01-01T00:00:00Z","updated_by":"{ADMIN}","updated_at":"2026-01-02T03:04:05.000006Z"}}"#
    );
    writes_as(&user, &pinned);
    reads_back::<User>(&pinned);

    let tenant = Tenant {
        id: tenant(),
        identifier: Arc::from("acme"),
        display_name: Arc::from("Acme"),
        status: EntityState::Active,
        created_by: admin(),
        created_at: MockClock::reference_time(),
        updated_by: admin(),
        updated_at: at!("2026-01-02T00:00:00.000000007Z"),
    };
    let pinned = format!(
        r#"{{"id":"{TENANT}","identifier":"acme","display_name":"Acme","status":"Active","created_by":"{ADMIN}","created_at":"2026-01-01T00:00:00Z","updated_by":"{ADMIN}","updated_at":"2026-01-02T00:00:00.000000007Z"}}"#
    );
    writes_as(&tenant, &pinned);
    reads_back::<Tenant>(&pinned);
}

#[cfg(feature = "device")]
#[test]
fn a_device_row_keeps_every_stamp_of_the_device_and_its_bindings() {
    let device = Device {
        id: DeviceId::from_bytes([4; 16]),
        tenant_id: tenant(),
        user_id: Some(user()),
        trust_level: DeviceTrustLevel::Seen,
        fingerprint_hash: FingerprintHash::from_bytes([5; 32]),
        first_seen_at: MockClock::reference_time(),
        last_seen_at: at!("2026-01-01T00:00:10.123Z"),
        revoked_at: None,
        demoted_at: Some(at!("2026-01-01T00:00:05Z")),
        bindings: vec![
            DeviceBinding::Cookie {
                token_hash: FingerprintHash::from_bytes([5; 32]),
                issued_at: MockClock::reference_time(),
                last_used_at: at!("2026-01-01T00:00:10.123456Z"),
            },
            DeviceBinding::WebAuthn {
                credential_id: "Y3JlZA".into(),
                attestation_class: AttestationClass::None,
                bound_at: at!("2026-01-01T00:00:01Z"),
                last_used_at: at!("2026-01-01T00:00:02.123456789Z"),
            },
            DeviceBinding::Refresh {
                family_id: "family-1".into(),
                issued_at: at!("2026-01-01T00:00:03Z"),
                last_used_at: at!("2026-01-01T00:00:04Z"),
            },
        ],
    };
    let pinned = format!(
        r#"{{"id":"{DEVICE}","tenant_id":"{TENANT}","user_id":"{USER}","trust_level":"Seen","fingerprint_hash":"{HASH}","first_seen_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:10.123Z","revoked_at":null,"demoted_at":"2026-01-01T00:00:05Z","bindings":[{{"kind":"Cookie","token_hash":"{HASH}","issued_at":"2026-01-01T00:00:00Z","last_used_at":"2026-01-01T00:00:10.123456Z"}},{{"kind":"WebAuthn","credential_id":"Y3JlZA","attestation_class":"none","bound_at":"2026-01-01T00:00:01Z","last_used_at":"2026-01-01T00:00:02.123456789Z"}},{{"kind":"Refresh","family_id":"family-1","issued_at":"2026-01-01T00:00:03Z","last_used_at":"2026-01-01T00:00:04Z"}}]}}"#
    );
    writes_as(&device, &pinned);
    assert_eq!(reads_back::<Device>(&pinned), device);

    // A row written before `demoted_at` existed, or with `revoked_at` left
    // out, reads with neither set.
    let old = format!(
        r#"{{"id":"{DEVICE}","tenant_id":"{TENANT}","user_id":null,"trust_level":"Revoked","fingerprint_hash":"{HASH}","first_seen_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:00Z","revoked_at":"2026-01-01T00:00:09.9Z"}}"#
    );
    let read: Device = serde_json::from_str(&old).expect("a row without demoted_at reads");
    assert_eq!(read.demoted_at, None);
    assert_eq!(read.revoked_at, Some(at!("2026-01-01T00:00:09.900Z")));
    let without_revoked = old.replace(r#","revoked_at":"2026-01-01T00:00:09.9Z""#, "");
    let read: Device =
        serde_json::from_str(&without_revoked).expect("a row without revoked_at reads");
    assert_eq!(read.revoked_at, None);
}

#[test]
fn an_audit_filter_keeps_its_window() {
    let filter = EventQueryFilter {
        user_id: Some(user()),
        event_type: None,
        status: None,
        from: Some(MockClock::reference_time()),
        until: Some(at!("2026-01-31T23:59:59.999Z")),
        include_unscoped: false,
        limit: 50,
    };
    let pinned = format!(
        r#"{{"user_id":"{USER}","event_type":null,"status":null,"from":"2026-01-01T00:00:00Z","until":"2026-01-31T23:59:59.999Z","include_unscoped":false,"limit":50}}"#
    );
    writes_as(&filter, &pinned);
    reads_back::<EventQueryFilter>(&pinned);
    let open: EventQueryFilter = serde_json::from_str(
        r#"{"user_id":null,"event_type":null,"status":null,"include_unscoped":true,"limit":1}"#,
    )
    .expect("a filter without a window reads");
    assert_eq!((open.from, open.until), (None, None));
}

#[test]
fn a_session_row_keeps_every_stamp_of_its_state() {
    let assurance = FactorAssurance {
        kind: FactorKind::Password,
        at: at!("2026-01-01T00:00:01.250Z"),
        user_verified: false,
        trust_anchor: None,
        credential: CredentialBinding::NotApplicable,
    };
    let mut data = SessionData {
        auth_state: AuthState::Authenticated {
            user_id: user(),
            tenant_id: tenant(),
            authn_time: at!("2026-01-01T00:00:02.000001Z"),
            signed_in_at: MockClock::reference_time(),
            factors_completed: vec![
                (FactorKind::Password, at!("2026-01-01T00:00:01.250Z")),
                (FactorKind::Totp, at!("2026-01-01T00:00:02.000001Z")),
            ],
            impersonator: Some(Impersonation {
                admin: admin(),
                since: at!("2025-12-31T23:59:59.999999999Z"),
            }),
            ldap_groups: None,
            assurance: vec![assurance.clone()],
        },
        touched_at: Some(at!("2026-01-01T00:01:00Z")),
        ending: Some(EndingClaim {
            since: at!("2026-01-01T00:02:00.5Z"),
            reason: SessionEndReason::AgeCap,
        }),
        ..SessionData::default()
    };
    data.custom = serde_json::json!({});
    let pinned = format!(
        r#"{{"version":3,"auth_state":{{"kind":"Authenticated","user_id":"{USER}","tenant_id":"{TENANT}","authn_time":"2026-01-01T00:00:02.000001Z","signed_in_at":"2026-01-01T00:00:00Z","factors_completed":[["Password","2026-01-01T00:00:01.250Z"],["Totp","2026-01-01T00:00:02.000001Z"]],"impersonator":{{"admin":"{ADMIN}","since":"2025-12-31T23:59:59.999999999Z"}},"assurance":[{{"kind":"Password","at":"2026-01-01T00:00:01.250Z","user_verified":false,"credential":"not_applicable"}}]}},"fingerprint":null,"device_id":null,"custom":{{}},"revision":0,"touched_at":"2026-01-01T00:01:00Z","ending":{{"since":"2026-01-01T00:02:00.500Z","reason":"session_age_cap"}}}}"#
    );
    writes_as(&data, &pinned);
    assert_eq!(
        reads_back::<SessionData>(&pinned).auth_state,
        data.auth_state
    );

    // The store writes the row as MessagePack: the same text in the same
    // places.
    let packed = rmp_serde::to_vec_named(&data).expect("packs");
    let unpacked: SessionData = rmp_serde::from_slice(&packed).expect("unpacks");
    assert_eq!(unpacked.auth_state, data.auth_state);
    assert_eq!(rmp_serde::to_vec_named(&unpacked).expect("packs"), packed);
    for text in [
        "2026-01-01T00:00:02.000001Z",
        "2025-12-31T23:59:59.999999999Z",
        "2026-01-01T00:02:00.500Z",
    ] {
        let mut needle = vec![0xa0 | u8::try_from(text.len()).expect("short")];
        needle.extend_from_slice(text.as_bytes());
        assert!(
            packed.windows(needle.len()).any(|w| w == needle.as_slice()),
            "the packed row holds {text} as a string"
        );
    }

    let pending = SessionData {
        auth_state: AuthState::Authenticating {
            user_id: user(),
            tenant_id: tenant(),
            method_name: Arc::from("password+totp"),
            remaining: vec![FactorStep::Required(FactorKind::Totp)],
            completed: vec![(FactorKind::Password, at!("2026-01-01T00:00:01.250Z"))],
            attempt_count: 1,
            last_attempt: Some(at!("2026-01-01T00:00:03Z")),
            ldap_groups: None,
            impersonator: None,
            assurance: Vec::new(),
            flow: AuthFlow::StepUp {
                signed_in_at: MockClock::reference_time(),
            },
        },
        custom: serde_json::json!({}),
        ..SessionData::default()
    };
    let pinned = format!(
        r#"{{"version":3,"auth_state":{{"kind":"Authenticating","user_id":"{USER}","tenant_id":"{TENANT}","method_name":"password+totp","remaining":[{{"Required":"Totp"}}],"completed":[["Password","2026-01-01T00:00:01.250Z"]],"attempt_count":1,"last_attempt":"2026-01-01T00:00:03Z","flow":{{"step_up":{{"signed_in_at":"2026-01-01T00:00:00Z"}}}}}},"fingerprint":null,"device_id":null,"custom":{{}},"revision":0,"touched_at":null}}"#
    );
    writes_as(&pending, &pinned);
    assert_eq!(
        reads_back::<SessionData>(&pinned).auth_state,
        pending.auth_state
    );

    let workflow = WorkflowState {
        kind: WorkflowKind::Signup,
        current_step: 0,
        total_steps: 1,
        initiated_at: MockClock::reference_time(),
        verification_digest: Some("digest".into()),
        verification_expires_at: Some(Until::At(at!("2026-01-01T01:00:00.000000001Z"))),
    };
    let pinned = r#"{"kind":"Signup","current_step":0,"total_steps":1,"initiated_at":"2026-01-01T00:00:00Z","verification_digest":"digest","verification_expires_at":"2026-01-01T01:00:00.000000001Z"}"#;
    writes_as(&workflow, pinned);
    assert_eq!(reads_back::<WorkflowState>(pinned), workflow);
    let unverified: WorkflowState = serde_json::from_str(
        r#"{"kind":"Signup","current_step":0,"total_steps":1,"initiated_at":"2026-01-01T00:00:00Z"}"#,
    )
    .expect("a workflow without a verification reads");
    assert_eq!(unverified.verification_expires_at, None);

    // A row written before `touched_at` existed reads with none.
    let old: SessionData = serde_json::from_str(
        r#"{"version":3,"auth_state":{"kind":"Guest"},"fingerprint":null,"custom":null}"#,
    )
    .expect("a row without touched_at reads");
    assert_eq!(old.touched_at, None);
}

#[test]
fn the_impersonation_anchor_hashes_the_start_in_nanoseconds() {
    let impersonation = Impersonation {
        admin: admin(),
        since: at!("2026-01-01T00:00:00.123456789Z"),
    };
    let anchor = impersonation.registry_anchor(&user());
    let far = Impersonation {
        admin: admin(),
        since: at!("+262142-12-31T23:59:59.999999999Z"),
    };
    let far_anchor = far.registry_anchor(&user());
    let zero = Impersonation {
        admin: admin(),
        since: at!("1970-01-01T00:00:00Z"),
    };
    // Past the nanosecond range the start hashes as zero, as the epoch does.
    assert_eq!(far_anchor, zero.registry_anchor(&user()));
    assert_eq!(
        format!("{anchor}|{far_anchor}"),
        "a66d301fc65ed9bc5cd2078c4d52b4c6334d93a1b25b20f288255fae2d229cdb|acb0211539d6ec90295eff376b56666be9f0595d0b492bf5cb931755688dc803",
        "the anchor of an impersonation is a stored key"
    );
}

#[test]
fn an_event_stamps_its_time_in_microseconds() {
    let event = AuthEventBuilder::new(
        None,
        None,
        AuthEventType::Authenticated,
        AuthEventStatus::Success,
    )
    .build_at(at!("2026-01-01T00:00:00.123456789Z"));
    assert_eq!(event.event_time, 1_767_225_600_123_456);
    let before = AuthEventBuilder::new(
        None,
        None,
        AuthEventType::Authenticated,
        AuthEventStatus::Success,
    )
    .build_at(at!("1969-12-31T23:59:59.999999500Z"));
    assert_eq!(before.event_time, -1, "microseconds round down, as before");
    let event = AuthEventBuilder::new(
        None,
        None,
        AuthEventType::Authenticated,
        AuthEventStatus::Success,
    )
    .build_at(MockClock::reference_time());
    assert_eq!(event.event_time, 1_767_225_600_000_000);
}

#[cfg(feature = "default-error-response")]
#[derive(Debug, thiserror::Error)]
#[error("store")]
struct StoreError;

/// A lockout's end goes to the client as RFC 3339 text with a numeric UTC
/// offset, with the fewest fraction digits that hold it.
#[cfg(feature = "default-error-response")]
#[tokio::test]
async fn a_lockout_body_states_its_end_with_a_numeric_offset() {
    use axess_core::authn::error::AuthnError;
    for (until, written) in [
        ("2026-01-01T00:05:00Z", "2026-01-01T00:05:00+00:00"),
        ("2026-01-01T00:05:00.250Z", "2026-01-01T00:05:00.250+00:00"),
        (
            "2026-01-01T00:05:00.000000001Z",
            "2026-01-01T00:05:00.000000001+00:00",
        ),
    ] {
        let err: AuthnError<StoreError> = AuthnError::Locked {
            until: Some(Until::At(at!(until))),
        };
        let response = err.into_response_at(MockClock::reference_time());
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("a body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(body["until_iso"], serde_json::json!(written));
    }
}

/// The timestamp a Cedar context carries is RFC 3339 text with a numeric UTC
/// offset, with the fewest fraction digits that hold it.
#[cfg(feature = "authz")]
#[test]
fn a_cedar_timestamp_keeps_its_fraction() {
    use axess_core::authz::context::{BuildRequestContext, StandardRequestContext};
    for (at, written) in [
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00"),
        ("2026-01-01T00:00:00.250Z", "2026-01-01T00:00:00.250+00:00"),
        (
            "2026-01-01T00:00:00.123456Z",
            "2026-01-01T00:00:00.123456+00:00",
        ),
    ] {
        let context = StandardRequestContext::at(false, None, at!(at))
            .to_cedar_context()
            .expect("a context");
        assert!(
            matches!(context.get("timestamp"), Some(cedar_policy::EvalResult::String(text)) if text == written),
            "{at}"
        );
    }
}
