#![allow(deprecated)]
//! The second AAD tag binds every envelope field a reader acts on.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axess_events::{
    AeadAlgorithm, EncryptedBlob, EnvelopeFields, Event, EventBody, EventId, EventPayload,
    EventStatus, EventSubject, KeyId, KindTag, TenantId, TraceContext, UserId, envelope_aad,
    envelope_aad_for, envelope_aad_v2, open_aads_for,
};

#[derive(Clone, Debug)]
struct Thing;

impl EventPayload for Thing {
    fn kind_tag(&self) -> KindTag {
        KindTag::from_static("test.thing.v1")
    }

    #[cfg(feature = "serde")]
    fn to_inner_json(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

fn sealed() -> Event<Thing> {
    Event {
        id: EventId::from_bytes([7; 16]),
        envelope_version: 1,
        time_micros: 1_700_000_000_000_000,
        tenant_id: Some(TenantId::from_bytes([1; 16])),
        kind: KindTag::from_static("test.thing.v1"),
        subject: Some(EventSubject::User(UserId::from_bytes([2; 16]))),
        actor: Some(EventSubject::User(UserId::from_bytes([3; 16]))),
        trace_context: Some(TraceContext {
            trace_id: [4; 16],
            span_id: [5; 8],
            flags: 1,
        }),
        status: EventStatus::Failure,
        body: EventBody::Encrypted(EncryptedBlob {
            key_id: KeyId::from_static("k1"),
            algorithm: AeadAlgorithm::Aes256Gcm,
            nonce: [0; 12],
            ciphertext: vec![1, 2, 3],
        }),
    }
}

fn aad(e: &Event<Thing>) -> Vec<u8> {
    envelope_aad_for(e).expect("an encrypted body has associated data")
}

#[test]
fn flipping_any_field_a_reader_acts_on_changes_the_v2_aad() {
    let base = sealed();
    let want = aad(&base);
    assert_eq!(aad(&sealed()), want, "deterministic");

    let mut cases: Vec<(&str, Event<Thing>)> = Vec::new();
    let mut e = sealed();
    e.status = EventStatus::Success;
    cases.push(("status", e));
    let mut e = sealed();
    e.actor = None;
    cases.push(("actor removed", e));
    let mut e = sealed();
    e.actor = Some(EventSubject::User(UserId::from_bytes([9; 16])));
    cases.push(("actor replaced", e));
    let mut e = sealed();
    e.time_micros += 1;
    cases.push(("time", e));
    let mut e = sealed();
    e.envelope_version = 2;
    cases.push(("envelope version", e));
    let mut e = sealed();
    e.trace_context = None;
    cases.push(("trace removed", e));
    let mut e = sealed();
    if let Some(t) = e.trace_context.as_mut() {
        t.flags = 0;
    }
    cases.push(("trace flags", e));
    let mut e = sealed();
    if let EventBody::Encrypted(b) = &mut e.body {
        b.algorithm = AeadAlgorithm::ChaCha20Poly1305;
    }
    cases.push(("algorithm", e));
    let mut e = sealed();
    if let EventBody::Encrypted(b) = &mut e.body {
        b.key_id = KeyId::from_static("k2");
    }
    cases.push(("key id", e));
    let mut e = sealed();
    e.kind = KindTag::from_static("test.thing.v2");
    cases.push(("kind", e));
    let mut e = sealed();
    e.tenant_id = None;
    cases.push(("tenant", e));
    let mut e = sealed();
    e.subject = None;
    cases.push(("subject", e));
    let mut e = sealed();
    e.id = EventId::from_bytes([8; 16]);
    cases.push(("id", e));

    for (name, changed) in cases {
        assert_ne!(aad(&changed), want, "{name} is bound by the v2 AAD");
    }
}

#[test]
fn the_first_tag_still_builds_and_never_collides_with_the_second() {
    let e = sealed();
    let EventBody::Encrypted(blob) = &e.body else {
        panic!("sealed() is encrypted");
    };
    let v1 = envelope_aad(&e.id, &e.kind, e.tenant_id.as_ref(), e.subject.as_ref());
    assert!(String::from_utf8_lossy(&v1).contains("envelope-aad/v1"));
    let v2 = envelope_aad_v2(&EnvelopeFields {
        id: &e.id,
        envelope_version: e.envelope_version,
        time_micros: e.time_micros,
        tenant: e.tenant_id.as_ref(),
        kind: &e.kind,
        subject: e.subject.as_ref(),
        actor: e.actor.as_ref(),
        trace_context: e.trace_context.as_ref(),
        status: e.status,
        key_id: &blob.key_id,
        algorithm: blob.algorithm,
    });
    assert_ne!(v1, v2);
    assert_eq!(v2, aad(&e), "the fields and the event give one value");
}

#[test]
fn a_clear_body_has_no_associated_data() {
    let mut e = sealed();
    e.body = EventBody::Clear(Thing);
    assert!(envelope_aad_for(&e).is_none());
}

fn cipher() -> Aes256Gcm {
    Aes256Gcm::new_from_slice(&[0x5a; 32]).expect("key")
}

/// Seal `plain` into the event's blob under `aad`.
fn seal(event: &mut Event<Thing>, aad: &[u8], plain: &[u8]) {
    let EventBody::Encrypted(blob) = &mut event.body else {
        panic!("encrypted body");
    };
    blob.ciphertext = cipher()
        .encrypt(Nonce::from_slice(&blob.nonce), Payload { msg: plain, aad })
        .expect("seal");
}

/// Open the way a reader does: each candidate AAD in order.
fn open(event: &Event<Thing>) -> Option<(usize, Vec<u8>)> {
    let EventBody::Encrypted(blob) = &event.body else {
        return None;
    };
    open_aads_for(event)?
        .into_iter()
        .enumerate()
        .find_map(|(i, aad)| {
            cipher()
                .decrypt(
                    Nonce::from_slice(&blob.nonce),
                    Payload {
                        msg: &blob.ciphertext,
                        aad: &aad,
                    },
                )
                .ok()
                .map(|plain| (i, plain))
        })
}

/// A newly sealed event is sealed under the second tag, opens under it, and
/// fails to open once its status is edited at rest.
#[test]
fn a_newly_sealed_event_fails_to_open_after_its_status_is_edited() {
    let mut event = sealed();
    let aad = envelope_aad_for(&event).expect("aad");
    seal(&mut event, &aad, b"secret");
    assert_eq!(
        open(&event),
        Some((0, b"secret".to_vec())),
        "opens under the second tag"
    );

    event.status = EventStatus::Success;
    assert_eq!(open(&event), None, "an edited status does not open");

    let mut event = sealed();
    let aad = envelope_aad_for(&event).expect("aad");
    seal(&mut event, &aad, b"secret");
    event.actor = None;
    assert_eq!(open(&event), None, "an edited actor does not open");
    event.actor = sealed().actor;
    event.time_micros += 1;
    assert_eq!(open(&event), None, "an edited time does not open");
}

/// An event sealed under the first tag still opens, through the second
/// candidate, and its status stays editable: that is what the first tag
/// authenticated.
#[test]
fn an_event_sealed_under_the_first_tag_still_opens() {
    let mut event = sealed();
    let aad = envelope_aad(
        &event.id,
        &event.kind,
        event.tenant_id.as_ref(),
        event.subject.as_ref(),
    );
    seal(&mut event, &aad, b"old");
    assert_eq!(open(&event), Some((1, b"old".to_vec())));
}
