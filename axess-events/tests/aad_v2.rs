//! The second AAD tag binds every envelope field a reader acts on, a reader
//! refuses the first tag unless it names the opt-in, and an event sealed
//! under the first tag is moved to the second by the documented pass.

use std::time::{Duration, SystemTime};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axess_events::{
    AeadAlgorithm, EncryptedBlob, EnvelopeFields, Event, EventBody, EventId, EventPayload,
    EventStatus, EventSubject, FirstTag, KeyId, KindTag, TenantId, TraceContext, UserId,
    envelope_aad_for, envelope_aad_v2, open_aads_for,
};

#[derive(Clone, Debug, PartialEq)]
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

/// The reader's clock, `secs` seconds after the Unix epoch.
fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// The first-tag AAD of an event, as an event sealed before the second tag
/// carries it: the second value an accepting reader is listed.
fn first_tag_aad(e: &Event<Thing>) -> Vec<u8> {
    open_aads_for(e, FirstTag::Accept, at(0))
        .expect("an encrypted body has associated data")
        .pop()
        .expect("an accepting policy lists the first tag last")
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
    let v1 = first_tag_aad(&e);
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
        .encrypt(&Nonce::from(blob.nonce), Payload { msg: plain, aad })
        .expect("seal");
}

/// Open the way a reader under `first_tag` does at `now`: each
/// listed AAD in order. The index says which tag opened the event.
fn open_under(
    event: &Event<Thing>,
    first_tag: FirstTag,
    now: SystemTime,
) -> Option<(usize, Vec<u8>)> {
    let EventBody::Encrypted(blob) = &event.body else {
        return None;
    };
    open_aads_for(event, first_tag, now)?
        .into_iter()
        .enumerate()
        .find_map(|(i, aad)| {
            cipher()
                .decrypt(
                    &Nonce::from(blob.nonce),
                    Payload {
                        msg: &blob.ciphertext,
                        aad: &aad,
                    },
                )
                .ok()
                .map(|plain| (i, plain))
        })
}

/// Open the way a reader does by default: under the one value
/// `envelope_aad_for` returns, with no clock and no policy.
fn open(event: &Event<Thing>) -> Option<(usize, Vec<u8>)> {
    let EventBody::Encrypted(blob) = &event.body else {
        return None;
    };
    cipher()
        .decrypt(
            &Nonce::from(blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad: &envelope_aad_for(event)?,
            },
        )
        .ok()
        .map(|plain| (0, plain))
}

/// An event sealed under the first tag, as a release before the second tag
/// left it in the store.
fn sealed_under_the_first_tag(plain: &[u8]) -> Event<Thing> {
    let mut event = sealed();
    let aad = first_tag_aad(&event);
    seal(&mut event, &aad, plain);
    event
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

/// The default refuses the first tag: the one value listed is the second
/// tag's, whatever the clock reads, and an event sealed under the first tag
/// does not open.
#[test]
fn the_default_refuses_an_event_sealed_under_the_first_tag() {
    assert_eq!(FirstTag::default(), FirstTag::Reject);
    let event = sealed_under_the_first_tag(b"old");
    assert_eq!(open(&event), None, "the default reader");
    for now in [at(0), at(1_700_000_000), at(u64::from(u32::MAX))] {
        assert_eq!(
            open_aads_for(&event, FirstTag::default(), now).expect("aads"),
            vec![aad(&event)],
            "only the second tag is listed"
        );
        assert_eq!(open_under(&event, FirstTag::Reject, now), None);
    }
    assert!(!FirstTag::Reject.accepts_at(at(0)));
    assert!(FirstTag::Accept.accepts_at(at(u64::from(u32::MAX))));
}

/// Under the named opt-in an event sealed under the first tag opens, through
/// the second value listed, and its status stays editable: that is what the
/// first tag authenticated, and why accepting it is not the default.
#[test]
fn the_opt_in_opens_an_event_sealed_under_the_first_tag_rewritten_or_not() {
    let mut event = sealed_under_the_first_tag(b"old");
    assert_eq!(
        open_under(&event, FirstTag::Accept, at(0)),
        Some((1, b"old".to_vec()))
    );
    event.status = EventStatus::Success;
    assert_eq!(
        open_under(&event, FirstTag::Accept, at(0)),
        Some((1, b"old".to_vec())),
        "the first tag does not bind the status"
    );
    assert_eq!(open(&event), None, "and the default refuses it either way");
}

/// With a cutoff the first tag is tried before it and refused from it on,
/// on the reader's clock, whatever the event's own time says. The cutoff
/// and the clock are instants, so no unit can be mistaken for another.
#[test]
fn the_first_tag_is_refused_from_the_cutoff_on_the_readers_clock() {
    let mut event = sealed_under_the_first_tag(b"old");
    event.status = EventStatus::Success;
    let cutoff = at(1_800_000_000);
    let just_before = cutoff - Duration::from_micros(1);
    assert!(
        event.time_micros < 1_800_000_000_000_000,
        "the event's own time is before the cutoff"
    );

    assert_eq!(
        open_under(&event, FirstTag::AcceptUntil(cutoff), just_before).map(|(i, _)| i),
        Some(1),
        "before the cutoff the first tag is still tried"
    );
    for now in [cutoff, cutoff + Duration::from_secs(1)] {
        assert_eq!(
            open_under(&event, FirstTag::AcceptUntil(cutoff), now),
            None,
            "from the cutoff on the first tag is refused"
        );
        assert_eq!(
            open_aads_for(&event, FirstTag::AcceptUntil(cutoff), now)
                .expect("aads")
                .len(),
            1,
            "only the second tag is listed from the cutoff on"
        );
    }
    assert_eq!(
        open_aads_for(&event, FirstTag::AcceptUntil(cutoff), just_before)
            .expect("aads")
            .len(),
        2
    );
    assert!(FirstTag::AcceptUntil(cutoff).accepts_at(just_before));
    assert!(!FirstTag::AcceptUntil(cutoff).accepts_at(cutoff));
}

/// The documented pass: an event that opens only under the first tag is
/// sealed again under the second, with a fresh nonce, and from then on opens
/// under the default and no longer opens once a field is edited. An event
/// already under the second tag is left alone.
#[test]
fn the_reseal_pass_moves_a_first_tag_event_to_the_second_tag() {
    let mut store = vec![sealed_under_the_first_tag(b"old"), {
        let mut current = sealed();
        current.id = EventId::from_bytes([8; 16]);
        let aad = envelope_aad_for(&current).expect("aad");
        seal(&mut current, &aad, b"new");
        current
    }];
    let untouched = store[1].clone();

    let mut moved = 0;
    for event in &mut store {
        match open_under(event, FirstTag::Accept, at(0)) {
            Some((0, _)) => {}
            Some((_, plain)) => {
                if let EventBody::Encrypted(blob) = &mut event.body {
                    blob.nonce = [9; 12];
                }
                let aad = envelope_aad_for(event).expect("aad");
                seal(event, &aad, &plain);
                moved += 1;
            }
            None => panic!("every event of this store opens under one of the tags"),
        }
    }

    assert_eq!(moved, 1, "one event was sealed under the first tag");
    assert_eq!(open(&store[0]), Some((0, b"old".to_vec())));
    assert_eq!(open(&store[1]), Some((0, b"new".to_vec())));
    assert_eq!(
        store[1].body, untouched.body,
        "an event under the second tag is not rewritten"
    );
    store[0].status = EventStatus::Success;
    assert_eq!(
        open_under(&store[0], FirstTag::Accept, at(0)),
        None,
        "after the pass an edited status no longer opens, under any policy"
    );
}
