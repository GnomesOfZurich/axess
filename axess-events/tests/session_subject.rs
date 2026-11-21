//! A session subject: a new event names a session by its key, and an event
//! an earlier release wrote with a session id still reads, still opens and
//! writes back unchanged.
//!
//! The associated data each test expects is built here by hand from the
//! documented encoding, not by the crate, so a change to how the crate
//! encodes a session subject shows as a difference from these bytes.

use axess_events::{
    AeadAlgorithm, EncryptedBlob, Event, EventBody, EventId, EventPayload, EventStatus,
    EventSubject, EventSubjectRef, KeyId, KindTag, SessionId, SessionKey, TenantId,
    envelope_aad_for,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

const ID: [u8; 16] = [7; 16];
const TENANT: [u8; 16] = [1; 16];
const TIME_MICROS: i64 = 1_700_000_000_000_000;
const KIND: &str = "test.thing.v1";
const KEY_ID: &str = "k1";

/// An encrypted event with the given subject and actor, its ciphertext
/// still empty.
fn event(subject: EventSubject, actor: EventSubject) -> Event<Thing> {
    Event {
        id: EventId::from_bytes(ID),
        envelope_version: 1,
        time_micros: TIME_MICROS,
        tenant_id: Some(TenantId::from_bytes(TENANT)),
        kind: KindTag::from_static(KIND),
        subject: Some(subject),
        actor: Some(actor),
        trace_context: None,
        status: EventStatus::Success,
        body: EventBody::Encrypted(EncryptedBlob {
            key_id: KeyId::from_static(KEY_ID),
            algorithm: AeadAlgorithm::Aes256Gcm,
            nonce: [3; 12],
            ciphertext: Vec::new(),
        }),
    }
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("a short field");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// A subject as the associated data encodes it: its tag, then its bytes
/// behind their length.
fn subject_field(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag];
    put(&mut buf, bytes);
    buf
}

/// The second-tag associated data of [`event`] with the two encoded
/// subjects, written out field by field.
fn second_tag_aad(subject: &[u8], actor: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    put(&mut buf, b"axess-events/envelope-aad/v2");
    put(&mut buf, &ID);
    buf.push(1);
    buf.extend_from_slice(&TIME_MICROS.to_be_bytes());
    put(&mut buf, KIND.as_bytes());
    buf.push(1);
    put(&mut buf, &TENANT);
    buf.extend_from_slice(subject);
    buf.extend_from_slice(actor);
    buf.push(0); // no trace context
    buf.push(1); // success
    put(&mut buf, KEY_ID.as_bytes());
    buf.push(1); // AES-256-GCM
    buf
}

/// The first-tag associated data of [`event`] with the encoded subject.
#[cfg(feature = "serde")]
fn first_tag_aad(subject: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    put(&mut buf, b"axess-events/envelope-aad/v1");
    put(&mut buf, &ID);
    put(&mut buf, KIND.as_bytes());
    buf.push(1);
    put(&mut buf, &TENANT);
    buf.extend_from_slice(subject);
    buf
}

mod aead {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use axess_events::{Event, EventBody};

    use super::Thing;

    fn cipher() -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&[0x5a; 32]).expect("key")
    }

    pub fn seal(event: &mut Event<Thing>, aad: &[u8], plain: &[u8]) {
        let EventBody::Encrypted(blob) = &mut event.body else {
            panic!("an encrypted body");
        };
        blob.ciphertext = cipher()
            .encrypt(&Nonce::from(blob.nonce), Payload { msg: plain, aad })
            .expect("seal");
    }

    pub fn open(event: &Event<Thing>, aad: &[u8]) -> Option<Vec<u8>> {
        let EventBody::Encrypted(blob) = &event.body else {
            panic!("an encrypted body");
        };
        cipher()
            .decrypt(
                &Nonce::from(blob.nonce),
                Payload {
                    msg: &blob.ciphertext,
                    aad,
                },
            )
            .ok()
    }
}

#[test]
fn a_subject_named_by_its_key_is_bound_by_tag_6_and_its_32_bytes() {
    let subject = SessionKey::of(&SessionId::from_bytes([0x11; 16]));
    let actor = SessionKey::of(&SessionId::from_bytes([0x22; 16]));
    let e = event(
        EventSubject::SessionKey(subject),
        EventSubject::SessionKey(actor),
    );

    let mut subject_bytes = vec![6, 0, 0, 0, 0x20];
    subject_bytes.extend_from_slice(subject.as_bytes());
    assert_eq!(subject_field(6, subject.as_bytes()), subject_bytes);
    let want = second_tag_aad(&subject_bytes, &subject_field(6, actor.as_bytes()));
    assert_eq!(
        envelope_aad_for(&e).expect("encrypted"),
        want,
        "a key subject is tag 6, the length 32 and the key's bytes"
    );
}

#[test]
fn an_event_sealed_with_a_key_subject_opens() {
    let key = SessionKey::of(&SessionId::from_bytes([0x33; 16]));
    let mut e = event(EventSubject::SessionKey(key), EventSubject::SessionKey(key));
    let aad = envelope_aad_for(&e).expect("encrypted");
    aead::seal(&mut e, &aad, b"payload");
    let reread = envelope_aad_for(&e).expect("encrypted");
    assert_eq!(aead::open(&e, &reread).as_deref(), Some(&b"payload"[..]));
    match e.subject.as_ref().map(EventSubject::as_ref) {
        Some(EventSubjectRef::SessionKey(k)) => assert_eq!(*k, key),
        other => panic!("a key subject, got {other:?}"),
    }
}

#[cfg(feature = "serde")]
mod json {
    use super::*;

    #[test]
    fn an_event_sealed_with_a_key_subject_round_trips_through_json() {
        let key = SessionKey::of(&SessionId::from_bytes([0x44; 16]));
        let mut e = event(EventSubject::SessionKey(key), EventSubject::SessionKey(key));
        let aad = envelope_aad_for(&e).expect("encrypted");
        aead::seal(&mut e, &aad, b"payload");

        let json = serde_json::to_string(&e).expect("json");
        assert!(
            json.contains(&format!(r#"{{"SessionKey":"{key}"}}"#)),
            "the key's 64 characters under the variant's name: {json}"
        );
        let back: Event<Thing> = serde_json::from_str(&json).expect("read back");
        assert_eq!(back, e);
        let reread = envelope_aad_for(&back).expect("encrypted");
        assert_eq!(aead::open(&back, &reread).as_deref(), Some(&b"payload"[..]));
    }

    /// The JSON of a 0.19.0 event naming a session by its id, as subject
    /// and as actor, with a payload sealed over the 16 bytes of each.
    ///
    /// No variant but the session's changed its JSON, so the text is this
    /// release's JSON of the same event with user subjects, the variant's
    /// name changed; the ciphertext is sealed under the associated data
    /// written out by hand, as that release computed it.
    fn earlier_release_json(subject: SessionId, actor: SessionId) -> String {
        let mut template = event(
            EventSubject::User(axess_events::UserId::from_bytes(*subject.as_bytes())),
            EventSubject::User(axess_events::UserId::from_bytes(*actor.as_bytes())),
        );
        let aad = second_tag_aad(
            &subject_field(4, subject.as_bytes()),
            &subject_field(4, actor.as_bytes()),
        );
        aead::seal(&mut template, &aad, b"earlier payload");
        let json = serde_json::to_string(&template).expect("json");
        let user = |id: &SessionId| format!(r#"{{"User":"{id}"}}"#);
        let session = |id: &SessionId| format!(r#"{{"Session":"{id}"}}"#);
        let json = json
            .replace(&user(&subject), &session(&subject))
            .replace(&user(&actor), &session(&actor));
        assert_eq!(json.matches(r#"{"Session":""#).count(), 2, "{json}");
        json
    }

    #[test]
    fn an_event_of_an_earlier_release_reads_opens_and_writes_back_unchanged() {
        let subject = SessionId::from_bytes([0x55; 16]);
        let actor = SessionId::from_bytes([0x66; 16]);
        let json = earlier_release_json(subject, actor);

        let e: Event<Thing> = serde_json::from_str(&json).expect("the earlier form still reads");
        let (Some(EventSubject::Session(read_subject)), Some(EventSubject::Session(read_actor))) =
            (&e.subject, &e.actor)
        else {
            panic!("both read as recorded session ids: {e:?}");
        };
        assert_eq!(read_subject.as_bytes(), subject.as_bytes());
        assert_eq!(read_actor.as_bytes(), actor.as_bytes());
        assert_eq!(read_subject.key(), SessionKey::of(&subject));
        assert_eq!(read_actor.key(), SessionKey::of(&actor));

        let aad = envelope_aad_for(&e).expect("encrypted");
        assert_eq!(
            aad,
            second_tag_aad(
                &subject_field(4, subject.as_bytes()),
                &subject_field(4, actor.as_bytes()),
            ),
            "a recorded id is tag 4, the length 16 and the id's bytes"
        );
        assert_eq!(
            aead::open(&e, &aad).as_deref(),
            Some(&b"earlier payload"[..]),
            "the sealed payload of the earlier release still opens"
        );
        assert_eq!(serde_json::to_string(&e).expect("json"), json);
    }

    #[test]
    fn the_first_tag_binds_a_recorded_subject_by_its_16_bytes() {
        let subject = SessionId::from_bytes([0x77; 16]);
        let json = earlier_release_json(subject, subject);
        let e: Event<Thing> = serde_json::from_str(&json).expect("reads");
        let aads = axess_events::open_aads_for(
            &e,
            axess_events::FirstTag::Accept,
            std::time::SystemTime::UNIX_EPOCH,
        )
        .expect("encrypted");
        assert_eq!(
            aads.last(),
            Some(&first_tag_aad(&subject_field(4, subject.as_bytes())))
        );
    }

    #[test]
    fn a_recorded_session_is_not_read_from_anything_but_an_id() {
        for text in ["not an id", "", "00000000"] {
            let json = format!(r#"{{"Session":"{text}"}}"#);
            assert!(
                serde_json::from_str::<EventSubject>(&json).is_err(),
                "{json} reads as no subject"
            );
        }
    }
}

#[cfg(feature = "rkyv")]
mod archived {
    use super::*;
    use axess_events::DeviceId;
    use axess_events::subject::ArchivedEventSubject;
    use rkyv::rancor::Error;

    /// The archived bytes of a session subject of the earlier form: the
    /// archive of a device subject over the same 16 bytes, its tag changed
    /// to the session's. The two variants hold 16 bytes at the same place.
    fn archived_recorded_subject(id: [u8; 16]) -> Vec<u8> {
        let device = EventSubject::Device(DeviceId::from_bytes(id));
        let mut bytes = rkyv::to_bytes::<Error>(&device).expect("archive").to_vec();
        assert_eq!(bytes.len(), size_of::<ArchivedEventSubject>());
        assert_eq!(bytes[0], 2, "the device variant is the third");
        assert_eq!(&bytes[1..17], &id, "its 16 bytes follow the tag");
        bytes[0] = 3;
        bytes
    }

    #[test]
    fn an_archived_recorded_subject_reads_and_archives_back_to_the_same_bytes() {
        let id = [0x88; 16];
        let bytes = archived_recorded_subject(id);
        let read: EventSubject = rkyv::from_bytes::<EventSubject, Error>(&bytes).expect("reads");
        let EventSubject::Session(recorded) = &read else {
            panic!("a recorded session, got {read:?}");
        };
        assert_eq!(recorded.as_bytes(), &id);
        assert_eq!(recorded.key(), SessionKey::of(&SessionId::from_bytes(id)));

        let again = rkyv::to_bytes::<Error>(&read).expect("archive");
        assert_eq!(&again[..], &bytes[..], "the same bytes at the same place");
        let back: EventSubject = rkyv::from_bytes::<EventSubject, Error>(&again).expect("reads");
        assert_eq!(back, read);
    }

    #[test]
    fn a_key_subject_round_trips_through_an_archive() {
        let subject = EventSubject::SessionKey(SessionKey::of(&SessionId::from_bytes([0x99; 16])));
        let bytes = rkyv::to_bytes::<Error>(&subject).expect("archive");
        let back: EventSubject = rkyv::from_bytes::<EventSubject, Error>(&bytes).expect("reads");
        assert_eq!(back, subject);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_recorded_subject_read_from_json_archives_and_reads_back() {
        let id = SessionId::from_bytes([0xaa; 16]);
        let read: EventSubject =
            serde_json::from_str(&format!(r#"{{"Session":"{id}"}}"#)).expect("reads");
        let bytes = rkyv::to_bytes::<Error>(&read).expect("archive");
        assert_eq!(&bytes[..], &archived_recorded_subject(*id.as_bytes())[..]);
        let back: EventSubject = rkyv::from_bytes::<EventSubject, Error>(&bytes).expect("reads");
        assert_eq!(back, read);
    }

    /// The archived sizes the migration page states: the key variant's 32
    /// bytes behind a tag make the enum 36 bytes where it was 20, and an
    /// optional subject 40 where it was 24.
    #[test]
    fn the_archived_subject_is_36_bytes_and_an_optional_one_40() {
        assert_eq!(size_of::<ArchivedEventSubject>(), 36);
        assert_eq!(size_of::<rkyv::Archived<Option<EventSubject>>>(), 40);
    }
}
