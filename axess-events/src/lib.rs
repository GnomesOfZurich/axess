//! Shared event vocabulary for the axess workspace and platform domains.
//!
//! [`Event<P>`] is the cross-cutting envelope: id, time, tenant, kind,
//! subject, actor, trace context, status, body. The body is either a
//! clear typed payload `P` or an opaque [`EncryptedBlob`]; chosen by
//! the producer at emission time, transparent to subscribers without
//! the key.
//!
//! Each domain defines its own payload enum implementing
//! [`EventPayload`]; the envelope crate stays domain-agnostic.
//!
//! # Quick start
//!
//! ```
//! use axess_events::{Event, EventBody, EventId, EventPayload, EventStatus, KindTag};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
//! enum DemoPayload {
//!     Hello { who: String },
//! }
//!
//! impl EventPayload for DemoPayload {
//!     fn kind_tag(&self) -> KindTag {
//!         match self {
//!             DemoPayload::Hello { .. } => KindTag::from_static("demo.hello.v1"),
//!         }
//!     }
//!
//!     fn to_inner_json(&self) -> serde_json::Value {
//!         match self {
//!             DemoPayload::Hello { who } => serde_json::json!({ "who": who }),
//!         }
//!     }
//! }
//!
//! let payload = DemoPayload::Hello { who: "world".into() };
//! let event = Event::<DemoPayload> {
//!     id: EventId::NIL,
//!     envelope_version: Event::<DemoPayload>::ENVELOPE_VERSION,
//!     time_micros: 0,
//!     tenant_id: None,
//!     kind: payload.kind_tag(),
//!     subject: None,
//!     actor: None,
//!     trace_context: None,
//!     status: EventStatus::Info,
//!     body: EventBody::Clear(payload),
//! };
//! assert_eq!(event.kind.as_str(), "demo.hello.v1");
//! ```
//!
//! # Feature flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `serde` | yes | All envelope types implement `Serialize` / `Deserialize`. |
//! | `rkyv`  | no  | All envelope types implement rkyv `Archive` / `Serialize` / `Deserialize`. Required for org-internal binary streams (Iggy, replay archives). |
//! | `full`  | no  | Both `serde` and `rkyv`. |

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod encryption;
pub mod id;
pub mod kind;
pub mod sink;
pub mod status;
pub mod subject;
pub mod trace;

pub use encryption::{AeadAlgorithm, EncryptedBlob, KeyId};
pub use id::{DeviceId, EventId, SessionId, TenantId, UserId};
pub use kind::{EventPayload, KindTag};
pub use sink::{EventSink, LogAndSwallow, NoopEventSink, SinkError};
pub use status::EventStatus;
pub use subject::{EventSubject, EventSubjectRef};
pub use trace::TraceContext;

/// Cross-cutting event envelope. Domain-specific payload `P` lives in
/// the [`body`](Event::body) field, wrapped in [`EventBody`] to allow
/// either clear payloads or opaque encrypted bytes.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event<P>
where
    P: EventPayload,
{
    /// 16-byte ULID-shaped identifier. Sortable by time.
    pub id: EventId,
    /// Monotone version of the envelope schema. Bumps when fields are
    /// added or layout changes; subscribers reject envelopes with a
    /// version they don't recognise rather than mis-decode them.
    pub envelope_version: u8,
    /// Wall-clock instant the event was minted, expressed as
    /// microseconds since the Unix epoch (UTC). i64 covers ±292,000
    /// years from 1970, enough headroom for any audit horizon.
    /// Aligns with the workspace-wide epoch-microseconds convention
    /// (MiFID II nanosecond-precision regulation tolerates µs).
    pub time_micros: i64,
    /// Tenant scope. `None` only for system-level events that
    /// genuinely transcend tenants (operator account flows,
    /// cross-tenant admin work).
    pub tenant_id: Option<TenantId>,
    /// Wire-form kind discriminator. Lets brokers route without
    /// decoding the payload. Derived from
    /// [`EventPayload::kind_tag`] at construction time.
    pub kind: KindTag,
    /// "Who is this event *about*": the entity whose state changed.
    /// `None` for events with no specific subject.
    pub subject: Option<EventSubject>,
    /// "Who initiated this event": the principal who *did* the
    /// thing. Differs from `subject` for impersonation flows; equals
    /// the system principal for autonomous flows. `None` when
    /// unknown.
    pub actor: Option<EventSubject>,
    /// W3C trace context for cross-service correlation. `None` if no
    /// upstream context is in scope.
    pub trace_context: Option<TraceContext>,
    /// Coarse outcome bucket. Detail lives in the payload.
    pub status: EventStatus,
    /// Clear payload or opaque encrypted bytes.
    pub body: EventBody<P>,
}

impl<P: EventPayload> Event<P> {
    /// Current envelope schema version. Producers stamp this onto
    /// [`Event::envelope_version`]; subscribers compare on read.
    pub const ENVELOPE_VERSION: u8 = 1;
}

/// Either a clear typed payload or an opaque encrypted blob.
///
/// The kind tag on the envelope tells subscribers what type the
/// plaintext is supposed to be, regardless of whether the body is
/// `Clear` or `Encrypted` here. Subscribers without the decryption
/// key can still route on every other envelope field.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventBody<P>
where
    P: EventPayload,
{
    /// Decrypted, typed payload available in-process.
    Clear(P),
    /// Encrypted bytes. Decrypt to recover the typed payload.
    Encrypted(EncryptedBlob),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test payload for envelope round-trip exercises.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(
        feature = "rkyv",
        derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
    )]
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum TestPayload {
        LoginAttempt { user: UserId },
        DeviceFirstSeen { device: DeviceId },
    }

    impl EventPayload for TestPayload {
        fn kind_tag(&self) -> KindTag {
            match self {
                TestPayload::LoginAttempt { .. } => KindTag::from_static("test.login_attempt.v1"),
                TestPayload::DeviceFirstSeen { .. } => {
                    KindTag::from_static("test.device_first_seen.v1")
                }
            }
        }

        #[cfg(feature = "serde")]
        fn to_inner_json(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap_or_default()
        }
    }

    /// 2026-05-08T12:00:00Z in epoch microseconds.
    const SAMPLE_TIME_MICROS: i64 = 1_778_500_800_000_000;

    fn sample_event() -> Event<TestPayload> {
        let payload = TestPayload::LoginAttempt { user: UserId::NIL };
        Event {
            id: EventId::NIL,
            envelope_version: Event::<TestPayload>::ENVELOPE_VERSION,
            time_micros: SAMPLE_TIME_MICROS,
            tenant_id: None,
            kind: payload.kind_tag(),
            subject: Some(EventSubject::User(UserId::NIL)),
            actor: None,
            trace_context: None,
            status: EventStatus::Success,
            body: EventBody::Clear(payload),
        }
    }

    #[test]
    fn kind_tag_is_derived_from_payload() {
        let event = sample_event();
        assert_eq!(event.kind.as_str(), "test.login_attempt.v1");
    }

    #[test]
    fn envelope_version_is_one() {
        assert_eq!(Event::<TestPayload>::ENVELOPE_VERSION, 1);
    }

    #[test]
    fn event_body_clear_round_trip() {
        let event = sample_event();
        match event.body {
            EventBody::Clear(TestPayload::LoginAttempt { .. }) => {}
            _ => panic!("expected Clear(LoginAttempt)"),
        }
    }

    #[test]
    fn event_body_encrypted_carries_metadata() {
        let body: EventBody<TestPayload> = EventBody::Encrypted(EncryptedBlob {
            key_id: KeyId::from_static("kms.test.v1"),
            algorithm: AeadAlgorithm::Aes256Gcm,
            nonce: [0u8; 12],
            ciphertext: vec![1, 2, 3, 4, 5],
        });
        match body {
            EventBody::Encrypted(blob) => {
                assert_eq!(blob.key_id.as_str(), "kms.test.v1");
                assert_eq!(blob.algorithm, AeadAlgorithm::Aes256Gcm);
                assert_eq!(blob.ciphertext, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_round_trips_clear_event() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: Event<TestPayload> = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_round_trips_encrypted_event() {
        let mut event = sample_event();
        event.body = EventBody::Encrypted(EncryptedBlob {
            key_id: KeyId::from_static("kms.test.v1"),
            algorithm: AeadAlgorithm::ChaCha20Poly1305,
            nonce: [7u8; 12],
            ciphertext: vec![10, 20, 30],
        });
        let json = serde_json::to_string(&event).unwrap();
        let back: Event<TestPayload> = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[cfg(feature = "rkyv")]
    #[test]
    fn rkyv_round_trips_clear_event() {
        use rkyv::{from_bytes, rancor::Error, to_bytes};
        let event = sample_event();
        let bytes = to_bytes::<Error>(&event).unwrap();
        let back: Event<TestPayload> = from_bytes::<Event<TestPayload>, Error>(&bytes).unwrap();
        assert_eq!(event, back);
    }

    /// Pin: the no-op sink accepts every batch.
    #[tokio::test]
    async fn noop_sink_accepts_every_batch() {
        let sink: NoopEventSink<TestPayload> = NoopEventSink::new();
        let events = vec![sample_event(), sample_event()];
        sink.emit(&events).await.unwrap();
    }

    /// Pin: LogAndSwallow turns sink errors into Ok and logs.
    #[tokio::test]
    async fn log_and_swallow_swallows_errors() {
        struct Failing;
        impl EventSink<TestPayload> for Failing {
            async fn emit(&self, events: &[Event<TestPayload>]) -> Result<(), SinkError> {
                Err(SinkError::Unavailable(format!(
                    "forced (rejected batch of {})",
                    events.len()
                )))
            }
        }

        let sink = LogAndSwallow(Failing);
        let events = vec![sample_event()];
        // Returns Ok despite the inner Err.
        sink.emit(&events).await.unwrap();
    }
}
