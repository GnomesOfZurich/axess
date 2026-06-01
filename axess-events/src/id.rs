//! Typed identifiers for the event vocabulary.
//!
//! These newtypes are re-exported from
//! [`axess-identity`](https://docs.rs/axess-identity), the foundation
//! crate that owns the typed-identifier primitives shared between
//! axess-core and axess-events. Locating them in axess-identity
//! avoids parallel definitions and keeps both crates byte-equivalent
//! and type-identical at the language level. `axess_events::TenantId`
//! IS `axess_identity::TenantId`, not a sibling type.
//!
//! Each newtype wraps [`uuid::Uuid`] (16 bytes, `Copy`). Wire format
//! under serde is the standard hyphenated UUID string; under rkyv
//! it's the 16-byte body. See
//! [`axess_identity`](https://docs.rs/axess-identity) for the full
//! constructor surface (`new<R: SecureRng>`, `from_uuid`,
//! `from_namespaced_str`, `from_bytes`, `try_new`).

pub use axess_identity::{DeviceId, EventId, SessionId, TenantId, UserId};
