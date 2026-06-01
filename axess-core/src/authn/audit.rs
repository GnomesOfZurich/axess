//! Audit pipeline: downstream of `AuthEvent` emission.
//!
//! axess emits a regulatory [`AuthEvent`](super::event::AuthEvent) for
//! every login attempt, factor verification, session creation, and
//! revocation. This module groups the two paths that consume those
//! events after emission:
//!
//! - `archive`: hot/cold retention. Adopters move aged `authn_hist`
//!   rows to long-term cold storage (filesystem JSONL, S3 + Object
//!   Lock, WORM appliance, …) via the [`AuditArchiver`](archive::AuditArchiver)
//!   trait and the optional [`AuditRetentionLoop`](archive::AuditRetentionLoop)
//!   helper. Schedule is adopter-owned; axess defines the contract.
//! - `analytics`: denormalised real-time fanout. The
//!   [`AuthnAnalyticsSink`](analytics::AuthnAnalyticsSink) trait carries
//!   a [`RichAuthnEvent`](analytics::RichAuthnEvent) (regulatory core +
//!   adopter enrichment: geo, UA, device trust) to whatever streaming
//!   pipeline the adopter wires (typical: rkyv → Apache Iggy →
//!   ClickHouse / DuckDB / Snowflake).
//!
//! The two paths are orthogonal; adopters typically wire both: the
//! archive path is daily/hourly batch for regulatory durability; the
//! analytics path is real-time-ish for SOC dashboards and fraud
//! investigation.

pub mod analytics;
pub mod archive;
