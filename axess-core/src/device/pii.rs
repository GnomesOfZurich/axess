//! PII tokenisation + GDPR Art 17 erasure for the device subsystem.
//!
//! [`Device`](super::Device) rows are deliberately PII-free: identifying
//! metadata (display name, last-known UA / IP / accept-language / screen
//! metrics) lives in a separate `device_pii_mappings` table keyed by
//! [`PiiToken`]. Deleting a mapping = crypto-shredding for that data
//! subject without breaking the audit trail (audit-event rows reference
//! `device_id`, which carries no PII; resolving the token after erasure
//! returns a redacted placeholder).
//!
//! This module implements the **token-and-mapping** pattern from the
//! canonical project shape (`gov-core::pii`); `PiiToken` deliberately
//! uses the `"pii:<uuid>"` wire format so a future promotion of pii
//! primitives into a shared crate is mechanical.
//!
//! See [`docs/identity/device.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/identity/device.md)
//! §5 for the full design rationale (lawful basis, right-to-portability,
//! storage limitation), and [`docs/production/audit-events.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/production/audit-events.md)
//! for how the `Device*` events interact with erasure.
//!
//! # What this module does
//!
//! - `PiiToken`: opaque newtype over the canonical `"pii:<uuid>"` form.
//! - `DevicePiiCategory`: typed bucket for the kind of value
//!   (`DisplayName`, `UserAgentString`, `IpAddress`, …) so backends can
//!   apply category-specific retention or redaction.
//! - `DevicePiiMapping`: one row per `(token, subject_id, tenant_id,
//!   category)` quadruple. The plaintext `value` lives here.
//! - `DevicePiiStore`: async persistence trait. Production backends
//!   encrypt `value` envelope-style internally; the trait surface stays
//!   plaintext so callers don't have to thread key material through.
//! - `MemoryDevicePiiStore`: in-memory implementation for DST and
//!   single-node examples.
//! - `DevicePiiResolver`: lighter-weight read-only surface (just
//!   `resolve`) for code paths that only need to render values
//!   (audit-display, portability export). Auto-implemented for any
//!   `DevicePiiStore`.
//! - `RedactedResolver`: degenerate resolver that always returns
//!   `"[redacted]"`. Use after a subject has been erased, or in test
//!   fixtures where the actual values are not under test.
//!
//! # What this module does NOT do
//!
//! - **Envelope encryption.** AES-GCM encryption of `value` lives in the
//!   SQL/Valkey backends, behind the trait. The trait
//!   itself is encryption-agnostic.
//! - **`Device` struct extension.** The doc-level §4.1 sketch carries
//!   `display_name_token: PiiToken` and `fingerprint_token: PiiToken`
//!   on the [`Device`](super::Device) row. The current implementation
//!   keeps those out and resolves on-demand by `(subject_id, category)`
//!   lookup; if/when a future iteration wants direct token columns on
//!   `Device`, the mapping shape here already accommodates it.
//! - **Cascade-on-DeviceStore-revoke.** Erasure is an explicit
//!   data-subject-rights call, not an automatic side-effect of device
//!   revocation. A revoked device row with un-erased PII is the
//!   deliberate state during the 30-day Art 5(1)(e) grace window
//!   (see [`docs/identity/device.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/identity/device.md) §5.7).

use crate::authn::ids::{TenantId, UserId};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ── PiiToken ─────────────────────────────────────────────────────────────────

/// Opaque token referencing a [`DevicePiiMapping`] row.
///
/// Wire format: `"pii:<uuid>"`. The `pii:` prefix is the canonical
/// project shape (matches `gov-core::pii::PiiToken`). The UUID half
/// is a fresh v4 minted at [`PiiToken::new`] time; tokens are
/// unguessable and uncorrelated across mappings (two values stored
/// for the same subject do not produce related tokens).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PiiToken(Arc<str>);

impl PiiToken {
    /// Mint a fresh token with a v4 UUID.
    ///
    /// The UUID is sourced from [`Uuid::new_v4`] (OS-randomness). Tests
    /// that need deterministic tokens should construct via
    /// [`PiiToken::from_uuid`] with a [`MockRng`](crate::testing::mock_random::MockRng)-derived value.
    pub fn new() -> Self {
        Self::from_uuid(Uuid::new_v4())
    }

    /// Construct from an explicit UUID. Use from a DST harness that
    /// drives the value via an injected RNG.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(Arc::from(format!("pii:{}", uuid.as_hyphenated())))
    }

    /// Return the wire string (`"pii:<uuid>"`). Stable across releases.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return `true` when `s` is a syntactically well-formed `PiiToken`
    /// wire string. Use to reject an inbound value before constructing
    /// the type. Does NOT validate that the token resolves; that's a
    /// store-side concern.
    pub fn is_well_formed(s: &str) -> bool {
        s.strip_prefix("pii:")
            .and_then(|rest| Uuid::parse_str(rest).ok())
            .is_some()
    }

    /// Parse a wire string into a [`PiiToken`]. Returns `None` for any
    /// shape that wouldn't round-trip through [`Self::new`] (missing
    /// `pii:` prefix, non-UUID body).
    pub fn parse(s: &str) -> Option<Self> {
        if Self::is_well_formed(s) {
            Some(Self(Arc::from(s)))
        } else {
            None
        }
    }
}

impl Default for PiiToken {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PiiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── DevicePiiCategory ────────────────────────────────────────────────────────

/// Typed bucket for what a [`DevicePiiMapping`] row holds.
///
/// Backends use the category for retention scheduling (e.g. demote
/// `IpAddress` after 24h on a privacy-preserving tenant) and for
/// category-specific redaction shapes (e.g. truncate IPs to /24).
/// `Other` is the escape hatch for application-specific PII the
/// library doesn't need to know the meaning of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DevicePiiCategory {
    /// User-editable display name for the device ("Alice's iPhone").
    DisplayName,
    /// `User-Agent` header value at last sighting.
    UserAgentString,
    /// `Accept-Language` header value at last sighting.
    AcceptLanguage,
    /// Last-known IP address (full string, including any `:port`).
    IpAddress,
    /// Screen metrics (size / DPR / colorDepth) used as a fingerprint
    /// input. Stringified form is application-defined.
    ScreenMetrics,
    /// Application-specific PII the library doesn't know the meaning of.
    Other,
}

impl DevicePiiCategory {
    /// Stable string form. Used by SQL backends as the `category` column
    /// value and by SOC dashboards to filter by category. Wire-stable
    /// across releases.
    pub fn as_str(&self) -> &'static str {
        match self {
            DevicePiiCategory::DisplayName => "display_name",
            DevicePiiCategory::UserAgentString => "user_agent_string",
            DevicePiiCategory::AcceptLanguage => "accept_language",
            DevicePiiCategory::IpAddress => "ip_address",
            DevicePiiCategory::ScreenMetrics => "screen_metrics",
            DevicePiiCategory::Other => "other",
        }
    }
}

// ── DevicePiiMapping ─────────────────────────────────────────────────────────

/// One mapping row: token → plaintext value, scoped to a `(tenant,
/// subject)` for cascade-erasure on Art 17 / user-delete.
///
/// Backends MAY envelope-encrypt `value` at rest (recommended for
/// production; see the SQL/Valkey impls). The trait surface is always
/// plaintext: callers don't need to know whether the backend
/// encrypts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePiiMapping {
    /// Opaque token. Primary key.
    pub token: PiiToken,
    /// Subject the value is about. Drives [`DevicePiiStore::erase_subject`].
    pub subject_id: UserId,
    /// Tenant this mapping is scoped to. Cross-tenant lookup is forbidden:
    /// resolving a token from tenant A while the mapping is in tenant B
    /// returns the redacted placeholder, not the value.
    pub tenant_id: TenantId,
    /// What the value represents. See [`DevicePiiCategory`].
    pub category: DevicePiiCategory,
    /// Plaintext value at the trait surface. Backends MAY persist a
    /// ciphertext form internally.
    pub value: String,
    /// Wall-clock instant the mapping was first recorded. Drives the
    /// per-category retention sweep when implemented.
    pub created_at: DateTime<Utc>,
}

// ── DevicePiiStore trait ─────────────────────────────────────────────────────

/// Async persistence trait for device PII mappings.
///
/// Implementors:
/// - `MemoryDevicePiiStore`: single-process / DST.
/// - SQL / Valkey impls carry envelope encryption inside the impl.
pub trait DevicePiiStore: Send + Sync {
    /// Backend error type. `Infallible` for the in-memory impl;
    /// concrete `*StoreError` for SQL / Valkey.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Record a new mapping. Returns the freshly-minted token.
    ///
    /// Backends are responsible for ensuring token uniqueness; the
    /// in-memory impl mints a v4 UUID per call, so collision is
    /// cryptographically negligible.
    fn record(
        &self,
        subject_id: &UserId,
        tenant_id: &TenantId,
        category: DevicePiiCategory,
        value: String,
        now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<PiiToken, Self::Error>> + Send;

    /// Resolve a token to its plaintext value. Returns `Ok(None)` when
    /// the mapping is absent (erased, never existed, cross-tenant
    /// lookup), distinct from `Err(_)` which is reserved for backend
    /// outages.
    ///
    /// `expected_tenant` is enforced as a structural rail: a mapping
    /// stored under tenant A is invisible to a resolve from tenant B,
    /// even if the token guess hits. The default impl in [`MemoryDevicePiiStore`]
    /// honours this; SQL impls MUST replicate it via `WHERE tenant_id = ?`.
    fn resolve(
        &self,
        token: &PiiToken,
        expected_tenant: &TenantId,
    ) -> impl std::future::Future<Output = Result<Option<String>, Self::Error>> + Send;

    /// Delete every mapping for `subject_id` in `tenant_id`. The Art 17
    /// "right to erasure" primitive: applications call this from
    /// their data-subject-rights workflow.
    ///
    /// Returns the count of mappings actually erased so the caller can
    /// audit (e.g. via `DevicePurged Success` events with `error =
    /// "art17_erasure"`).
    fn erase_subject(
        &self,
        subject_id: &UserId,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;

    /// List all mappings for `subject_id` in `tenant_id`. Drives the
    /// Art 20 "right to portability" export.
    fn list_for_subject(
        &self,
        subject_id: &UserId,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<Vec<DevicePiiMapping>, Self::Error>> + Send;
}

// ── DevicePiiResolver trait ──────────────────────────────────────────────────

/// Read-only resolver surface. Use from code paths that render values
/// (audit-display, portability export, debug logs) and don't need
/// the full [`DevicePiiStore`] write surface.
///
/// Auto-implemented for any [`DevicePiiStore`] (the resolver call
/// delegates to the store's `resolve`). Use [`RedactedResolver`] for
/// post-erasure paths or test fixtures.
pub trait DevicePiiResolver: Send + Sync {
    /// Resolver error type: typically the underlying store's error,
    /// or [`std::convert::Infallible`] for the redacted resolver.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolve a token. Returns `"[redacted]"` (the canonical
    /// placeholder) when the mapping is absent: same shape regardless
    /// of whether the row was erased, never existed, or is in a
    /// different tenant. Callers that need to distinguish those cases
    /// should reach for the underlying [`DevicePiiStore::resolve`].
    fn resolve_or_redacted(
        &self,
        token: &PiiToken,
        expected_tenant: &TenantId,
    ) -> impl std::future::Future<Output = Result<String, Self::Error>> + Send;
}

/// Canonical placeholder returned by [`DevicePiiResolver`] when a
/// mapping is absent. Stable across releases.
pub const REDACTED_PLACEHOLDER: &str = "[redacted]";

// ── MemoryDevicePiiStore ─────────────────────────────────────────────────────

/// Infallible in-memory [`DevicePiiStore`]. Backed by a [`DashMap`]
/// keyed on the token. **For tests and single-node examples only.**
#[derive(Debug, Clone, Default)]
pub struct MemoryDevicePiiStore {
    mappings: Arc<DashMap<PiiToken, DevicePiiMapping>>,
}

impl MemoryDevicePiiStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of mappings currently stored. Useful in tests asserting
    /// erasure counts.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// `true` when no mappings are stored.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

/// Infallible error for the in-memory store. Aliased to
/// [`std::convert::Infallible`] so `?`-propagation and exhaustive
/// matches behave the canonical way (matches `MemoryRegistryError`
/// and `MemoryDeviceStoreError` shape).
pub type MemoryDevicePiiStoreError = std::convert::Infallible;

impl DevicePiiStore for MemoryDevicePiiStore {
    type Error = MemoryDevicePiiStoreError;

    async fn record(
        &self,
        subject_id: &UserId,
        tenant_id: &TenantId,
        category: DevicePiiCategory,
        value: String,
        now: DateTime<Utc>,
    ) -> Result<PiiToken, Self::Error> {
        let token = PiiToken::new();
        let mapping = DevicePiiMapping {
            token: token.clone(),
            subject_id: *subject_id,
            tenant_id: *tenant_id,
            category,
            value,
            created_at: now,
        };
        self.mappings.insert(token.clone(), mapping);
        Ok(token)
    }

    async fn resolve(
        &self,
        token: &PiiToken,
        expected_tenant: &TenantId,
    ) -> Result<Option<String>, Self::Error> {
        // Tenant rail: a mapping stored under tenant A is invisible to
        // tenant B even if the token guess hits; same shape as
        // missing. Never expose cross-tenant data through resolve.
        Ok(self
            .mappings
            .get(token)
            .filter(|m| &m.tenant_id == expected_tenant)
            .map(|m| m.value.clone()))
    }

    async fn erase_subject(
        &self,
        subject_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<u64, Self::Error> {
        let mut erased = 0u64;
        // Collect-then-remove avoids holding a DashMap iterator across
        // mutations. The collected key set is small (bounded by the
        // subject's mapping count, typically <100).
        let to_remove: Vec<PiiToken> = self
            .mappings
            .iter()
            .filter(|m| &m.subject_id == subject_id && &m.tenant_id == tenant_id)
            .map(|m| m.key().clone())
            .collect();
        for key in to_remove {
            if self.mappings.remove(&key).is_some() {
                erased += 1;
            }
        }
        Ok(erased)
    }

    async fn list_for_subject(
        &self,
        subject_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<DevicePiiMapping>, Self::Error> {
        Ok(self
            .mappings
            .iter()
            .filter(|m| &m.subject_id == subject_id && &m.tenant_id == tenant_id)
            .map(|m| m.value().clone())
            .collect())
    }
}

// Auto-implement DevicePiiResolver for any DevicePiiStore.
impl<S: DevicePiiStore> DevicePiiResolver for S {
    type Error = <S as DevicePiiStore>::Error;

    async fn resolve_or_redacted(
        &self,
        token: &PiiToken,
        expected_tenant: &TenantId,
    ) -> Result<String, Self::Error> {
        Ok(self
            .resolve(token, expected_tenant)
            .await?
            .unwrap_or_else(|| REDACTED_PLACEHOLDER.to_string()))
    }
}

// ── RedactedResolver ─────────────────────────────────────────────────────────

/// Degenerate [`DevicePiiResolver`] that always returns
/// [`REDACTED_PLACEHOLDER`].
///
/// Use:
/// - In an audit-display path AFTER a subject's mappings have been
///   erased, so historical audit rows render `"[redacted]"` for the
///   tokens they captured.
/// - In test fixtures where the actual values are not under test and
///   constructing a real store would be incidental scaffolding.
/// - As a fail-safe wrapper for code that has been GDPR-audited to
///   "must not reach a real store" (e.g. anonymous-mode rendering).
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactedResolver;

impl DevicePiiResolver for RedactedResolver {
    type Error = std::convert::Infallible;

    async fn resolve_or_redacted(
        &self,
        token: &PiiToken,
        expected_tenant: &TenantId,
    ) -> Result<String, Self::Error> {
        tracing::trace!(
            target: "axess::device::pii",
            ?token,
            %expected_tenant,
            "RedactedResolver: returning placeholder regardless of token",
        );
        Ok(REDACTED_PLACEHOLDER.to_string())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
