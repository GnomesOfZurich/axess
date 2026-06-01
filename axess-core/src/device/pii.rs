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
mod tests {
    use super::*;

    fn user(s: &str) -> UserId {
        axess_identity::testing::user(s)
    }

    fn tenant(s: &str) -> TenantId {
        axess_identity::testing::tenant(s)
    }

    /// Token wire format is `"pii:<uuid-hyphenated>"` and
    /// round-trips through `parse`. This is the documented canonical
    /// shape compatible with `gov-core::pii::PiiToken`; changing it is
    /// a wire-break.
    #[test]
    fn token_wire_format_is_pii_colon_uuid() {
        let uuid = Uuid::nil();
        let token = PiiToken::from_uuid(uuid);
        assert_eq!(token.as_str(), "pii:00000000-0000-0000-0000-000000000000");

        let parsed = PiiToken::parse(token.as_str()).expect("round-trip parse");
        assert_eq!(parsed, token);
    }

    /// `is_well_formed` rejects shapes that wouldn't round-trip
    /// through `new`. Stable rejection set so callers can use it as a
    /// pre-store validation gate.
    #[test]
    fn is_well_formed_rejects_malformed() {
        // Missing prefix.
        assert!(!PiiToken::is_well_formed(
            "00000000-0000-0000-0000-000000000000"
        ));
        // Wrong prefix.
        assert!(!PiiToken::is_well_formed(
            "pii_00000000-0000-0000-0000-000000000000"
        ));
        // Non-UUID body.
        assert!(!PiiToken::is_well_formed("pii:not-a-uuid"));
        // Empty.
        assert!(!PiiToken::is_well_formed(""));
        assert!(!PiiToken::is_well_formed("pii:"));
        // Right shape.
        assert!(PiiToken::is_well_formed(
            "pii:00000000-0000-0000-0000-000000000000"
        ));
    }

    /// `record` → `resolve` round-trips the value plaintext;
    /// the returned token is the same token now stored. Pins the
    /// Memory backend's basic contract.
    #[tokio::test]
    async fn record_then_resolve_round_trips_value() {
        let store = MemoryDevicePiiStore::new();
        let now = Utc::now();
        let token = store
            .record(
                &user("u1"),
                &tenant("t1"),
                DevicePiiCategory::DisplayName,
                "Alice's iPhone".to_string(),
                now,
            )
            .await
            .unwrap();
        assert!(PiiToken::is_well_formed(token.as_str()));
        let value = store.resolve(&token, &tenant("t1")).await.unwrap();
        assert_eq!(value.as_deref(), Some("Alice's iPhone"));
    }

    /// Structural tenant rail. A mapping recorded under tenant
    /// A is invisible to a resolve issued from tenant B, even when
    /// the caller has the right token. Same shape as missing.
    /// Without this rail, a multi-tenant deployment can leak PII via
    /// token-guessing across tenants.
    #[tokio::test]
    async fn resolve_refuses_cross_tenant_lookup() {
        let store = MemoryDevicePiiStore::new();
        let token = store
            .record(
                &user("u1"),
                &tenant("alpha"),
                DevicePiiCategory::IpAddress,
                "203.0.113.42".to_string(),
                Utc::now(),
            )
            .await
            .unwrap();

        // Same-tenant resolve hits.
        let same = store.resolve(&token, &tenant("alpha")).await.unwrap();
        assert_eq!(same.as_deref(), Some("203.0.113.42"));

        // Cross-tenant resolve returns None; same as a missing token.
        let cross = store.resolve(&token, &tenant("beta")).await.unwrap();
        assert!(
            cross.is_none(),
            "cross-tenant lookup must be invisible, not leak the value"
        );
    }

    /// `erase_subject` deletes every mapping for the
    /// `(subject, tenant)` pair, leaves other subjects' mappings
    /// alone, and returns the count erased. Subsequent `resolve` of
    /// an erased token returns `None` (forms the basis of the
    /// `RedactedResolver` post-erasure contract).
    #[tokio::test]
    async fn erase_subject_removes_only_target_subject_mappings() {
        let store = MemoryDevicePiiStore::new();
        let now = Utc::now();
        let t = tenant("t1");

        // Two mappings for the target user across two categories.
        let alice_dn = store
            .record(
                &user("alice"),
                &t,
                DevicePiiCategory::DisplayName,
                "Alice".into(),
                now,
            )
            .await
            .unwrap();
        let alice_ip = store
            .record(
                &user("alice"),
                &t,
                DevicePiiCategory::IpAddress,
                "203.0.113.1".into(),
                now,
            )
            .await
            .unwrap();
        // One mapping for a different user that must NOT be touched.
        let bob_dn = store
            .record(
                &user("bob"),
                &t,
                DevicePiiCategory::DisplayName,
                "Bob".into(),
                now,
            )
            .await
            .unwrap();

        let erased = store.erase_subject(&user("alice"), &t).await.unwrap();
        assert_eq!(erased, 2, "must erase exactly Alice's 2 rows");

        // Alice's tokens no longer resolve.
        assert!(store.resolve(&alice_dn, &t).await.unwrap().is_none());
        assert!(store.resolve(&alice_ip, &t).await.unwrap().is_none());

        // Bob's mapping survives; erasure is per-subject, not per-tenant.
        assert_eq!(
            store.resolve(&bob_dn, &t).await.unwrap().as_deref(),
            Some("Bob"),
        );
    }

    /// `erase_subject` is also tenant-scoped. Erasing a
    /// `(subject, tenantA)` pair must NOT touch a same-named subject
    /// in `tenantB`: different tenants are different data subjects
    /// from the controller's perspective.
    #[tokio::test]
    async fn erase_subject_is_tenant_scoped() {
        let store = MemoryDevicePiiStore::new();
        let alice_alpha = store
            .record(
                &user("alice"),
                &tenant("alpha"),
                DevicePiiCategory::DisplayName,
                "Alice@alpha".into(),
                Utc::now(),
            )
            .await
            .unwrap();
        let alice_beta = store
            .record(
                &user("alice"),
                &tenant("beta"),
                DevicePiiCategory::DisplayName,
                "Alice@beta".into(),
                Utc::now(),
            )
            .await
            .unwrap();

        let erased = store
            .erase_subject(&user("alice"), &tenant("alpha"))
            .await
            .unwrap();
        assert_eq!(erased, 1);

        assert!(
            store
                .resolve(&alice_alpha, &tenant("alpha"))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .resolve(&alice_beta, &tenant("beta"))
                .await
                .unwrap()
                .as_deref(),
            Some("Alice@beta"),
            "erasure in tenant alpha must not touch tenant beta"
        );
    }

    /// `list_for_subject` drives the Art 20 portability export.
    /// Returns every mapping for the `(subject, tenant)` pair, no
    /// others. Tenant-scoped (mirrors erase_subject's scoping).
    #[tokio::test]
    async fn list_for_subject_returns_all_mappings_in_tenant() {
        let store = MemoryDevicePiiStore::new();
        let t = tenant("t1");
        let now = Utc::now();
        store
            .record(
                &user("alice"),
                &t,
                DevicePiiCategory::DisplayName,
                "Alice".into(),
                now,
            )
            .await
            .unwrap();
        store
            .record(
                &user("alice"),
                &t,
                DevicePiiCategory::UserAgentString,
                "Mozilla/5.0".into(),
                now,
            )
            .await
            .unwrap();
        store
            .record(
                &user("bob"),
                &t,
                DevicePiiCategory::DisplayName,
                "Bob".into(),
                now,
            )
            .await
            .unwrap();

        let alice_rows = store.list_for_subject(&user("alice"), &t).await.unwrap();
        assert_eq!(
            alice_rows.len(),
            2,
            "portability export must include all of Alice's mappings"
        );
        assert!(
            alice_rows.iter().all(|m| m.subject_id == user("alice")),
            "list_for_subject must not leak other subjects' rows"
        );
    }

    /// The auto-impl of `DevicePiiResolver` for
    /// `DevicePiiStore` collapses missing mappings to the canonical
    /// `[redacted]` placeholder. Same shape regardless of whether the
    /// row was erased, never existed, or is cross-tenant.
    #[tokio::test]
    async fn resolver_returns_redacted_for_missing_token() {
        let store = MemoryDevicePiiStore::new();
        let bogus = PiiToken::new();
        let resolved = store
            .resolve_or_redacted(&bogus, &tenant("t1"))
            .await
            .unwrap();
        assert_eq!(resolved, REDACTED_PLACEHOLDER);
    }

    /// The auto-impl of `DevicePiiResolver` returns the real
    /// value when present. Pins that the redacted-on-missing
    /// behaviour is conditional, not unconditional.
    #[tokio::test]
    async fn resolver_returns_real_value_when_present() {
        let store = MemoryDevicePiiStore::new();
        let token = store
            .record(
                &user("u1"),
                &tenant("t1"),
                DevicePiiCategory::DisplayName,
                "Alice".into(),
                Utc::now(),
            )
            .await
            .unwrap();
        let resolved = store
            .resolve_or_redacted(&token, &tenant("t1"))
            .await
            .unwrap();
        assert_eq!(resolved, "Alice");
    }

    /// `RedactedResolver` always returns the placeholder,
    /// regardless of whether the token would resolve in some other
    /// store. Pins the post-erasure / fail-safe contract.
    #[tokio::test]
    async fn redacted_resolver_unconditionally_returns_placeholder() {
        let resolver = RedactedResolver;
        let token = PiiToken::new();
        let resolved = resolver
            .resolve_or_redacted(&token, &tenant("t1"))
            .await
            .unwrap();
        assert_eq!(resolved, REDACTED_PLACEHOLDER);
    }

    /// `DevicePiiCategory::as_str` wire strings are stable.
    /// Pinned for the same reason `AuthEventType` strings are pinned:
    /// SQL backends and SOC dashboards key off these exact strings.
    #[test]
    fn category_wire_strings_are_stable() {
        for (variant, expected) in [
            (DevicePiiCategory::DisplayName, "display_name"),
            (DevicePiiCategory::UserAgentString, "user_agent_string"),
            (DevicePiiCategory::AcceptLanguage, "accept_language"),
            (DevicePiiCategory::IpAddress, "ip_address"),
            (DevicePiiCategory::ScreenMetrics, "screen_metrics"),
            (DevicePiiCategory::Other, "other"),
        ] {
            assert_eq!(variant.as_str(), expected);
        }
    }

    #[test]
    fn pii_token_display_matches_as_str() {
        let token = PiiToken::new();
        assert_eq!(format!("{token}"), token.as_str());
    }

    #[tokio::test]
    async fn memory_store_len_and_is_empty_track_inserts() {
        let store = MemoryDevicePiiStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());

        let token = PiiToken::new();
        let mapping = DevicePiiMapping {
            token: token.clone(),
            subject_id: axess_identity::testing::user("u-pii"),
            tenant_id: axess_identity::testing::tenant("t-pii"),
            category: DevicePiiCategory::IpAddress,
            value: "1.2.3.4".to_string(),
            created_at: chrono::Utc::now(),
        };
        store.mappings.insert(token, mapping);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }
}
