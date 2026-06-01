//! Denormalised authentication telemetry for operational analytics.
//!
//! axess's regulatory audit path is [`AuthEvent`] →
//! [`IdentityAuthnLog::record_event`](crate::authn::store::IdentityAuthnLog::record_event):
//! every login attempt, factor verification, session creation, and
//! revocation event lands in the adopter's `authn_hist` table.
//! That table answers regulator questions ("did this user authenticate
//! on date X?") but is wrong-shaped for SOC dashboards, fraud
//! investigation, or product analytics: those want denormalised,
//! join-free records they can stream into a columnar store (DuckDB,
//! ClickHouse, Snowflake) and aggregate cheaply.
//!
//! This module defines the **shape** of that analytics stream so
//! multiple adopters can share downstream consumers. axess does not
//! ship a concrete sink; adopters wire their own pipeline (typical:
//! rkyv-serialise → Iggy / Kafka → columnar store).
//!
//! # Why not extend `AuthEvent`?
//!
//! `AuthEvent` is the regulatory record. Adding analytics fields to it
//! would either bloat every audit row (extra storage) or make some
//! fields silently optional (regulator can't tell whether the field
//! was missing or unrecorded: a finding waiting to happen).
//!
//! `RichAuthnEvent` carries `event: AuthEvent` as its core plus
//! adopter-supplied enrichment that doesn't survive in the audit
//! table. Adopters who enable the analytics path get the rich record;
//! adopters who don't pay nothing.
//!
//! # Hot path
//!
//! Sinks are called fire-and-forget: the auth hot path MUST NOT
//! block on analytics writes. Sinks that need durability should
//! buffer and flush asynchronously, accepting the trade-off that a
//! crash between event emission and flush loses analytics data (but
//! never the regulatory `AuthEvent`, which is on a separate
//! synchronous path).

use crate::authn::event::AuthEvent;
#[cfg(feature = "device")]
use crate::device::types::DeviceTrustLevel;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ── UserAgentSummary ─────────────────────────────────────────────────────────

/// Parsed user-agent fields useful for analytics. axess does not run a
/// UA parser; adopters populate this from their own parsing path
/// (e.g. the `uaparser` crate fed from a `User-Agent` header captured
/// upstream of the auth flow).
///
/// All fields are optional because UA strings vary in completeness and
/// adopters may choose to parse only the subset they need (bot
/// detection alone is a common case).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct UserAgentSummary {
    /// Browser family: `"Chrome"`, `"Safari"`, `"Firefox"`, …
    pub browser_family: Option<String>,
    /// Browser version, free-form: `"139.0.7233"`, `"17.6"`, …
    pub browser_version: Option<String>,
    /// Operating-system family: `"macOS"`, `"Windows"`, `"iOS"`, …
    pub os_family: Option<String>,
    /// Operating-system version, free-form.
    pub os_version: Option<String>,
    /// Adopter's bot detection result. axess has no opinion on what
    /// counts as a bot; leave `false` if you don't run a detector.
    pub is_bot: bool,
}

// ── RichAuthnEvent ───────────────────────────────────────────────────────────

/// Denormalised authentication event for the analytics stream.
///
/// Combines the regulatory [`AuthEvent`] (always present) with optional
/// enrichment fields. Adopters construct this from the `AuthEvent`
/// their `IdentityAuthnLog::record_event` impl receives plus whatever
/// context they have available (GeoIP lookup, UA parser, device
/// trust resolution, …) and hand it to the configured
/// [`AuthnAnalyticsSink`].
///
/// # rkyv compatibility
///
/// All fields are rkyv-derivable under the `rkyv` feature. Adopters
/// streaming to Apache Iggy / Kafka / similar can serialise with
/// `rkyv::to_bytes::<_, 1024>(&event)` and consume zero-copy on the
/// downstream side. The schema is intentionally stable: adding new
/// fields is a non-breaking change as long as they are `Option<T>` or
/// have a `Default`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct RichAuthnEvent {
    /// The regulatory core: the same `AuthEvent` that gets persisted
    /// to the adopter's `authn_hist` table via
    /// [`IdentityAuthnLog::record_event`](crate::authn::store::IdentityAuthnLog::record_event).
    pub event: AuthEvent,

    /// Device trust level resolved at event time. `None` when the
    /// `device` feature is off, the event fires pre-device-resolution
    /// (login attempt), or the adopter doesn't run the device
    /// subsystem.
    #[cfg(feature = "device")]
    pub device_trust_level: Option<DeviceTrustLevel>,

    /// ISO 3166-1 alpha-2 country code inferred from the client IP.
    /// Adopter resolves this via their own GeoIP path (MaxMind,
    /// IPinfo, …) before constructing the rich event. axess does not
    /// pull a GeoIP database into the library.
    pub geo_country: Option<String>,

    /// Autonomous system number of the client's network. Same
    /// adopter-supplied path as `geo_country`.
    pub geo_asn: Option<u32>,

    /// Parsed user-agent summary. See [`UserAgentSummary`].
    pub user_agent_summary: Option<UserAgentSummary>,

    /// Free-form adopter-controlled tags. Keep keys short and the
    /// vocabulary stable: these often end up as column headers in
    /// the analytics store. Typical: `"channel" => "mobile"`,
    /// `"experiment" => "step-up-v2"`.
    pub tags: Vec<(String, String)>,
}

impl RichAuthnEvent {
    /// Construct an enrichment-free rich event from a regulatory
    /// `AuthEvent`. Use the `.with_*` fluent helpers to populate
    /// enrichment fields before handing to the sink.
    pub fn from_event(event: AuthEvent) -> Self {
        Self {
            event,
            #[cfg(feature = "device")]
            device_trust_level: None,
            geo_country: None,
            geo_asn: None,
            user_agent_summary: None,
            tags: Vec::new(),
        }
    }

    /// Set the resolved device trust level. Requires the `device` feature.
    #[cfg(feature = "device")]
    pub fn with_device_trust_level(mut self, level: DeviceTrustLevel) -> Self {
        self.device_trust_level = Some(level);
        self
    }

    /// Set the ISO-3166 alpha-2 country code.
    pub fn with_geo_country(mut self, country: impl Into<String>) -> Self {
        self.geo_country = Some(country.into());
        self
    }

    /// Set the network ASN.
    pub fn with_geo_asn(mut self, asn: u32) -> Self {
        self.geo_asn = Some(asn);
        self
    }

    /// Set the parsed UA summary.
    pub fn with_user_agent_summary(mut self, ua: UserAgentSummary) -> Self {
        self.user_agent_summary = Some(ua);
        self
    }

    /// Append a free-form tag.
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.push((key.into(), value.into()));
        self
    }
}

// ── AuthnAnalyticsSink ───────────────────────────────────────────────────────

/// Sink for [`RichAuthnEvent`] records. Adopters implement this against
/// their analytics infrastructure; typical patterns include
/// rkyv-serialising to Apache Iggy or Kafka, JSONL-appending to a
/// rotating filesystem path, or HTTP-posting to a managed analytics
/// service.
///
/// # Hot path
///
/// `record_rich` is called fire-and-forget from the auth path. The
/// returned future is spawned without `.await` so a slow sink never
/// stalls authentication. Sinks that need durability should buffer
/// internally and flush asynchronously; an unbounded channel with a
/// dedicated drain task is the usual shape.
///
/// # Error handling
///
/// The returned `Result` is logged inside axess but does not propagate
/// to the caller. A failing sink does not fail authentication; the
/// regulatory record on [`IdentityAuthnLog`](crate::authn::store::IdentityAuthnLog)
/// is the source of truth, and the analytics path is best-effort by
/// design.
pub trait AuthnAnalyticsSink: Send + Sync + 'static {
    /// Sink-specific error type. Most implementations will wrap an I/O
    /// error, a channel-send error, or a serialisation error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sink a denormalised analytics event.
    ///
    /// The implementation MUST NOT block the auth path. axess spawns
    /// this call without awaiting, so a sink that takes seconds to
    /// flush will not slow login; but the event is at risk of being
    /// dropped on process shutdown if the sink hasn't drained its
    /// buffer.
    fn record_rich(
        &self,
        event: RichAuthnEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Human-readable name for log lines + dashboards.
    fn name(&self) -> &'static str;
}

/// No-op analytics sink. Returns `Ok(())` without persisting anything.
///
/// Used as the default when no analytics infrastructure is wired:
/// makes [`AuthnService`](crate::authn::service::AuthnService) type
/// signatures stable across "no analytics" and "with analytics"
/// deployments without requiring a generic bound every adopter must
/// satisfy.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuthnAnalyticsSink;

impl AuthnAnalyticsSink for NoopAuthnAnalyticsSink {
    type Error = std::convert::Infallible;

    async fn record_rich(&self, event: RichAuthnEvent) -> Result<(), Self::Error> {
        tracing::trace!(
            target: "axess::audit::analytics",
            event_type = ?event.event.event_type,
            event_time = event.event.event_time,
            "NoopAuthnAnalyticsSink: rich event discarded",
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

// ── AuditLogWithAnalytics ──────────────────────────────────────────────────────────────

/// Decorator that splits the regulatory audit path so every
/// [`record_event`](crate::authn::store::IdentityAuthnLog::record_event) call
/// also reaches an [`AuthnAnalyticsSink`].
///
/// Wraps a hot [`IdentityAuthnLog`](crate::authn::store::IdentityAuthnLog) impl
/// plus an analytics sink plus an enricher closure that turns a bare
/// [`AuthEvent`] into a [`RichAuthnEvent`] using whatever adopter
/// context is available (GeoIP, UA parser, device resolver, …).
///
/// The hot path stays synchronous: the inner log's `record_event` is
/// awaited so a regulatory write failure surfaces to the caller. The
/// analytics path runs in a `tokio::spawn` task so an enricher panic
/// or a slow sink does not block authentication.
///
/// ```rust,ignore
/// use axess_core::authn::audit::analytics::{AuditLogWithAnalytics, RichAuthnEvent};
///
/// let log = AuditLogWithAnalytics::new(
///     postgres_backend,
///     iggy_sink,
///     |event| async move {
///         let ua = parse_ua(event.user_agent.as_deref()).await;
///         let geo = geoip_lookup(event.ip_address.as_deref()).await;
///         RichAuthnEvent::from_event(event)
///             .with_user_agent_summary(ua)
///             .with_geo_country(geo.country)
///             .with_geo_asn(geo.asn)
///     },
/// );
/// ```
pub struct AuditLogWithAnalytics<L, S, E> {
    inner: L,
    sink: std::sync::Arc<S>,
    enricher: std::sync::Arc<E>,
}

impl<L, S, E> AuditLogWithAnalytics<L, S, E>
where
    L: crate::authn::store::IdentityAuthnLog,
    S: AuthnAnalyticsSink,
    E: Send + Sync + 'static,
{
    /// Construct a tee decorator. The `enricher` closure receives the
    /// regulatory `AuthEvent` and returns a future yielding the
    /// denormalised `RichAuthnEvent`: adopters do GeoIP / UA parsing
    /// / device-trust resolution inside this closure.
    pub fn new(inner: L, sink: S, enricher: E) -> Self {
        Self {
            inner,
            sink: std::sync::Arc::new(sink),
            enricher: std::sync::Arc::new(enricher),
        }
    }

    /// Borrow the inner regulatory log.
    pub fn inner(&self) -> &L {
        &self.inner
    }

    /// Shared handle to the analytics sink: useful for tests or
    /// dashboards that want to read sink-side state directly.
    pub fn sink(&self) -> &std::sync::Arc<S> {
        &self.sink
    }
}

// `IdentityAuthnLog` and `IdentityLookup` are blanket-forwarded to the
// inner log. The analytics-side spawn lives in `record_event` only;
// lookups and admin-side calls are unaffected.
impl<L, S, E, EFut> crate::authn::store::IdentityLookup for AuditLogWithAnalytics<L, S, E>
where
    L: crate::authn::store::IdentityAuthnLog,
    S: AuthnAnalyticsSink,
    E: Fn(AuthEvent) -> EFut + Send + Sync + 'static,
    EFut: std::future::Future<Output = RichAuthnEvent> + Send + 'static,
{
    type Error = <L as crate::authn::store::IdentityLookup>::Error;

    fn find_user(
        &self,
        identifier: &str,
        tenant_id: &crate::authn::ids::TenantId,
    ) -> impl std::future::Future<Output = Result<Option<crate::authn::types::User>, Self::Error>> + Send
    {
        self.inner.find_user(identifier, tenant_id)
    }

    fn get_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> impl std::future::Future<Output = Result<Option<crate::authn::types::User>, Self::Error>> + Send
    {
        self.inner.get_user(user_id)
    }

    fn find_tenant(
        &self,
        identifier: &str,
    ) -> impl std::future::Future<Output = Result<Option<crate::authn::types::Tenant>, Self::Error>> + Send
    {
        self.inner.find_tenant(identifier)
    }

    fn default_tenant(
        &self,
    ) -> impl std::future::Future<Output = Result<crate::authn::types::Tenant, Self::Error>> + Send
    {
        self.inner.default_tenant()
    }

    fn account_status(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> impl std::future::Future<Output = Result<crate::authn::types::EntityState, Self::Error>> + Send
    {
        self.inner.account_status(user_id)
    }

    fn lockout_policy_for_tenant(
        &self,
        tenant_id: &crate::authn::ids::TenantId,
    ) -> crate::authn::types::LockoutPolicy {
        self.inner.lockout_policy_for_tenant(tenant_id)
    }
}

impl<L, S, E, EFut> crate::authn::store::IdentityAuthnLog for AuditLogWithAnalytics<L, S, E>
where
    L: crate::authn::store::IdentityAuthnLog,
    S: AuthnAnalyticsSink,
    E: Fn(AuthEvent) -> EFut + Send + Sync + 'static,
    EFut: std::future::Future<Output = RichAuthnEvent> + Send + 'static,
{
    fn record_event(
        &self,
        event: AuthEvent,
    ) -> impl std::future::Future<
        Output = Result<(), <L as crate::authn::store::IdentityLookup>::Error>,
    > + Send {
        // Clone for the analytics path; the regulatory path takes
        // ownership for `inner.record_event`.
        let event_for_analytics = event.clone();
        let sink = std::sync::Arc::clone(&self.sink);
        let enricher = std::sync::Arc::clone(&self.enricher);

        tokio::spawn(async move {
            let rich = enricher(event_for_analytics).await;
            let sink_name = sink.name();
            if let Err(e) = sink.record_rich(rich).await {
                tracing::warn!(
                    sink = %sink_name,
                    error = %e,
                    "authn analytics sink rejected event; regulatory record is unaffected",
                );
            }
        });

        // Regulatory write is awaited synchronously; its failure
        // surfaces to the caller. Analytics failure does not.
        self.inner.record_event(event)
    }

    fn record_failed_attempt(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> impl std::future::Future<
        Output = Result<u32, <L as crate::authn::store::IdentityLookup>::Error>,
    > + Send {
        self.inner.record_failed_attempt(user_id)
    }

    fn reset_failed_attempts(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> impl std::future::Future<
        Output = Result<(), <L as crate::authn::store::IdentityLookup>::Error>,
    > + Send {
        self.inner.reset_failed_attempts(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_sink_accepts_any_event() {
        let sink = NoopAuthnAnalyticsSink;
        let event = RichAuthnEvent::from_event(make_test_event());
        assert!(sink.record_rich(event).await.is_ok());
        assert_eq!(sink.name(), "noop");
    }

    #[test]
    fn rich_event_builder_chain_populates_optionals() {
        let event = make_test_event();
        let rich = RichAuthnEvent::from_event(event)
            .with_geo_country("CH")
            .with_geo_asn(13335)
            .with_tag("channel", "mobile");

        assert_eq!(rich.geo_country.as_deref(), Some("CH"));
        assert_eq!(rich.geo_asn, Some(13335));
        assert_eq!(rich.tags.len(), 1);
        assert_eq!(rich.tags[0], ("channel".to_string(), "mobile".to_string()));
    }

    fn make_test_event() -> AuthEvent {
        use crate::authn::event::{AuthEventBuilder, AuthEventStatus, AuthEventType};
        AuthEventBuilder::new(
            None,
            None,
            AuthEventType::LoginAttempt,
            AuthEventStatus::Failure,
        )
        .build()
    }
}
