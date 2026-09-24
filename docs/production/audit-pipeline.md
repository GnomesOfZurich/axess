# Audit pipeline

The audit pipeline is what moves events from the authentication
hot path to the storage layers that compliance, incident response,
and operations consume. The pipeline has two streams (regulatory
and analytics), three retention tiers (hot, archived, deleted),
and a small number of trait surfaces that adopters implement
against their own storage. This chapter covers the architecture,
the configuration, and the operational patterns that make the
pipeline trustworthy under load.

The chapter pairs with *Audit events*, which catalogues what
flows through the pipeline; this chapter covers how the flow
itself works.

## The dual stream

Two audiences read the audit trail. Compliance auditors want
completeness, immutability, and unambiguous provenance; they
will accept slow queries and rigid schemas in exchange. SOC and
operations teams want low query latency, flexible aggregation,
and enrichment with operational context (geo lookups, ASN data,
parsed user-agent strings); they accept some loss of fidelity
and some divergence from the wire format in exchange.

The two requirements conflict. A single store optimised for one
audience disserves the other. The pipeline's answer is to fan
out: the same event flows into two streams, each shaped for its
audience.

The regulatory stream uses `AuthEvent` directly. The shape is
exactly what the catalogue in *Audit events* describes: stable
fields, no enrichment, byte-for-byte uniform across deployments.
The stream feeds the regulatory store, which is typically a
database or a log archive with strong durability and immutability
guarantees.

The analytics stream uses `RichAuthnEvent`, a denormalised wrapper
that adds optional enrichment fields (device trust level, geo
lookup, parsed user-agent, ASN, configurable tags). The deployment
populates whatever of them it wants when it builds the
`RichAuthnEvent` around the `AuthEvent`; axess defines the shape so
downstream consumers can be shared between adopters, and does not
populate the fields for you. The stream feeds the analytics store, which is typically a columnar
database (ClickHouse, DuckDB) or a streaming platform (Apache
Iggy with rkyv).

```text
       the authentication operation
                    │
                    ▼  awaited, once
           IdentityAuthnLog::record_event        <- you implement this
                    │
       ┌────────────┴────────────┐               <- and everything below
       ▼                         ▼
  AuthnAnalyticsSink        AuditArchiver
  (RichAuthnEvent)          (cold tier)
       │                         │
       ▼                         ▼
  analytics store           archive store
```

Axess does not fan out. It calls `record_event` and
awaits it; whether that write also feeds an analytics stream or an
archive is decided by the implementation you supply.

## Reliability, and who owns it

Axess does not buffer, queue, retry or fan out audit events. It builds
the `AuthEvent` on the authentication path and awaits one call:
`IdentityAuthnLog::record_event`. That is the whole of the pipeline
axess ships, and everything after it is the implementation you provide.

Two consequences follow, and they are the reason to read this section
before choosing a sink.

**The write is on the hot path.** Whatever `record_event` does, the
login waits for it. A sink that talks to the network over a slow link
makes logins slow. If you want the latency off the request, buffer
inside your own implementation: return as soon as the event is durable
somewhere you trust, and dispatch onward in the background. That is a
choice axess deliberately leaves to you, because the right answer
depends on whether losing an event is worse than slowing a login, and
only the deployment knows that.

**A failed write fails the login.** Since 0.6.0, `record_event`
returning an error surfaces as `AuthnError::Store` (and on OAuth paths
as `OAuthError::AuditStore`), and the authentication does not complete.
An authentication that leaves no evidence has not, for evidence
purposes, happened. Earlier versions logged the error and continued,
which meant an audit outage silently produced authentications nobody
could later account for.

This trades availability for evidence, and the trade has a sharp edge:
**logins fail while your audit store does**. Put the sink behind
something durable: write locally, ship onward in the background
rather than a remote service on the request path, and page on
`AuthnMetrics::audit_store_outage`.

**To drop an event without failing the login, return
`AuditOutcome::Shed`.** That is the valve for the hazard this creates:
every failed login writes a row, including for identifiers that do not
exist, so an unauthenticated caller can drive writes at your storage
without bound, and exhausting it would otherwise fail every login for
every user. A shed event continues the flow and fires
`AuthnMetrics::audit_event_shed`.

**Shed on a criterion independent of the identifier**: a global rate,
a queue depth, a disk watermark. Shedding based on anything derived
from *which* identifier was tried makes the drop observable per
identifier, and rebuilds the user-enumeration oracle that emitting
unattributed events exists to close.

`axess-events` has two wrappers worth knowing when you build one.
`LogAndSwallow` takes a sink and turns its errors into log lines, which
is the fail-soft shape written once. `NoopEventSink` discards
everything, which is what tests and the analytics stream want when it
is switched off.

## The IdentityAuthnLog sink

The regulatory sink is the `IdentityAuthnLog` implementation the
application already provides for the lockout policy (covered in
*Identity store implementation*). The pipeline writes events to
this sink as the canonical record. The sink's storage backend is
the application's choice; the typical pattern is a Postgres or
MySQL table with append-only writes and an index on
`(user_id, tenant_id, timestamp)` for the lockout-policy queries.

The pattern means the regulatory store is what the application
already needs for lockout. The pipeline does not add a second
database; it just uses what is already there.

## The AuthnAnalyticsSink

The analytics sink is the optional stream for the SIEM and
analytics consumers. The trait:

```rust,ignore
pub trait AuthnAnalyticsSink: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn record_rich(
        &self,
        event: RichAuthnEvent,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// A stable name for this sink, used in log lines and metrics.
    fn name(&self) -> &'static str;
}
```

The sink is a fire-and-forget dispatcher. A failed dispatch is
logged and dropped; the buffer's retry semantics handle the
transient cases. The implementations the
`audit-archive-fs` feature provides cover the filesystem case;
for streaming or columnar stores, the implementation is the
application's.

A typical Apache Iggy implementation:

```rust,ignore
struct IggyAnalyticsSink {
    client: IggyClient,   // from the `iggy` crate
    topic: String,
}

impl AuthnAnalyticsSink for IggyAnalyticsSink {
    type Error = MySinkError;

    async fn record_rich(&self, event: RichAuthnEvent) -> Result<(), Self::Error> {
        let bytes = rkyv::to_bytes::<_, 256>(&event)?;
        self.client.send(self.topic.clone(), bytes.to_vec()).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "iggy"
    }
}
```

The rkyv serialisation is the recommendation. `RichAuthnEvent`
derives `rkyv::Archive`, `rkyv::Serialize`, and
`rkyv::Deserialize`, which produces a wire format that is
significantly more compact than JSON, much faster to serialise,
and zero-copy on the deserialise side. For a stream that pumps
millions of events per day, the difference is operationally
meaningful.

A ClickHouse implementation is the equivalent for batch shipping:
the sink accumulates events in memory until a threshold (batch
size or time interval), then issues a bulk insert. The pattern
matches ClickHouse's preferred ingestion shape.

## The three-tier retention

The regulatory stream's events grow without bound by default. A
deployment with millions of users produces hundreds of millions
of events per year; the storage cost and the query cost both
trend up unless the deployment manages the retention.

The retention story has three tiers, with explicit transitions
between them.

The hot tier is the live `authn_attempts` table (or whatever the
regulatory sink writes to). Events stay in the hot tier for as
long as they are operationally useful: the lockout policy's
`last_attempts` query, the SIEM's recent-events dashboards, the
incident-response window. The recommended hot retention is
between 7 and 90 days, with 30 days as a sensible default for
most deployments.

The archived tier is a cheaper, slower store that holds events
for the compliance retention period. The data is the same; the
access pattern is different. Queries against the archive are
slower (typically minutes rather than milliseconds) and less
flexible (no indexed lookup; full-scan reads against a known
date range). The archive is the answer to "show me everything
that happened to this user three years ago." The retention here
is set by the regulatory regime: PCI-DSS asks for one year;
banking regulations ask for seven years; HIPAA asks for six
years. Configure to match.

The deleted tier is what comes after the archive expires. The
events are removed entirely and the underlying data is gone.
Record the deletion itself somewhere durable, with the date range
and the count: axess has no event for it, and an expiry nobody
wrote down is indistinguishable from a gap. Some deployments never reach
this tier (an indefinite archive is a defensible choice for
small-volume deployments); others rotate through it on the
regulatory schedule.

## AuditArchiver

The transition from hot to archived runs through the
`AuditArchiver` trait:

```rust,ignore
pub trait AuditArchiver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn archive_batch(
        &self,
        events: &[AuthEvent],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// A stable name for this archiver, used in log lines and metrics.
    fn name(&self) -> &'static str;
}
```

The trait has one write verb and a name. `archive_batch` takes the
events by slice, so an implementation that streams them does not force
an allocation, and returns your own `Self::Error`.

There is no purge verb. Deleting from the cold store is the cold
store's business (an S3 lifecycle rule, a partition drop, a retention
setting on the object bucket), and it is usually configured where the
storage lives rather than driven from the application. An archiver that
wants to purge on a schedule does it inside its own implementation.
Axess never calls it.

The pipeline runs an `AuditRetentionLoop<S, A>` (S is the source
`IdentityAuthnLog`, A is the archiver) that drives the
transitions on a configurable schedule:

```rust,ignore
let retention_policy = AuditRetentionPolicy {
    archive_after: Duration::from_secs(30 * 86400),   // 30 days; default is 90
    purge_hot_after_archive: Duration::from_secs(7 * 86400),
    delete_archive_after: None,                       // never purge archive
};

let loop_handle = AuditRetentionLoop::new(
    retention_source,
    my_archiver,
    retention_policy,
)
.with_tick_interval(Duration::from_secs(3600))  // the default
.with_batch_size(10_000)                        // the default
.spawn();                                       // JoinHandle<()>
```

The loop ticks once per `tick_interval`, hourly by default, archiving
up to `batch_size` events per tick. Each tick reads the hot-tier events
that have aged past `archive_after`, hands them to the archiver, and
purges the hot rows whose archive copy was made more than
`purge_hot_after_archive` ago. `spawn` returns a `JoinHandle`; the loop
runs until that handle is dropped. `tick` is public too, for a
deployment that would rather drive it from its own scheduler and read
the `RetentionTickReport` each pass returns.

The `delete_archive_after` field is the optional final
transition. `None` means the archive grows indefinitely; a
configured duration means the archive itself is purged at that
age.

The defaults (90 days hot, then the verification window before the hot
row goes, and no archive deletion) are conservative for finance.
`delete_archive_after: None` is the right default for most adopters,
because regulators penalise premature deletion far more harshly than
they reward storage savings. PCI-DSS asks
for one year of audit retention, which the defaults satisfy by
keeping events in the archive indefinitely. Other regulatory
regimes have different requirements; tune to match.

## Filesystem archive

The `audit-archive-fs` feature ships
`FilesystemAuditArchiver`, a reference implementation that
writes archived events to a day-partitioned JSONL directory:

```text
/var/lib/axess/audit/
    YYYY-MM-DD.jsonl
    YYYY-MM-DD.jsonl
    YYYY-MM-DD.jsonl
    ...
```

Each file is append-only, fsynced per batch, and contains
newline-delimited JSON-encoded events. The format is readable by
standard tools (`grep`, `jq`, `awk`), survives forensic
investigation, and lifts cleanly into cloud object storage when
the deployment moves the archive there.

The reference implementation is for deployments with
straightforward audit-storage needs. Larger deployments typically
use S3 (with object-lock for immutability), GCS (with retention
policies), or a dedicated audit-log service (Splunk, Datadog,
SumoLogic). The trait surface is the same; the implementation is
the deployment's.

## Backpressure and tenant isolation

Since the buffer is yours, so is the backpressure. Worth deciding
before a busy tenant decides it for you.

`AuthEvent` carries `tenant_id`, so a sink can route per tenant: its
own buffer, its own retention, its own destination. That is what makes
a per-tenant audit SLA real rather than a deployment-wide average, and
it keeps one tenant's spike off another's stream. The cost is a
configuration per tenant and the operational surface that comes with
it.

A single shared sink with conservative behaviour is fine for most
deployments, and is the sensible starting point. Reach for per-tenant
routing when a contract names a number.

What axess will not do is stop authenticating because the audit is
behind. It has no policy to drop, block or shut down on a full buffer,
because it has no buffer. If you need a fail-shut posture, see
*Reliability* above.

## From events to a defensible trail

The pipeline is what turns axess's audit events into a defensible
production audit trail. The dual stream serves the two
audiences; the buffer absorbs latency without blocking the hot
path; the retention tiers balance storage cost against query
needs and regulatory requirements. The mechanism is small
(a handful of traits, one fan-out, one retention loop), and the
configuration is the deployment's lever for tuning to specific
requirements.

## Further reading

*Audit events* catalogues what flows through the pipeline.
*Identity store implementation* covers the regulatory sink
(the `IdentityAuthnLog` trait). *Multi-tenancy* covers the
per-tenant configuration patterns. *Security posture* covers
the GDPR posture for archived audit data and the PII fields
that may need scrubbing before archive.
