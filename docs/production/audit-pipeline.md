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
lookup, parsed user-agent, ASN, configurable tags). The fields
are populated by an `EventEnrichment` closure the application
provides; the closure runs once per event, populates whatever
data the deployment wants, and returns the enriched event. The
stream feeds the analytics store, which is typically a columnar
database (ClickHouse, DuckDB) or a streaming platform (Apache
Iggy with rkyv).

```text
              AuthEvent (regulatory wire)
                       │
                       ▼
                ┌──────────────┐
                │  AuditPipe   │
                └───┬──────────┘
                    │ fan-out
        ┌───────────┼────────────┐
        ▼           ▼            ▼
   IdentityAuthnLog   AuthnAnalyticsSink    AuditArchiver
    (lockout depends)    (enriched stream)    (cold tier)
        │                  │                     │
        ▼                  ▼                     ▼
   primary store      analytics store        archive store
```

The fan-out runs once per event. The performance cost is small
because each sink is fire-and-forget; a slow sink does not slow
the authentication hot path, but it can lose events under
pressure, which is the next concern.

## Reliability and fire-and-forget

The pipeline's emit path is synchronous (the event is constructed
on the authentication hot path and handed to the pipeline before
the operation returns), but the dispatch to each sink is
asynchronous. The trade-off is what every audit-pipeline design
has to make.

A fully-synchronous pipeline blocks the authentication operation
until every sink acknowledges the event. The latency cost is the
sum of every sink's latency; one slow sink slows every login. The
pattern is a non-starter for production.

A fully-asynchronous pipeline with no durability lets the events
fan out to sinks in the background. The latency cost is zero
(the operation returns before the sinks see the event). The
trade-off is that an event lost between emit and the sink is
genuinely lost; there is no retry, no acknowledgement, no
delivery guarantee.

Axess takes a middle position. The synchronous emit produces an
event handed to the pipeline; the pipeline buffers the event in
memory or in a durable queue (the choice is configuration); a
background task dispatches from the buffer to each sink with
retry. The buffer absorbs sink latency without blocking the
authentication operation; the buffer's durability determines
whether events survive an application crash.

The configuration shape:

```rust,ignore
pub struct AuditPipeConfig {
    pub regulatory_sink: Arc<dyn IdentityAuthnLog>,
    pub analytics_sink: Option<Arc<dyn AuthnAnalyticsSink>>,
    pub buffer: BufferStrategy,    // InMemory | FsBacked { path }
    pub max_buffer_size: usize,
    pub on_buffer_full: BufferFullPolicy,  // DropOldest | Block | ShutdownAuthn
    pub enrichment: Option<Arc<dyn EventEnrichment>>,
}
```

`buffer` controls where the in-flight events live. `InMemory` is
the simple choice: a bounded VecDeque that holds events between
emit and dispatch. Events in the buffer are lost on application
crash; for most deployments, the regulatory sink's own durability
(the database transaction that records the event) is what
matters, and the in-memory buffer is just for absorbing latency
spikes.

`FsBacked { path }` writes the buffer to disk so events survive
a crash. The cost is one local-disk write per event; the benefit
is that the audit trail does not lose events to short network
outages or process restarts. Deployments in regulated
environments use the file-backed buffer; everyone else uses the
in-memory one.

`max_buffer_size` is the cap. Above it, the `on_buffer_full`
policy fires.

`on_buffer_full` is the choice for what happens when the buffer
fills. `DropOldest` is the high-throughput default: the oldest
buffered events are evicted so the newest fit. `Block` is the
strict choice: the authentication operation that produced the
event blocks until the buffer has room; the latency cost can be
substantial but no events are lost. `ShutdownAuthn` is the
fail-shut choice: the authentication subsystem stops accepting
new logins until the buffer drains. Regulated deployments
typically choose `Block` or `ShutdownAuthn`; permissive
deployments choose `DropOldest`.

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
#[async_trait]
pub trait AuthnAnalyticsSink: Send + Sync {
    async fn dispatch(&self, event: RichAuthnEvent) -> Result<(), SinkError>;
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
    client: IggyClient,
    topic: String,
}

#[async_trait]
impl AuthnAnalyticsSink for IggyAnalyticsSink {
    async fn dispatch(&self, event: RichAuthnEvent) -> Result<(), SinkError> {
        let bytes = rkyv::to_bytes::<_, 256>(&event).map_err(SinkError::serialize)?;
        self.client.send(self.topic.clone(), bytes.to_vec()).await
            .map_err(SinkError::transport)?;
        Ok(())
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
events are removed entirely; the deletion is auditable (a
`DeletionEvent` itself, recording the date range and the count)
but the underlying data is gone. Some deployments never reach
this tier (an indefinite archive is a defensible choice for
small-volume deployments); others rotate through it on the
regulatory schedule.

## AuditArchiver

The transition from hot to archived runs through the
`AuditArchiver` trait:

```rust,ignore
#[async_trait]
pub trait AuditArchiver: Send + Sync {
    async fn archive_batch(&self, events: Vec<AuthEvent>) -> Result<(), ArchiveError>;
    async fn purge_batch(&self, range: ArchiveDateRange) -> Result<usize, ArchiveError>;
}
```

The trait has two methods. `archive_batch` writes a batch of
events to the cold store. `purge_batch` removes a date range from
the archive (for the deleted-tier transition).

The pipeline runs an `AuditRetentionLoop<S, A>` (S is the source
`IdentityAuthnLog`, A is the archiver) that drives the
transitions on a configurable schedule:

```rust,ignore
let retention_policy = AuditRetentionPolicy {
    archive_after: Duration::from_secs(30 * 86400),   // 30 days
    purge_hot_after_archive: Duration::from_secs(7 * 86400),
    delete_archive_after: None,                       // never purge archive
};

let loop_handle = AuditRetentionLoop::new(
    identity_authn_log.clone(),
    Arc::new(my_archiver),
    retention_policy,
).run();
```

The loop runs once per configured interval (typically daily).
Each run does three things: it reads the events from the hot
tier that have aged past `archive_after`, it batches them into
the archiver, and it purges the hot tier of events whose
archive copy was made more than `purge_hot_after_archive` ago.

The `delete_archive_after` field is the optional final
transition. `None` means the archive grows indefinitely; a
configured duration means the archive itself is purged at that
age.

The defaults (30 days hot, 7 days hot retention after archive,
no archive deletion) are conservative for finance. PCI-DSS asks
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

In a multi-tenant deployment, one tenant's audit load can
overwhelm the pipeline if the buffer is shared. The pattern that
works is per-tenant pipelines: each tenant has its own
`AuditPipe` with its own buffer and its own retention
configuration. The configuration matches what the tenant has
agreed to (high-throughput tenants get larger buffers; regulated
tenants get file-backed buffers). One tenant's spike does not
affect another's.

The cost is operational complexity: one configuration per
tenant. The benefit is isolation; the SLA you offer a tenant is
genuinely a per-tenant SLA, not a deployment-wide average.

For most deployments, a single shared pipeline with conservative
defaults is fine. The per-tenant shape is for deployments with
strict per-tenant guarantees.

## What this enables

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
