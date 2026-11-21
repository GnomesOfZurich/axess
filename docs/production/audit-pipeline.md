# Audit pipeline

The audit pipeline moves events from the authentication
hot path to the storage layers that compliance, incident response,
and operations consume. The pipeline has two streams (regulatory
and analytics), three retention tiers (hot, archived, deleted),
and a few traits that adopters implement
against their own storage.

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

The two requirements conflict: a single store optimised for one
audience serves the other badly. The answer is to fan
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
fills the ones it wants when it builds the
`RichAuthnEvent` around the `AuthEvent`. Axess defines the shape, so
downstream consumers can be shared between adopters, but does not
fill the fields. The stream feeds the analytics store, which is typically a columnar
database (ClickHouse, DuckDB) or a streaming platform (Apache
Iggy with rkyv).

```text
              the authentication operation
                           │
                           ▼  awaited, once
             IdentityAuthnLog::record_event         <- you implement this
                │                         │
                ▼                         ▼  AuditLogWithAnalytics (opt-in)
            hot store                 bounded queue
                │                         │
                ▼  AuditRetentionLoop     ▼  AnalyticsWorker
          AuditArchiver            AuthnAnalyticsSink   <- you implement this
          (cold tier)              (RichAuthnEvent)
                │                         │
                ▼                         ▼
          archive store            analytics store
```

On the authentication path axess calls `record_event` and awaits it,
nothing more. The fan-out to analytics is `AuditLogWithAnalytics`, an
opt-in wrapper around your `IdentityAuthnLog` that, once the write has
returned `AuditOutcome::Recorded`, queues the event for an
`AuthnAnalyticsSink`. The archive is fed by
`AuditRetentionLoop`, which reads the hot store through your
`AuditRetentionSource` on its own schedule and hands the rows to an
`AuditArchiver`. You implement the log, the source and the analytics
sink, and the archiver unless the filesystem one fits; axess ships the
wrapper, the worker and the loop.

## Reliability, and who owns it

On the authentication path axess builds the `AuthEvent` and awaits one
call: `IdentityAuthnLog::record_event`. It does not buffer, queue or
retry that write, and whatever the call does is the implementation you
provide. The analytics queue and the retention loop are opt-in and run
off that path (*The AuthnAnalyticsSink*, *AuditArchiver*).

Two consequences follow; read them before choosing a sink.

**The write is on the hot path.** Whatever `record_event` does, the
login waits for it. A sink that talks to the network over a slow link
makes logins slow. If you want the latency off the request, buffer
inside your own implementation: return as soon as the event is durable
somewhere you trust, and dispatch onward in the background. Axess leaves
that choice to you, because the right answer
depends on whether losing an event is worse than slowing a login, and
only the deployment knows that.

**A failed write fails the login.** `record_event` returning an error
surfaces as `AuthnError::Store` (and on OAuth paths as
`OAuthError::AuditStore`), and the authentication does not complete.
An authentication that leaves no evidence has not, for evidence
purposes, happened. Logging the error and continuing would let an audit
outage silently produce authentications nobody could later account for.

This trades availability for evidence, and the trade has a sharp edge:
**logins fail while your audit store does**. Put the sink behind
something durable rather than a remote service on the request path:
write locally, ship onward in the background, and page on
`AuditMetrics::audit_store_outage`.

**To drop an event without failing the login, return
`AuditOutcome::Shed`.** That is the valve for the hazard this creates:
every failed login writes a row, including for identifiers that do not
exist, so an unauthenticated caller can drive writes at your storage
without bound. Exhausting that storage would otherwise fail every login
for every user. A shed event continues the flow and fires
`AuditMetrics::audit_event_shed`.

**Shed on a criterion independent of the identifier**: a global rate,
a queue depth, a disk watermark. Shedding based on anything derived
from *which* identifier was tried makes the drop observable per
identifier, and rebuilds the user-enumeration oracle that emitting
unattributed events exists to close.

`axess-events` has two wrappers worth knowing. Both implement its
generic `EventSink`, the sink for `Event<P>`, which is neither the
regulatory sink nor the `AuthnAnalyticsSink` of this page.
`LogAndSwallow` turns a sink's errors into log lines, the
fail-soft shape written once; `NoopEventSink` discards everything,
for tests that switch an event stream off. The analytics sink needs
neither: its worker already logs a failed dispatch and drops the event.

An event whose payload is sealed (`EventBody::Encrypted`) is opened
under the associated data that `envelope_aad_for` returns, the second tag.
The second tag binds every envelope field a reader acts on, so an event whose
status, actor or time was rewritten at rest no longer opens. That is the
only value a reader tries by default.

Events sealed by a release before 0.18.0 carry the first tag, which bound
only id, kind, tenant and subject, and they do not open under the default.
`open_aads_for(event, first_tag, now)` lists the values to try under a
`FirstTag` policy: `Reject`, the default, lists the second tag alone;
`Accept` adds the first tag after it; `AcceptUntil(cutoff)` adds it while
the reader's clock is before the cutoff. The cutoff is compared with the
reader's clock, not with the event's own time, which the first tag does
not authenticate. The cutoff and the reader's clock are both a
`std::time::SystemTime`, so a clock in
one unit cannot be read against a cutoff in another. Accepting the first tag means accepting that a status,
actor or time rewritten at rest still opens, which is why it is a named
opt-in and not the default.

The library computes associated data; it holds neither the key nor the
store, so the process that holds the key moves old events to the second tag
in a one-time pass: read each encrypted event and open it with the
values `open_aads_for(event, FirstTag::Accept, now)` lists. Leave an event
that opens under the first value listed (the second tag). For one that
opens only under the second value listed (the first tag), seal its
plaintext again under `envelope_aad_for(event)`, with a
fresh nonce, and write it back. The re-seal binds the fields as the store
holds them at that moment; it cannot show they are the ones originally
written, only stop them changing unnoticed afterwards. When the pass is
done, or the old events are past retention, readers run under the
default. The 0.19.0-to-0.20.0 migration page has the loop.

Neither `LogAndSwallow` nor `NoopEventSink` can be wrapped around the
regulatory sink, and that is deliberate. Swallowing an `IdentityAuthnLog` error is exactly the
fail-open that 0.6.0 removed; the way to drop a regulatory event is
`AuditOutcome::Shed`, which is explicit and counted.

## The two sinks

One is the record; the other is the stream you can drop.

### The IdentityAuthnLog sink

The regulatory sink is the `IdentityAuthnLog` implementation the
application already provides for the lockout policy (covered in
*Identity store implementation*). The pipeline writes events to
this sink as the canonical record. The sink's storage backend is
the application's choice; the typical pattern is a Postgres or
MySQL table with append-only writes and an index on
`(tenant_id, user_id, event_time)` for `AuditQuery::query_events`,
which always scopes to a tenant and can narrow by user and time range.
The lockout itself reads
the failure counter (`failed_attempts`), not this table.

The regulatory store is therefore the one the application already
needs for lockout; the pipeline adds no second database.

### The AuthnAnalyticsSink

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

The sink never runs on the authentication path. `AuditLogWithAnalytics`
places each event on a bounded queue (10,000 events by default,
`with_capacity` to change it) once the regulatory write has
succeeded, and a worker you run drains the queue into the sink one
event at a time, in order. A full queue sheds the analytics copy and
counts it (`dropped_events()`), logging at the first drop and each
time the total doubles; the regulatory record is never shed. A failed
dispatch is logged and dropped, so a sink that needs retries owns
them. Start the worker with `AnalyticsWorker::spawn` and keep the
handle; `flush()` waits for the queue to empty and `shutdown()` flushes
and releases the handle, after which the worker finishes. The only
analytics sink axess ships is `NoopAuthnAnalyticsSink`, which discards
every event; for a streaming, columnar or file store, the
implementation is the application's.

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

The recommended serialisation is rkyv. `RichAuthnEvent`
derives `rkyv::Archive`, `rkyv::Serialize`, and
`rkyv::Deserialize`, which produces a wire format that is
significantly more compact than JSON, much faster to serialise,
and zero-copy on the deserialise side. For a stream of
millions of events per day, the difference matters.

A ClickHouse implementation is the equivalent for batch shipping:
the sink accumulates events in memory until a threshold (batch
size or time interval), then issues a bulk insert. The pattern
matches ClickHouse's preferred ingestion shape.

## Retention and archival

How long rows live, and what moves them off the hot store.

### The three-tier retention

The regulatory stream's events grow without bound by default. A
deployment with millions of users produces hundreds of millions
of events per year; storage and query costs both
grow unless the deployment manages retention.

Retention has three tiers, with explicit transitions
between them.

The hot tier is the live `auth_events` table of the example schema (or
whatever the regulatory sink writes to). Events stay in the hot tier for
as long as they are operationally useful: `AuditQuery::query_events`
lookups, the SIEM's recent-events dashboards, the
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
events are removed entirely.
Record the deletion itself somewhere durable, with the date range
and the count: axess has no event for it, and an expiry nobody
wrote down is indistinguishable from a gap. Some deployments never reach
this tier (an indefinite archive is a defensible choice for
small-volume deployments); others rotate through it on the
regulatory schedule.

### AuditArchiver

The transition from hot to archived runs through the
`AuditArchiver` trait:

```rust,ignore
pub trait AuditArchiver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn archive_batch(
        &self,
        batch: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// A stable name for this archiver, used in log lines and metrics.
    fn name(&self) -> &'static str;
}
```

The trait has one write verb and a name. `archive_batch` takes the
events by slice, so an implementation that streams them does not force
an allocation, and returns your own `Self::Error`.

The `batch` id is derived from the source id of every event in the batch
(in any order), so a batch the loop re-sends after a failed
`mark_archived` carries the same id, and two batches that differ in any
row do not. An archiver that records the ids it has applied can skip the
repeat; `FilesystemAuditArchiver` does, in a `.batches` file beside each
day file. Your `EventId` type must be `Display`, since the loop renders
the event ids to derive the batch id.

There is no purge verb. Deleting from the cold store is the cold
store's business (an S3 lifecycle rule, a partition drop, a retention
setting on the object bucket), and it is usually configured where the
storage lives rather than driven from the application. An archiver that
wants to purge on a schedule does it inside its own implementation.
Axess never purges the cold store.

The pipeline runs an `AuditRetentionLoop<S, A>` (S is the
`AuditRetentionSource` that reads and purges the hot table, A is the
archiver) that drives the
transitions on a configurable schedule:

```rust,ignore
let retention_policy = AuditRetentionPolicy {
    archive_after: Duration::from_secs(30 * 86400),   // 30 days; default is 90
    purge_hot_after_archive: Duration::from_secs(7 * 86400),
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

The loop wakes when it starts and then once per `tick_interval`, hourly
by default, and on each wake ticks back to back while a tick comes back
full (`drain`, at most 100 ticks per wake), so a backlog larger than
`batch_size` clears without waiting an interval per batch. A tick archives
up to `batch_size` events. Each tick reads the hot-tier events
that have aged past `archive_after`, hands them to the archiver, and
purges the hot rows whose archive copy was made more than
`purge_hot_after_archive` ago.

The two steps do not wait on each other:
when the archiver refuses a batch, the tick offers its rows one at a time,
marks the ones taken as archived and returns the first refusal as its
error, and the purge runs whether or not the archive step succeeded, so a
sink that is down, or one row it cannot take, never keeps archived rows on
the hot table.

A row the archiver keeps refusing is set aside so it cannot
hold up the rows behind it, whatever the batch size: at once when the
archiver took another row in the same tick, otherwise after three refusals
in as many ticks (a batch of one, or a bad row at each end of a batch, looks
like a sink that is down). A row set aside is left out of the selection for
an hour and then offered again. The set-aside record is held in memory,
so a restart offers every row afresh.

`spawn` returns a `JoinHandle`; dropping
it leaves the loop running, so call `abort` on it to stop retention.
The loop rests a full interval after each drain, so one that overruns
is not followed by catch-up drains. The cutoffs come from the injected clock, while the pacing is
the Tokio timer's. `tick` and `drain` are public too, for a
deployment that would rather drive it from its own scheduler and read
the `RetentionTickReport` each pass returns.

The policy ends at the hot purge. The cold sink owns its own expiry,
so the archive grows until the sink's lifecycle rule, WORM retention
setting or scheduled job removes something, and axess never deletes
from it.

The defaults (90 days hot, then the verification window before the hot
row goes) are conservative for finance. Leaving the cold sink without an
expiry is the right choice for most adopters, because regulators
penalise premature deletion far more harshly than they reward storage
savings. PCI-DSS asks for one year of audit retention, which the
defaults satisfy by keeping events in the archive until the sink is told
otherwise. Other regulatory regimes have different requirements; tune
the sink's expiry to match.

### Filesystem archive

The `audit-archive-fs` feature (of `axess`, which forwards it to
`axess-core`) ships `axess::authn::FilesystemAuditArchiver`, a reference
implementation that writes archived events to a day-partitioned JSONL
directory:

```text
/var/lib/axess/audit/
    .archive.lock
    YYYY/MM/DD/audit-YYYY-MM-DD.jsonl
    YYYY/MM/DD/audit-YYYY-MM-DD.jsonl.batches
    ...
```

Each file is append-only, fsynced per batch (together with the directories
it created, so a crash after a batch is acknowledged cannot lose a day
file), and contains
newline-delimited JSON-encoded events. The format is readable by
standard tools (`grep`, `jq`, `awk`), survives forensic
investigation, and lifts cleanly into cloud object storage when
the deployment moves the archive there.

A file that a crash left ending in a partial line (the bytes of a write
that was never acknowledged) is cut back to its last newline before the
next batch is appended, so a torn line cannot swallow the first line of the
batch that follows.

Writers on one root take an exclusive lock on `.archive.lock` for the
whole batch (duplicate check, writes, rollback and fsync), so two
archivers or two processes pointed at the same directory cannot race or
undo each other's batches, and a call that times out cannot release the
lock while its writes are still running. Give each archiver its own root
unless that sharing is intended.

The reference implementation is for deployments with
straightforward audit-storage needs. Larger deployments typically
use S3 (with object-lock for immutability), GCS (with retention
policies), or a dedicated audit-log service (Splunk, Datadog,
SumoLogic). The trait surface is the same; the implementation is
the deployment's.

## Backpressure and tenant isolation

Any buffer in front of the regulatory store is yours, and so is its
backpressure policy. Decide it before a busy tenant's spike tests it.

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
behind. It puts no buffer in front of the regulatory write, so it has
no policy to drop, block or shut down on a full one. The one queue it
runs is the analytics queue of `AuditLogWithAnalytics`, and a full one
drops the analytics copy, never the record. If you need a fail-closed
posture, see *Reliability* above.

## From events to a defensible trail

The pipeline turns axess's audit events into a defensible
production audit trail. The dual stream serves the two
audiences; the analytics queue keeps the analytics sink off the hot
path; the retention tiers balance storage cost against query
needs and regulatory requirements. The mechanism is small
(a handful of traits, one opt-in fan-out, one retention loop), and the
deployment tunes it to its requirements through configuration.

## Further reading

*Audit events* catalogues what flows through the pipeline.
*Identity store implementation* covers the regulatory sink
(the `IdentityAuthnLog` trait). *Multi-tenancy* covers the
per-tenant configuration patterns. *Security posture* covers
the GDPR posture for archived audit data and the PII fields
that may need scrubbing before archive.
