# Audit events

Axess records what happened to an authentication as an `AuthEvent`: one
flat struct, with `AuthEventType` naming the operation and
`AuthEventStatus` the outcome. Authorisation is not in here.
A Cedar decision is a `tracing` event on its own target, for the
reason *Cedar providers* explains, and this chapter says where to look
instead.

The write is synchronous with the operation, so an operation that
succeeded has its event. Since 0.6.0 the sink is **fail-closed**: a
`record_event` error fails the authentication, because an
authentication that leaves no evidence has not, for evidence purposes,
happened. A sink that wants to drop an event under load says so with
`AuditOutcome::Shed`, which continues the flow; see *Audit pipeline*
for why that valve exists and the rule for using it safely.

This chapter covers the vocabulary, the fields every event carries, who
emits each name, the SOC thresholds worth alerting on, and SIEM queries
that work against the real column names.

The chapter pairs with *Audit pipeline*, which covers how the
events get from the application into the regulatory store and the
analytics path.

## What the events are for

Authentication is a security-sensitive operation, and security-sensitive
operations need a defensible audit trail. Three audiences read the
trail.

**The compliance auditor.** A regulator (or an external
auditor verifying compliance with a regulator's requirements) needs
to verify that the application enforced the controls the
regulation requires: that MFA was demanded where MFA was required,
that lockouts fired when configured, that no cross-tenant access
happened. The audit trail is what answers these questions.

**The incident responder.** When something goes wrong (a
user reports unauthorised access, a SIEM rule fires on an
anomalous pattern, a breach is suspected), the responder needs to
reconstruct what happened: which sessions were active, what
authentications succeeded, what authorisations were granted. The
audit trail is what supports the reconstruction.

**The operational dashboard.** Your running
state is visible through the audit trail: how many logins succeed
per hour, what fraction trigger lockouts, which tenants are
active. The trail feeds the SIEM rules and the operational
metrics.

The three audiences want different things from the same data,
which is what drives the dual-stream design: a regulatory stream
optimised for completeness and immutability, an analytics stream
optimised for query latency and aggregation. *Audit pipeline*
covers the streams; this chapter covers the events themselves.

## The shape of an event

One flat struct, `AuthEvent`, carries every event. What happened and
how it turned out are **separate fields**, not separate types:
`event_type` says which operation, `event_status` says the outcome.
So a failed login is `LoginAttempt` + `Failure`, not a `LoginFailed`
type, and a locked one is `LoginAttempt` + `Locked`.

`AuthEventStatus` has five values, and the same split applies as to the
event names: axess sets three, and two are there for you.

| status | wire | means | set by |
|---|---|---|---|
| `Success` | `success` | the operation completed | axess |
| `Failure` | `failure` | it did not (bad credential, and so on) | axess |
| `Locked` | `locked` | refused because the account is locked out | axess |
| `Expired` | `expired` | refused because something had expired | adopter |
| `Suspicious` | `suspicious` | completed or refused, and flagged as anomalous | adopter |

`Locked` is what a lockout records, on both `LoginAttempt` and
`FactorVerified`. Filter on the status column for those, not on a
substring of `error`.

`Expired` and `Suspicious` are unset for the same structural reason the
adopter-emitted event names are. The paths where they would apply sit
outside the service layer that owns the log: refresh-token expiry is
`refresh_session`, a free function over a `RefreshTokenStore` with no
audit sink in its signature, and a fingerprint mismatch comes from your
`DeviceResolver`. Use them when you write those rows; a SIEM rule that
matches on them will not fire on anything axess wrote.

## The event catalogue

These are the `AuthEventType` values. The wire string is the stable
contract: it is what lands in the audit row and what a SIEM rule
matches, and `axess-core`'s own tests pin every one of them.

The **Emitted by** column matters more than it looks. Axess emits from
its own service layer, which is the part that owns an `IdentityStore`
to write through. The rest of the vocabulary exists for glue the
adopter implements: a `DeviceResolver`, a `SessionStore`, the
delegated-credential primitives. Axess defines the name and the wire
string so every deployment spells these the same way; emitting them is
the adopter's, because axess is not on the call path.

### Authentication

| variant | wire string | emitted by |
|---|---|---|
| `LoginAttempt` | `login_attempt` | axess |
| `Authenticated` | `authenticated` | axess |
| `LogoutAttempt` | `logout_attempt` | axess |
| `FactorVerified` | `factor_verified` | axess |

`LoginAttempt` covers the start and the refusal of a login; the
status separates them. `Authenticated` is the end-to-end success,
emitted once every required factor has passed.

A refusal is emitted even when there is nothing to attribute it to.
An attempt against a tenant that does not exist writes an unattributed
row with `error = "unknown_tenant"`; one against a real tenant and an
unknown identifier writes a tenant-attributed row with
`error = "unknown_identifier"`. Two things follow. A credential-stuffing
run over addresses that are not registered is visible in the trail
rather than only in a metric, which is usually the first sign of one.
And because every rejection path writes, an audit-store outage fails
them all identically, so it cannot be used to tell registered
identifiers from unregistered ones.

### Factors and methods

| variant | wire string | emitted by |
|---|---|---|
| `FactorSetup` | `factor_setup` | axess |
| `FactorEnabled` | `factor_enabled` | axess |
| `FactorDisabled` | `factor_disabled` | axess |
| `MethodEnabled` | `method_enabled` | adopter |
| `MethodDisabled` | `method_disabled` | adopter |

### Credentials and account state

| variant | wire string | emitted by |
|---|---|---|
| `PasswordResetRequested` | `password_reset_requested` | axess |
| `PasswordReset` | `password_reset` | axess |
| `SignupStarted` | `signup_started` | axess |
| `SignupCompleted` | `signup_completed` | axess |
| `AccountSuspended` | `account_suspended` | axess |
| `AccountActivated` | `account_activated` | axess |
| `Impersonation` | `impersonation` | axess |

`Impersonation` is the administrative act of assuming another
user's identity, emitted on both the successful and the refused
path.

### Sessions

| variant | wire string | emitted by |
|---|---|---|
| `SessionExpired` | `session_expired` | adopter |
| `SessionInvalidated` | `session_invalidated` | adopter |

Both belong to the `SessionStore` implementation, which owns when a
session ends.

### Devices

| variant | wire string | emitted by |
|---|---|---|
| `DeviceFirstSeen` | `device_first_seen` | axess |
| `DeviceRevoked` | `device_revoked` | axess |
| `DeviceBindingAdded` | `device_binding_added` | axess |
| `DeviceTrustGranted` | `device_trust_granted` | adopter |
| `DevicePurged` | `device_purged` | adopter |
| `DeviceFingerprintMismatch` | `device_fingerprint_mismatch` | adopter |

`DeviceFingerprintMismatch` is the cookie-replay signal: a request
carried a valid device cookie whose recomputed fingerprint did not
match. Record it `Suspicious`. It comes from the `DeviceResolver`,
which is adopter-implemented, so axess cannot emit it for you; see
*Device identity* for what a resolver does.

### What is not here

Authorisation gets no events of its own. A Cedar decision is not an
`AuthEvent`; it is a `tracing` event on the target
`axess::authz::decision`, carrying `principal`, `action`, `resource`,
`decision` (`allow` or `deny`), `reasons` and `latency_us`. Axess ships
no audit transport of its own, so route that target with
`tracing-subscriber` to wherever the audit goes. *Cedar providers*
covers the schema.

The catalogue covers authentication only. Workload-identity, rate-limit, tenant-lifecycle and
delegated-access events. Those subsystems are adopter-composed
primitives with no audit sink on their call path, so nothing is
emitted for them today, and the vocabulary has no names reserved for
them either.

## Emit cadence and fields

Events fire synchronously from the operation that produced them, so an
operation that succeeded has an event. They are written through
`IdentityStore::record_event`, which the deployment implements: that is
the sink, and where it goes next is the deployment's decision. A write
that fails is logged at `error` and does not fail the user's request,
because a SOC blind spot is an incident but so is an outage.

Every event is the same struct. There are no per-variant field sets:

| field | type | notes |
|---|---|---|
| `event_type` | `AuthEventType` | which operation |
| `event_status` | `AuthEventStatus` | the outcome |
| `event_time` | `i64` | epoch **microseconds**, not a `DateTime`, so the event is rkyv-archivable end to end |
| `user_id` | `Option<UserId>` | `None` when attribution was not available, e.g. a login for a user that does not exist |
| `tenant_id` | `Option<TenantId>` | `None` when the tenant could not be identified |
| `session_id` | `Option<SessionId>` | session-related events |
| `factor_kind` | `Option<FactorKind>` | which factor, where one is involved |
| `device_id` | `Option<DeviceId>` | omitted from the wire form entirely when absent |
| `ip_address` | `Option<IpAddr>` | typed, so a forged or malformed value cannot be stored. `None` unless the request path called `AuthnService::with_audit_context` |
| `user_agent` | `Option<String>` | same: `None` unless a context was attached |
| `request_id` | `Option<String>` | from `X-Request-Id`, for log correlation |
| `geo_country` | `Option<String>` | ISO 3166-1 alpha-2, derived from the IP |
| `error` | `Option<AuthFailureReason>` | *why* it failed, as a tag a dashboard can group by. Not the place to look for the outcome; that is `event_status` |

The three client-metadata fields are `None` on every event unless the
route attached an [`AuditContext`]. Axess cannot resolve a trustworthy
client address by itself: that needs the TCP peer and your trusted-proxy
set, so it records nothing rather than something forgeable. Wire it with
`AuthnService::with_audit_context`, and build with
`AuditContextPolicy::Required` if a blank IP should be an error rather
than a silence.

[`AuditContext`]: https://docs.rs/axess-core/latest/axess_core/authn/event/struct.AuditContext.html

Store `user_id` and `tenant_id` as nullable columns. Both are legitimately
absent, and a schema that requires them will reject exactly the rows a
SOC most wants: the ones where the attacker was not who they claimed.

## SOC alert thresholds

The events are designed to feed SOC (Security Operations Center)
alerting. The thresholds below are starting points; tune to the
specific deployment.

Rules match on the pair, not on a type alone, because the outcome
lives in `event_status`.

**`factor_verified` + `failure` from a single source IP above one per
second** indicates brute-forcing. The per-IP lockout (see
*Multi-tenancy* §"Three-lever lockout") catches the worst cases at the
application layer; the SIEM alert covers the rate even when individual
attempts stay under the lockout threshold.

**Any `locked` status at all** is worth reviewing. A legitimate user
occasionally mistypes and trips a lockout, so a handful per day across
a deployment is normal. A spike is credential stuffing or a
misconfiguration. The status is the whole filter here: `login_attempt`
and `factor_verified` both produce `locked` rows.

**`device_fingerprint_mismatch`** is a stolen cookie being replayed
until proven otherwise. Above a few per hour, either the fingerprint
inputs are too strict (calibrate them) or it is real. Your
`DeviceResolver` emits these, so the rate depends on what you chose to
fingerprint.

**`impersonation`** at any rate should be attributable to a named
operator and a ticket. It is the one event where a low rate is not
reassuring on its own.

**Cedar denies** are not audit rows. Alert on the `tracing` target
`axess::authz::decision` where `decision = "deny"`. A spike is either a
policy denying what it should permit, or someone probing for a
privilege-escalation hole. The same target carries `latency_us`, so the
rule that alerts on denials can also alert on evaluation getting slow.

Workload-identity refusals, rate-limit rejections and delegated-consent
moments produce no events today. If you need them, emit your own from
the glue that performs them.

## SIEM query patterns

Axess does not define the table. `IdentityStore::record_event` is
yours, so the column names below are the struct's field names on the
assumption you stored them as-is; rename to match your schema.

Two things trip people up. The values are the **wire strings**,
lower-snake-case (`login_attempt`), not the Rust variant names. And
`event_time` is **epoch microseconds as a signed integer**, not a
timestamp type, so it needs converting before any date function
touches it.

```sql
-- Brute-force: top failing source IPs per minute.
-- The outcome is in event_status; event_type alone does not say it failed.
SELECT
    ip_address,
    DATE_TRUNC('minute', TO_TIMESTAMP(event_time / 1000000.0)) AS minute,
    COUNT(*) AS failures
FROM auth_events
WHERE event_type = 'factor_verified'
  AND event_status = 'failure'
  AND event_time > EXTRACT(EPOCH FROM NOW() - INTERVAL '1 hour') * 1000000
GROUP BY 1, 2
ORDER BY failures DESC
LIMIT 20;
```

```sql
-- Lockouts in the last day. Filter on the status, not on a string in
-- `error`: both login_attempt and factor_verified produce locked rows.
SELECT
    user_id,
    COUNT(*) AS lockouts,
    MAX(event_time) AS last_lockout
FROM auth_events
WHERE event_status = 'locked'
  AND event_time > EXTRACT(EPOCH FROM NOW() - INTERVAL '1 day') * 1000000
GROUP BY user_id
ORDER BY lockouts DESC;
```

```sql
-- Cookie replay: a fingerprint mismatch followed by a trust grant
-- within the hour. Both events come from your DeviceResolver, so this
-- returns nothing unless you emit them.
SELECT
    mismatch.user_id,
    mismatch.device_id,
    mismatch.event_time AS mismatch_at,
    granted.event_time AS granted_at
FROM auth_events mismatch
JOIN auth_events granted
    ON mismatch.device_id = granted.device_id
WHERE mismatch.event_type = 'device_fingerprint_mismatch'
  AND granted.event_type = 'device_trust_granted'
  AND granted.event_time > mismatch.event_time
  AND granted.event_time < mismatch.event_time + 3600 * 1000000;
```

Authorisation denials are not in this table. They are `tracing` events
on `axess::authz::decision`; query them wherever that subscriber writes.

The queries assume a SQL-shaped SIEM (Splunk SPL, Sumo Logic LogReduce, ClickHouse). Adapt to the deployment's
chosen tool.

## Extending the catalogue

You cannot add an `AuthEventType`. It is a closed enum in
`axess-core`, and the wire strings are a contract the crate's own
tests pin, so a new variant is an axess change and a breaking one.

What you can do is own the sink. `IdentityStore::record_event` is
yours to implement, and every axess event arrives there before it goes
anywhere. A domain event of your own (a fund transfer, a configuration
change, a sensitive read) can be written to the same table, through the
same connection, in the same transaction if you want it atomic with the
thing it records. Axess leaves you to it, because it has no
envelope type and no payload trait, and it ships no audit transport.

The trade-off is schema. An event type your SIEM does not know about
feeds no dashboard and fires no alert, so agree the shape with whoever
owns the SIEM before you start writing rows.

## Answering an auditor

The catalogue is what makes a deployment answerable to an auditor: who
authenticated, when, from where, and what was refused. The events are
typed, the wire strings are stable, and the sink is the deployment's
own, so the trail lives wherever the rest of the compliance evidence
already lives.

Be clear-eyed about the edges. Authorisation decisions go to a
`tracing` target rather than the audit trail; workload identity, rate
limiting, delegated access and tenant provisioning emit nothing; and
six of the vocabulary's names are for glue you implement, so they only
appear if you emit them. *Audit pipeline* covers how events flow from
the application to storage.

## Further reading

*Audit pipeline* covers the dual-stream architecture (regulatory
plus analytics), the hot/cold retention tiering, and the
reliability story for the asynchronous dispatch. *Multi-tenancy*
covers the tenant-scoped routing of events. *Cedar policy
fundamentals* covers the policy evaluator, whose decisions go to the
`axess::authz::decision` tracing target rather than to an audit row. *Security posture* covers the GDPR and PCI-DSS
posture for audit-event PII.
