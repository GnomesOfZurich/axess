# Audit events

Every authentication and authorisation decision axess makes
produces an audit event. The events are typed
(`AuthEvent`, with one variant per kind of decision), they
carry every field a compliance review needs, and they emit
asynchronously so the authentication hot path does not block on
the audit dispatch. This chapter covers the event catalogue, the
fields each variant carries, the SOC alert thresholds that map
events to operational signals, and the SIEM query patterns the
events are designed to feed.

The chapter pairs with *Audit pipeline*, which covers how the
events get from the application into the regulatory store and the
analytics path.

## What the events are for

Authentication is a security-sensitive operation, and security-sensitive
operations need a defensible audit trail. Three audiences read the
trail.

The first is the compliance auditor. A regulator (or an external
auditor verifying compliance with a regulator's requirements) needs
to verify that the application enforced the controls the
regulation requires: that MFA was demanded where MFA was required,
that lockouts fired when configured, that no cross-tenant access
happened. The audit trail is what answers these questions.

The second is the incident responder. When something goes wrong (a
user reports unauthorised access, a SIEM rule fires on an
anomalous pattern, a breach is suspected), the responder needs to
reconstruct what happened: which sessions were active, what
authentications succeeded, what authorisations were granted. The
audit trail is what supports the reconstruction.

The third is the operational dashboard. The application's running
state is visible through the audit trail: how many logins succeed
per hour, what fraction trigger lockouts, which tenants are
active. The trail feeds the SIEM rules and the operational
metrics.

The three audiences want different things from the same data,
which is what drives the dual-stream design: a regulatory stream
optimised for completeness and immutability, an analytics stream
optimised for query latency and aggregation. *Audit pipeline*
covers the streams; this chapter covers the events themselves.

## The event catalogue

`AuthEvent` is the enum. The variants are stable across axess
versions; new variants can be added (variants are appended, not
renumbered), but existing variants do not change shape.

The catalogue is grouped by the operation that produces each
event. The grouping below is for readability; the wire format is
flat.

### Authentication lifecycle

`LoginStarted` records the beginning of a login attempt. Fields:
`user_id`, `tenant_id`, `method_name`, `client_ip`, `user_agent`,
`device_id` (optional), `timestamp`.

`FactorVerified` records each successful factor verification.
Fields: `user_id`, `tenant_id`, `factor_kind`, `attempt_index`,
`timestamp`.

`FactorFailed` records each failed factor verification. Fields:
`user_id`, `tenant_id`, `factor_kind`, `attempt_index`,
`failure_reason` (string), `timestamp`.

`LoginCompleted` records a successful end-to-end login. Fields:
`user_id`, `tenant_id`, `method_name`, `factors_completed`,
`session_id`, `device_id` (optional), `timestamp`.

`LoginFailed` records a failed end-to-end login (any factor
failed beyond retry, or a configuration error). Fields:
`user_id` (optional, may be unknown), `tenant_id`,
`method_name` (optional), `failure_reason`, `timestamp`.

`Logout` records a session ending. Fields: `user_id`,
`tenant_id`, `session_id`, `reason` (user-initiated,
admin-revoked, session-expired, cookie-fingerprint-mismatch),
`timestamp`.

### Lockout

`LockoutTriggered` records the per-user or per-tenant or per-IP
lockout firing. Fields: `scope` (User, Tenant, IP), `scope_value`,
`until` (optional unlock time), `triggered_by_event` (the
preceding `FactorFailed` id), `timestamp`.

`LockoutCleared` records the lockout ending (either timing out or
being administratively cleared). Fields: `scope`, `scope_value`,
`cleared_by` (Timeout, Admin), `timestamp`.

### Device identity

The six device events fire on the device-identity lifecycle
covered in *Device identity*.

`DeviceFirstSeen` records a previously-unknown device fingerprint
appearing. Fields: `device_id` (newly minted), `user_id`,
`tenant_id`, `fingerprint_features` (the redacted feature set),
`timestamp`.

`DeviceTrustGranted` records a device transitioning to `Trusted`.
Fields: `device_id`, `user_id`, `tenant_id`, `granted_by` (User,
Admin), `timestamp`.

`DeviceRevoked` records a device transitioning to `Revoked`.
Fields: `device_id`, `user_id`, `tenant_id`, `revoked_by` (User,
Admin, System), `reason`, `timestamp`.

`DevicePurged` records a device record being deleted (retention
sweep). Fields: `device_id`, `user_id`, `tenant_id`,
`purged_at_age_days`, `timestamp`.

`DeviceBindingAdded` records a new refresh-token binding to the
device. Fields: `device_id`, `user_id`, `tenant_id`,
`refresh_token_id`, `timestamp`.

`DeviceFingerprintMismatch` records a session presenting a
fingerprint that does not match its bound device. Fields:
`device_id`, `user_id`, `tenant_id`, `session_id`, `policy_action`
(Warn, Reauth, Revoke), `timestamp`.

### Authorisation

`AuthzAllow` records a successful Cedar evaluation. Fields:
`principal_uid`, `tenant_id`, `action`, `resource_uid`,
`matched_policy_ids`, `timestamp`.

`AuthzDeny` records a denied evaluation. Fields: `principal_uid`,
`tenant_id`, `action`, `resource_uid`, `matched_policy_ids` (the
policies that produced the deny, if any), `denial_reason`,
`timestamp`.

`AuthzEntityNotFound` records an evaluation failure where the
entity provider could not produce an entity the policies needed.
Fields: `principal_uid`, `missing_entity_uid`, `policy_id_referencing`,
`timestamp`.

### Workload identity

The workload events fire on the workload-identity resolvers'
decisions.

`WorkloadAuthenticated` records a successful workload
authentication. Fields: `workload_id`, `trust_domain`, `issuer`,
`tenant_id`, `client_ip`, `timestamp`.

`WorkloadRejected` records a failed workload authentication.
Fields: `attempted_workload_id` (optional), `attempted_trust_domain`,
`failure_reason`, `client_ip`, `timestamp`.

### Tenant lifecycle

`TenantCreated`, `TenantSuspended`, `TenantUnsuspended`, and
`TenantDeleted` record the tenant lifecycle from *Multi-tenancy*.
Fields are uniform: `tenant_id`, `operator_principal`, `reason`,
`timestamp`.

### Delegated access

`DelegatedConsentGranted` records a user granting an application
OBO access (the moment of OAuth consent). Fields: `user_id`,
`tenant_id`, `downstream`, `scopes`, `expires_at` (optional),
`timestamp`.

`DelegatedCredentialUsed` records a refresh of a stored OBO
credential. Fields: `user_id`, `tenant_id`, `downstream`,
`timestamp`.

`DelegatedConsentRevoked` records a user (or admin) revoking
consent. Fields: `user_id`, `tenant_id`, `downstream`,
`revoked_by`, `timestamp`.

`DelegatedTokenExchanged` records an RFC 8693 token exchange.
Fields: `subject_principal_uid`, `tenant_id`, `audience`,
`scopes`, `timestamp`.

### Administrative

`UserSuspended`, `UserUnsuspended`, `UserDeleted`, `PasswordReset`
(by admin), `FactorReset` (by admin), `SessionInvalidated` (by
admin) cover the administrative operations. Fields name the
target user, the operator principal, the reason, and the
timestamp.

## Emit cadence and fields

The events fire synchronously from the operation that produces
them (the factor verification, the policy evaluation, the
administrative action). The synchronous emit guarantees that an
operation that succeeds has an event; an event without a
corresponding operation is impossible.

The events are then handed to the audit pipeline (a sink trait
the application configures), which dispatches them asynchronously.
The pipeline's failure modes do not block the operation that
produced the event; a sink that is slow or unavailable does not
slow the application's hot path. The trade-off is that an event
the sink fails to receive is lost, which is why the pipeline has
a durable buffer in front of network-bound sinks. *Audit pipeline*
covers the pipeline's reliability story.

Every event carries: a stable wire shape (so external systems can
parse against a single schema), a per-event id (for deduplication
and cross-referencing), a tenant id (so multi-tenant deployments
can route events to per-tenant sinks), and a timestamp (in UTC,
generated through the injected `Clock` trait for DST).

The fields specific to each variant are listed in the catalogue
above. The complete schema lives in the
[`axess-events`](https://docs.rs/axess-events) crate documentation.

## SOC alert thresholds

The events are designed to feed SOC (Security Operations Center)
alerting. The thresholds below are starting points; tune to the
specific deployment.

`FactorFailed` events from a single source IP at a rate above
one per second indicate brute-forcing. The per-IP lockout (covered
in *Multi-tenancy* §"Three-lever lockout") catches the worst
cases at the application layer; the SIEM alert covers the rate
even when individual events fall below the lockout threshold.

`LockoutTriggered` events at any rate are worth reviewing. A
legitimate user occasionally mistypes their password and triggers
a lockout; the rate should be a handful per day across a
deployment. A spike indicates either a credential-stuffing attack
or a configuration problem.

`DeviceFingerprintMismatch` events fire on every mismatch beyond
the configured tolerance. Above a few per hour, either the
tolerance is too tight (a legitimate-traffic issue, calibrate the
tolerance) or there is a real attack (a stolen cookie being
replayed). Investigate.

`AuthzDeny` events fire on every policy deny. The rate should
correlate with legitimate user error (trying to access something
they cannot); a spike correlates with either a policy misconfiguration
(the rule is denying things it should permit) or with an attempt
to find privilege-escalation holes.

`WorkloadRejected` events fire on every failed workload
authentication. A clean deployment should see almost none of
these; even a small rate indicates either a configuration problem
or an attempted attack against the workload-identity surface.

`DelegatedConsentGranted` events fire on every user consent
moment. The rate is informational; the events are most useful at
the per-user level for "show me everything this user has granted
the application permission to do."

## SIEM query patterns

The events are designed for cheap aggregation in a SIEM. A
sketch of useful queries:

```sql
-- Brute-force detection: top failing source IPs per minute.
SELECT
    client_ip,
    DATE_TRUNC('minute', timestamp) AS minute,
    COUNT(*) AS failures
FROM auth_events
WHERE event_type = 'FactorFailed'
  AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY 1, 2
ORDER BY failures DESC
LIMIT 20;
```

```sql
-- Lockout activity: users locked out in the last day.
SELECT
    scope_value AS user_id,
    COUNT(*) AS lockouts,
    MAX(timestamp) AS last_lockout
FROM auth_events
WHERE event_type = 'LockoutTriggered'
  AND scope = 'User'
  AND timestamp > NOW() - INTERVAL '1 day'
GROUP BY scope_value
ORDER BY lockouts DESC;
```

```sql
-- Step-up gaps: users hitting AuthzDeny on actions requiring stronger factors.
SELECT
    principal_uid,
    action,
    COUNT(*) AS denials
FROM auth_events
WHERE event_type = 'AuthzDeny'
  AND denial_reason LIKE '%factors_completed%'
  AND timestamp > NOW() - INTERVAL '1 day'
GROUP BY 1, 2
ORDER BY denials DESC;
```

```sql
-- Suspicious devices: fingerprint mismatches followed by trust grant.
SELECT
    mismatch.user_id,
    mismatch.device_id,
    mismatch.timestamp AS mismatch_at,
    grant.timestamp AS granted_at
FROM auth_events mismatch
JOIN auth_events grant
    ON mismatch.device_id = grant.device_id
WHERE mismatch.event_type = 'DeviceFingerprintMismatch'
  AND grant.event_type = 'DeviceTrustGranted'
  AND grant.timestamp > mismatch.timestamp
  AND grant.timestamp < mismatch.timestamp + INTERVAL '1 hour';
```

The queries assume a SQL-shaped SIEM (Splunk SPL, Sumo Logic LogReduce, ClickHouse). Adapt to the deployment's
chosen tool.

## Extending the catalogue

Applications occasionally need to record events that axess does
not emit: a domain-specific operation that should appear in the
same trail (a fund transfer, a configuration change, a sensitive
read). The pattern is to extend the audit pipeline with a custom
event type that rides the same machinery.

The mechanism is the `AuthEventEnvelope` wrapper: any
`Serialize + Deserialize` type can be carried alongside the
built-in `AuthEvent` variants as long as it implements
`AuditPayload`. The application's domain events go into the
envelope; the audit pipeline routes them to the same sinks as
the axess events.

The trade-off is schema. A custom event type that the SIEM does
not know about does not feed the dashboards or alerts. The
typical pattern is to coordinate the schema with the SIEM team
before adding new event types, so the dashboards and alerts can
update in parallel.

## What this enables

The audit catalogue is what makes axess defensible against
regulatory and incident-response scrutiny. The events are typed,
complete, asynchronous, and built for the SIEM tooling that
production deployments already run. The catalogue itself is the
reference; the *Audit pipeline* chapter covers how the events
flow from the application to the storage layer.

## Further reading

*Audit pipeline* covers the dual-stream architecture (regulatory
plus analytics), the hot/cold retention tiering, and the
reliability story for the asynchronous dispatch. *Multi-tenancy*
covers the tenant-scoped routing of events. *Cedar policy
fundamentals* covers the policy evaluator that produces the
`Authz*` events. *Security posture* covers the GDPR and PCI-DSS
posture for audit-event PII.
