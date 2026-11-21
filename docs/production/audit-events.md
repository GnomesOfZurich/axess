# Audit events

Axess records what happened to an authentication as an `AuthEvent`: one
flat struct, with `AuthEventType` naming the operation and
`AuthEventStatus` the outcome. Authorisation is not recorded
here: a Cedar decision is a `tracing` event on its own target, for the
reason *Cedar providers* explains, and *What is not here* below says
where to find it.

The write is synchronous with the operation, so an operation that
succeeded has its event. The sink is **fail-closed**: a
`record_event` error fails the authentication, because an
authentication that leaves no evidence has not, for evidence purposes,
happened. A sink that wants to drop an event under load says so with
`AuditOutcome::Shed`, which continues the flow; see *Audit pipeline*
for why that valve exists and the rule for using it safely.

The chapter pairs with *Audit pipeline*, which covers how the
events get from the application into the regulatory store and the
analytics path.

## What the events are for

Authentication is security-sensitive and needs a defensible audit
trail. Three audiences read it.

**The compliance auditor.** A regulator, or an external
auditor working to a regulator's requirements, needs
to verify that the application enforced the controls the
regulation requires: that MFA was demanded where required,
that lockouts fired when configured, that no cross-tenant access
happened. The audit trail answers these questions.

**The incident responder.** When something goes wrong (a
user reports unauthorised access, a SIEM rule fires on an
anomalous pattern, a breach is suspected), the responder needs to
reconstruct what happened: which sessions were active, what
authentications succeeded, what was refused. The audit trail supports
the reconstruction.

**The operational dashboard.** The audit trail
shows the deployment's running state: how many logins succeed
per hour, what fraction trigger lockouts, which tenants are
active. The trail feeds the SIEM rules and the operational
metrics.

The three audiences want different things from the same data,
which drives the dual-stream design: a regulatory stream
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
event names: axess sets three on its own paths, sets the other two on one
path each, and leaves those two to you everywhere else.

| status | wire | means | set by |
|---|---|---|---|
| `Success` | `success` | the operation completed | axess |
| `Failure` | `failure` | it did not (bad credential, and so on) | axess |
| `Locked` | `locked` | refused because the account is locked out | axess |
| `Expired` | `expired` | refused because something had expired | axess (a session past an age cap), adopter |
| `Suspicious` | `suspicious` | completed or refused, and flagged as anomalous | axess (a refused device-key proof), adopter |

`Locked` is what a lockout records, on both `LoginAttempt` and
`FactorVerified`. Filter on the status column for those, not on a
substring of `error`.

`Expired` is set by axess in one place: the row of a session the session
layer ended because it outlived an age cap (see *Sessions* below).
`Suspicious` is set by axess in one place too: the `DeviceKeyProofRefused`
row (see *Devices* below). Every other expiry, and every other
`Suspicious`, is unset for the same structural reason the adopter-emitted
event names are. The paths where they would apply sit outside the service
layer that owns the log: refresh-token expiry is `Refresh::run`, which runs
over a `RefreshTokenStore` with no audit sink in its signature, and a
fingerprint mismatch comes from your `DeviceResolver`. Use them when you
write those rows; a SIEM rule that matches on `Suspicious` fires, among
the rows axess wrote, only on refused device-key proofs, and one that
matches on `Expired` only on the age-cap rows.

## The event catalogue

These are the `AuthEventType` values. The wire string is the stable
contract: it is what lands in the audit row and what a SIEM rule
matches, and `axess-core`'s own tests pin every one of them.

The **Emitted by** column matters. Axess emits from
its own service layer, the part that owns an `IdentityStore`
to write through. The rest of the vocabulary exists for glue the
adopter implements: a `DeviceResolver`, a `SessionStore`, device
revocation and the retention sweep. Axess defines the name and the wire
string so every deployment spells these the same way; the adopter
emits them, because axess is not on the call path.

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

A refusal is emitted even when there is nothing to attribute it to. An
attempt against a tenant that does not exist writes an unattributed row
with `error = "unknown_tenant"`; one against a real tenant with an
unknown identifier writes a tenant-attributed row with
`error = "unknown_identifier"`. Two things follow:

- A credential-stuffing run over unregistered addresses is visible in
  the trail, not only in a metric. That is usually the first sign of one.
- Because every rejection path writes, an audit-store outage fails them
  all identically, so it cannot be used to tell registered identifiers
  from unregistered ones.

### Factors and methods

| variant | wire string | emitted by |
|---|---|---|
| `FactorSetup` | `factor_setup` | axess |
| `FactorEnabled` | `factor_enabled` | axess |
| `FactorDisabled` | `factor_disabled` | axess |
| `MethodEnabled` | `method_enabled` | axess (provider changes), adopter |
| `MethodDisabled` | `method_disabled` | axess (provider changes), adopter |

`MethodEnabled` and `MethodDisabled` are written by the audited provider
changes on the request-scoped service (`reload_oauth_provider_as`,
`remove_tenant_oauth_provider_as` and the rest): a reload that added or
replaced a provider is `MethodEnabled`, a removal `MethodDisabled`. The row names the
administrator as `actor_id`, the provider as `factor_kind` (`Federated` with
the kind the OAuth provider is configured with, `Custom(name)` when it names
none; `Fido2`; `LdapBind`) and, for a tenant's provider, the tenant. The rows
of an operator's attestation of a client and of a pair's hand-over name each
record's provider the same way, by the kind the record is configured with. A refused change is the same row with `Failure` and the refusal in
`error`. A change whose row cannot be written is undone, so the trail never
lacks a change that took effect.

### Credentials and account state

| variant | wire string | emitted by |
|---|---|---|
| `PasswordResetRequested` | `password_reset_requested` | axess |
| `PasswordReset` | `password_reset` | axess |
| `SignupStarted` | `signup_started` | axess |
| `SignupResumed` | `signup_resumed` | axess |
| `SignupCompleted` | `signup_completed` | axess |
| `AccountSuspended` | `account_suspended` | axess |
| `AccountActivated` | `account_activated` | axess |
| `AccountDeleted` | `account_deleted` | axess |
| `Impersonation` | `impersonation` | axess |

`SignupResumed` is a resubmit from the session that started a signup still
waiting for verification; nothing is created.

`SignupCompleted` is a `Success` when the account was activated and the
session authenticated. It is a `Failure` whose `error` is
`session_not_registered` (`SIGNUP_SESSION_NOT_REGISTERED_REASON`) when the
session registry did not register the session: the account was not
activated and the signup is still pending, so the same secret completes it
later.

`Impersonation` records an administrator assuming another
user's identity, on both the successful and the refused
path. A refused credential change of an impersonated session (a refresh
token, a factor enrolled or deleted) and a refused second impersonation
carry the reason `impersonated`, whichever operation was refused.

### Sessions

| variant | wire string | emitted by |
|---|---|---|
| `SessionExpired` | `session_expired` | axess (the session layer's age caps, through its audit sink), adopter |
| `SessionInvalidated` | `session_invalidated` | axess, on the audited kick methods, through the back-channel logout hook and through the session layer's audit sink |

`LogoutAttempt` is also the row of an OAuth token revocation made through
`oauth_for_session` or `oauth_in_tenant`. Each revocation writes two rows
under one `request_id`: `factor_kind` names the provider, and `user_id` and
`tenant_id` are the session's. The request row, written before the provider is asked, is a
`Failure` whose `error` is `oauth_token_revocation_requested`
(`OAUTH_REVOCATION_REQUESTED_REASON`), so a request with no recorded outcome
never reads as a revoked token. The outcome row is a `Success` when the
provider revoked the token, and a `Failure` whose `error` starts with
`oauth token revocation refused` when it refused, or with
`oauth token revocation unconfirmed` when it did not answer.

A session that idles out belongs to the `SessionStore` implementation: the
row's TTL removes it, no request is on the call path, and a
`SessionExpired` row for it is the adopter's to write. `SessionInvalidated`
is written by the `invalidate_session` and `invalidate_user_sessions`
methods of the request-scoped authentication service, which take an `Actor`,
end the sessions and then record the user, the session when one was named
and the acting administrator (none for `Actor::System`).

`invalidate_other_sessions` ends every session of a user but the one it is
told to keep, revokes the user's refresh tokens, and writes one row for the
user, with no session. The row is a `Success` when the registry ended the
other sessions and the refresh tokens were revoked (or the service has no
refresh token store, or the caller kept them by calling
`invalidate_other_sessions_keeping_refresh_tokens`). When the registry did
not confirm that it ended the sessions, the row is a `Failure` whose `error`
is `other_sessions_not_ended` (`OTHER_SESSIONS_NOT_ENDED_REASON`): they may
still be live. When the sessions were ended and the refresh tokens could not
be revoked, it is a `Failure` whose `error` is `refresh_tokens_not_revoked`
(`REFRESH_TOKENS_NOT_REVOKED_REASON`).
When another request carrying the same cookie had moved the kept session
to a new key before the call, every session of the user is ended,
that one included, and the row is the same `Success`; the call then
returns `OtherSessionsError::CallerEnded`.

The back-channel logout handler ends sessions on the IdP's word, with no
administrator and no user request. It writes a row for each session it ends
when given a hook: pass `authn.backchannel_logout_audit()` to
`BackChannelLogoutHandler::with_audit`, and each session gets a
`SessionInvalidated` row naming the user and the session, with no actor and
no client address. Without the hook, axess does not record the logout. A
failing audit write is logged and does not undo the logout.

The session layer ends a signed-in session (an authenticated one, or one in
a step-up of it) by itself in seven cases. Three are met on the next request
that presents the session: it outlived an absolute age cap
(`with_max_session_age`, or `with_max_impersonation_age` for an
impersonation), the registry no longer holds it (for an impersonation, no
longer holds the entry registered under its administrator), or device keys
are required (`KeyBindingPolicy::Require`) and it is still not bound to a
key when its registration window, which runs from its login, has passed.
Three are
met at the end of a request that rotated the session's id: the session was
revoked while the id rotated, the registry could not register or confirm
the rotated id (under `UnknownLiveness::Reject`, the default), or the
session store could not move the session to its new id. The seventh is
met by the session validator (`SessionValidator::enforce`, which
`require_valid_session` runs): the identity store
does not confirm the tenant the session names for its user.

Each of these endings is one row, written through the audit sink every
`SessionLayer` constructor takes: pass `authn.session_end_audit()`. The row
names the user, the tenant and the session, and carries the reason in
`error`. The tenant is the one the session signed in to, read from the
session itself, so the row is the same for a user who has been deleted
since. The actor is the administrator when the session carried an
impersonation, whatever the reason it ended, and empty otherwise. No row
has a client address: the client whose request met the session did not end
it.

| ending | event | status | `error` |
|---|---|---|---|
| the session's age cap | `SessionExpired` | `Expired` | `session_age_cap` |
| the impersonation's age cap | `SessionExpired` | `Expired` | `impersonation_age_cap` |
| the registry no longer holds the session (at the load, or in the session validator) | `SessionInvalidated` | `Success` | `session_not_registered` |
| the registry no longer holds the administrator's entry | `SessionInvalidated` | `Success` | `impersonation_not_registered` |
| the session was revoked while its id rotated | `SessionInvalidated` | `Success` | `session_revoked_during_rotation` |
| the registry could not track the rotated id | `SessionInvalidated` | `Success` | `session_not_tracked` |
| the store could not rotate the session | `SessionInvalidated` | `Success` | `session_rotation_failed` |
| device keys are required and the session is still not bound | `SessionInvalidated` | `Success` | `key_binding_required` |
| the session validator: the identity store does not confirm the session's tenant | `SessionInvalidated` | `Success` | `session_tenant_not_confirmed` |

The audit row comes first. The layer calls the sink while the session is
still stored, and removes the stored session only when the sink has answered. While the
audit write fails, a session past an age cap, gone from the registry or past
its key registration window unbound stays stored and is refused on every
request: the request runs as a guest, the client keeps its cookie, and
each request that presents the session tries the write again. A session to be ended at the end of a rotating request keeps its row
and its cookie when the write fails, and the next request that presents it
meets the registry again: a session the registry does not hold is ended
there, with its row. A session left stored this way and never presented
again idles out with its row's lifetime, as any abandoned session does, and
that expiry has no row (see the idle case above). The work runs in a task
of its own, so a client that disconnects in the middle of a request loses
neither the row nor the ending.

The session a row names is the one whose stored row the layer removes. For
a session revoked or untracked while its id rotated, that is the rotated id,
where the row has moved by then. When the store could not move the row, the
same user's session is named by the id it had before the request. A login
whose rotation failed is named by the id the login registered, which no row
ever held. A request that changed who the session is (the start or the end
of an impersonation) and could not rotate leaves two rows, one for the
stored session it ended and one for the session that was to replace it.

One ending is one row. Several requests that carry the same ended cookie at
once write one between them: the layer claims the session with a
compare-and-swap on its row (`SessionData::ending`) before it calls the
sink, one request wins the claim, and the others are refused the session and
write nothing. The claim is the decision to end the session, and it keeps
the reason. A request that finds a claim more than thirty seconds old (the
request that made it stopped, or the session store failed to remove the
row) finishes the ending for that reason, whatever the checks would say of
the session by then: a claimed session is never served again.

That is where one ending can leave two rows: the first request wrote its
row and the session's row was not removed, and the request that finishes
the ending writes the row again. The two rows differ in `event_time` and in
nothing else: the same `session_id`, user, tenant, actor and `error`.
`session_id` is the session's key, the 64 hexadecimal characters the
session table, the registry and the logs name the session by, and it is
the identifier of the ending. One session has one key at a time, a key is
never issued twice and the layer ends a session once, so a consumer keeps
the first row for each `session_id` among the rows whose `error` is one of
the nine
reasons above, and drops any later one. The same holds for a session ended at
the end of a rotating request whose row the store then failed to remove: its
row stays claimed with its reason, and a later request that presents it
writes the same row again, the same reason included.

The row of a kick and the row of a back-channel
logout name the session as well; they carry no `error` and are rows of
their own. The row of a kick names the key the session was under when it
ended: a kick may name a key the session held before a rotation, and the
row names the key it rotated to. The `LogoutAttempt` row of
`RequestAuthnService::logout` names the key whose registry entry the logout
ended (`AuthSession::registered_key`): after a rotation earlier in the same
request that the registry has not followed yet, the key the request arrived
with, not the key the session carries. The row of a back-channel logout names the
key the session's login registered, which the session may have rotated away
from before the logout ended it. A back-channel logout for a session that
had already ended writes no row.

Two endings can leave no row, each only when two things fail at once. When
the session store cannot rotate the session of a login and the audit write
fails too, no session exists, since none was ever stored, and no
`session_rotation_failed` row says so. What is lost is the record that the
login, whose own rows are in the trail, left no session; the layer logs
the audit error at `error` with the reason. When a session store that
rotates in two steps has removed the old row before it fails, and the audit
write fails too, the stored session is gone without its
`session_rotation_failed` row. The layer logs the audit error and, at
`error`, that the session is gone without an audit row. It does not write
the old session back, which could return a session a concurrent logout
removed.

A kick through the audited methods removes the stored rows itself when the
service was given the session store (`with_session_store`), and the layer
then never meets the session. Without the store the kick ends the session
in the registry only, and it leaves two rows for a session that is
presented again: the kick's, naming the administrator, when it happened,
and the layer's `session_not_registered` row when the layer met the session
and removed its row. A session ended in the registry and never presented
again has only the first.

A layer that records none of this says so by name: build it with
`UnrecordedSessionEnds::insecure()`, which logs at `error` when it is
called; its endings are then logged and not recorded. An application with a
sink of its own implements `SessionEndAudit` instead of passing the
service's.

A request that fails the session binding check is not an ending: the
request is refused the session and runs as a guest, the stored session
stays for the client it is bound to, and no row is written. Neither is a
request that meets a registry that cannot answer: under
`UnknownLiveness::Reject` it runs as a guest and the session stays stored. Axess
does not record a session ended by any path other than these methods, the
back-channel hook or the layer's sink.

### Devices

| variant | wire string | emitted by |
|---|---|---|
| `DeviceFirstSeen` | `device_first_seen` | axess |
| `DeviceRevoked` | `device_revoked` | adopter |
| `DeviceBindingAdded` | `device_binding_added` | axess |
| `DeviceTrustGranted` | `device_trust_granted` | axess, from `DeviceLifecycleService::grant_trust`; adopter, for a level set through the store |
| `DevicePurged` | `device_purged` | adopter |
| `DeviceFingerprintMismatch` | `device_fingerprint_mismatch` | adopter |
| `DeviceKeyRegistered` | `device_key_registered` | axess |
| `DeviceKeyProofRefused` | `device_key_proof_refused` | axess |
| `SessionKeyBound` | `session_key_bound` | axess |

The last three belong to device keys (the `device-keys` feature) and are
written through the sink given to `DeviceKeyService::with_event_sink`.
`DeviceKeyRegistered` is a `Success` when a device takes a key and a
`Failure` whose `error` names why a registration was refused
(`proof_refused`, `not_owner`, `already_registered`). `SessionKeyBound`
records the session layer binding a session to a device key, at a
registration or on a request that proved by key a device the session's user
owns. It is written once the write that stores the binding has landed, and
not at all for a binding whose write did not land (the session was ended
meanwhile, the write lost to concurrent writes or failed). For an
impersonated session the device is the administrator's, and the row names
the administrator as actor.

`DeviceKeyProofRefused` is always `Suspicious`, and it is the one
`Suspicious` row axess writes itself. It is written when the caller holds
what was copied from the device and not the key, or sends one proof twice:
the device's current challenge came back with a signature that is not its
key's; a keyed device's refresh token was presented with no proof, with a
value that is no proof, or with another key's proof; a request proof by the
key was presented a second time; or a request that held a session bound to
the device carried a request proof by another key. A device without a key
writes none. When `KeyBindingPolicy::Require` ends a session because it never
bound, that is not a device-key row: it is one of the endings the session layer
makes by itself, written through the layer's sink as a `SessionInvalidated`
whose `error` is `key_binding_required` (see the table of those endings
above), with the administrator as actor for an impersonation.

`DeviceRevoked` is yours to write where you revoke: `revoke_device` and
the refresh-family cascade take no audit sink: they change the rows and
the tokens and return what they did.

`DeviceFingerprintMismatch` is the cookie-replay signal: a request
carried a valid device cookie whose recomputed fingerprint did not
match. Record it `Suspicious`. The stock `LifecycleDeviceResolver`
finds a device by its token and compares no fingerprint, so it never
has this to report; the name is there for a `DeviceResolver` of your
own that does compare one. See *Device identity* for what a resolver
does.

### What is not here

Authorisation gets no events of its own. A Cedar decision is not an
`AuthEvent`; it is a `tracing` event on the target
`axess::authz::decision`, carrying `principal`, `action`, `resource`,
`decision` (`allow` or `deny`), `reasons` and `latency_us`. Axess ships
no audit transport of its own, so route that target with
`tracing-subscriber` to wherever the audit goes. *Cedar providers*
covers the schema.

The catalogue covers authentication only. It has no workload-identity,
rate-limit, tenant-lifecycle or delegated-access events: those subsystems
are adopter-composed primitives with no audit sink on their call path, so
nothing is emitted for them today, and the vocabulary has no names reserved
for them either.

## Emit cadence and fields

Events are written synchronously, from the operation that produced them,
through `IdentityAuthnLog::record_event`, which the deployment implements: that is
the sink, and where it goes next is the deployment's decision. A failed
write is logged at `error` and returned as an error to the caller of the
operation it records: a login is refused, and a kick, which ends the
sessions before it writes its row, returns the error with the sessions
ended. The session layer's endings have no caller to fail and take the
other order: the row is written first, and the session stays stored, and
refused, until it can be. The back-channel logout's row is written after
the logout through its hook, where a failing write is logged and the
logout stands.

Every event is the same struct. There are no per-variant field sets:

| field | type | notes |
|---|---|---|
| `event_type` | `AuthEventType` | which operation |
| `event_status` | `AuthEventStatus` | the outcome |
| `event_time` | `i64` | epoch **microseconds**, not a `Timestamp`, so the event is rkyv-archivable end to end |
| `user_id` | `Option<UserId>` | `None` when attribution was not available, e.g. a login for a user that does not exist |
| `tenant_id` | `Option<TenantId>` | `None` when the tenant could not be identified |
| `session_id` | `Option<SessionKey>` | session-related events: the session's key, 64 hexadecimal characters (a row written before 0.20.0 holds the session id, which reads as the key of that id) |
| `factor_kind` | `Option<FactorKind>` | which factor, where one is involved |
| `device_id` | `Option<DeviceId>` | omitted from the wire form entirely when absent |
| `ip_address` | `Option<IpAddr>` | typed, so a forged or malformed value cannot be stored. `None` where nothing trustworthy resolved |
| `ip_source` | `Source` | how the address was arrived at: `unknown`, `peer`, `forwarded` or `supplied` |
| `user_agent` | `Option<String>` | from the request the context was extracted from, cut to 512 bytes (on a character boundary, with `...` appended when anything was cut) because the client sets it |
| `request_id` | `Option<String>` | the typed value the request-id layer left behind, under the `request-id` feature; `None` without it |
| `trace_id` | `Option<String>` | the W3C trace id, under the `trace-context` feature |
| `geo_country` | `Option<String>` | ISO 3166-1 alpha-2, derived from the IP |
| `error` | `Option<AuthFailureReason>` | *why* it failed, as a tag a dashboard can group by. Not the place to look for the outcome; that is `event_status` |
| `actor_id` | `Option<UserId>` | the administrator who acted on the subject's behalf, distinct from `user_id` (the subject) |
| `factors_completed` | `Vec<(FactorKind, i64)>` | on `Authenticated` events: the factors verified to reach the state, each with its time in epoch microseconds, in completion order |

Every event carries an [`AuditContext`], because the methods that write
one live on `RequestAuthnService` and the only way to hold a `RequestAuthnService` is
to have supplied a context. What the context contains is a separate
question: axess cannot resolve a trustworthy client address by itself,
since that needs the TCP peer and your trusted-proxy set. Install
`axess::client_ip::layer` and the address is there; leave it out and
`ip_address` is `None`, with `ip_source = 'unknown'` saying so; the first
query below finds those rows.

[`AuditContext`]: https://docs.rs/axess-core/latest/axess_core/authn/event/struct.AuditContext.html

Store `user_id` and `tenant_id` as nullable columns. Both can legitimately be
absent, and a schema that requires them will reject exactly the rows a
SOC most wants: the ones where the attacker was not who they claimed.

## SOC alert thresholds

The events feed SOC (Security Operations Center)
alerting. The thresholds below are starting points; tune them to the
deployment.

Rules match on the type and the status together, not on a type alone,
because the outcome lives in `event_status`.

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

Axess does not define the table. `IdentityAuthnLog::record_event` is
yours, so the column names below assume you stored the struct's field
names as they are; rename them to match your schema.

Two details are easy to miss. The values are the **wire strings**,
lower-snake-case (`login_attempt`), not the Rust variant names. And
`event_time` is **epoch microseconds as a signed integer**, not a
timestamp type, so it needs converting before any date function
touches it.

These queries assume the request path wired an `AuditContext` and that
`client_ip::layer` is installed. If either is missing, `ip_address` is NULL and
the IP-keyed queries below return one useless bucket.

Check for rows without an address:

```sql
-- Rows whose address nothing resolved. Should be zero.
SELECT event_type, COUNT(*)
FROM auth_events
WHERE ip_source = 'unknown' AND event_time > <recent>
GROUP BY event_type;
```

A non-zero count names the operations whose routes need fixing, and `ip_source` distinguishes
the two causes that look identical in `ip_address`: `unknown` means
nothing resolved an address, `peer` on a deployment that runs a proxy
means the trusted set does not name it. Run it once after wiring and
again after any route is added.

No runtime policy fails a login for a route without a context. Whether a
route attached a context at all is a compile-time property, checked by
putting the authenticating methods on a type you cannot construct without
a context. Such a policy also could not tell how much a context contains,
so a context carrying no address would satisfy it. The query above answers
the case the type cannot: a route that attached a context while the layer
was missing.

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
-- within the hour. The mismatch comes from your DeviceResolver, so this
-- returns nothing unless you emit it. Axess writes the trust grant from
-- DeviceLifecycleService::grant_trust.
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

The queries are written in PostgreSQL's dialect (`DATE_TRUNC`,
`TO_TIMESTAMP`, `EXTRACT(EPOCH FROM ...)`). Translate them for the
deployment's tool: ClickHouse SQL spells some of the time functions differently,
and Splunk SPL and the Sumo Logic query language are not SQL.

## Extending the catalogue

You cannot add an `AuthEventType`. It is a closed enum in
`axess-core`, and the wire strings are a contract the crate's own
tests pin, so a new variant is an axess change and a breaking one.

What you can do is own the sink. `IdentityAuthnLog::record_event` is
yours to implement, and every axess event arrives there before it goes
anywhere. A domain event of your own (a fund transfer, a configuration
change, a sensitive read) can be written to the same table, through the
same connection, in the same transaction if you want it atomic with the
thing it records. Axess leaves you to it: `record_event` takes only an
`AuthEvent`, and axess ships no audit transport. The envelope `Event<P>`
and the `EventPayload` trait in `axess-events` carry domain payloads to
an `EventSink`, which *Audit pipeline* places on the analytics stream, not
through this sink.

The trade-off is schema. An event type your SIEM does not know about
feeds no dashboard and fires no alert, so agree the shape with whoever
owns the SIEM before you start writing rows.

## Answering an auditor

The catalogue is what makes a deployment answerable to an auditor: who
authenticated, when, from where, and what was refused. The events are
typed, the wire strings are stable, and the sink is the deployment's
own, so the trail lives wherever the rest of the compliance evidence
already lives.

The trail has limits. Authorisation decisions go to a
`tracing` target rather than the audit trail; workload identity, rate
limiting, delegated access and tenant provisioning emit nothing; and
three of the vocabulary's names are for glue you implement, with four
more that axess writes on its own paths and leaves to you on the others,
so they only appear there if you emit them. *Audit pipeline* covers how events flow from
the application to storage.

## Further reading

*Audit pipeline* covers the dual-stream architecture (regulatory
plus analytics), the hot/cold retention tiering, and the
reliability of the asynchronous dispatch. *Multi-tenancy*
covers the tenant-scoped routing of events. *Cedar policy
fundamentals* covers the policy evaluator, whose decisions go to the
`axess::authz::decision` tracing target rather than to an audit row. *Security posture* covers the GDPR and PCI-DSS
posture for audit-event PII.
