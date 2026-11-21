# Schema migration

The `SessionData` struct can change between axess versions. Fields are added, renamed or removed, and the auth state machine gains variants. Axess does not carry a stored session
across such a change: a row is read only in the shape the running
release writes, and a row written under an earlier schema version is
not served. Its holder signs in again.

This is a short chapter because there is no mechanism to describe
beyond the version field and what a row below it does.

## The version field

`SessionData::version` is a `u8` set at construction and serialised
with the rest of the data on every save. The current value is the
`SESSION_DATA_VERSION` constant; a row with no `version` member reads
as 1.

```rust,ignore
pub const SESSION_DATA_VERSION: u8 = 3;

pub struct SessionData {
    #[serde(default = "default_version")]
    pub version: u8,
    pub auth_state: AuthState,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    pub custom: serde_json::Value,
    // ... `device_proven` (never stored), `revision`, `touched_at`,
    // `key_binding` and `ending`.
}
```

The history of the field: version 1 was the first schema, version 2
added `device_id`, and version 3 added the pending state's `flow`, the
signed-in state's `signed_in_at` and the session's `key_binding`.

## What a row below the version does

The stores that share the session codec (SQLite, PostgreSQL, MySQL and
Valkey) read the version of a row before the rest of it. A row below
`SESSION_DATA_VERSION` is not decoded: the store hands up its version
alone, and never re-seals or writes it back. The memory store holds
typed rows and hands the version up as it was saved.

The session layer refuses such a row whatever state it carries. The
request runs as a fresh guest, as for a row the store does not hold,
and the row is left untouched: not written, not deleted and not claimed, so no ending is made outside the ending protocol and no audit
row names it. It expires with its lifetime. The refusal is counted
(`SessionMetrics::session_row_refused`) and logged at `warn`:

```text
WARN a stored session below the current schema version was not served session=4be3d46f... version=2 current=3
```

`session` is the first eight characters of the session's key, never
the id a cookie carries; the line holds nothing else of the row.

Every later read of the row in the same request refuses it too: the
merge of a rotation, the merging write of a changed session, the
release of an ending claim and the ending of a failed rotation. A row
put under the key while the request ran is therefore never served,
merged, released or ended; each step treats it as a store error, a case it already handles.

A row of a higher version is served, because during a rolling upgrade to a later release an older node must read rows a newer node wrote.

A store of your own whose decoder fails on a row below the version
reports its own error instead; the request is a guest all the same,
and nothing is counted.

## One shape is read

The reader of `AuthState` reads the shape this release writes and no
other. A field the writer always writes is required: a pending state's
`flow` (`login`, or `{"step_up": {"signed_in_at": ...}}`), its
`remaining` steps and timed `completed` factors, and a signed-in
state's `signed_in_at` and timed `factors_completed`. A field the
writer skips when it is empty (`ldap_groups`, `impersonator`,
`assurance`) reads as empty when it is absent. A row in any other
shape, whatever version it carries, fails to decode in the store's
`load`, and the request is a guest.

A row that does not decode is logged by the session layer at `warn`
and the request runs as a fresh `Guest`; the row is not deleted and
stays until its expiry or the next cleanup. The layer cannot tell a
row that will never decode from a store that is down for a moment, so
it does not replace the cookie either: the client keeps presenting it,
and each request fails the load and logs the warning again, until a
response stores a session for the guest and sets its cookie. For most applications that is the login; for one whose pages mint a CSRF token it comes earlier.

A row that decodes and no longer means anything (its user was
deleted, its tenant is gone) is ended by the account-status check on
the request path, or by the session registry.

## After an upgrade

Every session the previous release stored is signed out once at the upgrade. Watch `session_row_refused` through the upgrade window: it
rises while clients present cookies of the earlier release's
sessions, and falls to zero as they sign in again. A count above zero after the window means something other than this library writes rows to the session store. The upgrade from 0.19.0 to 0.20.0 is the exception: the count stays at zero, because 0.20.0 names a stored row by the session's key, a digest of its id, and finds no row 0.19.0 stored under the id.

A rollback serves a row the new release stored only if the earlier release decodes it in the shape that release reads (see "One shape is read"). A rollback from 0.20.0 to 0.19.0 finds none of the sessions 0.20.0 stored, because 0.19.0 looks a row up by the session id.

## Adding a custom field

Adopters who add their own fields to `SessionData::custom` version
them in their own code. The `custom` value is JSON; you version each application-owned key independently.

The common pattern is to wrap the custom value in a small struct
with its own version field:

```rust,ignore
#[derive(Serialize, Deserialize)]
struct MyAppSessionData {
    schema_version: u32,
    preferences: UserPreferences,
    feature_flags: Vec<String>,
    draft_form_state: Option<DraftForm>,
}

fn read_app_data(session: &SessionData) -> MyAppSessionData {
    session
        .custom
        .get("my_app")
        .and_then(|v| serde_json::from_value::<MyAppSessionData>(v.clone()).ok())
        .map(|d| d.upgrade_if_needed())
        .unwrap_or_default()
}
```

The application's version field is independent of axess's: the two change on different schedules, and yours records your changes.

## When to reach for a different mechanism

The version field covers the shape of the session data. It is not a tool for moving between storage backends, which takes a one-off copy script over the old backend's own rows (neither store trait lists them), or for changes to the encryption envelope, which the key-rotation mechanism handles (see *Operations runbook*).

Nor is it a tool for application-level data migrations that touch the
database. A change that says "every user gains a new field on their
user record" runs against the user store (via `sqlx::migrate!` or
whatever migration tool you use), not against the session store. The
session machinery does not interact with the user table.

## Further reading

*Session lifecycle and crypto envelope* covers the load this check is
part of. *Backends* covers the storage backends and their own
(database-level) schema statements. *Migration guide* in Part VIII
covers each release's breaking changes, the ones that raise
`SESSION_DATA_VERSION` among them.
