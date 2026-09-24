# Schema migration

The `SessionData` struct can change between axess versions. New
fields get added, old fields get renamed or removed, the auth state
machine gains a new variant. Existing sessions in the store carry
the old shape; new code reads them and needs to produce the new
shape. The mechanism that bridges the two is the schema migration
on read.

This is a short chapter because the mechanism is small. The
mechanism is small because the design pushes the version field
into the data itself rather than into the store.

## The version field

`SessionData::version` is a `u8` set at construction and serialised
with the rest of the data. The current value is the
`SESSION_DATA_VERSION` constant. At read time the deserialiser fills
in whatever a newer field's `#[serde(default)]` supplies, and
`migrate` then walks the row forward one version step at a time.

```rust,ignore
pub const SESSION_DATA_VERSION: u8 = 2;

pub struct SessionData {
    #[serde(default = "default_version")]
    pub version: u8,
    pub auth_state: AuthState,
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    pub custom: serde_json::Value,
}

impl SessionData {
    /// Returns whether anything changed, so the caller knows to re-save.
    pub fn migrate(&mut self) -> bool {
        if self.version >= SESSION_DATA_VERSION {
            return false;
        }
        // v1 -> v2: added `device_id`. The field's serde default already
        // supplied `None`, so the only work is bumping the version so a
        // re-save records the current schema.
        // ... one arm per step, each bumping `self.version` itself.
        true
    }
}
```

Three properties of that shape are worth stating.

It migrates in place, `&mut self`, and returns whether anything
changed. That boolean is the signal to persist: a row already at the
current version is not rewritten, so a deploy does not rewrite every
session in the store on first read.

Each version step bumps `self.version` itself, and there is no
unconditional assignment to `SESSION_DATA_VERSION` at the end. The
trailing assignment is tempting and wrong: it makes every step look
correct from the outside, because the version ends up right whether or
not the step ran. Bumping per step keeps each one observable, which is
what lets a mutation test tell "this branch runs" from "this branch is
dead".

Most steps do nothing but bump. A field added with
`#[serde(default)]` is already correct in memory by the time `migrate`
sees it; the migration exists to record that the row has been read
under the new schema. Real transformation work only appears when a
field changes meaning rather than merely appearing.

The migration functions are pure transformations. They take the
old shape (which serde has parsed against an older `SessionData`
definition, possibly with the version-bumped fields defaulted)
and produce the new shape. Each migration handles one version
step; chained migrations are run in sequence to bridge multiple
version gaps.

The version is bumped every time the shape changes in a way that
older code would not handle correctly. Adding an optional field
with a `Default` impl typically does not bump the version (older
code reads `None`, which is fine). Removing or renaming a field
does. Changing the meaning of a field does.

## What migrations cannot do

A migration is a pure function on the serialised bytes. It cannot
talk to a database, cannot consult the user store, cannot make
network calls. The version of the data is determined entirely by
what is in the cookie's session record at the moment of read.

The implication: if a new shape needs information that the old
shape did not carry, the migration cannot synthesise it. The
options are to default the field (set it to `None`, or to a known
placeholder), to discard the session (the migration returns an
error, the layer treats the session as invalid and starts a fresh
one), or to defer the population (the field is set later in the
request lifecycle from your own stores).

The first option is the standard pattern. New fields get
sensible defaults, the session continues to work with the new
shape, and you populate the real value on the next
dirty write.

## When the session is invalidated

Sometimes the shape change is breaking in a way that no migration
can bridge. The session's data refers to a user who has been
deleted, the auth state references a tenant that no longer exists,
the factor list contains a kind that the new version has removed.
The migration's right response is to error, and the layer's right
response is to treat the session as invalid.

The mechanism is the `SessionData::deserialize` path returning
`Err`. The session layer catches the error, deletes the session
row (or marks it expired), and treats the request as a fresh
`Guest`. The user's cookie is still valid; the next request sets
a new session, the user logs in again.

The pattern is the right one because the alternative (the layer
falling through to a degraded state, leaving the session in an
inconsistent shape) lets bugs persist for the lifetime of the
session. Invalidating eagerly converts the bug into a one-time
user-facing event (re-login) that is fixable in one round-trip,
rather than a long-tail bug that surfaces sporadically.

## Adding a custom field

Adopters who add their own fields to `SessionData::custom` follow
the same pattern in their own code. The `custom` value is
JSON-shaped; each application-owned key is independently
versioned by you.

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
        .map(|d| d.migrate_if_needed())
        .unwrap_or_default()
}
```

The application's own version field is independent of axess's. The
two evolve on different cadences, and your own version field
captures your changes.

## When to reach for a different mechanism

The schema migration is the right tool for evolutions of the
session data shape. It is the wrong tool for migrations between
storage backends (use the cross-backend `Store<K, V>` trait or a
one-off copy script) or for changes to the encryption envelope
(the key-rotation mechanism, covered in *Operations runbook*).

It is also the wrong tool for application-level data migrations
that touch the database. A migration that says "every user gains
a new field on their user record" runs against the user store
(via `sqlx::migrate!` or whatever migration tool you use), not
against the session store. The session machinery does not interact
with the user table.

The mechanism's scope is narrow on purpose. Each piece of state
has its own evolution mechanism, and conflating them produces
migrations that have to consider too many cases at once.

## Further reading

*Session lifecycle and crypto envelope* covers the lifecycle that
the migration runs as part of. *Backends* covers the storage
backends and their own (database-level) migration mechanisms.
*Migration guide* in Part VIII covers the cross-axess-version
migrations that bump the `SESSION_DATA_VERSION` constant.
