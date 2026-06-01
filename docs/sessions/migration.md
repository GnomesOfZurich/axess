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

`SessionData::schema_version` is a `u32` field set at construction
and serialised with the rest of the data. At read time the
deserialiser inspects the version, dispatches to the appropriate
migration function for that version, and produces a current-shape
`SessionData`.

```rust,ignore
pub struct SessionData {
    pub schema_version: u32,
    pub auth_state: AuthState,
    pub principal_hint: Option<PrincipalHint>,
    pub custom: HashMap<String, serde_json::Value>,
}

impl SessionData {
    const CURRENT_VERSION: u32 = 2;

    fn migrate(self) -> Self {
        match self.schema_version {
            0 => migrate_from_v0(self),
            1 => migrate_from_v1(self),
            _ => self,  // current, no migration needed
        }
    }
}
```

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
request lifecycle from the application's stores).

The first option is the standard pattern. New fields get
sensible defaults, the session continues to work with the new
shape, and the application populates the real value on the next
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
the same pattern at the application layer. The `custom` map is
JSON-shaped; each application-owned key is independently
versioned by the application.

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

The application's `schema_version` is independent of axess's. The
two evolve on different cadences and the application's version
field captures the application's own changes.

## When to reach for a different mechanism

The schema migration is the right tool for evolutions of the
session data shape. It is the wrong tool for migrations between
storage backends (use the cross-backend `Store<K, V>` trait or a
one-off copy script) or for changes to the encryption envelope
(the key-rotation mechanism, covered in *Operations runbook*).

It is also the wrong tool for application-level data migrations
that touch the database. A migration that says "every user gains
a new field on their user record" runs against the user store
(via `sqlx::migrate!` or the application's migration tool), not
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
migrations that bump the `SessionData::schema_version` constant.
