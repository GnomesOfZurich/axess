# Migration guide

This chapter is the cross-version migration reference. Each axess
release that ships a breaking change documents the change here,
with the symptom (what the compiler or the runtime will tell you),
the rationale (why the change happened), and the fix (what to
update in adopter code). The pattern is ordered by version, with
the most recent breaks first.

The chapter is sorted by what you will see, not by what we
changed. A breaking change manifests as either a compile error
(the type system rejected something it accepted before), a runtime
error (a deserialization fails, a config rejects), or a behaviour
change (the same code does something subtly different). The
sections below group by symptom; finding your case is faster than
reading the full changelog.

## 0.2.0 to 0.2.1

`v0.2.1` is a patch release. The only behavioural change is a
CSRF hardening: the double-submit token now binds to the session
id (`HMAC(signing_key, nonce || session_id)`) rather than to the
signing key alone, and `CsrfLayer` fails closed with 403 when the
session-id extension is missing on a state-changing request. Two
adopter-facing consequences:

Adopters MUST layer `CsrfLayer` inside (i.e. run after) the
session layer so the `SessionHandle` request extension is present
by the time CSRF validation runs. In `axum`, later `.layer(...)`
calls wrap earlier ones, so `.layer(csrf).layer(session_layer)`
is the correct order. Stacks that had the layers in the opposite
order silently validated an unbound token before 0.2.1; that shape
now returns 403.

Clients that cache the CSRF token across a session change (login,
session regeneration) MUST re-read the token after the change or
their first post-change state-changing request will 403. Tokens
minted under one session id no longer verify against another.

## 0.1.x to 0.2.0

The first crates.io publish is the 0.2.0 release. The accumulated
changes since the previous stable line are catalogued
exhaustively in
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md);
this chapter covers the breaking ones an adopter has to act on.

### Compile errors you will see

`use axess::PolicyStore` becomes `use axess::AuthzStore`. The
authorisation entry point was renamed for consistency with the
`Authz*` prefix convention. The new name better describes what
the type is (an immutable store of policies plus schema, not
just a policy collection).

`use axess::AxessSession` becomes `use axess::AuthSession`. The
session extractor was renamed; the new prefix is the shared
`Auth*` prefix from the naming conventions (*Architecture at a
glance*).

`use axess::backends::SqliteStore` becomes
`use axess::backends::sqlite::SessionStore`. The backend module
layout was reorganised so the same trait name (`SessionStore`)
appears under each backend's namespace; the previous flat
`SqliteStore` symbol no longer exists.

`AuthnService::new(backend)` becomes
`AuthnService::new(identity_store, factor_store)`. The service
now takes the two stores separately so adopters can wire
different implementations (for instance, a read-replica
identity store and a write-only factor store). When the two
stores are the same type (the common case), pass it twice.

`SessionLayer::with_secret` becomes
`SessionLayer::with_signing_key`. The previous name was
ambiguous; the new name names what the bytes are used for
(HMAC signing the cookie).

`AuthState::Logged` becomes `AuthState::Authenticated`. The
state was renamed for clarity; nothing else changed about the
variant.

### Configuration changes

The `axess_factors_default_password_hasher` config function is
gone. Argon2id is now the default; deployments that need a
different hasher (PBKDF2, legacy bcrypt) implement a custom
factor and register it. *Factors and methods* covers the
extension pattern.

The `AuditPipeConfig` shape changed. The `sinks: Vec<Box<dyn Sink>>`
field was replaced with explicit `regulatory_sink: Arc<...>`
and `analytics_sink: Option<Arc<...>>` fields, reflecting the
dual-stream architecture from *Audit pipeline*. The change
makes the wire-stable vs. enriched stream distinction explicit
in the config.

The `RateLimitConfig` no longer accepts a `key_fn` field
directly; use `KeyExtractor::Custom(Arc<dyn KeyExtractorFn>)`
to provide a custom extractor, or use one of the built-in
variants (`PeerIp`, `SessionId`, `UserId`, `TenantId`,
`WorkloadId`, `Composite`). The change is to make the common
cases discoverable without losing the escape hatch.

### Behaviour changes

The `Authenticating` state now carries a `Vec<FactorKind>` for
`remaining` rather than the previous `Option<FactorKind>`. The
change is what enables multi-factor methods longer than two
factors. Code that pattern-matched on `Some(kind)` needs to
adapt to `remaining.first()` or to iterate over the list.

The lockout policy now defaults to per-IP in addition to
per-user and per-tenant. The previous default only locked the
user; the new default also throttles the source IP. Deployments
that explicitly want only per-user lockout configure
`LockoutPolicy::per_user_only()`.

The session cookie's `SameSite` attribute now defaults to `Lax`
rather than `Strict`. The change is to match modern browser
defaults and to admit cross-site link-to-app navigations as
legitimate. Deployments that need `Strict` configure it
explicitly.

The fingerprint binding now defaults to `FingerprintPolicy::Warn`
rather than `FingerprintPolicy::Reauth`. The new default is
quieter during initial rollout. Production deployments that
want stricter posture lift to `Reauth` or `Revoke` after
calibrating the warn rate (*Cookies, fingerprinting, hijack
detection* covers the calibration).

### Schema migrations

The `users` table gained a `tenant_status` field for the
tenant-suspension support. The migration is a single ALTER TABLE
that adds the column with a default value. The
[`examples/sqlite/migrations/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite/migrations)
shows the SQL.

The `devices` table gained a `fingerprint_hash` field and lost
the previous `fingerprint_raw` field. The migration is destructive:
the `fingerprint_raw` field carried PII that the new design
hashes before storage (*Device identity* covers the rationale).
Adopters who want to preserve the audit trail of past fingerprints
write the migration accordingly; adopters who do not, just
drop the column.

The `authn_attempts` table gained an `event_kind` enum field
that distinguishes between attempt outcomes, rather than relying
on a separate `outcome` string. The migration is non-destructive;
the `outcome` field stays for backward compatibility and is
populated from `event_kind` automatically.

The session-data schema version bumped from 1 to 2. The new
version adds a `device_id` field on `Authenticated` (for the
device-binding work covered in *Device identity*). The
schema-migration code (*Schema migration*) handles existing
sessions transparently; no manual data migration is needed.

### Workspace structure changes

The `axess-delegated` crate folded back into `axess-core`. The
adopter import paths stay the same (`axess::delegated::*`
continues to work through facade re-export); the
`Cargo.toml` no longer needs an explicit `axess-delegated`
dependency, just the `delegated` feature on `axess`. The
workspace dropped from 11 to 10 library crates.

### Recommended migration sequence

For deployments running on the 0.1.x line:

The first step is to read this chapter end-to-end. Make a
checklist of every change that applies to your code.

The second step is a parallel-deploy approach. Stand up a 0.2.0
build alongside the production 0.1.x; route a small fraction of
traffic to it; observe behaviour. The session cookies between
the two versions are not compatible (the schema-migration
mechanism handles cookie reads but not writes across major
versions), so the parallel deploy needs to be on isolated
session storage.

The third step is the cutover. Once the 0.2.0 build has been
green for at least the session TTL on the production-like
sample, route 100% of traffic to it. The 0.1.x build can be
decommissioned after a roll-back window has passed without
incident.

The roll-back path: if 0.2.0 surfaces problems, route traffic
back to 0.1.x; the sessions that started under 0.2.0 will be
invalid against 0.1.x and will land as `Guest`, prompting
re-login. The user-visible impact is one re-login; the
behavioural impact is bounded.

## Future migrations

The pattern from 0.2.0 to 0.2.1 is the pattern future migrations
will follow. Each migration documents itself here, sorted by
release. The pattern:

Symptom: what the compiler or the runtime will tell you.

Rationale: why the change happened. Most changes happen because
the previous shape was wrong in a specific way (a footgun, a
performance bug, a security gap, an inconsistency with the rest
of the library). The rationale gives the explanation; the next
section gives the action.

Action: what to update in adopter code. The action is the
shortest possible change that satisfies the new shape; longer
restructurings are flagged as optional improvements.

A typical migration entry runs five to ten lines for a
small change, a few paragraphs for a larger one. The chapter
grows additively; older migrations are not removed.

## What does not migrate

Some adopter changes do not produce a migration entry. The
patterns:

Behaviour that was bug-fixed. A previous version's incorrect
behaviour might have been load-bearing for an adopter who built
around it; the fix is still the right thing to do, and the
adopter has to adapt. The fix appears in the changelog as a
bug fix; if the bug-fix is large enough to warrant a migration
entry, it lands here, but not all of them do.

Internal refactors that do not change the public API. The
internal split between `axess-core` modules is free to
reorganise without producing a migration entry, as long as the
public re-exports stay stable.

Configuration defaults that change but are configurable. A
default that flipped is a behaviour change, captured above. A
default that is configurable in both directions and the
configuration is the source of truth does not produce a
migration entry; the adopter's existing configuration continues
to apply.

## Further reading

*Schema migration* covers the per-session schema migration
mechanism that handles session-data shape changes. The
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md)
covers the exhaustive list of changes per release; this chapter
is the curated migration subset. *Security posture* covers the
security-relevant breaking changes specifically, with the
disclosure protocol for security fixes.
