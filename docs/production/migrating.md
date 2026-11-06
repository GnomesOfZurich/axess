# Migration guide

Find your version below; the newest is first. Each break is listed by
**what you will see** rather than by what we changed, because a compile
error, a failed deserialization and a behaviour that quietly differs
send you looking in different places. Each one names the symptom and the
fix.

The behaviour changes are the ones to read closely. Nothing tells you
about those.

## One file per step

Each step from one release to the next is its own page, newest first; read
the steps between your version and the one you move to, in order. A step
names what you will see (a compile error, a failed read, a quietly different
behaviour) and the fix beside it.

| From | To | Page | Lines |
|---|---|---|---|
| 0.15.0 | 0.16.0 | [`0.15.0-to-0.16.0.md`](migrating/0.15.0-to-0.16.0.md) | 364 |
| 0.14.0 | 0.15.0 | [`0.14.0-to-0.15.0.md`](migrating/0.14.0-to-0.15.0.md) | 154 |
| 0.13.0 | 0.14.0 | [`0.13.0-to-0.14.0.md`](migrating/0.13.0-to-0.14.0.md) | 227 |
| 0.12.0 | 0.13.0 | [`0.12.0-to-0.13.0.md`](migrating/0.12.0-to-0.13.0.md) | 273 |
| 0.11.0 | 0.12.0 | [`0.11.0-to-0.12.0.md`](migrating/0.11.0-to-0.12.0.md) | 91 |
| 0.10.0 | 0.11.0 | [`0.10.0-to-0.11.0.md`](migrating/0.10.0-to-0.11.0.md) | 142 |
| 0.9.0 | 0.10.0 | [`0.9.0-to-0.10.0.md`](migrating/0.9.0-to-0.10.0.md) | 94 |
| 0.8.1 | 0.9.0 | [`0.8.1-to-0.9.0.md`](migrating/0.8.1-to-0.9.0.md) | 75 |
| 0.7.0 | 0.8.0 | [`0.7.0-to-0.8.0.md`](migrating/0.7.0-to-0.8.0.md) | 55 |
| 0.6.0 | 0.7.0 | [`0.6.0-to-0.7.0.md`](migrating/0.6.0-to-0.7.0.md) | 191 |
| 0.5.0 | 0.6.0 | [`0.5.0-to-0.6.0.md`](migrating/0.5.0-to-0.6.0.md) | 297 |
| 0.4.0 | 0.5.0 | [`0.4.0-to-0.5.0.md`](migrating/0.4.0-to-0.5.0.md) | 90 |
| 0.2.2 | 0.3.0 | [`0.2.2-to-0.3.0.md`](migrating/0.2.2-to-0.3.0.md) | 45 |
| 0.2.0 | 0.2.1 | [`0.2.0-to-0.2.1.md`](migrating/0.2.0-to-0.2.1.md) | 19 |
| 0.1.x | 0.2.0 | [`0.1.x-to-0.2.0.md`](migrating/0.1.x-to-0.2.0.md) | 153 |

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
