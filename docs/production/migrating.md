# Migration guide

Find your version below; the newest is first. Each break is listed by
**what you will see** rather than by what changed, because a compile
error, a failed deserialization and a behaviour that quietly differs
send you looking in different places. Each one names the symptom and the
fix.

Read the behaviour changes closely: neither the compiler nor a failed
read tells you about those.

## One file per step

Each step from one release to the next is its own page. Read the steps
between your version and the one you move to, in order.

| From | To | Page | Lines |
|---|---|---|---|
| 0.19.0 | 0.20.0 | [`0.19.0-to-0.20.0.md`](migrating/0.19.0-to-0.20.0.md) | 3412 |
| 0.18.0 | 0.19.0 | [`0.18.0-to-0.19.0.md`](migrating/0.18.0-to-0.19.0.md) | 316 |
| 0.17.0 | 0.18.0 | [`0.17.0-to-0.18.0.md`](migrating/0.17.0-to-0.18.0.md) | 428 |
| 0.16.0 | 0.17.0 | [`0.16.0-to-0.17.0.md`](migrating/0.16.0-to-0.17.0.md) | 111 |
| 0.15.0 | 0.16.0 | [`0.15.0-to-0.16.0.md`](migrating/0.15.0-to-0.16.0.md) | 427 |
| 0.14.0 | 0.15.0 | [`0.14.0-to-0.15.0.md`](migrating/0.14.0-to-0.15.0.md) | 159 |
| 0.13.0 | 0.14.0 | [`0.13.0-to-0.14.0.md`](migrating/0.13.0-to-0.14.0.md) | 231 |
| 0.12.0 | 0.13.0 | [`0.12.0-to-0.13.0.md`](migrating/0.12.0-to-0.13.0.md) | 279 |
| 0.11.0 | 0.12.0 | [`0.11.0-to-0.12.0.md`](migrating/0.11.0-to-0.12.0.md) | 97 |
| 0.10.0 | 0.11.0 | [`0.10.0-to-0.11.0.md`](migrating/0.10.0-to-0.11.0.md) | 154 |
| 0.9.0 | 0.10.0 | [`0.9.0-to-0.10.0.md`](migrating/0.9.0-to-0.10.0.md) | 96 |
| 0.8.1 | 0.9.0 | [`0.8.1-to-0.9.0.md`](migrating/0.8.1-to-0.9.0.md) | 77 |
| 0.7.0 | 0.8.0 | [`0.7.0-to-0.8.0.md`](migrating/0.7.0-to-0.8.0.md) | 57 |
| 0.6.0 | 0.7.0 | [`0.6.0-to-0.7.0.md`](migrating/0.6.0-to-0.7.0.md) | 194 |
| 0.5.0 | 0.6.0 | [`0.5.0-to-0.6.0.md`](migrating/0.5.0-to-0.6.0.md) | 301 |
| 0.4.0 | 0.5.0 | [`0.4.0-to-0.5.0.md`](migrating/0.4.0-to-0.5.0.md) | 91 |
| 0.2.2 | 0.3.0 | [`0.2.2-to-0.3.0.md`](migrating/0.2.2-to-0.3.0.md) | 47 |
| 0.2.0 | 0.2.1 | [`0.2.0-to-0.2.1.md`](migrating/0.2.0-to-0.2.1.md) | 21 |
| 0.1.x | 0.2.0 | [`0.1.x-to-0.2.0.md`](migrating/0.1.x-to-0.2.0.md) | 145 |

## Future migrations

Each future step gets its own page in the table above, laid out as the
recent ones are: compile breaks first, each named by what the compiler
reports; then behaviour changes, which the compiler does not catch; then
changed defaults and what is new and breaks nothing; and last the
defaults and decisions the release leaves where they were.

Each entry says what you will see, why the change happened and the
shortest change to adopter code that satisfies the new shape. Most
changes happen because the previous shape was wrong in a specific way (a
footgun, a performance bug, a security gap, an inconsistency with the
rest of the library). Longer restructurings are flagged as optional
improvements.

A typical migration entry runs five to ten lines for a
small change, a few paragraphs for a larger one. The chapter
grows additively; older migrations are not removed.

## What does not migrate

Some changes produce no migration entry:

Bug fixes. An adopter may have built around a previous version's
incorrect behaviour; the fix stands, and the adopter adapts. The
fix appears in the changelog as a bug fix; one large enough to
warrant a migration entry also appears here.

Internal refactors that do not change the public API. The
`axess-core` modules may be reorganised without a migration entry,
as long as the public re-exports stay stable.

A changed default is not in this list: it changes what a deployment
that never set the value sees, so it gets an entry (the 0.19.0 to
0.20.0 page gathers them under "Changed defaults"). A deployment that
sets the value explicitly keeps its setting.

## Further reading

*Schema migration* covers the per-session schema migration
mechanism that handles session-data shape changes. The
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md)
lists every change per release; this chapter
is the migration subset. *Security posture* covers the
security-relevant breaking changes specifically, with the
disclosure protocol for security fixes.
