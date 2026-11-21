Atomically replace the stored factor config with `updated` only if the
currently stored config matches `prior`. Returns `Ok(true)` on
successful swap and `Ok(false)` if the stored value has changed since
it was loaded (indicating a concurrent update; for TOTP/HOTP this
means the credential has already been spent in another request).

This method is **required**: implementations MUST make the conditional
update atomic with respect to other writes; typically a single
`UPDATE ... WHERE` statement using the prior values as a guard, or
an equivalent single-transaction primitive on the backend. A
non-atomic load-compare-save would re-open the TOTP/HOTP replay
window the trait exists to close.

**What "matches" means.** `prior` is the value the caller loaded, as this
build reads it. It carries no version and no row id, so a store cannot
compare a version column against it. A store matches it against the stored
row as a value, never as the stored bytes. A row written by an earlier
release, or by a tool, can lack a field that has a default since (the
`attempt_count` of an HOTP row, the `under_previous_pepper` of a
recovery-code set), or order its keys differently; its text then differs
from the text `prior` serialises to although nothing was spent. A store
that compares text answers `false` for such a row on every attempt, and
the right code reads as a replay until the row is rewritten.

A SQL store that keeps the configuration in one column therefore swaps in
two statements, and the second decides. It reads the row's id, its version
and its configuration; compares the configuration, read into a
`FactorConfig`, with `prior`; then writes with one
`UPDATE ... WHERE id = ? AND version = ?` naming the version it just read,
and answers by the rows affected. The version column moves on every write
of the configuration, whoever makes it (a trigger keeps that true for
statements written later too), so a row that changed between the two
statements is not written and the answer is `false`. No transaction spans
the two statements, so no read lock is upgraded and nothing answers a lock
error. The SQLite example is written this way.

A store that keeps what a factor advances in columns of its own
(`last_step` for TOTP, `counter` and `attempt_count` for HOTP) may compare
those columns in one statement, and must then write those columns and no
others. `updated` is the caller's whole configuration, built from what it
loaded: writing all of it after comparing a part would undo a change made
meanwhile to another part, a secret enrolled again for one.

It follows that a concurrent change to any field a swap would write makes
the swap answer `false`: the caller verified against a configuration that
is no longer the stored one, and verifies again against the new one.

A swap never succeeds on a factor the store would no longer load. Where a
store keeps a flag that takes a factor out of use (the `enabled` column of
the SQLite example) and its loads skip such a row, the swap's guard names
the flag as well: a factor disabled between a caller's load and its swap
answers `false` and is not written. A flag that does not move the version
is not covered by the version guard and has to be in the guard itself.

A swap that loses to a concurrent writer answers `Ok(false)`, never
an error: the service reads `false` as a replay and an error as a
failed login. A store that reads the row and then writes it inside a
transaction that takes its write lock late (a deferred transaction in
SQLite) answers a lock error when two logins meet, and breaks this
even though each request alone is served correctly.

A store of your own MUST run
`assert_compare_and_save_factor_contract` (in
`testing::store_contract`, behind the `testing` feature) in its
tests, on a multi-thread runtime and against the store as production
opens it. The check races sixteen swaps on one stored value for each
of a TOTP step, an HOTP counter with its attempt count and a recovery
code's spent mark, and holds the store to one `true`, fifteen
`false` and no error. The in-tree stores (the mock store,
`InMemoryBackend` through it, and the SQLite example) run it.
