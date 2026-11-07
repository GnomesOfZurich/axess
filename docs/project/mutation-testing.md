# Mutation testing

The test suite is graded by `cargo-mutants`: it changes one thing in the
library code at a time (a `>` to a `>=`, a function body to
`Default::default()`) and runs the tests. A change the tests notice is
*caught*; one they do not is *missed*, and a missed mutant names code
whose behaviour no test pins. This page is how the sweep runs, what it
guarantees and how it fails.

## What runs, and when

- **On a pull request** the workflow mutates only the lines the PR
  touches (`--in-diff`) and fails the PR on a missed mutant or a timeout.
- **Every Sunday at 03:00 UTC**, or on a manual dispatch with
  `full_sweep`, it mutates the whole workspace and reports the kill rate
  per file on the run's summary page. Survivors are listed, not failed:
  the weekly sweep is a measurement.

## Why it is sharded

The whole workspace is about 7700 mutants. Measured on `ubuntu-latest`
from the 2026-11-01 run, an `axess-core` mutant costs about 113 s to
build and 300 s to test when caught (its lib test binary runs all of its
1540 tests before it reports a failure) and about 500 s when missed; an
`axess-factors` mutant about 220 s; the small crates seconds. That is
about 335 s a mutant on average and about 720 runner-hours for one sweep.

One job has six hours, so the single-job sweep never finished: every
scheduled run from the first on 2026-06-07 to 2026-11-01 was cancelled at
the job limit, two hung mutants having eaten 56 minutes each, and every
one of them passed with a warning. The sweep now runs as a matrix of
shards:

- `shards = ceil(mutants / 43)`, about 180 today. 43 mutants at 335 s is
  about 4 h, plus setup, inside the shard step's 5 h and the job's 6 h.
- Mutants are dealt round-robin (`--sharding round-robin`), so each
  shard gets the same mix of slow and fast crates.
- Ten shards run at a time (`max-parallel: 10`), half of a free
  organisation's twenty concurrent jobs, so pull-request CI is not queued
  behind the sweep. A full sweep takes about three days of wall-clock.
- The unmutated suite runs once, in its own job, rather than once per
  shard (`--baseline skip`).
- A mutant's tests stop after 1500 s and its build after 900 s, so a
  hung mutant costs at most 25 minutes instead of five times the
  whole-workspace baseline.

## Running it yourself

Both halves are scripts, so a local run is the CI run:

```bash
# How many mutants a filter selects, and how many shards that makes.
scripts/mutants-sweep.sh plan -f axess-cache/src/cache.rs

# Run shard 1 of 4 into out/mutants-shard-1.
scripts/mutants-sweep.sh shard 1 4 out -f axess-cache/src/cache.rs

# Merge every shard and refuse an incomplete sweep.
scripts/mutants-summary.py out --shards 4 --expected-total 39
```

`MUTANTS_PER_SHARD`, `MUTANTS_TEST_TIMEOUT`, `MUTANTS_BUILD_TIMEOUT` and
`MUTANTS_BASELINE` override the defaults. For one file, plain
`cargo mutants -f <file>` works too; `scripts/mutants.sh` runs it in a
separate worktree.

## Invariants

- **A sweep that did not see everything fails.** The summary job fails
  the run, by name, when a shard is missing, was cancelled, did not
  finish (`end_time` is null in its `outcomes.json`), recorded fewer
  outcomes than it was assigned, or when the shards together tested a
  different number of mutants than the plan listed. The plan job runs
  `scripts/mutants-summary.py --self-test` first, which proves each of
  those refusals on fixtures.
- **`-f` narrows.** `.cargo/mutants.toml` carries no `examine_globs`,
  because cargo-mutants adds a command-line `--file` to that list
  instead of intersecting with it: with the list in place,
  `cargo mutants -f axess-cache/src/cache.rs` selected all 7725 mutants.
  The excludes there select the same set without it.
- **Every mutant is built with `--all-features`.** A narrower build
  would report false survivors in feature-gated code.

## Failure modes

| What you see | What it means |
|---|---|
| `mutation sweep is blind: mutants-shard-K: no outcomes.json` | Shard K did not run or its artifact was not uploaded. |
| `... the run did not finish (end_time is null)` | Shard K was cancelled or hit its step limit; resize the shards. |
| `... N outcomes for M assigned mutants` | Shard K stopped part-way. |
| `the shards tested N mutants; the plan listed M` | A shard's selection differs from the plan's; the config or the tree moved under the run. |
| `the shard job(s) ended 'cancelled'` | At least one shard was cancelled; the kill rate is not a measurement. |
| `N mutant(s) survived or timed out` | On a pull request: write the test that catches them. |
| `error: ... over GitHub's matrix cap of 256` | The workspace outgrew the matrix; cut the per-mutant cost before raising the per-shard count. |

## Equivalent mutants

A mutant that no test can catch because it changes nothing observable
is removed at its source where the code allows it, rather than excluded
by name, because an exclusion regex also hides the next real mutant with
the same name. The `if count > 0` guards around the invalidation
counters in `ClockTtlCache` were such a case: adding zero to an atomic
counter is a no-op, so `>` and `>=` there were indistinguishable, and
the guards are gone.

## Migration

None for adopters: this changes CI, the cargo-mutants config and tests,
not the library.
