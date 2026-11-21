# Mutation testing

The test suite is graded by `cargo-mutants`: it changes one thing in the
library code at a time (a `>` to a `>=`, a function body to
`Default::default()`) and runs the tests. A change the tests notice is
*caught*; one they do not is *missed*, and a missed mutant names code
whose behaviour no test pins. This page covers how the sweep runs, what it
guarantees and how it fails.

## What runs, and when

- **On a pull request** the workflow mutates only the lines the PR
  touches (`--in-diff`) and fails the PR on a missed mutant or a timeout.
- **Every Sunday at 03:00 UTC**, on a push to `release/next` or
  `release/X.Y.x` (a release commit), or on a manual dispatch with
  `full_sweep`, it mutates the whole workspace and reports the kill rate
  per file on the run's summary page. Survivors are listed, not failed:
  the full sweep is a measurement. It ends in success when every shard
  finished. The release workflow reads the full sweep on the release
  commit and reports its address and ending without waiting for it
  (`--mutants-report-only`). No full sweep has yet passed at the shard
  size below; once one has, the workflow drops the option and requires
  the sweep.

## Why it is sharded

The whole workspace has 11771 mutants in 0.20.0, and had about 7700 at
the measurement that follows. Measured on `ubuntu-latest`
from the 2026-11-01 run, which tested with `cargo test`, an `axess-core`
mutant costs about 113 s to build and 300 s to test when caught (its lib
test binary runs all of its 1540 tests before it reports a failure) and
about 500 s when missed; an `axess-factors` mutant about 220 s; the small
crates seconds. That is about 335 s a mutant on average: about 720
runner-hours for one sweep then, and about 1100 at 11771 mutants.

A job may run for at most six hours, so the single-job sweep never finished.
Every scheduled run from the first, on 2026-06-07, to 2026-11-01 was
cancelled at the job limit (in one measured run, two hung mutants took
56 minutes each), and every one of those runs passed with a warning. The
sweep now runs as a matrix of shards:

- `shards = ceil(mutants / 48)`, 246 for the 11771 mutants of 0.20.0.
  48 is provisional, chosen to fit GitHub's matrix cap of 256 shards
  (43, the size the measurement above gave, made 274), and was raised
  without the measured per-mutant cost that the failure table below asks
  for. 43 mutants at 335 s is about 4 h, plus setup, against the shard
  step's 5 h and the job's 6 h. In the 0.19.0 sweep (203 shards of 43,
  tested with `cargo test`) the shard step took about 216 minutes at the
  median, 3 shards ran into the step's limit, and 23 ran longer than 269
  minutes, which is 300 at 48 a shard. At that cost about one shard in
  nine at 48 runs into the limit, in its run and in its second run, which
  repeats the same mutants, and the sweep ends red. How much
  cargo-nextest's stop at the first failing test saves is not yet
  measured; the outcomes of the shards that finish give that cost, and a
  per-mutant cost measured under cargo-nextest replaces 48 before the
  release workflow requires the sweep.
- Mutants are dealt round-robin (`--sharding round-robin`), so each
  shard gets the same mix of slow and fast crates.
- The width (how many shards run at a time) is set once at the top of
  `mutants.yml` and depends on the trigger. A free organisation has twenty
  concurrent jobs, shared by every workflow. The weekly and dispatched
  sweeps take 10 (`MUTANTS_WIDTH_SWEEP`), so pull-request CI is not queued
  behind them: 246 shards of two to five hours each (the 0.19.0 sweep's
  shards and the step's limit) at 10 at a time is 25 rounds, 50 to 125
  hours. The sweep a push to a release branch starts is the one on the
  release commit, so it takes 16 (`MUTANTS_WIDTH_RELEASE`) and leaves 4
  for the release pull request's CI and the Hardening runs: 16 rounds, 32
  to 80 hours.
- Each mutant is tested with cargo-nextest (`test_tool = "nextest"` in
  `.cargo/mutants.toml`) under the `mutants` profile of
  `.config/nextest.toml`: the run stops at the first failing test and ends
  the tests still running, and a test past the profile's slow timeout is
  ended and counts as failed.
- The unmutated suite runs once, in its own job, rather than once per
  shard (`--baseline skip`), under the same tool and profile.
- A mutant's build stops after 900 s and its tests after 1500 s, so a
  hung mutant costs at most 40 minutes (15 to build, 25 to test) instead
  of five times the whole-workspace baseline.

## Running it yourself

Both halves are scripts, so a local run is the CI run. cargo-nextest must
be installed, at the version `mutants.yml` installs
(`cargo install cargo-nextest@<version> --locked`):

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

- **A lost shard is run once more, and never counts as a missed
  mutant.** After the shards, a job lists every shard whose artifact
  holds no whole `outcomes.json` (`mutants-summary.py --lost`): cancelled
  at the job limit, its runner gone, or failed for another reason. Those
  shards run once more in the same run, under artifacts named
  `mutants-retry-K`, and a shard whose second run finished counts as
  finished. The summary states shards planned, finished (and how many on
  the second run) and lost, and mutants caught, missed, unviable and timed
  out; a shard lost in both runs fails the sweep by number, with a
  message that says the sweep did not finish, not that a mutant was missed.
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
- **A mutant no test ran against is missed, not caught.** nextest exits
  with an error when it runs no test, and cargo-mutants counts every
  failing test run as a caught mutant, so the sweep passes
  `--no-tests=warn`. nextest does not run doctests: a behaviour that only
  a doctest pins shows as missed.

## Failure modes

| What you see | What it means |
|---|---|
| `mutation sweep is blind: mutants-shard-K: no outcomes.json` | Shard K did not run or its artifact was not uploaded. |
| `... the run did not finish (end_time is null)` | Shard K was cancelled or hit its step limit; resize the shards. |
| `... N outcomes for M assigned mutants` | Shard K stopped part-way. |
| `the shards tested N mutants; the plan listed M` | A shard's selection differs from the plan's; the config or the tree moved under the run. |
| `the sweep did not finish: shard(s) K lost in both runs` | Shard K did not finish in its run or in the second run the workflow gave it; its mutants were not judged. The summary page gives each run's reason. Not a missed mutant. |
| `the lost job ended '...'` | The job that lists the lost shards did not run to its end, so no shard could be judged. |
| `N mutant(s) were missed or timed out: a test is weak, every shard finished` | On a pull request: write the test that catches them. |
| `error: ... over GitHub's matrix cap of 256` | The workspace outgrew the matrix; cut the per-mutant cost, and measure it, before raising the per-shard count. 48, the count in force, was raised without that measurement while the release workflow only reports the sweep ([Why it is sharded](#why-it-is-sharded)). |

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
