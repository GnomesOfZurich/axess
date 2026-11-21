# Contributing

This chapter lists what a pull request needs before it is merged. Read
the DST section even if you skip the rest: its requirement is the one
contributors least expect.

The chapter has two halves: guidance specific to working on axess,
then the canonical [`CONTRIBUTING.md`](https://github.com/GnomesOfZurich/axess/blob/main/CONTRIBUTING.md)
from the repo root, included so the workflow checklist is in one
place.

## Before you open a PR

**Read or skim *Architecture at a glance*.** Review
holds new code against the four architectural decisions it sets out:
the verifier-versus-orchestrator boundary, the three state slices, the
DST discipline and the naming conventions. A PR that violates one of
them is harder to land.

**Find the ROADMAP entry or the issue.** The ROADMAP lists, by
name, what is still to be built and what waits on upstream. A PR that
lands an entry names it in its description and removes it from the
ROADMAP in the same PR, since the ROADMAP lists only what is not built. A bug fix links its GitHub issue
when there is one. Commit messages and code carry no tracking
keys: they say what now holds.

**Discuss substantial changes before writing them.**
Review is faster when the maintainers have agreed the shape in
advance. A drive-by PR that rewrites a module
is usually rejected even when the rewrite is well-thought-out;
the cost of integration is higher than the value of the
rewrite. Open a discussion before the work starts: an issue, a draft PR
description or a comment in an existing thread.

## Testing requirements

Every change passes its tests under both the production and the
mock implementations of `Clock`, `SecureRng`, and the backend
traits. This DST discipline is required, not aspirational.

A test that fails on the production implementation but passes on
the mock has found a real bug in the production code (or in the
test). A test that fails on the mock but passes on production has
found either a timing-dependent bug or an over-strict test;
investigate it before landing.

Each test assembles its own world from the mocks:

```rust,ignore
#[tokio::test]
async fn login_succeeds_with_correct_password() {
    // The mocks are builders, assembled per test, so each test states
    // the world it needs rather than inheriting a shared fixture. The
    // world runs on one clock: `MockClock::at_reference` pins the instant
    // every test can share, `MockClock::reference_time`, and it does not
    // move unless the test advances it. Every part is built on it.
    let clock = MockClock::at_reference();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(fixture_tenant())
        .with_user(fixture_user());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();

    let outcome = service
        .verify_factor(
            &FactorCredential::Password("Sample2+".into()),
            &session,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, FactorOutcome::Authenticated));
}
```

A test reads only its own world's clock. `axess_core::testing::fixtures`
(which the tests in `axess-core/tests` import as `common`) holds the world
a test starts in. `test_clock()` is that world's clock, built once per
test and handed to every part of it; `start()` is the instant the world
starts at, and the fixtures there stamp their records with it. Every service,
store, cipher, layer and provider an integration test drives is built on the
test's clock through its `with_clock`, and a helper that builds part of the
world takes the clock as a parameter. A test that measures real elapsed
time (a deliberately slow identity provider, the cost of a password hash)
reads `axess_testing::stopwatch::Stopwatch`. `scripts/check-clock-usage.sh`
holds every crate's tests and test modules to this rule, and doc examples,
which teach production code, to the library rule. Against an empty
baseline it refuses `Utc::now`, `SystemTime::now`, `Instant::now` in any spelling,
`MockClock::now`, `SystemClock`, a renamed clock type and a helper that can
only run on the system clock (`make_password_service`, where
`make_password_service_on` takes the clock). In an integration test it
also refuses a part built without its clock and a second clock in one
function. It finds the constructors that fall back to the system clock from their
signatures: a constructor of a type whose clock `with_clock` sets, handed
no clock and nothing carrying one (`MemorySessionStore::new`,
`oauth_discover_provider`), counts unless its chain sets the clock. A clock
that a test's helper builds, in the file or in a module it declares,
counts where the helper is called, so a test whose helpers each build
their own has more than one. The script's header lists what a text rule
cannot see.

There is no all-in-one harness. The pieces are `MockIdentityStore` and
`MockFactorStore` for the identity and factor halves of a backend,
`MemorySessionStore` and `MemorySessionRegistry` for sessions,
`MockClock` and `MockRng` for the injected clock and randomness, and
`MockOAuthProvider`, `MockFido2Provider`, `MockLdapProvider`,
`MockPolicyEvaluator` and `MockEntityProvider` where a test reaches
those seams. Wiring them per test is more typing and leaves each test
saying what it depends on, which is worth more in a suite this size.

A test that needs a running server (a store's SQL or Valkey adapter,
the Keycloak login) sits behind the store's feature and is marked
`#[ignore]` with the server it needs as the reason:

```rust,ignore
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_saved_session_is_loaded_again() {
    let store = store().await; // panics when POSTGRES_URL is unset or unreachable
    // ... the test, against the live server
}
```

The attribute keeps the test out of the default `cargo test` run, so
the inner loop stays in-process. `scripts/check-live-stores.sh` runs
every ignored test of the workspace
(`cargo test --workspace --all-features -- --ignored`) against Valkey, a
Valkey cluster, PostgreSQL, MySQL and Keycloak; CI's Test Suite job and
the release preflight both run it, and it refuses to start without all
five URLs. A test run this way fails when its server is missing: it
never returns early as a pass. `scripts/check-ignore-reasons.sh` refuses
an `#[ignore]` with no reason. Every `#[ignore]` marks a test of a live
server, run and judged by `scripts/check-live-stores.sh`. A test Miri cannot interpret (a
tokio runtime's I/O driver, hundreds of randomised sequences), and a test
that reaches a dependency's aligned SIMD load, which Miri's symbolic
alignment check reports as a possible alignment error, carries
`#[cfg_attr(miri, ignore = "...")]` instead: it is ignored under Miri
alone, and every other run executes it as an ordinary test. What is not a
test is not
written as one: a measurement of time is a benchmark (`axess-core/benches`,
which CI's benchmark job runs), a property that would be measured as time
is asserted as the work it costs (the Argon2 parameters of each run, as
`axess_factors::password::recording` reports them), and a program that
writes files is an example target run by name (the fixture generator of
the workload-identity example).

The servers are shared, so a live Valkey test leaves nothing on them: it
writes under a prefix from `axess_core::testing::valkey_sweep`, whose
`KeySweep` removes every key whose name holds the prefix when the test
ends, passed or failed. A module's live-store helper returns its store wrapped
with the sweep in a `Swept`, which a test uses as the store. Every
prefix holds the run's token, `AXESS_TEST_RUN`, and
`scripts/check-live-stores.sh` refuses a run that left a key holding it
on the node or on a primary of the cluster (`scripts/live-keys-left.sh`).
A key written outside every sweep holds no token, so that check cannot
see it; `scripts/check-live-sweeps.sh` refuses a live Valkey test that
holds no sweep, unless `scripts/live-sweep-exemptions.txt` names it with
the reason it writes no key.
A test that changes the server itself, its `maxmemory-policy` or a user
of its own, holds a guard from `axess-core/src/testing/valkey_server.rs`,
made before the change, that puts it back when the test ends, passed or
failed.

A test that needs a Valkey cluster sits under a module named
`valkey_cluster`, at any depth, since a run on one Valkey node leaves the
cluster tests out by that name (`--skip valkey_cluster`, and the live
mutation job's `test(valkey) - test(valkey_cluster)`). Two guards hold the
convention: `cluster_url` in `axess-core/src/testing/valkey_cluster.rs`
panics when a test named outside such a module takes the cluster's URL,
so the test fails in the run that has the cluster too, and
`scripts/check-cluster-url-reads.sh` refuses any other read of
`VALKEY_CLUSTER_URL`, so no test reaches the cluster past that guard.

## What good PR descriptions look like

Reviewers read the PR description first. It explains what the PR
does, why, and what to look for, in this shape:

A one-sentence summary at the top. "Add the bearer-token factor for
inbound API authentication." Not "Misc fixes." The
summary shows in the PR list and in the commit history.

A "Why" paragraph. What problem does the change solve? The
problem might be a documented bug, a missing capability or an
operational signal that needs a response. The reviewer's first
question after "what" is always "why now"; answer it in the
description rather than the comments.

A "How" section. The shape of the change: the modules
touched, the traits added or modified, the tests added.
The reviewer's first question after "why" is "where to look";
the section is the map.

A "Testing" section. What tests cover the change. The default
expectation is unit tests against the mocks; integration tests
where the change crosses an integration boundary; manual
testing notes for changes that are hard to automate
(typically migrations or operational tooling).

A "Migration" section if the change is breaking. What downstream
code has to update. The section feeds the *Migration
guide* chapter: the PR author drafts the wording, and the maintainers
add the entry as part of the merge.

The ROADMAP entry or issue the work belongs to, by name or
link. If the work is substantial, that entry has the larger
context; the PR description summarises the slice this PR
delivers.

## Naming and visibility

Review enforces the naming conventions from *Architecture at a
glance*:

A type that is shared across authentication and authorisation
uses the `Auth*` prefix. A type used only for authentication
uses `Authn*`. A type used only for authorisation uses `Authz*`.
A type that does not fit any of the three either picks one
(typically the broader one) or argues in the PR description
why the convention does not apply.

A type's suffix carries its role. `*Store`, `*Registry`,
`*Provider`, `*Resolver`, `*Config`, `*Error`, `*Outcome`,
`*Decision`. A new type that does not fit any of these picks
the closest match or argues its case in the PR description. The
conventions are tight but not exhaustive; a rare exception is
acceptable when documented.

A method's verb carries its complexity. `get_*` is O(1) by
primary key. `find_*` may scan. `load_*` and `save_*` are
serialisation pairs. `begin_*` and `complete_*` are ceremony
starts and finishes. `verify_*` is a credential check. A
method that does not fit any of these picks the closest match.

Visibility defaults to `pub(crate)`. A type becomes
`pub` only when an external consumer needs it, and the PR must
justify the promotion. This keeps an internal helper from becoming,
by accident, public surface that has to be maintained forever.

## The no-`#[non_exhaustive]` policy

Axess does not use `#[non_exhaustive]` on its public enums and
structs. The attribute trades exhaustiveness checking (the
downstream compiler does not catch missing match arms) for
backward compatibility (the upstream can add variants without
breaking downstream). For axess, the trade is the wrong way
around: missing match arms downstream are bugs the compiler should
catch, and the backward-compatibility cost of adding variants is
manageable through the migration guide of each minor release.

A PR that adds `#[non_exhaustive]` to a public type is rejected
unless the reasoning in the PR description argues a specific
case. The default when a variant is added is to make a breaking
release (while axess is pre-1.0, the minor version: `0.x.y` to
`0.x+1.0`), document the change in the migration guide, and let the
downstream's compiler catch the missing arm.

## The DST non-negotiable

The DST discipline is reproduced from *Architecture at a glance*
as a contributor reminder:

Every code path that reads wall time goes through the `Clock`
trait. Every code path that sources entropy goes through the
`SecureRng` trait. Every backend trait has a mock implementation
that the tests use. A PR that introduces a read of the system
clock (`SystemTime::now()`, or another time library's), a
`getrandom()` call, or a direct database read outside the trait
surface is rejected.

The exceptions are narrow: the `IntoResponse` impl for `AuthnError`
(the trait method cannot take a clock; call `into_response_at` where one
is held), and the production `SystemClock`
and `SystemRng` implementations, which delegate to the OS and are
the only places where the OS calls happen. New code introduces
no further exception and no workaround that hides the same
problem.

The discipline is what lets the test suite be reproducible. A
contributor who finds the discipline frustrating is usually
about to introduce a bug; the friction is the point.

## Dependency versions wait seven days

No crates.io version younger than seven days enters a lockfile. The
resolver keeps to it through `registry.global-min-publish-age` in
`.cargo/config.toml` (cargo 1.100 and later), and
`scripts/check-lock-age.sh` checks every tracked `Cargo.lock` against
the last release tag, in CI and in the release preflight, using the
publish times of the crates.io index. A version that new is taken only
to fix an advisory: run the cargo command that changes the lockfile
with `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`, and end the
message of the commit that changes it with one trailer per crate taken
this way, `Cooldown-Exempt: <advisory id> <crate>`, where the id is a
`RUSTSEC-`, `GHSA-` or `CVE-` id. A message that only mentions an advisory admits
nothing. The section "New dependency versions wait seven days" below
gives the commands.

## Canonical CONTRIBUTING.md

The rest of this chapter is the canonical `CONTRIBUTING.md` from
the repo root.

{{#include ../../CONTRIBUTING.md}}

## Further reading

*Architecture at a glance* covers the architectural decisions
that review enforces. *Publishing runbook* covers the
maintainer-only release process. The
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md)
catalogues what each release has shipped, which is useful
context for the next PR.
