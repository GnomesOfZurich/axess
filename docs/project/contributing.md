# Contributing

This chapter is the contributor reference. It covers what we
expect of pull requests, the testing requirements (including the
non-negotiable DST discipline), the AX-NNN tracking convention,
and the naming and visibility conventions that show up at code
review.

The chapter has two halves. The first half is contributor-facing
guidance specific to working on axess. The second half is the
canonical [`CONTRIBUTING.md`](https://github.com/GnomesOfZurich/axess/blob/main/CONTRIBUTING.md)
from the repo root, included so the workflow checklist is in one
place.

## Before you open a PR

Three things to do before you open a PR.

The first is to read or skim *Architecture at a glance*. The
verifier-versus-orchestrator boundary, the three state slices, the
DST discipline, and the naming conventions are the four
architectural decisions that the review process holds new code
against. A PR that violates one of them is harder to land; a PR
written with them in mind sails through.

The second is to find or create an AX-NNN tracking entry. The
ROADMAP is the source of truth for "what is being worked on" and
"what is committed." A PR that lands a feature should reference
an AX-NNN. A PR that lands a bug fix can do without (though one
is often associated even with fixes). The number lives in the
PR description and in the commit messages; the format is
`AX-NNN` (no `#`, no space).

The third is to discuss substantial changes before writing them.
The review cycle is faster when the maintainers have agreed to
the shape ahead of time. A drive-by PR that rewrites a module
is usually rejected even when the rewrite is well-thought-out;
the cost of integration is higher than the value of the
rewrite. A discussion (an issue, a draft PR description, a
comment in an existing thread) before the work starts is the
shape that lands.

## Testing requirements

Every change passes its tests under both the production and the
mock implementations of `Clock`, `SecureRng`, and the backend
traits. The DST discipline is the testing non-negotiable; it is
not aspirational.

A test that fails on the production implementation but passes on
the mock is detecting a real bug in the production code (or in
the test). A test that fails on the mock but passes on
production is detecting either a real timing-dependent bug or
an over-strict test; either way it is worth investigating before
landing.

The pattern in the test code is to parameterise:

```rust,ignore
#[tokio::test]
async fn login_succeeds_with_correct_password() {
    let suite = TestSuite::default();  // sets up the mocks
    let outcome = suite.service
        .verify_factor(
            &suite.session(),
            FactorCredential::Password("Gnomes2+".into()),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, FactorOutcome::Authenticated));
}
```

`TestSuite::default()` wires `MockClock`, `MockRng`,
`MockBackend`, `MockRegistry`, the in-memory session store, and
the in-memory device store. The test runs entirely in process,
deterministically, against a known initial state.

For tests that need a real database (integration tests that
verify SQL adapters), the pattern is to feature-gate them and
run them in CI under a service container:

```rust,ignore
#[tokio::test]
#[ignore = "requires Postgres"]
async fn postgres_session_round_trip() {
    let pool = sqlx::PgPool::connect(env_var("TEST_POSTGRES_URL")?).await?;
    // ... full integration test
}
```

The `#[ignore]` attribute keeps the test out of the default
`cargo test` run; the CI runs them explicitly with
`cargo test --features integration -- --ignored`. The pattern
keeps the inner loop fast (default `cargo test` is in-process)
while still exercising the integration tests in CI.

## What good PR descriptions look like

The PR description is what reviewers read first. The goal is to
explain what the PR does, why, and what to look for. The shape:

A one-sentence summary at the top. "Add the `BearerToken`
factor for inbound API authentication." Not "Misc fixes." The
summary is what shows up in the PR list and in the commit
history.

A "Why" paragraph. What problem does the change solve. The
problem might be a documented bug, a missing capability, an
operational signal that needs response. The reviewer's first
question after "what" is always "why now"; answer it in the
description rather than the comments.

A "How" section. The shape of the change. Which modules
touched, which traits added or modified, which tests added.
The reviewer's first question after "why" is "where to look";
the section is the map.

A "Testing" section. What tests cover the change. The default
expectation is unit tests against the mocks; integration tests
where the change crosses an integration boundary; manual
testing notes for changes that are hard to automate
(typically migrations or operational tooling).

A "Migration" section if the change is breaking. What downstream
code has to update. The section is what feeds the *Migration
guide* chapter; the maintainers add the entry there as part of
the merge, but the PR author drafts the wording.

A reference to the AX-NNN tracking number. If the work is
substantial, the AX entry has the larger context; the PR
description summarises the slice this PR delivers.

## Naming and visibility

The naming conventions from *Architecture at a glance* are
enforced at review. The shapes:

A type that is shared across authentication and authorisation
uses the `Auth*` prefix. A type used only for authentication
uses `Authn*`. A type used only for authorisation uses `Authz*`.
A type that does not fit any of the three either picks one
(typically the broader one) or argues in the PR description
why the convention does not apply.

A type's suffix carries its role. `*Store`, `*Registry`,
`*Provider`, `*Resolver`, `*Config`, `*Error`, `*Outcome`,
`*Decision`. A new type that does not fit any of these picks
the closest match or argues in the PR description; the
conventions are tight, but they are not exhaustive, and the
rare exception is acceptable when documented.

A method's verb carries its complexity. `get_*` is O(1) by
primary key. `find_*` may scan. `load_*` and `save_*` are
serialisation pairs. `begin_*` and `complete_*` are ceremony
starts and finishes. `verify_*` is a credential check. A
method that does not fit any of these picks the closest match.

Visibility defaults to `pub(crate)`. A type is promoted to
`pub` only when an external consumer needs it; the default is to
not export, and the burden is on the PR to justify the
promotion. The convention catches the common case where an
internal helper accidentally becomes public surface that has to
be maintained forever.

## The no-`#[non_exhaustive]` policy

Axess does not use `#[non_exhaustive]` on its public enums and
structs. The attribute trades exhaustiveness checking (the
downstream compiler does not catch missing match arms) for
backward compatibility (the upstream can add variants without
breaking downstream). For axess, the trade is the wrong way
around: missing match arms in the downstream are bugs we want to
catch, and the backward-compatibility cost of adding variants is
manageable through deprecation cycles and the migration guide.

A PR that adds `#[non_exhaustive]` to a public type is rejected
unless the reasoning in the PR description argues a specific
case. The default is to bump the semver major version when a
variant is added, document the change in the migration guide,
and let the downstream's compiler catch the missing arm.

## The DST non-negotiable

The DST discipline is reproduced from *Architecture at a glance*
as a contributor reminder:

Every code path that reads wall time goes through the `Clock`
trait. Every code path that sources entropy goes through the
`SecureRng` trait. Every backend trait has a mock implementation
that the tests use. A PR that introduces a `chrono::Utc::now()`
call, a `getrandom()` call, or a direct database read outside
the trait surface is rejected.

The exceptions are extremely narrow: the `axess-cache` crate's
`moka-cache` feature uses wall-clock-driven eviction (opt-in,
documented as DST-breaking), and the production `SystemClock`
and `SystemRng` implementations delegate to the OS (these are
the only places where the OS calls happen). New code introduces
neither another exception nor a workaround that hides the same
problem.

The discipline is what lets the test suite be reproducible. A
contributor who finds the discipline frustrating is usually
about to introduce a bug; the friction is the point.

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
context for understanding what the next PR is meant to do.
