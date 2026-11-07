# Publishing runbook

Maintainers only. Publishing to crates.io is irreversible and versions
cannot be reused, so the order below is not advisory.

The audience is the maintainer cutting a release. An adopter
does not need this chapter; the chapter is here so the
maintainer has a written reference and so the procedure can be
followed by a different maintainer if needed.

## The release process

The process is enforced, not remembered: GitHub refuses a change to
`main` that skips it, and the release workflow refuses a tag that does
not match what was reviewed. The settings that make GitHub refuse are
under [Settings a repository owner applies once](#settings-a-repository-owner-applies-once).

### Branches

`main` holds releases only: one squashed commit per release, each
tagged `vX.Y.Z`. Nothing lands on `main` except by the release pull
request.

`release/next` is where all work lands, one change at a time. After
each release from `main` the release workflow levels it with `main`
(moved to the released commit when nothing newer is on it, `main`
merged into it otherwise), so it starts at the commit the last tag
points at and is never deleted. Contributors' pull requests
target it (see [`CONTRIBUTING.md`](../../CONTRIBUTING.md)). The branch
name carries no version: the version is fixed during release
preparation, by the semver check and the changelog.

`release/X.Y.x` is a patch line, cut only when a released line needs a
fix: from the tag `vX.Y.Z`, never from `release/next`. The fix lands
there, the patch release is prepared, tagged and published from that
branch, and the branch is then merged forward into `release/next` so
the next release carries the fix too.

### Who does what

Contributors and the maintainer prepare: they land work on `release/next`, do the release
preparation below, run `./scripts/release-preflight.sh` locally, and
the maintainer confirms that every finding the release claims to fix
is closed in the project's issue register before the pull request is
opened. That register is not part of this repository, so no CI job
can read it; the check stays local.

The maintainer releases: the maintainer pushes the release branch, opens the pull request
from it into `main` and lets it merge (squash) once the required checks
pass (`gh pr merge --squash --auto`); the merge is tagged `vX.Y.Z` by
[`tag.yml`](../../.github/workflows/tag.yml), which starts the release
workflow; the maintainer approves the `crates-io` deployment when that
workflow asks for it, and the workflow's last job levels `release/next`
with `main`. Two human acts: the pull request, the approval.

### Release preparation

As soon as a release's version is known (the semver check and the
changelog decide it: a breaking change in a 0.x release is a minor
bump), the version goes in and the changelog section gets its heading,
with `unreleased` in place of the date:

```text
Cargo.toml       [workspace.package] version = "X.Y.Z", every internal
                 axess-* entry in [workspace.dependencies] = "=X.Y.Z"
CHANGELOG.md     an empty "## [Unreleased]" heading, then
                 "## [X.Y.Z] - unreleased" with the entries
```

[`docs/production/release.md`](../production/release.md) has the
mechanics of the bump, the version badge and the changelog entries.
On release day, still on the release branch:

1. Write the date in: `## [X.Y.Z] - YYYY-MM-DD`. Only an empty
   `## [Unreleased]` heading stays above it.
2. Measure coverage and commit the badge, beside the version badge.
   Run the Coverage job's command with the two store URLs it uses, then
   write the badge from the result:

   ```bash
   VALKEY_URL=redis://127.0.0.1:6390 \
   POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5490/postgres \
     cargo llvm-cov --workspace --all-features --no-report
   ./scripts/coverage-badge.sh write
   ./scripts/update-badges.sh
   ```

   The Coverage job on the release pull request refuses a committed
   figure more than one point from the one it measures; the script's
   header says why one point.
3. Run `./scripts/release-preflight.sh` with the live stores up. Its
   "Release version and dated changelog" step refuses an `unreleased`
   heading, a version the internal pins disagree with, and entries left
   under `[Unreleased]`.
4. The maintainer confirms every finding the release fixes is closed in
   the project's issue register.

The rest of the old checklist still holds and the preflight does not
read it: the migration guide (*Migrating* in the book) has an entry for
every breaking change; every published crate carries `description`,
`license`, `repository`, `keywords`, `categories` and the
`[package.metadata.docs.rs]` block (`all-features = true`,
`rustdoc-args = ["--cfg", "docsrs"]`); and no crate that should publish
says `publish = false`.

### The release pull request and its checks

A pull request into `main` runs every job of
[`ci.yml`](../../.github/workflows/ci.yml), which between them run every
step of `scripts/release-preflight.sh`. The main branch ruleset requires
these checks by name (the job `name:` values); renaming a job is a
ruleset edit in the same release.

| Required check | What it runs | What it prevents |
|---|---|---|
| Release Gate | needs every other job, matrix rows included; `scripts/check-ci-gate.sh` | a failing Build Check, Feature Isolation or Factor Isolation row, or a job added to `ci.yml` but to no gate |
| Release Version | the pull request comes from `release/next` or `release/X.Y.x` of this repository; `scripts/check-release-version.sh` strict | a release from a topic branch or a fork; a tag, workspace version, internal pin or dated changelog section that disagree; entries left under `[Unreleased]` |
| Format Check | `cargo fmt --check` | unformatted code |
| Ban #[non_exhaustive] | grep of first-party crates | the attribute the project refuses |
| Ban cargo-mutants markers | grep of first-party crates | a mutation left in the source by a local cargo-mutants run |
| Lockfile Drift | `cargo metadata --locked` | a `Cargo.lock` that does not match the manifests |
| Detect orphan .rs files | module reachability | a source file the compiler never reads |
| Clippy Lints | clippy, all targets, all features, `-D warnings` | lint regressions |
| Rustdoc (-D warnings) | rustdoc links, Markdown links, prose style, documented identifiers, methods, imports and versions | docs that point at names, paths, chapters or versions that do not exist |
| Source Rules | inline test block sizes, file and function sizes | modules and functions past the size limits |
| Book | the book built and its code compiled with the pinned mdBook | a book that fails only after the merge, in the docs workflow |
| Test Suite | every non-ignored test, then `scripts/check-live-stores.sh` against Valkey, PostgreSQL, MySQL and Keycloak | a red test, including a live-store test |
| CockroachDB Compatibility | the PostgreSQL suite against CockroachDB | a wire-compatibility regression |
| MSRV | `scripts/check-msrv.sh` | a `rust-version` promise the code no longer keeps |
| Examples | the example applications build | an example that no longer compiles |
| Fuzz Smoke | each fuzz target for 30 seconds | an easy crash in a decoder |
| Benchmarks | the benchmarks run | a benchmark that panics |
| Publish Dry-Run | `cargo publish --dry-run` for leaf crates, `cargo package --list` for the rest | a crate crates.io would refuse |
| SemVer Checks | `scripts/check-semver.sh` against the last release tag | a breaking change in the classes cargo-semver-checks covers, released as a patch |
| Security Audit | advisory ignore lists agree, `cargo audit`, `cargo deny` | an unpatched advisory, a banned licence, source or duplicate |
| Coverage | the instrumented suite; the committed badge within one point | a stale coverage badge |
| Badges in sync | version and licence badges regenerated | a stale version or licence badge |

The matrix rows (Build Check, Feature Isolation and Factor Isolation)
are required through Release Gate rather than one by one, so a row
added to the matrix is required the moment it exists.

A pull request into `release/next` or `release/X.Y.x` runs the same
jobs. Only Release Version differs: it runs with `--allow-unreleased`,
so the version's heading may still say `unreleased`, or the version may
not be known yet and only `## [Unreleased]` exists.

### The release workflow

A tag `vX.Y.Z` starts
[`release.yml`](../../.github/workflows/release.yml). The tag comes from
[`tag.yml`](../../.github/workflows/tag.yml): on every push to `main` it
checks that the workspace version has a dated changelog section and no
tag yet, creates `v$VERSION` at the pushed commit and dispatches
`release.yml` from the tag (a tag made with the workflow token fires no
tag-push run by itself). If `tag.yml` fails, tag by hand:
`git tag vX.Y.Z <merge commit> && git push origin vX.Y.Z`, which starts
the same workflow. In order:

1. **Verify release tag** refuses a run that is not for a tag, a tag
   whose commit is on neither `main` nor a `release/X.Y.x` branch
   (`git merge-base --is-ancestor` against origin), and a tag that is
   not `v` plus the workspace version or whose version has no dated
   changelog section.
2. **CI** runs the whole of `ci.yml` on the tagged commit.
3. **Publish to crates.io** waits for the maintainer's approval in the
   `crates-io` environment, then publishes the crates in dependency
   order with the organisation secret `CARGO_REGISTRY_TOKEN`, which only
   a job in that environment reaches. Moving to crates.io trusted
   publishing (settings step 5) removes that stored token.
4. **GitHub Release + SBOM** generates the CycloneDX SBOM, attests its
   provenance with Sigstore keyless signing, and creates the GitHub
   release with generated notes.
5. **Level release/next with main** runs only for a tag on `main`:
   when `release/next` is behind `main` or carries the same tree as the
   squashed release, the branch is moved to the released commit; when
   work landed on it since the release pull request was opened, `main`
   is merged into it; a conflict ends the job by name and the
   maintainer merges by hand (`git checkout release/next && git merge
   main && git push`). A tag on `release/X.Y.x` leaves `release/next`
   alone; the patch line is merged forward by hand.

To re-run an existing tag (a publish that stopped part-way, a
rate-limit wait that outlived the 30-minute token), dispatch the
workflow from the tag, not from a branch:

```bash
gh workflow run release.yml --repo GnomesOfZurich/axess --ref vX.Y.Z
```

The publish step skips any crate whose version is already uploaded.
A dispatch from a branch is refused in step 1, and the `crates-io`
environment admits tags only.

## Topological dependency order

The workspace's library crates publish in dependency order: a
crate must be published before any crate that depends on it. The
order:

1. `axess-strings` (no axess deps)
2. `axess-clock` (no axess deps)
3. `axess-rng` (no axess deps)
4. `axess-identity` (no axess deps)
5. `axess-cache` (depends on `axess-clock`)
6. `axess-events` (depends on `axess-identity`)
7. `axess-factors` (depends on `axess-identity`, `axess-clock`,
   `axess-rng`)
8. `axess-macros` (no axess deps; procedural macros stand alone)
9. `axess-core` (depends on everything in the previous tier)
10. `axess` (the facade, depends on `axess-core` and
    `axess-factors` and `axess-macros`)

The release workflow publishes in this order; the maintainer should
know it so a publish that fails partway through can be read at a
glance.

## The dry-run

The Publish Dry-Run job runs on every pull request, so the release
pull request has already dry-run the release. To repeat it locally:

```bash
cargo publish --dry-run -p axess-strings
cargo publish --dry-run -p axess-clock
cargo publish --dry-run -p axess-rng
for c in axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess; do
  cargo package --list -p "$c" >/dev/null
done
```

The dry-run does everything the publish does except the upload.
It builds the package, verifies the manifest, runs the publish-time
checks, and prints the path of the `.crate` file it would have
uploaded. A failure here is an opportunity to fix without having
to yank a half-published release.

Only the leaf crates dry-run end to end: a downstream crate's dry-run
resolves its `axess-*` dependencies against crates.io, where the new
version does not exist until the release workflow publishes it, so
`cargo package --list` validates the manifest and the shipped file set
instead.

## The publish

The release workflow publishes; nobody runs `cargo publish` by hand.
Once trusted publishing is set up (settings step 5), every crate can be
set to accept trusted publishing only, so a token on a maintainer's
machine could not publish anyway.

The workflow waits 30 seconds between crates so each one is in the
crates.io index before the next resolves it, and on a "429 Too Many
Requests" it sleeps until the time crates.io names. If the run stops
part-way, re-run the tag as above: crates already uploaded are
skipped, and the rest continue in order.

After the run, verify on crates.io that all ten crates are listed at
the new version.

## The smoke test

After the publish, run a smoke test against a fresh dependency
on the published version. The shape:

```bash
mkdir /tmp/axess-smoke
cd /tmp/axess-smoke
cargo new --name axess-smoke .
echo 'axess = "0.18"' >> Cargo.toml
cargo build
```

The build pulls the published crates from crates.io (not from
the workspace) and verifies they assemble. A failure here
indicates an issue that the dry-run did not catch (typically a
crates.io-specific issue like a missing file in the package
manifest); the rollback procedure is the response.

For a more thorough smoke test, copy `examples/sqlite/` to a
fresh directory, point its `Cargo.toml` at the published
versions (replacing `path = "../../axess"` with
`version = "0.2"`), and verify it builds and runs.

The smoke test is the last gate before announcing the release.
A successful smoke test means the publish is real.

## The announcement

After the smoke test passes:

The tag already exists (it started the release) and the workflow has
created the
[GitHub release](https://github.com/GnomesOfZurich/axess/releases)
with the SBOM. The GitHub releases page is the canonical announcement;
the project's other channels mirror it as appropriate.

Cut the next `release/next` from `main`, so the next change lands on
a branch that starts at this release:

```bash
git fetch origin
git push origin --delete release/next
git push origin origin/main:refs/heads/release/next
```

`CHANGELOG.md` already has the empty `## [Unreleased]` heading the
next change lands under.

The copy-pasteable dependency snippets in the READMEs, the book and
the `testing` doc-comments are checked rather than remembered:
`./scripts/check-doc-versions.sh` compares every
`axess... = { version = "..." }` in a tracked `.md` or `.rs` file
against `[workspace.package] version`, and
`./scripts/release-preflight.sh` runs it among its cheap early gates. The comparison is
cargo's compatibility rule, not string equality, so `"0.4"` and
`"0.4.0"` both satisfy a 0.4.0 workspace; for 0.x the minor is the
breaking unit. `CHANGELOG.md` is exempt because its entries are
supposed to name the versions they shipped in, and non-semver
placeholders such as the `0.NEW.0` in `docs/production/release.md`
are ignored.

Bump the workspace version first, then run the check: it will list
every snippet the bump left behind.

## Rollback

If the publish goes wrong (a critical bug surfaces, a crate is
broken on crates.io, the release was premature), the rollback
procedure:

`cargo yank --version 0.2.0 axess` (and every other crate)
withdraws the version from crates.io. Yanked versions remain
available to existing consumers (so `Cargo.lock` references
continue to work), but new resolves do not pick them up. Yanking
needs a crates.io owner's login or an API token with the yank scope;
"Require trusted publishing for all new versions" governs publishing,
not yanking.

A yanked version cannot be unyanked, and a new publish with the
same version number is not possible. The next release picks a
new version; the fix lands on the patch line `release/X.Y.x` cut
from the yanked release's tag and is released from there. The tag
of the yanked release stays: the tag ruleset forbids moving or
deleting it, and the yank, not a missing tag, is what says the
version is withdrawn.

In practice the rollback is needed less often than the dry-run
suggests; the topological-publish discipline catches most issues
before the upload. A yank is the genuine emergency response,
typically for a security issue that warrants withdrawing a
specific version.

## Post-release maintenance

After the release lands, the maintenance window is the period
where the maintainer watches for issues. The shape:

The first 24 hours: monitor crates.io for download numbers (a
quick check that the publish reached an audience); monitor the
GitHub issue tracker for new bug reports; monitor the dashboards
of any deployments that follow main closely.

The first week: triage the issues that come in; assess whether
any warrant a patch release. The criteria for a patch release: a
critical bug, a security issue, a regression from the previous
release that the migration guide did not catch. A patch release
goes through `release/X.Y.x` (see [Branches](#branches)).

The first month: roll up the lessons learned. The patches
shipped, the issues that surfaced, the documentation gaps the
release exposed. The roll-up feeds the next release's planning.

## Settings a repository owner applies once

Each is written down to be applied as it stands. Every GitHub setting is given as the web UI path
and as a `gh api` command with its JSON body. Apply them in this order:
the `crates-io` environment must exist before the first tag the new
workflow publishes, since the publish job runs in it.

The facts the commands use: the repository is `GnomesOfZurich/axess`
(id 1031441157). `<maintainer-login>` below stands for the GitHub login of the
maintainer who approves releases, and `<maintainer-id>` for its numeric
id (`gh api users/<maintainer-login> -q .id`). Repository admins and
organisation owners can create release tags; accounts with write
access can merge pull requests. The GitHub Actions app, which
reports every check below, has integration id 15368.

### 1. Merge settings: squash only

UI: Settings, General, Pull Requests: tick "Allow squash merging" with
the default commit message "Pull request title and description";
untick "Allow merge commits" and "Allow rebase merging".

```bash
gh api -X PATCH repos/GnomesOfZurich/axess \
  -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
  -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY
```

The squashed commit on `main` then carries the release pull request's
title and description, which is where the release commit message goes.

### 2. The main branch ruleset

UI: Settings, Rules, Rulesets, New ruleset, New branch ruleset. Name
"main: releases only"; Enforcement status Active; Bypass list empty;
Target branches: Add target, Include by pattern, `main`. Rules: tick
"Restrict deletions", "Require linear history", "Require a pull
request before merging" (required approvals 0, since the author is the
only maintainer and cannot approve his own pull request; under
"Allowed merge methods" leave only Squash), "Require status checks to
pass" (tick "Require branches to be up to date before merging"; add
each check below, choosing GitHub Actions as its source) and "Block
force pushes".

```bash
gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "main: releases only",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["squash"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Release Gate", "integration_id": 15368 },
          { "context": "Release Version", "integration_id": 15368 },
          { "context": "Format Check", "integration_id": 15368 },
          { "context": "Ban #[non_exhaustive]", "integration_id": 15368 },
          { "context": "Ban cargo-mutants markers", "integration_id": 15368 },
          { "context": "Lockfile Drift", "integration_id": 15368 },
          { "context": "Detect orphan .rs files", "integration_id": 15368 },
          { "context": "Clippy Lints", "integration_id": 15368 },
          { "context": "Rustdoc (-D warnings)", "integration_id": 15368 },
          { "context": "Source Rules", "integration_id": 15368 },
          { "context": "Book", "integration_id": 15368 },
          { "context": "Test Suite", "integration_id": 15368 },
          { "context": "CockroachDB Compatibility", "integration_id": 15368 },
          { "context": "MSRV", "integration_id": 15368 },
          { "context": "Examples", "integration_id": 15368 },
          { "context": "Fuzz Smoke", "integration_id": 15368 },
          { "context": "Benchmarks", "integration_id": 15368 },
          { "context": "Publish Dry-Run", "integration_id": 15368 },
          { "context": "SemVer Checks", "integration_id": 15368 },
          { "context": "Security Audit", "integration_id": 15368 },
          { "context": "Coverage", "integration_id": 15368 },
          { "context": "Badges in sync", "integration_id": 15368 }
        ]
      }
    }
  ]
}
JSON
```

The integration id ties each check to GitHub Actions, so a commit
status of the same name posted by anything else does not satisfy it.
What the ruleset prevents: a direct push to `main` (a pull request is
required, and the bypass list is empty, admins included), a merge
commit or a rebase, a merge while any check above is red, pending or
stale against `main`, a force-push that rewrites a release, and the
deletion of `main`.

What it cannot do: say which branch the pull request comes from (the
Release Version check refuses anything but `release/next` and
`release/X.Y.x` of this repository), or keep the pull request from
editing `ci.yml` itself, since a pull request runs the workflow as the
pull request has it. Read a release pull request's changes under
`.github/` before merging.

### 3. Tag rulesets: only the maintainer and `tag.yml` create `v*`, nobody moves or deletes one

Two rulesets, because a bypass actor bypasses every rule of its
ruleset: creation names two bypasses (repository admins, and GitHub
Actions so that `tag.yml` can create the tag after a merge into
`main`), immutability names none.

UI: Settings, Rules, Rulesets, New ruleset, New tag ruleset. First:
name "release tags: created by admins"; Active; Bypass list: Add
bypass, Repository admin, Always allow, then Add bypass, GitHub
Actions (under Apps), Always allow; Target tags: Include by pattern,
`v*`; Rules: tick "Restrict creations". Second: name "release tags:
immutable"; Active; Bypass list empty; the same target; Rules: tick
"Restrict updates", "Restrict deletions" and "Block force pushes".

```bash
gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "release tags: created by admins",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" },
    { "actor_id": 15368, "actor_type": "Integration", "bypass_mode": "always" }
  ],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" } ]
}
JSON

gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "release tags: immutable",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [
    { "type": "update", "parameters": { "update_allows_fetch_and_merge": false } },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
JSON
```

Rulesets name a role or a team as a bypass, not a person. Repository
admin (role id 5) is the bypass, so anyone made an admin of this
repository or an owner of the organisation can create a release tag.
A team holding only the release maintainers is the narrower bypass
if one is wanted. What the pair prevents: a release started by anyone
else, and a published version whose tag is later moved to other code
or deleted.

### 4. The `crates-io` environment

UI: Settings, Environments, New environment, name `crates-io`.
Deployment protection rules: tick "Required reviewers" and add
`<maintainer-login>`; leave "Prevent self-review" unticked (one maintainer may
both push the tag and approve); untick "Allow administrators to bypass configured
protection rules". Deployment branches and tags: "Selected branches
and tags", Add deployment branch or tag rule, Ref type Tag, pattern
`v*`. No environment secrets.

```bash
gh api -X PUT repos/GnomesOfZurich/axess/environments/crates-io --input - <<'JSON'
{
  "wait_timer": 0,
  "prevent_self_review": false,
  "reviewers": [ { "type": "User", "id": <maintainer-id> } ],
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON

gh api -X POST repos/GnomesOfZurich/axess/environments/crates-io/deployment-branch-policies \
  -f name='v*' -f type=tag
```

Untick the administrators' bypass in the UI even when applying the
rest with `gh api`. What the environment prevents: a publish nobody
approved, and a publish from a run on a branch (a workflow edited on a
branch and dispatched from it never reaches the publish job).

### 5. Later: crates.io trusted publishing, per crate

The workflow publishes with the organisation secret
`CARGO_REGISTRY_TOKEN` today. To remove that stored token, set up
trusted publishing on every crate as below, then change the publish
job to authenticate with `rust-lang/crates-io-auth-action` (job
permission `id-token: write`, its token passed as
`CARGO_REGISTRY_TOKEN`) instead of reading the secret.

Trusted publishing needs each crate configured on crates.io, by an
owner of the crate, and only for a crate that already exists there
(all ten do). For each of `axess-strings`, `axess-clock`, `axess-rng`,
`axess-identity`, `axess-events`, `axess-cache`, `axess-factors`,
`axess-core`, `axess-macros` and `axess`:

UI: https://crates.io/crates/CRATE/settings, Trusted Publishing, Add,
GitHub. Repository owner `GnomesOfZurich`; Repository name `axess`;
Workflow filename `release.yml`; Environment `crates-io`. Save.

The environment field is what makes the GitHub approval binding: a
token is issued only to a job of `release.yml` in this repository that
runs in `crates-io`, which only a `v*` tag the maintainer approved reaches.

After the first release published this way, on the same settings page
of each crate tick "Require trusted publishing for all new versions",
so a crates.io API token can no longer publish a version. Then remove
this repository's access to the organisation secret
`CARGO_REGISTRY_TOKEN`, which the workflow no longer reads (or delete
the secret if no other repository publishes with it), and revoke that
token on crates.io:

```bash
gh api -X DELETE orgs/GnomesOfZurich/actions/secrets/CARGO_REGISTRY_TOKEN/repositories/1031441157
```

That call works when the secret's repository access is "Selected
repositories"; with "All repositories" change it in the organisation's
Settings, Secrets and variables, Actions.

### 6. Recommended: release lines keep their history

Not part of the approved list; recommended because the release
workflow's "on a `release/X.Y.x` branch" check reads the branch as it
stands. UI: a branch ruleset "release lines", Active, Bypass list
empty, target pattern `release/*.x`, "Restrict deletions" and "Block
force pushes".

```bash
gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "release lines",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["refs/heads/release/*.x"], "exclude": [] } },
  "rules": [ { "type": "deletion" }, { "type": "non_fast_forward" } ]
}
JSON
```

`release/next` is left out on purpose: the release workflow moves it
or merges `main` into it after every release, which a ruleset refusing
non-fast-forward updates would block.

### 7. Optional: only an admin merges into `main`

The main ruleset requires a pull request but lets anyone with write
access (`gnomes-ops` today) merge one whose checks pass. To keep the
merge with repository admins, a third branch ruleset restricts updates to `main` and
lets repository admins bypass that one rule through a pull request
only, so a direct push is still refused for everyone:

```bash
gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "main: merged by admins",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [ { "type": "update", "parameters": { "update_allows_fetch_and_merge": false } } ]
}
JSON
```

UI: a branch ruleset "main: merged by admins", Active, Bypass list:
Repository admin with "For pull requests only", target `main`, rule
"Restrict updates".

### Checking what applies

```bash
gh api repos/GnomesOfZurich/axess/rulesets --jq '.[] | [.id, .name, .target, .enforcement] | @tsv'
gh api repos/GnomesOfZurich/axess/rules/branches/main --jq '.[].type'
gh api repos/GnomesOfZurich/axess/environments/crates-io \
  --jq '{protection_rules, deployment_branch_policy, can_admins_bypass}'
```

The second command lists the rules in force on `main` from every
ruleset together: `deletion`, `non_fast_forward`,
`required_linear_history`, `pull_request` and `required_status_checks`
(and `update` with step 7). Read these rather than testing with a
real push or a tag deletion, which a misapplied ruleset would let
through.

## Further reading

*Migration guide* covers the cross-version compatibility surface
that the release-management decisions depend on. *Contributing*
covers the development workflow that produces the changes a
release ships. The
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md)
covers the exhaustive list of changes per release.
