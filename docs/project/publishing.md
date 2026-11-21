# Publishing runbook

Maintainers only. Publishing to crates.io is irreversible and versions
cannot be reused, so the order below is not advisory.

An adopter does not need this chapter. It gives the maintainer
cutting a release a written reference, and lets a different
maintainer follow the same procedure.

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
merged into it otherwise), so afterwards it contains the commit the last
tag points at. The branch is never deleted. Contributors' pull requests
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

The maintainer releases: they push the release branch, open the pull request
from it into `main` and let it merge (squash) once the required checks
pass (`gh pr merge --squash --auto`); the merge is tagged `vX.Y.Z` by
[`tag.yml`](../../.github/workflows/tag.yml), which starts the release
workflow; the maintainer approves the `crates-io` deployment when that
workflow asks for it, after the check under
[Before approving](#before-approving), and the workflow's last job
levels `release/next` with `main`. Two human acts: the pull request,
the approval.

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
5. The maintainer opens the settings page of each of the eleven crates
   (https://crates.io/crates/CRATE/settings) and confirms its Trusted
   Publishing list holds the entry of settings step 5. The release
   workflow cannot check this before it publishes ([The publish](#the-publish)
   says why), and a crate left out stops the release at that crate, after the
   ones before it.

Three more requirements hold, and the preflight does not
check them: the migration guide (*Migrating* in the book) has an entry for
every breaking change; every published crate carries `description`,
`license`, `repository`, `keywords`, `categories` and the
`[package.metadata.docs.rs]` block (`all-features = true`, or a `features`
list in a crate with a feature docs.rs must not build, which
`scripts/check-docsrs-features.sh` holds to the crate's features, and
`rustdoc-args = ["--cfg", "docsrs"]`); and no crate that should publish
says `publish = false`.

### The release pull request and its checks

A pull request into `main` runs every job of
[`ci.yml`](../../.github/workflows/ci.yml), which between them run every
step of `scripts/release-preflight.sh` but one. The step on the
Hardening and Mutants runs (`scripts/check-scheduled-runs.sh --report`)
only reports their newest runs on `main`; the check on the release
commit runs in the release workflow, before publish (step 7 below),
where the Hardening run binds and the Mutants run is reported. The crafted cases of `scripts/check-scheduled-runs.sh` run in the Source Rules job. The main branch ruleset requires
these checks by name (the job `name:` values); renaming a job is a
ruleset edit in the same release.

| Required check | What it runs | What it prevents |
|---|---|---|
| Release Gate | needs every other job, matrix rows included; `scripts/check-ci-gate.sh` | a failing Build Check, Feature Isolation or Factor Isolation row, or a job added to `ci.yml` but to no gate |
| Release Version | the pull request comes from `release/next` or `release/X.Y.x` of this repository; `scripts/check-release-version.sh` strict | a release from a topic branch or a fork; a tag, workspace version, internal pin or dated changelog section that disagree; entries left under `[Unreleased]` |
| Format Check | `cargo fmt --check` | unformatted code |
| Ban #[non_exhaustive] | grep of first-party crates | the attribute the project refuses |
| Ban cargo-mutants markers | grep of first-party crates | a mutation left in the source by a local cargo-mutants run |
| Lockfile Drift | `cargo metadata --locked` for the workspace and for the fuzz crate, `scripts/check-fuzz-lock.sh`, and `scripts/check-lock-age.sh` with its crafted cases | a `Cargo.lock` that does not match the manifests, a fuzz lock file at other versions than the workspace's, or a crates.io entry added since the last release tag that was published less than seven days ago (`.cargo/config.toml`) and is not admitted by a `Cooldown-Exempt: <advisory id> <crate>` trailer on the commit that adds it |
| Detect orphan .rs files | module reachability | a source file the compiler never reads |
| Clippy Lints | clippy, all targets, all features, `-D warnings` | lint regressions |
| Rustdoc (-D warnings) | rustdoc links, Markdown links, prose style, documented identifiers, methods, imports and versions | docs that point at names, paths, chapters or versions that do not exist |
| Source Rules | inline test block sizes, file and function sizes, wall-clock and monotonic-clock reads outside axess-clock, `rsa::` call sites, the reason on every `#[ignore]`, the features docs.rs builds for each published crate, and the crafted cases of those scripts, of the test-log guard, of the supply-chain waiver and of the scheduled-run check | modules and functions past the size limits, a new clock read or `rsa::` site, an ignored test that does not say what it needs, a feature docs.rs would leave out or could not build, a source-rule script that no longer refuses its fixture |
| Shell Scripts | every shell script the repository tracks read by the ShellCheck `scripts/install-shellcheck.sh` pins (`scripts/check-shellcheck.sh`), and the crafted cases of that check | a directive ShellCheck cannot parse, which hides every later finding in its file; a finding at warning or above; a sourced file ShellCheck cannot find |
| Book | the book built and its code compiled with the pinned mdBook | a book that fails only after the merge, in the docs workflow |
| Test Suite | every non-ignored test, then `scripts/check-live-stores.sh` against Valkey, a three-node Valkey cluster, PostgreSQL, MySQL and Keycloak | a red test, including a live-store test |
| CockroachDB Compatibility | the PostgreSQL suite against CockroachDB | a wire-compatibility regression |
| SPIRE Workload API | `scripts/spire-live.sh`: the ignored tests of the Workload API client against a SPIRE server and agent started on the runner | a client that a real agent's SVIDs, bundles, rotation or withdrawal break |
| MSRV | `scripts/check-msrv.sh` | a `rust-version` promise the code no longer keeps |
| Examples | the example applications build | an example that no longer compiles |
| Fuzz Smoke | each target the fuzz crate lists for 30 seconds, and the Hardening matrix checked against that list | an easy crash in a decoder, or a target the Hardening workflow does not run |
| Benchmarks | the benchmarks run | a benchmark that panics |
| Publish Dry-Run | `cargo publish --dry-run` for leaf crates, `cargo package --list` for the rest | a crate crates.io would refuse |
| SemVer Checks | `scripts/check-semver.sh`: cargo-semver-checks (the version ci.yml pins) against the last release tag as a minor release, every break it reports held to the migration page, and the crafted cases of that check | a breaking change in the classes cargo-semver-checks covers that the migration page does not name, or a report the check cannot read |
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

### The hardening workflow

[`hardening.yml`](../../.github/workflows/hardening.yml) runs beside CI on
every pull request into those branches, on every push to them and to a
release tag, and nightly, with `contents: read` and nothing else. It runs:

- `scripts/check-workflow-pins.sh`, with its crafted cases first;
- `scripts/supply-chain.sh` (audit, deny with advisories, the unsafe
  report, one version of each crypto crate, no `testing`, `memory`,
  wiremock or tracing-subscriber in a release tree);
- the compile-fail test that `axess::testing` is absent without its
  feature;
- every fuzz target for 120 seconds;
- Miri over the crates that contain `unsafe` and over axess-clock.

No target has an allowance: one that fails, fails the run. The workflow is
not yet among the required checks; add it to the ruleset when it has been
green for a week.

The workflow pin check requires, in every `.yml` and `.yaml` workflow:
every action pinned to a commit with its release in a comment, every
image to a digest, every checkout without a stored credential, every
`cargo install` locked to an exact version and every other install route
refused, no flow-style `{uses: ...}` mapping, no tool installed in a job
that names a secret, may ask for an OIDC token or holds a token that can
write, the OIDC permission on no whole workflow, and an exact toolchain
in a workflow that publishes.

Such a job (one that names a secret, may ask for an OIDC token or holds a
token that can write) also runs only what the check reads: the programs it names,
repository scripts named from the repository's root, cargo's own
subcommands with `--locked`, the actions on its list, no file written
into the checkout, no arithmetic on a value the script did not make, a
publish to crates.io with no registry named, git, gh and curl to the
repository's own remote, GitHub, crates.io and the runner's services
alone, nothing a job that holds no secret made run or built, and never a
changed checkout beside code run from it.

In every job: no expression is pasted into a script; no program runs by
a path the repository does not hold, except a download the job checked;
no cargo subcommand runs that the job did not install at an exact
version; a file a step downloads with curl, wget or
`gh release download` is checked with `sha256sum --check` against a
SHA-256 written out in the workflow or the script before it is run or
unpacked; no stream is unpacked as it arrives; and no action is handed a
URL.

The check reads each workflow as YAML and each script a job runs as the
shell does, the repository scripts it calls included. It refuses by name
a form it does not read, and its header says what it does not judge,
why, and what covers it.

#### Moving the pin of an action

Every action a workflow uses stands in
[`scripts/lib/workflow_actions.txt`](../../scripts/lib/workflow_actions.txt)
with what it is trusted to do (install nothing, restore no cache, run no
script of the job's) and whether it may run beside a secret. The check
refuses an action that is not listed, a listed one that no workflow uses
any more, and any use that is not a full commit with its release in a
comment. It does not read what the pinned commit runs, and neither did
whoever wrote the list: the file says so. The control is the review of a
bump. A pull request that moves a pin shows the old and the new commit;
the maintainer reads the difference between them in the action's own
repository, and what its entry point runs, before merging, and changes the
line of the list in the same pull request when what the action does has
changed. A new action enters the same way: its line, its pin, and the
reading of that commit.

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
3. **Package the crates and the SBOM** runs `cargo package --workspace
   --locked` from the tagged tree, records the SHA-256 of every `.crate`
   and generates the CycloneDX SBOM from the same tree with a
   version-pinned `cargo-cyclonedx --locked`. It holds no secret and no
   OIDC permission, and restores no cache.
4. **Attest the packaged crates and the SBOM** is the one job that
   writes attestations; the publish job also holds `id-token: write`,
   for the crates.io token exchange alone. It runs no build: it downloads the files the
   previous job made and attests the build provenance of each `.crate`
   and of the SBOM with Sigstore keyless signing, so adopters can tie a
   crate to this workflow run and this commit.
5. **Audit the lockfile at release** runs `cargo audit` against the
   lockfile as the advisory database stands then. It is a job of its own,
   with no secret and no environment: `cargo install` builds and runs
   whatever the registry serves that day, so the runner that installs the
   tool is never the runner the registry token reaches.
   `scripts/check-workflow-pins.sh` refuses a job that names a secret,
   may ask for an OIDC token or holds a token that can write, and runs
   `cargo install` or anything else the check does not read.
6. **Hardening at release** runs the workflow pin check and
   `scripts/supply-chain.sh` on the tagged commit, in a job with no secret
   and no environment. `hardening.yml` runs the same gates on the tag
   push, but one workflow cannot wait for another's run, so the publish
   job waits for this one.
7. **Hardening and Mutants runs on the release commit** runs
   [`scripts/check-scheduled-runs.sh`](../../scripts/check-scheduled-runs.sh)
   with the job's own token, which may read Actions and nothing more. The
   release commit is, for a tag on `release/X.Y.x`, the tagged commit,
   and for the squash merge into `main`, the head of the release pull
   request (the release branch commit outside `main` with the tagged
   tree). The newest run of `hardening.yml` that counts on that exact
   commit (a push, a dispatch, or a pull request from this repository)
   must have ended in success. No run on an earlier commit counts. If
   that run has not ended, the job stops and prints its address to wait
   for; if there is no run, it stops and prints the command that starts
   one; any other ending, or a refusal from gh, stops the publish. The
   newest run of `mutants.yml` (a push or a dispatch: a pull request's
   sweep covers its diff alone) is read and reported and does not stop
   the publish (`--mutants-report-only`): the job prints its address and
   its ending, on an `OK` line when it ended in success and on a
   `REPORTED, NOT REQUIRED` line when it has not ended, ended otherwise,
   does not exist or could not be read.
   No full sweep has yet passed at the shard size
   `scripts/mutants-sweep.sh` plans; once one has, the requirement
   returns and the workflow drops the option. Both workflows run when the
   release commit is pushed to its branch; the mutation sweep takes days
   and the job does not wait for it.
8. **Publish to crates.io** waits for the maintainer's approval in the
   `crates-io` environment ([Before approving](#before-approving)). It
   packages the workspace again and refuses, by name, unless the sums
   equal the attested ones, then publishes in dependency order with
   `cargo publish --locked`. `cargo publish` packages once more before it
   uploads and cannot upload a file made elsewhere, so after each crate
   is published, or found already there, the job reads the checksum
   crates.io's index lists for that version and refuses, by name, unless
   it is the SHA-256 of the attested file: that comparison, not the
   packaging before it, is what ties the upload to the attestation. Both
   cargo commands run with `--no-verify`: the package job built and
   verified every crate, and this job, which may ask for an OIDC token,
   builds nothing, so no build script of a dependency runs in it. Its
   only actions are GitHub's own (checkout, download-artifact); its cargo
   is the runner image's rustup, which reads `rust-toolchain.toml` and
   fetches the release pinned there from static.rust-lang.org. rustup
   installs a missing pinned toolchain by default from 1.28.1 on (1.28.0
   alone did not), and the job sets `RUSTUP_AUTO_INSTALL=1` for a runner
   configured not to. Its first step reads the release from
   `rust-toolchain.toml` and stops the job by name, before anything is
   packaged, unless `cargo -vV` reports that release. It reads cargo's
   release, not rustc's: the job never runs rustc, rustup runs both from
   one toolchain, and the pin check lets no program it does not name run
   beside the OIDC permission. It
   publishes by crates.io trusted publishing and holds no stored secret:
   for each crate it hands the job's OIDC token to crates.io and is
   answered with a short-lived token, which the job revokes
   when `cargo publish` returns. The exchange names no crate: crates.io
   answers it when any crate's settings name this repository,
   `release.yml` and the `crates-io` environment (settings step 5), and
   the token publishes only the crates whose settings do. A run that is
   cancelled or times out during an upload revokes the token on its way
   out. The exchange is written out in the publish step with curl and
   jq, so the job runs no action and no repository script for it;
   [`scripts/release-publish-tests.sh`](../../scripts/release-publish-tests.sh)
   runs that step against a recorded curl and cargo.
9. **GitHub Release** creates the release with generated notes and the
   attested `.crate` files and SBOM as assets.
10. **Level release/next with main** runs only for a tag on `main`:
   when `release/next` is behind `main` or carries the same tree as the
   squashed release, the branch is moved to the released commit; when
   work landed on it since the release pull request was opened, `main`
   is merged into it; a conflict ends the job by name and the
   maintainer merges by hand (`git checkout release/next && git merge
   main && git push`). A tag on `release/X.Y.x` leaves `release/next`
   alone; the patch line is merged forward by hand.

To re-run an existing tag (a publish that stopped part-way), dispatch
the workflow from the tag, not from a branch:

```bash
gh workflow run release.yml --repo GnomesOfZurich/axess --ref vX.Y.Z
```

The publish step skips any crate whose version is already uploaded,
once the index shows that the version there is the attested file.
A dispatch from a branch is refused in step 1, and the `crates-io`
environment admits tags only.

### Before approving

The approval is the only gate that binds whoever made the tag. A tag's
run uses the `release.yml` of the tagged commit, so the jobs before the
approval are whatever that commit says they are: a tag on a commit
whose workflow was edited reaches the approval with every earlier job
green, the tag verification included. crates.io compares the
repository, the workflow's file name and the environment, never the
workflow's content. So before approving a deployment to `crates-io`,
check two things about the commit the waiting run is for.

It is the squash merge of the release pull request that was reviewed.
The first command prints the run's commit; the second prints the pull
request's state, its base, its merge commit and the head it was
reviewed at. The pull request is merged, its base is `main`, and its
merge commit is the run's commit:

```bash
gh run view RUN --repo GnomesOfZurich/axess --json headSha --jq .headSha
gh pr view PR --repo GnomesOfZurich/axess --json state,baseRefName,mergeCommit,headRefOid \
  --jq '[.state, .baseRefName, .mergeCommit.oid, .headRefOid] | @tsv'
```

Nothing under `.github/` differs between that commit and the reviewed
head. This prints nothing:

```bash
git fetch origin refs/pull/PR/head refs/tags/vX.Y.Z:refs/tags/vX.Y.Z
git diff --stat HEAD_REVIEWED vX.Y.Z -- .github/
```

For a patch release the commit is the reviewed head of
`release/X.Y.x`: the run's commit equals
`git rev-parse origin/release/X.Y.x` as it was reviewed, and
`git diff vX.Y.W vX.Y.Z -- .github/`, against the tag the line was cut
from, shows only changes that were reviewed.

If either check fails, reject the deployment. The tag cannot be moved
or deleted (settings step 3); the version it names is released, if at
all, by a later patch version from a reviewed commit.

The Mutants run does not stop the publish (step 7 under
[The release workflow](#the-release-workflow)). The log of the job
"Hardening and Mutants runs on the release commit" prints its address
and its ending: an `OK: Mutants` line for a sweep that ended in
success, a `REPORTED, NOT REQUIRED: Mutants` line for one still
running, ended otherwise, missing or unread. Read that line before
approving, so that the approval is given knowing where the sweep
stands.

## Topological dependency order

The workspace's library crates publish in dependency order: a
crate must be published before any crate that depends on it. The
order:

1. `axess-strings` (no axess deps)
2. `axess-clock` (no axess deps)
3. `axess-rng` (no axess deps)
4. `axess-testing` (no axess deps; a dev-dependency for adopters, so no
   published crate depends on it)
5. `axess-identity` (depends on `axess-rng`)
6. `axess-events` (depends on `axess-identity` and `axess-strings`)
7. `axess-cache` (depends on `axess-clock`)
8. `axess-factors` (depends on `axess-identity`, `axess-clock`,
   `axess-rng`)
9. `axess-core` (depends on `axess-factors`, `axess-identity`,
   `axess-cache`, `axess-clock` and `axess-rng`)
10. `axess-macros` (depends on `axess-core`)
11. `axess` (the facade, depends on `axess-core`, `axess-factors`,
    `axess-identity` and `axess-macros`)

The release workflow publishes in this order; the maintainer should
know it so a publish that fails part-way can be read at a
glance.

## The dry-run

The Publish Dry-Run job runs on every pull request, so the release
pull request has already dry-run the release. To repeat it locally:

```bash
cargo publish --dry-run -p axess-strings
cargo publish --dry-run -p axess-clock
cargo publish --dry-run -p axess-rng
cargo publish --dry-run -p axess-testing
for c in axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess; do
  cargo package --list -p "$c" >/dev/null
done
```

The dry-run does everything the publish does except the upload.
It builds the package, verifies the manifest, runs the publish-time
checks, and prints the path of the `.crate` file it would have
uploaded. A failure here is fixed before anything is uploaded, with
no half-published release to yank.

Only the leaf crates dry-run end to end: a downstream crate's dry-run
resolves its `axess-*` dependencies against crates.io, where the new
version does not exist until the release workflow publishes it, so
`cargo package --list` validates the manifest and the shipped file set
instead.

## The publish

The release workflow publishes; nobody runs `cargo publish` by hand.
It publishes by trusted publishing (settings step 5), and once every
crate is set to accept trusted publishing only, a token on a
maintainer's machine could not publish anyway.

The workflow waits 30 seconds between crates so each one is in the
crates.io index before the next resolves it, and on a "429 Too Many
Requests" it sleeps until the time crates.io names; every attempt asks
crates.io for a token of its own, so a wait cannot outlive one. If the
run stops part-way, re-run the tag as above: crates already uploaded
are skipped, and the rest continue in order.

Of the three refusals below, the first two leave nothing to undo:
the crates already uploaded stay published, and a re-run of the tag
skips them and continues in order. The third needs a yank.

- **No crate trusts the workflow.** The exchange itself is refused: the
  job prints `refused: crates.io issued no trusted-publishing token`, the
  reason crates.io gave, and the crate it stopped at. On the first crate
  this happens before anything is uploaded; it means no crate has the
  entry of settings step 5, or the repository, workflow file or
  environment changed name. Fix the settings and re-run the tag.
- **One crate does not trust it.** The exchange names no crate, so
  crates.io answers it as long as any crate is set up, and the workflow
  cannot tell beforehand which one is missing (release preparation step
  5 is that check). The crate left out is refused at its own upload:
  `cargo publish` fails with crates.io's `403 Forbidden`, and the job
  prints `crates.io refused the token for CRATE` and stops, after the
  crates before it in the order. Until the re-run, the release is
  half-published: the crates after it are missing at the new version.
  Add the crate's entry (settings step 5) and re-run the tag.
- **crates.io holds another file.** After a crate is published or
  skipped, the job reads the checksum crates.io's index lists for that
  version and compares it with the SHA-256 of the attested file. When
  they differ it prints `refused: crates.io holds CRATE VERSION with
  SHA-256 ...` with both sums and stops before the next crate and
  before the GitHub release. Either `cargo publish` packaged other
  bytes than the package job did, or that version was uploaded from
  somewhere else before this run. Do not re-run the tag: yank that
  version of the crate ([Rollback](#rollback)), find out which upload
  it was, and release the next patch version. When the index does not
  list the version within ten reads, 30 seconds apart, the job prints
  `crates.io's index did not list CRATE VERSION` and stops without
  having compared; re-run the tag, and the crate is skipped and
  compared again.

A second run of a tag is safe: for a crate already at this version,
`cargo publish` answers that it is already uploaded (the registry's
wording) or already exists on the index (cargo's own), and the step
reads either as "skip", compares what is there with the attested file
as above, and goes on to the next crate.

A refusal the settings do not explain means the exchange no longer
matches what crates.io expects. A tag's workflow cannot change, so
correct the publish step of `release.yml` on `release/next` and release
the next patch version.

What the exchange was checked against. On 2026-11-13 the publish step
was compared with the source of the registry's own authentication
action (`rust-lang/crates-io-auth-action`, main branch: `main.ts`,
`utils.ts`, `registry_url.ts`, `post.ts`). It agrees on the audience
(`crates.io`), on the exchange (`POST` to
`https://crates.io/api/v1/trusted_publishing/tokens` with the JSON body
`{"jwt": ...}`, answered by `{"token": ...}`), on the revocation
(`DELETE` on the same URL with `Authorization: Bearer`), on the shape of
a refusal (`{"errors":[{"detail": ...}]}`) and on sending a `User-Agent`
with both calls; here it names this workflow and repository. Not
checked, because nothing here can reach the registry: how long the token
lives, that one token publishes every crate whose settings match (the
step asks for one per crate, so it does not depend on it), and cargo's
wording when crates.io refuses a crate that does not trust the workflow
(the step looks for `403 Forbidden`; without that match the job still
stops, with cargo's own message and `publishing CRATE failed`).

The index read was checked against the registry index format in the
Cargo book on 2026-11-13: the sparse index at `https://index.crates.io`
keeps a crate of four or more characters under its first two, then its
next two characters, then its name (so every crate here is under
`ax/es/`); its file has one JSON object per line and version, with `vers`
and `cksum`, the SHA-256 of the `.crate` file in hex; and a crate it does
not hold is answered 404, 410 or 451. The step reads all three as "not
listed" and reads again. The rustup behaviour above was checked against
rustup's changelog the same day. Not checked: cargo's wording of a rate
limit (`Please try again after <date> GMT`), which only sets how long the
step waits; a wording it does not match makes it wait two minutes.

After the run, verify on crates.io that all eleven crates are listed at
the new version.

## The smoke test

After the publish, run a smoke test against a fresh dependency
on the published version. The shape:

```bash
mkdir /tmp/axess-smoke
cd /tmp/axess-smoke
cargo new --name axess-smoke .
echo 'axess = "0.20"' >> Cargo.toml
cargo build
```

The build pulls the published crates from crates.io (not from
the workspace) and verifies they assemble. A failure here
is one the dry-run did not catch, typically a crates.io-specific
problem such as a missing file in the package manifest; respond with
the rollback procedure.

For a more thorough smoke test, copy `examples/sqlite/` to a
fresh directory, point its `Cargo.toml` at the version just published
(each `path = "../../CRATE"` removed, leaving that dependency's
`version`, which is already the release's), and verify it builds and
runs.

The smoke test is the last gate before announcing the release.

## The announcement

By the time the smoke test passes, the tag exists (it started the
release) and the workflow has created the
[GitHub release](https://github.com/GnomesOfZurich/axess/releases)
with the SBOM. The GitHub releases page is the canonical announcement;
the project's other channels mirror it.

`release/next` needs no cutting: the release workflow's last job
levelled it with `main` (release workflow, step 10), so the next change
lands on a branch that holds this release. If that job stopped on a
conflict, merge `main` into the branch by hand as that step says. The
branch is never deleted: every open pull request targets it, and a
deleted base closes them.

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
are ignored. A migrating page is held to the version it moves to
(`docs/production/migrating/0.18.0-to-0.19.0.md` to 0.19), so a bump
leaves the pages of earlier releases as they are.

Bump the workspace version first, then run the check: it lists
every snippet the bump left behind.

## Rollback

If the publish goes wrong (a critical bug surfaces, a crate is
broken on crates.io, the release was premature), roll it
back:

`cargo yank --version X.Y.Z axess` (and every other crate)
withdraws the version from crates.io. Yanked versions remain
available to existing consumers (so `Cargo.lock` references
continue to work), but new resolves do not pick them up. Yanking
needs a crates.io owner's login or an API token with the yank scope;
"Require trusted publishing for all new versions" governs publishing,
not yanking.

A yank can be undone (`cargo yank --undo --version X.Y.Z CRATE`), so
a version yanked by mistake is restored, not replaced. A new publish
with the same version number is not possible. The next release picks a
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

After the release, the maintainer watches for problems:

The first 24 hours: monitor crates.io for download numbers (a
quick check that the publish reached an audience); monitor the
GitHub issue tracker for new bug reports; monitor the dashboards
of any deployments that follow main closely.

The first week: triage the issues that come in; assess whether
any warrant a patch release. The criteria for a patch release: a
critical bug, a security issue, a regression from the previous
release that the migration guide did not catch. A patch release
goes through `release/X.Y.x` (see [Branches](#branches)).

The first month: summarise the patches shipped, the issues that
surfaced and the documentation gaps the release exposed, as input to
the next release's planning.

## Settings a repository owner applies once

Each is written down to be applied as it stands. Every GitHub setting is given as the web UI path
and as a `gh api` command with its JSON body. Apply them in this order:
the `crates-io` environment must exist, and every crate must be set up
for trusted publishing on crates.io (step 5), before the first tag the
workflow publishes, since the publish job runs in that environment and
has no other way to authenticate.

The facts the commands use: the repository is `GnomesOfZurich/axess`, and
`<repository-id>` below stands for its numeric id
(`gh api repos/GnomesOfZurich/axess -q .id`). `<maintainer-login>` stands for
the GitHub login of the maintainer who approves releases, and
`<maintainer-id>` for its numeric id
(`gh api users/<maintainer-login> -q .id`). Any account with write
access can merge a pull request, and, until step 8 is applied, create a
`v*` tag or a `release/X.Y.x` branch. The GitHub Actions app, which
reports every check below, has integration id 15368.

### 1. Merge settings: squash only, auto-merge allowed

UI: Settings, General, Pull Requests: tick "Allow squash merging" with
the default commit message "Pull request title and description";
untick "Allow merge commits" and "Allow rebase merging"; tick "Allow
auto-merge", so that `gh pr merge --squash --auto` can arm the release
pull request to merge by itself when its required checks pass.

```bash
gh api -X PATCH repos/GnomesOfZurich/axess \
  -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
  -F allow_auto_merge=true \
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
only maintainer and cannot approve their own pull request; under
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

### 3. Tag ruleset: nobody moves or deletes a `v*` tag

One ruleset, with no bypass actor, makes a release tag immutable:
nobody updates, deletes or force-pushes one, `tag.yml` included.

This ruleset does not restrict creating a tag: any account with write
access can create a `v*` tag, on any commit, and the tag starts
`release.yml` as that commit has it. `tag.yml` creates the tag with the
workflow token after a merge into `main`, and GitHub refuses the GitHub
Actions app as a bypass actor on a repository ruleset ("must be part of
the ruleset source or owner organization"), so a creation rule in this
ruleset would refuse the workflow. Nothing in `release.yml` bounds a
stray tag, because the tag's commit supplies the `release.yml` that
runs: the one gate that binds it is the maintainer's approval in the
`crates-io` environment, given after the check under
[Before approving](#before-approving). Step 8 restricts who creates a
tag.

UI: Settings, Rules, Rulesets, New ruleset, New tag ruleset: name
"release tags: immutable"; Active; Bypass list empty; Target tags:
Include by pattern, `v*`; Rules: tick "Restrict updates", "Restrict
deletions" and "Block force pushes".

```bash
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

The bypass list is empty, so the three rules hold for everyone,
repository admins and organisation owners included. What the ruleset
prevents: a published version whose tag is later moved to other code
or deleted. What it does not prevent: a release run started by a tag
any account with write access created. The approval in the `crates-io`
environment is what stops that run from publishing.

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
branch and dispatched from it never reaches the publish job). It does
not prevent a workflow edited on a commit that is then tagged from
reaching the approval: the approver's check is what does
([Before approving](#before-approving)).

### 5. crates.io trusted publishing, per crate

The publish job stores no registry token. It asks crates.io for a
short-lived one in exchange for the job's GitHub OIDC token, and the
token publishes only the crates whose settings name the workflow that
asks. So this step is required for every crate: a crate left out is
refused at its own upload, after the crates before it have published
(see [The publish](#the-publish)), and release preparation step 5 checks each crate before
every release.

Each crate is configured on crates.io by an owner of the crate, and
only once the crate exists there (all eleven do). For each of
`axess-strings`, `axess-clock`, `axess-rng`, `axess-testing`,
`axess-identity`, `axess-events`, `axess-cache`, `axess-factors`,
`axess-core`, `axess-macros` and `axess`:

UI: https://crates.io/crates/CRATE/settings, Trusted Publishing, Add,
GitHub. Repository owner `GnomesOfZurich`; Repository name `axess`;
Workflow filename `release.yml`; Environment `crates-io`. Save.

The environment field is what makes the GitHub approval binding: a
token is issued only to a job of `release.yml` in this repository that
runs in `crates-io`, which only a `v*` tag the maintainer approved reaches.
The four values are compared with the claims of the job's OIDC token,
so a renamed repository, workflow file or environment needs the same
change on every crate. They name the workflow file, not what it holds:
crates.io issues the token to any `release.yml` of this repository
that reaches the environment.

A crate added to the workspace is published once by hand with a
crates.io API token an owner creates for that one publish and revokes
after it (crates.io configures trusted publishing only for a crate that
exists), then set up as above before the next release.

After the first release published this way, on the same settings page
of each crate tick "Require trusted publishing for all new versions",
so a crates.io API token can no longer publish a version. The
organisation secret `CARGO_REGISTRY_TOKEN` is read by no workflow of
this repository: remove the repository's access to it (or
delete the secret if no other repository publishes with it), and revoke
that token on crates.io:

```bash
gh api -X DELETE orgs/GnomesOfZurich/actions/secrets/CARGO_REGISTRY_TOKEN/repositories/<repository-id>
```

That call works when the secret's repository access is "Selected
repositories"; with "All repositories" change it in the organisation's
Settings, Secrets and variables, Actions.

### 6. Recommended: release lines keep their history

Not required for a release to run; recommended because the release
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

The main ruleset requires a pull request but lets any account with
write access merge one whose checks pass. To keep the
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

### 8. Who creates a release tag or a release line

A repository owner applies this step. Until then, any account with write access
can create a `v*` tag or a `release/X.Y.x` branch, each of which starts
or feeds a release run. Two rulesets, each with a creation rule and
the repository admin role (id 5) as its only bypass:

```bash
gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "release tags: created by admins",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" } ]
}
JSON

gh api -X POST repos/GnomesOfZurich/axess/rulesets --input - <<'JSON'
{
  "name": "release lines: cut by admins",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "conditions": { "ref_name": { "include": ["refs/heads/release/*.x"], "exclude": [] } },
  "rules": [ { "type": "creation" } ]
}
JSON
```

UI: a tag ruleset "release tags: created by admins", Active, Bypass
list: Repository admin, target `v*`, rule "Restrict creations"; and a
branch ruleset "release lines: cut by admins" with the same bypass and
rule on `release/*.x`. They are rulesets of their own because a bypass
actor on the rulesets of steps 3 and 6 would let an admin move or
delete what those keep for everyone.

The tag rule also refuses `tag.yml`, whose workflow token is not a
bypass actor GitHub accepts (step 3). With the rule in force the
maintainer creates the tag by hand after the release pull request
merges, `git tag vX.Y.Z <merge commit> && git push origin vX.Y.Z`,
which starts `release.yml` by itself: a third human act. To keep the
tag automatic, register a GitHub App owned by the organisation, mint
its installation token in `tag.yml` (`actions/create-github-app-token`)
and add the app to the tag ruleset's bypass list; a tag pushed with
that token also starts `release.yml` by itself.

Either way the approval stays the gate that binds: these rules narrow
who can bring a run to it, to accounts that could change the rules.

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

*Migration guide* covers compatibility between versions, which
release decisions depend on. *Contributing* covers the development
workflow. The
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md)
lists every change in each release.
