# Release runbook

Step-by-step procedure for cutting a new axess release. The 10 library
crates are versioned in lockstep (`[workspace.package].version` is the
single source of truth) and published to crates.io bottom-up.

## Prerequisites

- The process in [the publishing runbook](../project/publishing.md):
  the release is prepared on `release/next` (or a patch line
  `release/X.Y.x`), reaches `main` by a squashed pull request, and is
  published by the release workflow through crates.io trusted
  publishing; no crates.io token is stored.
- A clean working tree on the release branch.

## 1. Pick the version

The workspace is pre-1.0 (`0.x`). Bumping rules:

- **`0.x.y` → `0.x.y+1`**: pure bug fixes, no public-API change.
  Detected by `cargo semver-checks check-release`.
- **`0.x.y` → `0.x+1.0`**: any public-API change (breaking or additive),
  any MSRV bump, any default-feature change.

Edit two lines in [`Cargo.toml`](../../Cargo.toml):

```toml
[workspace.package]
version = "0.NEW.0"

[workspace.dependencies]
axess-cache    = { path = "axess-cache",    version = "0.NEW.0" }
# ...one literal "0.NEW.0" per internal entry (find-and-replace works)
```

`cargo update --workspace` to refresh `Cargo.lock`.

## 2. Regenerate the repository version badge

The top-level repository README uses hand-rolled SVG badges under
[`.github/badges/`](../../.github/badges/). Crate READMEs link to those same
SVGs via absolute GitHub raw URLs, because `.github/` is excluded from the
published crates and relative badge paths break on crates.io. The coverage
badge is measured and committed during release preparation (the publishing
runbook's "Release preparation" has the commands); the other repository
badges are static and only change when the underlying value changes. On a
release, regenerate the version badge (and the status badge if the project
life-cycle stage moves):

```sh
./scripts/generate-badge.sh version "0.NEW.0" blue .github/badges/version.svg
# Optional: bump status if you are leaving pre-release territory.
# ./scripts/generate-badge.sh status "v1.x stable" brightgreen .github/badges/status.svg
```

Commit the regenerated SVG alongside the version bump.

## 3. Update the changelog

[`CHANGELOG.md`](../../CHANGELOG.md) follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/). As soon as the version
is known, move every entry from `[Unreleased]` under a new
`## [0.NEW.0] - unreleased` heading and group by `### Added` /
`### Changed (breaking)` / `### Fixed` / `### Security` as the entries
fit. Release day replaces `unreleased` with the date (`YYYY-MM-DD`);
`./scripts/check-release-version.sh` refuses the release until it does.

Recreate an empty `## [Unreleased]` heading at the top for the next
cycle, before the cut section. Without it the next change has nowhere to
land but a released section, which is how a finished release note grows
entries that were never in that release.

An entry is a bold lead plus the consequence, one to three lines, and a
breaking one says **Migrating:** with the step. The reasoning, the
measurements and the account of how a defect surfaced go in the commit
message, which is written anyway. A release section that is the longest
in the file is a defect, not a reflection of how much work it took.

## 4. Local pre-flight

Preferred entrypoint:

```sh
./scripts/release-preflight.sh
```

That script is the maintainer-facing pass/fail gate for a release cut. It runs
the same checks below in order and stops on first failure. It needs
`VALKEY_URL`, `POSTGRES_URL`, `MYSQL_URL` and `KEYCLOAK_URL` set to running
servers for the live-store step (Keycloak serves the `private_key_jwt` login
test against the FAPI example's realm), and refuses rather than skips when
one is missing;
`scripts/check-live-stores.sh` carries the container recipe. 0.13.0 was tagged
with four Valkey tests red because the preflight did not run that suite.

Underlying checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --all-features -- --ignored   # Valkey, PostgreSQL, MySQL
cargo doc --no-deps --all-features -p axess -p axess-core
cargo deny check licenses sources bans
cargo semver-checks check-release --workspace
# Leaf crates can dry-run end-to-end:
for c in axess-strings axess-clock axess-rng; do
  cargo publish --dry-run -p "$c"
done
# For non-leaf crates, `cargo publish --dry-run` fails before first publish
# because Cargo resolves internal deps against the live registry. Use
# `cargo package --list` instead to validate the manifest and shipped file set.
for c in axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess; do
  cargo package --list -p "$c" >/dev/null
done
```

The preflight's steps also run as CI jobs on the release pull request;
the publishing runbook lists them by their required check names.

## 5. Pull request, tag and publish

The maintainer pushes the release branch, opens its pull request into `main`,
merges it (squash) once the required checks pass, and pushes the tag
`v0.NEW.0` on the merge commit. The tag starts
[`release.yml`](../../.github/workflows/release.yml), which verifies the
tag, re-runs CI, waits for his approval in the `crates-io` environment
and publishes; [the publishing runbook](../project/publishing.md)
describes each step and how to re-run a tag.

## Why `cargo package --list` for non-leaf crates

Before the first publish, `cargo publish --dry-run` works only for leaf crates.
For downstream crates, Cargo tries to resolve `axess-* = 0.NEW.0` from the live
crates.io index and fails because those versions do not exist yet.

`cargo package --list` is the useful preflight in that case: it prepares the
package, validates the manifest, and shows the exact shipped file set without
requiring unpublished internal crates to exist on crates.io. The actual
registry-resolution path is exercised in `release.yml` when the crates are
published bottom-up.

