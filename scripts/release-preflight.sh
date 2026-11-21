#!/usr/bin/env bash
# axess: fail-fast release preflight for maintainers.
#
# Runs the same local gates documented in docs/production/release.md, but as a
# numbered executable checklist so release validation is reproducible and less
# error-prone than copying a long command block out of markdown.
#
# Usage: ./scripts/release-preflight.sh [--allow-dirty] [--with-fuzz]
#
#   --allow-dirty  passed through to `cargo package` so package steps do not
#                  require a clean tree (still fails if a listed file is
#                  actually missing).
#   Needs VALKEY_URL, VALKEY_CLUSTER_URL, POSTGRES_URL, MYSQL_URL and
#   KEYCLOAK_URL for the live-store step; scripts/check-live-stores.sh has
#   the container recipe.
#   --with-fuzz    additionally runs the fuzz-smoke step (nightly toolchain +
#                  cargo-fuzz required; adds ~3-5 min warm, 15-20 min cold).
#                  Off by default because CI runs it on every PR anyway.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AXESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ALLOW_DIRTY=false
WITH_FUZZ=false

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-dirty) ALLOW_DIRTY=true; shift ;;
    --with-fuzz) WITH_FUZZ=true; shift ;;
    -h|--help)
      sed -n '1,15p' "$0"
      exit 0
      ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

PACKAGE_ARGS=()
if [ "$ALLOW_DIRTY" = true ]; then
  PACKAGE_ARGS+=(--allow-dirty)
fi

# Derived, not declared. This number has desynced twice from the steps that
# actually run -- most recently when "Non-leaf package preflight" landed and
# left the denominator at 13, which failed the guard at the bottom and so
# failed the whole release gate on bookkeeping rather than on a real check.
# Counting the invocations keeps it honest; the guard below stays as a
# backstop for the case this grep cannot see.
TOTAL=$(grep -cE '^[[:space:]]*step "' "$SCRIPT_DIR/release-preflight.sh")
if [ "$WITH_FUZZ" != true ]; then
  # The fuzz smoke step is the one conditional invocation.
  TOTAL=$((TOTAL - 1))
fi

# Steps number themselves. Hand-written ordinals silently desync the moment a
# step is inserted, renumbered or reordered: adding step 2 once shifted the
# non-leaf package step onto 11, which the fuzz step already used, so
# `--with-fuzz` printed "[11/12]" twice with no other symptom.
STEP_NO=0

step() {
  local label="$1"
  shift
  STEP_NO=$((STEP_NO + 1))
  echo ""
  echo "[$STEP_NO/$TOTAL] $label"
  "$@"
}

step "Format check" cargo fmt --manifest-path "$AXESS_DIR/Cargo.toml" --all -- --check

# Sub-second, so it runs before the expensive gates: a stale snippet should
# stop the release immediately, not after a 40-minute test run. Docs carry
# copy-pasteable `axess = { version = "..." }` blocks that nothing else keeps
# in step with the workspace version, and a reader landing on a crate README
# from crates.io or the GitHub tree view will pin whatever it says.
step "Crafted cases for the documented-version check" "$AXESS_DIR/scripts/check-doc-versions-tests.sh"
step "Documented versions" "$AXESS_DIR/scripts/check-doc-versions.sh"

# Sub-second too: every migrating page is in the book and no section of one
# is a heading with nothing under it.
step "Migrating pages" "$AXESS_DIR/scripts/check-migrating-pages.sh"
step "Crafted cases for the migrating-page check" "$AXESS_DIR/scripts/check-migrating-pages-tests.sh"

# Sub-second as well: the changelog's sections from 0.20.0 on keep their
# form (the known headings once each, one sentence an entry, no tracker row,
# seat or author named), so the section being released reads as the ones
# before it.
step "Crafted cases for the changelog check" "$AXESS_DIR/scripts/check-changelog-tests.sh"
step "Changelog form" "$AXESS_DIR/scripts/check-changelog.sh"

# Sub-second as well. The preflight runs when a release is being prepared, so
# the strict mode applies: the version in Cargo.toml, the internal pins and a
# dated CHANGELOG.md section for it, with nothing left under [Unreleased].
# CI's "Release Version" job runs the same check on the release pull request
# and the release workflow runs it on the tag.
step "Release version and dated changelog" "$AXESS_DIR/scripts/check-release-version.sh"

# Also sub-second, and the only gate that reads the book. 108 of its 112
# Rust blocks are ```rust,ignore, so a chapter can name a type that does
# not exist and every other check stays green; one sweep found 59 such
# names, including an import in the getting-started tutorial.
step "Documented identifiers" "$AXESS_DIR/scripts/check-doc-identifiers.sh"

# The same failure one level down, in the doc comments rather than the book.
# `cargo doc` catches a broken intra-doc link and nothing catches a plain
# backticked `Type::method`; the first run found a Setup example calling a
# constructor that never existed, inside a ```text fence so nothing compiled
# it, and a password-change note pointing at the wrong revocation method.
step "Documented methods" "$AXESS_DIR/scripts/check-rustdoc-identifiers.sh"

# Neither identifier gate looks at the path. A name can be real and the
# module it is imported through fictional, which is how the crates.io front
# page came to describe `axess::middleware::*` and the mTLS chapter to import
# from `axess::factors`, in blocks nothing compiles.
step "Documented imports" "$AXESS_DIR/scripts/check-facade-paths.sh"

# Also sub-second. Guards the AGENTS.md rule that an inline `#[cfg(test)]`
# block over 200 lines moves to a sibling file: 24 blocks had drifted past
# it before the rule was enforced rather than remembered. A block under any
# `cfg` that asks for `test` counts, `#[cfg(all(test, ...))]` included.
step "Crafted cases for the inline test block check" "$AXESS_DIR/scripts/check-inline-tests-tests.sh"
step "Inline test block sizes" "$AXESS_DIR/scripts/check-inline-tests.sh"

# Also sub-second. Files stay under 800 lines and functions under 150 (Rust
# production code, and every shell and Python script), against a baseline of
# the offenders that predate the gate, so the numbers only go down.
step "Crafted cases for the size gate" "$AXESS_DIR/scripts/check-file-sizes-tests.sh"
step "File and function sizes" "$AXESS_DIR/scripts/check-file-sizes.sh"

# Library code reads the wall clock only through axess-clock, against a
# baseline of the reads that predate the gate, and a test reads no clock but
# its world's, against an empty one.
step "Crafted cases for the clock-usage check" "$AXESS_DIR/scripts/check-clock-usage-tests.sh"
step "Clock reads outside axess-clock and the test's" "$AXESS_DIR/scripts/check-clock-usage.sh"
step "Crafted cases for the test-log guard" "$AXESS_DIR/scripts/check-test-log-tests.sh"
step "Crafted cases for the disk floor" "$AXESS_DIR/scripts/check-disk-floor-tests.sh"
step "Crafted cases for the check of keys left by the live tests" "$AXESS_DIR/scripts/check-live-keys-left-tests.sh"
# A key written outside every sweep holds no run token, so the check after a
# run cannot see it: every live Valkey test holds a sweep, or is named with
# its reason in scripts/live-sweep-exemptions.txt.
step "Crafted cases for the live-sweep check" "$AXESS_DIR/scripts/check-live-sweeps-tests.sh"
step "Every live Valkey test holds a sweep" "$AXESS_DIR/scripts/check-live-sweeps.sh"
step "Crafted cases for the supply-chain waiver and geiger step" "$AXESS_DIR/scripts/supply-chain-tests.sh"

# The conformance runner's own cases, with no suite and no network: the
# conformance page's results section, its provenance included, is what the
# runner writes from scripts/conformance/results.json.
step "Crafted cases for the conformance runner" python3 -I "$AXESS_DIR/scripts/conformance/run_rp_tests.py"

# The deny.toml ignore for the rsa advisory is sound only while its uses stay
# in the reviewed files.
step "Crafted cases for the rsa call-site check" "$AXESS_DIR/scripts/check-rsa-sites-tests.sh"
step "rsa call sites" "$AXESS_DIR/scripts/check-rsa-sites.sh"

# jsonwebtoken fixes its crypto provider at the first operation in a process;
# every operation goes through the boundary that settles it first.
step "Crafted cases for the jsonwebtoken provider-site check" "$AXESS_DIR/scripts/check-jwt-provider-sites-tests.sh"
step "jsonwebtoken operations go through axess_factors::jwt" "$AXESS_DIR/scripts/check-jwt-provider-sites.sh"

# A run on one Valkey node leaves the cluster tests out by their module's
# name, and the cluster helper's guard refuses the cluster's URL to a test
# named otherwise; no other source reads the URL past that guard.
step "Crafted cases for the cluster URL read check" "$AXESS_DIR/scripts/check-cluster-url-reads-tests.sh"
step "VALKEY_CLUSTER_URL is read only in cluster_url, after its guard" "$AXESS_DIR/scripts/check-cluster-url-reads.sh"

# Text a caller, a tenant or a remote party chose reaches a log line through
# the one predicate; a raw field of it stands in the census with its reason.
step "Crafted cases for the log-text site census" "$AXESS_DIR/scripts/check-log-text-sites-tests.sh"
step "Raw log fields of caller text" "$AXESS_DIR/scripts/check-log-text-sites.sh"

# Also sub-second. The fuzz crate is a workspace of its own; its lock file is
# committed and held to the versions the workspace's lock file names, so the
# fuzz targets run against the code the workspace ships. A version bump or a
# dependency update that leaves it behind stops here, with the two commands
# that bring it back.
step "Crafted cases for the fuzz lock check" "$AXESS_DIR/scripts/check-fuzz-lock-tests.sh"
step "Fuzz lock agrees with the workspace's" "$AXESS_DIR/scripts/check-fuzz-lock.sh"

# Every crates.io entry added to a lockfile since the last release was
# published at least the cooldown of .cargo/config.toml ago, or is admitted
# by a Cooldown-Exempt trailer naming an advisory. Reads index.crates.io.
step "Crafted cases for the lock-age check" "$AXESS_DIR/scripts/check-lock-age-tests.sh"
step "No lockfile entry younger than the cooldown without an advisory trailer" "$AXESS_DIR/scripts/check-lock-age.sh"

# hardening.yml and mutants.yml run beside CI. The release workflow holds
# publish to a green Hardening run on the release commit and reports the
# Mutants run on it without waiting for it (scripts/check-scheduled-runs.sh
# --mutants-report-only); the release commit is not pushed yet when this
# runs. So this step only reports: the newest ended run of each on main,
# its date, the jobs that did not pass and its address. It exits 0 whatever
# it reads, and says when gh could not read.
step "Crafted cases for the scheduled-run check" "$AXESS_DIR/scripts/check-scheduled-runs-tests.sh"
# The sweep a push to a release branch starts, the one on the release
# commit, runs at the width mutants.yml names for it.
step "Crafted cases for the width of the mutation sweep" "$AXESS_DIR/scripts/check-mutants-width-tests.sh"
step "Newest Hardening and Mutants runs on main (a report)" bash -c 'cd "$0" && scripts/check-scheduled-runs.sh --report' "$AXESS_DIR"

# An ignored test is run only by the live-store step below, and its reason is
# what names the server it needs: a bare `#[ignore]` is a test nobody can
# place.
step "Crafted cases for the ignore-reason check" "$AXESS_DIR/scripts/check-ignore-reasons-tests.sh"
step "Every ignored test gives its reason" "$AXESS_DIR/scripts/check-ignore-reasons.sh"

# Every member takes the workspace's lint table, which denies cargo's
# unused-dependency lint and sets no lint to allow.
step "Crafted cases for the member lint check" "$AXESS_DIR/scripts/check-member-lints-tests.sh"
step "Every member takes the workspace lint table" "$AXESS_DIR/scripts/check-member-lints.sh"

# A warning is fixed where it fires, never allowed away: no `allow` or
# `expect` attribute in any Rust file and no lint-silencing flag in the
# cargo configuration.
step "Crafted cases for the lint-allowance check" "$AXESS_DIR/scripts/check-lint-allowances-tests.sh"
step "No lint allowed away in the source or the cargo configuration" "$AXESS_DIR/scripts/check-lint-allowances.sh"

# An unused name is not hidden behind a `_` prefix: a parameter a trait fixes
# is a bare `_`, a held guard a plain name dropped where it must end.
step "Crafted cases for the underscore-name check" "$AXESS_DIR/scripts/check-underscore-names-tests.sh"
step "No underscore-prefixed name in the Rust sources" "$AXESS_DIR/scripts/check-underscore-names.sh"

# Under pipefail a reader that exits early (`grep -q`, `head`) can kill its
# writer with SIGPIPE and fail the pipeline on some runs only: every pipe of
# every script and workflow step reads to the end.
step "Crafted cases for the pipe-reader check" "$AXESS_DIR/scripts/check-pipe-readers-tests.sh"
step "No pipe has a reader that may stop before its writer is done" "$AXESS_DIR/scripts/check-pipe-readers.sh"

# A public repository: tests, examples, doc examples, the book and scripts
# use neutral sample data, and the publisher is named only where the text
# names the publisher (scripts/owner-name-exemptions.txt says where and why).
step "Crafted cases for the owner-name check" "$AXESS_DIR/scripts/check-owner-names-tests.sh"
step "No name of the publisher outside its exemption list" "$AXESS_DIR/scripts/check-owner-names.sh"

# The release workflow publishes with a token crates.io issues in exchange
# for the job's OIDC token. The exchange cannot run here, so the publish step
# is run out of the workflow against a recorded curl and cargo: every way it
# can fail ends by name, and no token reaches the log.
step "Crafted cases for the publish step of the release workflow" "$AXESS_DIR/scripts/release-publish-tests.sh"

# The weekly watches that say when an accepted advisory can be fixed read
# crates.io; here their reading of an answer is held to its cases.
step "Crafted cases for the advisory-fix watch" "$AXESS_DIR/scripts/watch-advisory-fixes-tests.sh"

# Sub-second too, and the only gate that reads Markdown. `check-doc-links.sh`
# runs rustdoc and sees Rust intra-doc links, not the READMEs, so a crates.io
# front page that links at a chapter that moved fails here or nowhere.
step "Markdown links resolve" "$AXESS_DIR/scripts/check-markdown-links.sh"

# Also sub-second. The house style has no em dashes, no regression markers
# and no line-number citations in comments; a rule no gate holds does not
# stay held.
step "Crafted cases for the prose-style check" "$AXESS_DIR/scripts/check-prose-style-tests.sh"
step "Prose style" "$AXESS_DIR/scripts/check-prose-style.sh"

# Also sub-second. The release workflow runs actions in jobs that hold the
# OIDC permission or a token that can write, and an action pinned to a tag or
# a branch runs whatever its owner points the name at on the day.
step "Crafted cases for the workflow pin check" "$AXESS_DIR/scripts/check-workflow-pins-tests.sh"
step "Workflow actions pinned to commits" "$AXESS_DIR/scripts/check-workflow-pins.sh"

# A few seconds. Every shell script of the repository read by the
# ShellCheck scripts/install-shellcheck.sh pins, as CI's "Shell Scripts" job
# reads them: a directive ShellCheck cannot parse makes it skip the rest of
# that file, so a finding stays unseen until the next one is fixed.
step "Crafted cases for the shell-script check" "$AXESS_DIR/scripts/check-shellcheck-tests.sh"
step "Every shell script passes ShellCheck" "$AXESS_DIR/scripts/check-shellcheck.sh"


# Mirrors the `Ban #[non_exhaustive]` CI job: see the docstring on that job
# in .github/workflows/ci.yml for the policy rationale (trade one breakage
# class for another; project prefers loud call-site breaks on variant add).
step "Ban #[non_exhaustive]" bash -c '
  set -eu
  cd "$0"
  if grep -RIn --include="*.rs" \
      -e "#\[non_exhaustive\]" \
      -e "#\[ *non_exhaustive *\]" \
      axess axess-core axess-factors axess-macros examples; then
    echo "ERROR: #[non_exhaustive] is forbidden in first-party crates." >&2
    echo "See CONTRIBUTING.md, \"No #[non_exhaustive] on first-party enums\"." >&2
    exit 1
  fi
  echo "OK: no #[non_exhaustive] occurrences."
' "$AXESS_DIR"

# Every other compile step here is `--all-features`, which cannot see a
# feature-gated item named from ungated code; without this step CI finds
# such a reference after the push.
step "Feature matrix (mirrors ci.yml)" "$AXESS_DIR/scripts/check-feature-matrix.sh"

# The book is built only by the docs workflow, so a book.toml the pinned
# mdBook rejects fails nowhere local. Building it here catches content and
# config errors; it cannot catch a version skew, which is what this step
# warns about, because a newer local mdBook accepts config the pinned one
# refuses. That is how `edition = "2024"` reached CI.
step "Book builds" bash -c '
  set -eu
  cd "$0"
  if ! command -v mdbook >/dev/null 2>&1; then
    echo "SKIP: mdbook not installed (cargo install mdbook)."
    exit 0
  fi
  pinned=$(sed -n "s/^MDBOOK_VERSION=//p" scripts/install-mdbook.sh)
  local_v=$(mdbook --version | sed "s/^mdbook v\{0,1\}//")
  if [ "$pinned" != "$local_v" ]; then
    echo "WARNING: local mdbook $local_v, scripts/install-mdbook.sh pins $pinned."
    echo "         A newer local mdbook accepts book.toml keys the pinned one"
    echo "         rejects, so a green build here does not prove a green CI."
  fi
  # The Mermaid assets book.toml lists are written by `mdbook-mermaid install`
  # and are gitignored, so a fresh clone or worktree has none and the build
  # stops on "failed to open mermaid.min.js". Install them here when absent,
  # the same way the docs workflow does, and say what is missing otherwise.
  if [ ! -f docs/mermaid.min.js ] || [ ! -f docs/mermaid-init.js ]; then
    if command -v mdbook-mermaid >/dev/null 2>&1; then
      mdbook-mermaid install docs >/dev/null
      echo "Mermaid assets written into docs/ (mdbook-mermaid install docs)."
    else
      echo "ERROR: docs/mermaid.min.js is absent and mdbook-mermaid is not installed"
      echo "       (cargo install mdbook-mermaid, then mdbook-mermaid install docs)."
      exit 1
    fi
  fi
  mdbook build docs >/dev/null
  echo "OK: mdbook build docs (local mdbook $local_v)."
' "$AXESS_DIR"

# The docs job's last step and the CI "Book" job: build what the book's code
# imports, then compile every block not marked `ignore` against it
# (scripts/book-test.sh says how it finds the libraries and counts the
# blocks, so a pass over none of them cannot read as coverage).
step "Book code compiles" bash -c '
  set -eu
  if ! command -v mdbook >/dev/null 2>&1; then
    echo "SKIP: mdbook not installed (cargo install mdbook)."
    exit 0
  fi
  "$0/scripts/book-test.sh"
' "$AXESS_DIR"

step "Clippy" cargo clippy --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features --all-targets -- -D warnings
# Clippy refuses an unused dependency through the lint table; the probe
# proves the lint fires on a crate added to a copy of the tree.
step "Crafted cases for the unused-dependency lint check" "$AXESS_DIR/scripts/check-unused-dependency-lint-tests.sh"
step "The unused-dependency lint fires" "$AXESS_DIR/scripts/check-unused-dependency-lint.sh"
step "Workspace tests" cargo test --manifest-path "$AXESS_DIR/Cargo.toml" --workspace --all-features
# The stores that need a server. CI runs them in its "Test Suite" job, and a
# preflight without them lets a release be tagged with a live-store test
# red. The script refuses without the three URLs; it never passes over an
# empty run.
step "Live-store tests (Valkey, PostgreSQL, MySQL)" "$AXESS_DIR/scripts/check-live-stores.sh"
# `cargo doc -p axess -p axess-core` with warnings allowed documents two
# crates of the workspace and treats an unresolved intra-doc link as
# advice. The script covers the whole workspace under -D warnings and
# proves it documented every member, reporting each error with its crate.
step "Crafted cases for the documentation report" "$AXESS_DIR/scripts/check-doc-links-tests.sh"
step "Public docs build (rustdoc links)" "$AXESS_DIR/scripts/check-doc-links.sh"
# The same documentation as docs.rs builds it, crate by crate: the pinned
# nightly, each crate's docs.rs features and `--cfg docsrs`. A crate whose
# `doc(cfg(..))` needs the nightly feature it does not switch on fails here,
# not on docs.rs after the release.
step "Crafted cases for the docs.rs build" "$AXESS_DIR/scripts/check-docsrs-build-tests.sh"
step "Docs build as docs.rs builds them (the pinned nightly)" "$AXESS_DIR/scripts/check-docsrs-build.sh"

# Expensive (a second full build on the MSRV toolchain), so it sits after the
# cheap gates and the main test run. It belongs in the release gate rather than
# in test-all.sh: `rust-version` is a promise to adopters, and the moment to
# check a promise is before publishing it.
step "MSRV build + lib tests" "$AXESS_DIR/scripts/check-msrv.sh"

# One script for the supply chain: `cargo audit` over the lockfile (warnings
# denied), `cargo deny` for licenses, sources, bans and advisories (the
# advisory ignore lists in deny.toml and .cargo/audit.toml must name the same
# ids, because the two tools read different files), the unsafe report, the
# duplicate crypto crates, and the guard that a default-feature release build
# links no `testing`, `memory`, wiremock or tracing-subscriber. A deny hit,
# an unpatched advisory or a test feature in a release tree blocks the tag.
# Needs cargo-audit and cargo-deny >= 0.19; cargo-geiger reports when
# installed (STRICT=1 makes it fatal). scripts/supply-chain.sh says what
# each step reads.
step "Crafted cases for the testing-gate check" "$AXESS_DIR/scripts/check-testing-gates-tests.sh"
step "Every crate with a testing feature carries the release-build gate" "$AXESS_DIR/scripts/check-testing-gates.sh"
step "Crafted cases for the docs.rs feature check" "$AXESS_DIR/scripts/check-docsrs-features-tests.sh"
step "docs.rs builds every feature but the named exclusions" "$AXESS_DIR/scripts/check-docsrs-features.sh"
step "Crafted cases for the release-build check" "$AXESS_DIR/scripts/check-release-build-tests.sh"
step "Release build carries no testing feature; every mock example refuses one" "$AXESS_DIR/scripts/check-release-build.sh"
step "Supply chain (audit, deny, duplicates, release-build features)" "$AXESS_DIR/scripts/supply-chain.sh"

# The test-only crate and wiremock may reach a production graph from no normal or
# build edge; deny-production.toml bans them and the edge script reads cargo metadata.
step "Test-only crates stay out of production graphs" bash -c 'cd "$0" && cargo deny --config deny-production.toml check bans && scripts/check-test-crate-edges.sh' "$AXESS_DIR"

# chrono is a direct dependency where an upstream crate hands its values and
# of the agreement test alone, no public item names it, and no published
# crate's tree holds it with no feature chosen but through cedar-policy-core.
step "Crafted cases for the chrono-edges check" "$AXESS_DIR/scripts/check-chrono-edges-tests.sh"
step "chrono is named only where an upstream crate hands it" "$AXESS_DIR/scripts/check-chrono-edges.sh"

# `axess::testing` must not exist without the feature. The compile-fail test
# is compiled out under `--all-features`, which the workspace test step uses,
# so it runs here with the default features.
step "axess::testing unreachable without the feature" \
    cargo test --manifest-path "$AXESS_DIR/Cargo.toml" -p axess --test testing_unreachable

# Against the last release tag below HEAD, the baseline CI's "SemVer Checks"
# job uses, as a minor release so the major-level lints run; every break the
# tool reports must be named on the migration page. The script says what the
# tool cannot see (a field changing type, a change of behaviour), which stays
# hand-written, and what an "unsupported rustdoc format" failure means.
step "Crafted cases for the semver check and its inventory" "$AXESS_DIR/scripts/check-semver-tests.sh"
step "Semver checks (against the last release tag), every break named on the migration page" "$AXESS_DIR/scripts/check-semver.sh"

step "Leaf crate publish dry-runs" bash -c '
  set -euo pipefail
  cd "$0"
  shift
  publish_args=("$@")
  for c in axess-strings axess-clock axess-rng axess-testing; do
    cargo publish --dry-run -p "$c" ${publish_args[@]+"${publish_args[@]}"}
  done
' "$AXESS_DIR" bash ${PACKAGE_ARGS[@]+"${PACKAGE_ARGS[@]}"}

step "Non-leaf package preflight" bash -c '
  set -euo pipefail
  cd "$0"
  shift
  package_args=("$@")
  for c in axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess; do
    cargo package --list -p "$c" ${package_args[@]+"${package_args[@]}"} >/dev/null
  done
' "$AXESS_DIR" bash ${PACKAGE_ARGS[@]+"${PACKAGE_ARGS[@]}"}

# Fuzz smoke: opt-in because it needs a nightly toolchain + cargo-fuzz and
# takes several minutes even with warm caches. Off by default so the common
# preflight stays fast; the CI `Fuzz Smoke` job runs on every PR regardless.
if [ "$WITH_FUZZ" = true ]; then
  step "Fuzz smoke (the pinned nightly)" bash -c '
    set -euo pipefail
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
      echo "ERROR: cargo-fuzz not installed. Run: cargo install cargo-fuzz --locked" >&2
      exit 1
    fi
    nightly="$(sed -n "s/^channel *= *\"\(nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\)\" *\$/\1/p" "$0/nightly-toolchain.toml")"
    if [ -z "$nightly" ]; then
      echo "ERROR: nightly-toolchain.toml names no dated nightly." >&2
      exit 1
    fi
    if ! grep -q "^$nightly" <<<"$(rustup toolchain list)"; then
      echo "ERROR: the nightly nightly-toolchain.toml names is not installed. Run: rustup toolchain install $nightly" >&2
      exit 1
    fi
    cd "$0/fuzz"
    cargo +"$nightly" fuzz build
    for target in $(cargo +"$nightly" fuzz list); do
      cargo +"$nightly" fuzz run "$target" -- -max_total_time=30
    done
  ' "$AXESS_DIR"
fi

# TOTAL is still declared by hand (the fuzz step is conditional), so make a
# mismatch loud rather than letting the denominator quietly lie.
if [ "$STEP_NO" -ne "$TOTAL" ]; then
  echo "ERROR: ran $STEP_NO steps but TOTAL claims $TOTAL. Update TOTAL." >&2
  exit 1
fi

echo ""
echo "Release preflight: OK"
