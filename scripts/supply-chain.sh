#!/usr/bin/env bash
# axess: the supply-chain gate. Every check runs, and the script exits 1 if
# any failed, so one report shows every failure.
#
# What it covers, in order:
#   1. cargo audit against the lockfile, warnings denied (unmaintained and
#      yanked crates fail as vulnerabilities do);
#   2. cargo deny: licenses, sources, bans, and advisories, with the two
#      advisory ignore lists (deny.toml, .cargo/audit.toml) held identical;
#   3. cargo geiger over the first-party crates, in a target directory of
#      its own made for the run (a fresh build, as CI's runner has: geiger
#      reads the dep-info under the target, and a target other trees built
#      into holds dep-info naming files this tree does not have, on which
#      geiger stops and counts nothing). The step prints each crate's row;
#      when every crate was counted it prints OK with the total of geiger's
#      own warnings ("Found N warnings", on which geiger exits 1 after
#      counting). A crate geiger did not count, or one it stopped on with
#      another error, fails the step: informational unless STRICT=1, and the
#      step says so and why the gate goes on; it never prints OK for it.
#      Unused dependencies are not a step here: cargo's own
#      `unused_dependencies` lint, denied in Cargo.toml's
#      [workspace.lints.cargo], refuses an unused normal or build dependency
#      in every all-targets clippy and check (CI's Clippy job, the release
#      preflight; scripts/check-unused-dependency-lint.sh proves it fires),
#      and scripts/unused-dependencies.sh runs cargo-udeps on a nightly
#      toolchain for dev-dependencies, which the lint does not read;
#   4. the duplicate dependency listing: the default-feature tree of the
#      published crates must hold one version of each crypto crate bans names;
#   5. the release-build guard: the default-feature tree of axess and
#      axess-core carries no wiremock, no tracing-subscriber and no
#      testing, testing-oauth or memory feature; nor does any published crate
#      or example, apart from the examples named in EXAMPLES_WITH_MOCKS;
#      and `wiremock` resolves in no published crate's or example's normal
#      tree (it lives in axess-testing, a dev-dependency crate).
#
# Run from anywhere inside the repository:  scripts/supply-chain.sh
# Needs the advisory database (network on the first run) and these on PATH:
#   cargo-audit, cargo-deny >= 0.19 (the first line that reads CVSS 4.0
#   advisories; an older one fails step 2 on the RustSec database itself),
#   and for step 3 cargo-geiger.
#
# Environment:
#   STRICT=1                    a missing or failing geiger, or one that
#                               counted nothing, fails the gate instead
#                               of failing its step as informational
#   TMPDIR                      where geiger's target directory is made
#                               (removed when the step ends)
#   ALLOW_DENY_CVSS4_PARSE_ERROR=1
#                               only for a cargo-deny older than 0.19: turn a
#                               failure whose output carries the exact line
#                               "unsupported CVSS version: 4.0" into a named
#                               warning (cargo audit stays the advisory
#                               gate). Any other failure, and any advisory
#                               finding beside that line, still fails.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
[ -f Cargo.toml ] && [ -f deny.toml ] || { echo "not the axess repository root: $ROOT" >&2; exit 2; }

# The published crates, and the first-party crates geiger reads.
PUBLISHED=(axess axess-core axess-factors axess-clock axess-rng axess-identity axess-cache axess-events axess-strings axess-macros)
GEIGER_CRATES=(axess-strings axess-identity axess-cache axess-core axess-factors)
# Crates whose second major version bans.deny names; mirrors deny.toml.
SINGLE_VERSION_CRATES=(p256 rsa crypto-bigint)
# Examples that enable `testing` on purpose, for the mock stores and mock
# provider they demonstrate (scripts/lib/mock_examples.sh). Every other
# example must not.
# shellcheck source=lib/mock_examples.sh
. "$ROOT/scripts/lib/mock_examples.sh"

FAILED=()
# step, have, informational and what is read from geiger's report.
# shellcheck source=lib/supply_chain_steps.sh
. "$ROOT/scripts/lib/supply_chain_steps.sh"

# 1. cargo audit. Reads .cargo/audit.toml (the ignore list).
step "cargo audit" cargo audit --file Cargo.lock --deny warnings

# 2. cargo deny, advisories included.
#    The one failure ALLOW_DENY_CVSS4_PARSE_ERROR=1 may waive is the line
#    scripts/lib/cvss4_waiver.sh matches.
# shellcheck source=lib/cvss4_waiver.sh
. "$ROOT/scripts/lib/cvss4_waiver.sh"
deny_advisories() {
  local out rc
  out=$(cargo deny check advisories 2>&1); rc=$?
  echo "$out"
  if [ $rc -ne 0 ] && cvss4_parse_error_only "$out"; then
    if [ "${ALLOW_DENY_CVSS4_PARSE_ERROR:-0}" = 1 ]; then
      echo "::warning::cargo-deny advisories stopped on the CVSS 4.0 parse error of this cargo-deny version; cargo audit is the advisory gate for this run"
      return 0
    fi
    echo "::error::cargo-deny cannot parse the RustSec database (unsupported CVSS version: 4.0): install cargo-deny >= 0.19, or set ALLOW_DENY_CVSS4_PARSE_ERROR=1 to rely on cargo audit"
  fi
  return $rc
}
step "cargo deny check licenses sources bans" cargo deny check licenses sources bans
step "cargo deny check advisories" deny_advisories

advisory_ids() { grep -oE '^[[:space:]]*"RUSTSEC-[0-9]{4}-[0-9]{4}"' "$1" | tr -d ' "' | sort -u; }
ignore_lists_agree() { diff <(advisory_ids deny.toml) <(advisory_ids .cargo/audit.toml); }
step "advisory ignore lists agree (deny.toml vs .cargo/audit.toml)" ignore_lists_agree

# 3. Unsafe code. The first-party crates that contain
#    reviewed `unsafe` are covered by Miri in the hardening workflow; geiger
#    reports the count so a new block is visible.
GEIGER_REASON="the unsafe code it counts is reviewed and run under Miri in the hardening workflow, so its count is a report that makes a new block visible, not a gate"
geiger_run() { (cd "$1" && CARGO_TARGET_DIR="$2" cargo geiger --output-format Ratio); }
geiger() { geiger_count "${GEIGER_CRATES[@]}"; }
step "cargo geiger (unsafe usage)" informational geiger geiger "$GEIGER_REASON"

# 4. Duplicate versions. deny.toml carries the policy (multiple-versions is
#    "warn", with deny-multiple-versions for the crypto crates named there and
#    each accepted duplicate root skipped with its reason); this lists the
#    duplicates for the log and refuses a second version of a crypto crate in
#    the tree an adopter gets by default.
duplicates() {
  local rc=0 pkg tree c
  echo "--- every duplicate, whole workspace, all features (listing) ---"
  cargo tree -d --workspace --all-features -e normal,build --prefix none | sort -u || return 1
  for pkg in "${PUBLISHED[@]}"; do
    tree=$(cargo tree -d -p "$pkg" -e normal --prefix none 2>&1) || { echo "$tree"; return 1; }
    for c in "${SINGLE_VERSION_CRATES[@]}"; do
      if grep -qE "^$c v" <<<"$tree"; then
        echo "::error::$pkg: the default-feature tree holds two versions of $c:"
        grep -E "^$c v" <<<"$tree" | sort -u
        rc=1
      fi
    done
  done
  return $rc
}
step "duplicate dependencies (default-feature trees hold one version of each crypto crate)" duplicates

# 4b. A local IdP needs no `rsa`.
#     `local-idp` signs ES256, and its RSA keys are behind `local-idp-rsa`
#     because the crate carries RUSTSEC-2023-0071. On the aws-lc JWT backend
#     nothing else in such a build asks for `rsa`, so its normal tree holds
#     none. The second reading is the control: with `local-idp-rsa` the
#     crate is in the tree, so an empty first reading is one that looked.
LOCAL_IDP_FLAGS=(--no-default-features -e normal --prefix none)

# rsa_dependents <package> <features>: the crates that depend on any version
# of rsa along normal edges in that package's tree, one per line. Read from
# the depth-prefixed tree rather than with `-i rsa`, which a resolution
# holding two versions of rsa (a dev-dependency's included) refuses as
# ambiguous.
rsa_dependents() {
  cargo tree -p "$1" --no-default-features --features "$2" -e normal --prefix depth \
    | awk '{ match($0, /^[0-9]+/); depth = substr($0, 1, RLENGTH) + 0; split(substr($0, RLENGTH + 1), word, " ");
             parent[depth] = word[1]; if (word[1] == "rsa" && depth > 0) print parent[depth - 1] }' \
    | sort -u
}

local_idp_without_rsa() {
  local rc=0 pkg tree
  for pkg in axess-core axess; do
    tree=$(cargo tree -p "$pkg" --features local-idp,jwt-aws-lc "${LOCAL_IDP_FLAGS[@]}" 2>&1) || { echo "$tree"; return 1; }
    if grep -qE '^rsa v' <<<"$tree"; then
      echo "::error::$pkg with local-idp on the aws-lc JWT backend resolves rsa, a dependency of: $(rsa_dependents "$pkg" local-idp,jwt-aws-lc | tr '\n' ' ')"
      rc=1
    fi
    tree=$(cargo tree -p "$pkg" --features local-idp-rsa,jwt-aws-lc "${LOCAL_IDP_FLAGS[@]}" 2>&1) || { echo "$tree"; return 1; }
    if ! grep -qE '^rsa v' <<<"$tree"; then
      echo "::error::$pkg with local-idp-rsa resolves no rsa, so the reading above proves nothing."
      rc=1
    fi
  done
  return $rc
}
step "a local IdP on the aws-lc JWT backend resolves no rsa" local_idp_without_rsa

# 4c. A client assertion signs with RSA only where a build chose it.
#     On `jwt-rust-crypto` alone an RSA client key would sign in `rsa` 0.9,
#     and `ClientAssertionSigner` refuses it unless `client-assertion-rsa`
#     chose it. A tree cannot show which functions of a crate a build calls,
#     so it is read for what it can show: in an `oauth` or `outbound-oauth`
#     build on the pure-Rust backend no crate of this workspace depends on
#     `rsa` (its dependents are jsonwebtoken, whose `rust_crypto` backend
#     signs and verifies with it, and openidconnect, which verifies), and an
#     `outbound-oauth` build on the aws-lc backend holds no `rsa` at all.
#     The refusal itself is code; its tests run under each backend in
#     scripts/check-feature-matrix.sh.
client_assertion_rsa_edges() {
  local rc=0 pkg features out dependents tree
  for pkg in axess-factors axess-core; do
    for features in outbound-oauth,jwt-rust-crypto oauth,jwt-rust-crypto; do
      out=$(rsa_dependents "$pkg" "$features") || { echo "::error::cargo tree failed for $pkg with $features"; return 1; }
      dependents=$(tr '\n' ' ' <<<"$out")
      echo "$pkg with $features: rsa is a dependency of $dependents"
      if [ -z "$dependents" ]; then
        echo "::error::$pkg with $features names no dependent of rsa, so the reading proves nothing."
        rc=1
      elif grep -qE '(^| )axess' <<<"$dependents"; then
        echo "::error::$pkg with $features: a crate of this workspace depends on rsa: $dependents"
        rc=1
      fi
    done
    tree=$(cargo tree -p "$pkg" --no-default-features --features outbound-oauth,jwt-aws-lc -e normal --prefix none 2>&1) || { echo "$tree"; return 1; }
    if grep -qE '^rsa v' <<<"$tree"; then
      echo "::error::$pkg with outbound-oauth on the aws-lc JWT backend resolves rsa."
      rc=1
    else
      echo "$pkg with outbound-oauth,jwt-aws-lc: no rsa"
    fi
  done
  return $rc
}
step "a client assertion's RSA signature has no workspace edge to rsa" client_assertion_rsa_edges

# 5. Test-only code must not reach a release build.
#    `cargo tree` has no --release flag and does not need one: it resolves
#    features, not profiles. -e features,normal prints each enabled feature
#    as a node (`axess-core feature "testing"`) and leaves out dev edges, so
#    a feature a dev-dependency switches on is not counted. The root of a
#    tree does not print its own features, so each package is read inverted
#    from every crate that carries a `testing` surface (`-i`), which does;
#    a package whose tree does not hold that crate makes `-i` fail and is
#    skipped for it.
GUARDED=(axess-core axess-factors axess-rng axess-clock axess-identity)
FEATURE_RE='^axess[a-z-]* feature "(testing|testing-oauth|memory)"'

# test_features <package>: the testing and memory feature nodes in its normal tree.
test_features() {
  local pkg="$1" g out
  for g in "${GUARDED[@]}"; do
    out=$(cargo tree -p "$pkg" -e features,normal -i "$g" --prefix none 2>/dev/null) || continue
    grep -E "$FEATURE_RE" <<<"$out"
  done | sort -u
}

# in_tree <package> <crate>: prints the crate's inverted tree when it is in the package's normal tree.
in_tree() { cargo tree -p "$1" -e normal -i "$2" --prefix none 2>/dev/null; }

no_test_code_in_default() {
  local rc=0 pkg found c
  for pkg in axess axess-core; do
    for c in wiremock tracing-subscriber; do
      if [ -n "$(in_tree "$pkg" "$c")" ]; then
        echo "::error::$pkg default build pulls the test-only crate $c:"
        in_tree "$pkg" "$c" | sed -n 1,10p
        rc=1
      fi
    done
    found=$(test_features "$pkg")
    if [ -n "$found" ]; then
      echo "::error::$pkg default build enables a testing or memory feature:"
      echo "$found"
      rc=1
    fi
  done
  return $rc
}
step "default feature tree free of wiremock, tracing-subscriber, testing and memory" no_test_code_in_default

no_testing_in_targets() {
  local rc=0 pkg found allowed ex hits
  local targets=("${PUBLISHED[@]}")
  for ex in examples/*/Cargo.toml; do
    targets+=("$(sed -n 's/^name *= *"\(axess-example-[a-z-]*\)".*/\1/p' "$ex" | sed -n 1p)")
  done
  for pkg in "${targets[@]}"; do
    found=$(test_features "$pkg" | grep -E 'feature "testing(-oauth)?"')
    if [ -n "$found" ]; then
      allowed=0
      for ex in "${EXAMPLES_WITH_MOCKS[@]}"; do [ "$ex" = "$pkg" ] && allowed=1; done
      if [ $allowed = 1 ]; then
        echo "note: $pkg enables testing on purpose (named in EXAMPLES_WITH_MOCKS)"
      else
        echo "::error::$pkg links the testing feature in its normal tree:"
        echo "$found"
        rc=1
      fi
    fi
  done
  # wiremock lives in axess-testing, the one crate adopters take as a
  # dev-dependency, so it may reach no published crate's or example's normal
  # tree. `cargo tree -i` exits 0 with "nothing to print" when the package is
  # not in a graph, so the answer is read from what it prints.
  for pkg in "${targets[@]}"; do
    hits=$(cargo tree -p "$pkg" -e normal -i wiremock --prefix none 2>/dev/null)
    if [ -n "$hits" ]; then
      echo "::error::wiremock resolves in the normal dependency tree of $pkg:"
      head -20 <<<"$hits"
      rc=1
    fi
  done
  return $rc
}
step "no published crate or example links the testing feature, and wiremock does not resolve" no_testing_in_targets

if [ ${#FAILED[@]} -ne 0 ]; then
  printf '::error::supply-chain failures:\n'; printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
echo "supply-chain: all checks passed"
