#!/usr/bin/env bash
# axess: the supply-chain gate. Every check runs, and the script exits 1 if
# any failed, so one report shows every failure.
#
# What it covers, in order:
#   1. cargo audit against the lockfile, warnings denied (unmaintained and
#      yanked crates fail as vulnerabilities do);
#   2. cargo deny: licenses, sources, bans, and advisories, with the two
#      advisory ignore lists (deny.toml, .cargo/audit.toml) held identical;
#   3. cargo geiger over the first-party crates, and cargo machete (or
#      cargo +nightly udeps with UDEPS=1) for unused dependencies, both
#      informational unless STRICT=1;
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
#   and for step 3 cargo-geiger and cargo-machete (cargo-udeps with UDEPS=1).
#
# Environment:
#   STRICT=1                    a missing or failing geiger/machete/udeps
#                               fails the gate instead of reporting it
#   UDEPS=1                     use cargo +nightly udeps instead of machete
#   ALLOW_DENY_CVSS4_PARSE_ERROR=1
#                               only for a cargo-deny older than 0.19: turn a
#                               failure that is a CVSS 4.0 parse error into a
#                               named warning (cargo audit stays the advisory
#                               gate). Any other advisory finding still fails.
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
# provider they demonstrate. Every other example must not.
EXAMPLES_WITH_MOCKS=(axess-example-minimal axess-example-oauth axess-example-fapi)

FAILED=()
step() { # step <name> <cmd...>
  local name="$1"; shift
  echo "::group::$name"
  if "$@"; then echo "OK: $name"; else echo "::error::FAILED: $name"; FAILED+=("$name"); fi
  echo "::endgroup::"
}

have() { command -v "cargo-$1" >/dev/null 2>&1; }

# A step that is informational unless STRICT=1: it reports and returns 0, and
# a tool that is not installed is a named skip, never a silent pass.
informational() { # informational <tool> <function>
  local tool="$1" fn="$2"
  if ! have "$tool"; then
    if [ "${STRICT:-0}" = 1 ]; then
      echo "::error::cargo-$tool is not installed and STRICT=1 (cargo install --locked cargo-$tool)"
      return 1
    fi
    echo "::warning::SKIPPED: cargo-$tool is not installed (cargo install --locked cargo-$tool); nothing was checked"
    return 0
  fi
  if "$fn"; then return 0; fi
  if [ "${STRICT:-0}" = 1 ]; then return 1; fi
  echo "::warning::cargo-$tool reported a finding or an error (informational; STRICT=1 makes it fatal)"
  return 0
}

# 1. cargo audit. Reads .cargo/audit.toml (the ignore list).
step "cargo audit" cargo audit --file Cargo.lock --deny warnings

# 2. cargo deny, advisories included.
deny_advisories() {
  local out rc
  out=$(cargo deny check advisories 2>&1); rc=$?
  echo "$out"
  if [ $rc -ne 0 ] && [ "${ALLOW_DENY_CVSS4_PARSE_ERROR:-0}" = 1 ] \
     && grep -qiE 'cvss|failed to parse' <<<"$out" \
     && ! grep -qE 'error\[(vulnerability|unmaintained|yanked|unsound)\]' <<<"$out"; then
    echo "::warning::cargo-deny advisories stopped on the CVSS 4.0 parse issue of this cargo-deny version; cargo audit is the advisory gate for this run"
    return 0
  fi
  if [ $rc -ne 0 ] && grep -qiE 'cvss|failed to parse' <<<"$out"; then
    echo "::error::cargo-deny cannot parse the RustSec database (CVSS 4.0): install cargo-deny >= 0.19, or set ALLOW_DENY_CVSS4_PARSE_ERROR=1 to rely on cargo audit"
  fi
  return $rc
}
step "cargo deny check licenses sources bans" cargo deny check licenses sources bans
step "cargo deny check advisories" deny_advisories

advisory_ids() { grep -oE '^[[:space:]]*"RUSTSEC-[0-9]{4}-[0-9]{4}"' "$1" | tr -d ' "' | sort -u; }
ignore_lists_agree() { diff <(advisory_ids deny.toml) <(advisory_ids .cargo/audit.toml); }
step "advisory ignore lists agree (deny.toml vs .cargo/audit.toml)" ignore_lists_agree

# 3. Unsafe code and unused dependencies. The first-party crates that contain
#    reviewed `unsafe` are covered by Miri in the hardening workflow; geiger
#    reports the count so a new block is visible.
geiger() {
  local rc=0 c out
  for c in "${GEIGER_CRATES[@]}"; do
    # Only the crate's own total row is printed: geiger lists every
    # dependency, and warns on files it cannot parse, which fails its exit
    # status without a finding in first-party code.
    out=$(cd "$c" && cargo geiger --output-format Ratio 2>&1) || rc=1
    echo "$c: $(grep -E '^ *[0-9]+/[0-9]+=[0-9.]+%  *[0-9]+/[0-9]+=' <<<"$out" | tail -1)"
  done
  return $rc
}
step "cargo geiger (unsafe usage)" informational geiger geiger

# cargo-machete can report a dependency used only through a macro; list such
# a case under [package.metadata.cargo-machete] ignored = [...] with a reason.
if [ "${UDEPS:-0}" = 1 ]; then
  udeps() { cargo +nightly udeps --workspace --all-targets --all-features; }
  step "cargo udeps (unused dependencies)" informational udeps udeps
else
  machete() { cargo machete; }
  step "cargo machete (unused dependencies)" informational machete machete
fi

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

# 5. Test-only code must not reach a release build.
#    `cargo tree` has no --release flag and does not need one: it resolves
#    features, not profiles. -e features,normal prints each enabled feature
#    as a node (`axess-core feature "testing"`) and leaves out dev edges, so
#    a feature a dev-dependency switches on is not counted. The root of a
#    tree does not print its own features, so each package is read inverted
#    from every crate that carries a `testing` surface (`-i`), which does;
#    a package whose tree does not hold that crate makes `-i` fail and is
#    skipped for it.
GUARDED=(axess-core axess-factors axess-rng axess-clock)
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
        in_tree "$pkg" "$c" | head -10
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
    targets+=("$(sed -n 's/^name *= *"\(axess-example-[a-z-]*\)".*/\1/p' "$ex" | head -1)")
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
