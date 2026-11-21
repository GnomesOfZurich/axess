#!/usr/bin/env bash
# axess: crafted cases for the advisory waiver and the geiger step in
# scripts/supply-chain.sh.
#
# ALLOW_DENY_CVSS4_PARSE_ERROR=1 may turn one cargo-deny failure into a
# warning: the exact parse error an old cargo-deny prints on a CVSS 4.0
# vector, with no advisory finding beside it. The predicate that decides
# lives in scripts/lib/cvss4_waiver.sh, which the script sources too, and
# runs here on crafted outputs, so a widening of the match fails here.
#
# The geiger step: how a step reports (scripts/lib/supply_chain_steps.sh,
# which the script sources too), what is read from geiger's report, and the
# target directory geiger builds into. A step whose tool was missing, failed
# or counted nothing is never OK: it fails, or under the informational rule
# says it failed and why the gate goes on; geiger runs in a target directory
# made for the call, never the one the environment names, and removed after.
#
# Usage: ./scripts/supply-chain-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The constant and the predicate the script sources.
# shellcheck source=lib/cvss4_waiver.sh
. "$SCRIPT_DIR/lib/cvss4_waiver.sh"
if ! declare -f cvss4_parse_error_only >/dev/null; then
  echo "FAIL: cvss4_parse_error_only is not defined in scripts/lib/cvss4_waiver.sh" >&2
  exit 1
fi
if ! grep -q '^\. "\$ROOT/scripts/lib/cvss4_waiver.sh"$' "$SCRIPT_DIR/supply-chain.sh"; then
  echo "FAIL: scripts/supply-chain.sh does not source scripts/lib/cvss4_waiver.sh" >&2
  exit 1
fi

passed=0
failed=0
case_() { # case NAME WANT(0 waivable, 1 not) OUTPUT
  local name="$1" want="$2" out="$3" rc
  cvss4_parse_error_only "$out"; rc=$?
  if [ "$rc" -eq "$want" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted $want, got $rc" >&2
  fi
}

PARSE='error: failed to load advisory database
  caused by: parse error: unsupported CVSS version: 4.0'
case_ "the exact parse error alone is waivable" 0 "$PARSE"
case_ "the exact line with a vulnerability beside it is not" 1 "$PARSE
error[vulnerability]: Marvin attack on RSA
   ID: RUSTSEC-2023-0071"
case_ "the exact line with an unmaintained finding beside it is not" 1 "error[unmaintained]: dotenv is unmaintained
$PARSE"
case_ "another mention of CVSS is not" 1 "error: the advisory RUSTSEC-2025-0001 carries no cvss score"
case_ "a different parse error is not" 1 "error: failed to parse advisory RUSTSEC-2025-0002: invalid CVSS string prefix: \`CVSS:9.9\`"
case_ "a 4.0 version string elsewhere is not" 1 "error: dependency tool 4.0 is unsupported"
case_ "a plain advisory failure is not" 1 "error[vulnerability]: something
   ID: RUSTSEC-2025-0003"

# ── The geiger step ──────────────────────────────────────────────────────────

# shellcheck source=lib/supply_chain_steps.sh
. "$SCRIPT_DIR/lib/supply_chain_steps.sh"
if ! declare -f step >/dev/null || ! declare -f informational >/dev/null \
   || ! declare -f geiger_crate >/dev/null || ! declare -f geiger_count >/dev/null; then
  echo "FAIL: scripts/lib/supply_chain_steps.sh does not define step, informational, geiger_crate and geiger_count" >&2
  exit 1
fi
for line in '. "$ROOT/scripts/lib/supply_chain_steps.sh"' \
  'geiger_run() { (cd "$1" && CARGO_TARGET_DIR="$2" cargo geiger --output-format Ratio); }' \
  'geiger() { geiger_count "${GEIGER_CRATES[@]}"; }' \
  'step "cargo geiger (unsafe usage)" informational geiger geiger "$GEIGER_REASON"'; do
  if ! grep -qxF -- "$line" "$SCRIPT_DIR/supply-chain.sh"; then
    echo "FAIL: scripts/supply-chain.sh lacks the line: $line" >&2
    exit 1
  fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-supply-chain.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# expect NAME WANT_STATUS STATUS OUTPUT FRAGMENT [UNWANTED]: count one case.
expect() {
  local name="$1" want="$2" status="$3" out="$4" fragment="$5" unwanted="${6:-}"
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" <<<"$out" \
     && { [ -z "$unwanted" ] || ! grep -qF -- "$unwanted" <<<"$out"; }; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted status $want with '$fragment'${unwanted:+ and without '$unwanted'}, got $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

ROW='    0/0=0.00%    0/0=0.00%    1/2=50.00%    0/0=0.00%    3/4=75.00%  '
DEP_ROW='    9/9=100.00%  0/0=0.00%    0/0=0.00%    0/0=0.00%    0/0=0.00%  '
STALE='    Checking axess-strings v0.20.0 (/repo/axess-strings)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.23s
error: Io(Os { code: 2, kind: NotFound, message: "No such file or directory" }, "/repo/axess-core/tests/gone.rs")'

out=$(geiger_crate axess-strings "$DEP_ROW
$ROW" 0); expect "a counted crate prints its own row, the last" 0 $? "$out" "axess-strings: $ROW" "$DEP_ROW"
out=$(geiger_crate axess-strings "$STALE" 1); expect "geiger stopped on stale dep-info counts nothing and fails" 1 $? "$out" "axess-strings: cargo geiger counted nothing (exit 1): error: Io(Os { code: 2"
out=$(geiger_crate axess-strings "" 0); expect "an empty report fails even with exit 0" 1 $? "$out" "counted nothing (exit 0): no error line, and the report holds no row of ratios"
out=$(geiger_crate axess-strings "$ROW
error: could not parse src/odd.rs" 1); expect "an error after counting fails and names it" 1 $? "$out" "cargo geiger exited 1 after counting: error: could not parse src/odd.rs"
out=$(geiger_crate axess-core "$ROW
error: Found 209 warnings" 1); expect "geiger's summary of warnings after the row is a count, with the number" 0 $? "$out" "axess-core: counted, with 209 geiger warning(s)" "::error::"
out=$(geiger_crate axess-core "$ROW
error: Found 1 warning" 1); expect "one warning is a count too" 0 $? "$out" "counted, with 1 geiger warning(s)"
out=$(geiger_crate axess-core "error: Found 3 warnings" 1); expect "a summary of warnings with no row counts nothing" 1 $? "$out" "axess-core: cargo geiger counted nothing (exit 1): error: Found 3 warnings"
out=$(geiger_crate axess-core "$ROW
error: Found 3 warnings and a parse error" 1); expect "a line that is not the summary alone is an error" 1 $? "$out" "exited 1 after counting: error: Found 3 warnings and a parse error"

# run_step [STRICT] HAVE FUNCTION_STATUS: one geiger step with a stub tool
# check and a stub count; prints the step's lines, then FAILED=<count>.
run_step() (
  STRICT="$1"
  stub_have="$2"
  stub_status="$3"
  have() { [ "$stub_have" = yes ]; }
  stub() { echo "stub count ran"; return "$stub_status"; }
  FAILED=()
  export STRICT
  step "cargo geiger (unsafe usage)" informational geiger stub "the reason given"
  echo "FAILED=${#FAILED[@]}"
)

out=$(run_step 0 yes 0); expect "a count that ran is OK" 0 $? "$out" "OK: cargo geiger (unsafe usage)"
out=$(run_step 0 yes 1); expect "a failed count is a failed informational step, never OK" 0 $? "$out" "FAILED (informational, the gate goes on): cargo geiger (unsafe usage)" "OK: cargo geiger"
out=$(run_step 0 yes 1); expect "the informational failure says why the gate goes on" 0 $? "$out" "Informational: the reason given. STRICT=1 makes it fatal."
out=$(run_step 0 yes 1); expect "an informational failure leaves the gate's failures alone" 0 $? "$out" "FAILED=0"
out=$(run_step 1 yes 1); expect "under STRICT=1 a failed count fails the gate" 0 $? "$out" "FAILED=1" "OK: cargo geiger"
out=$(run_step 0 no 0); expect "a missing tool is a named skip and a failed informational step, never OK" 0 $? "$out" "SKIPPED: cargo-geiger is not installed" "OK: cargo geiger"
out=$(run_step 0 no 0); expect "a missing tool runs no count" 0 $? "$out" "FAILED (informational, the gate goes on)" "stub count ran"
out=$(run_step 1 no 0); expect "under STRICT=1 a missing tool fails the gate" 0 $? "$out" "FAILED=1"

# The target directory geiger_count hands geiger_run, whose line in the
# script (checked above) passes it to cargo as CARGO_TARGET_DIR. A stub
# geiger_run records the directory it was given and whether it was an empty
# directory, builds into it, then prints a report.
geiger_run() (
  dir="$2"
  state=missing
  [ -d "$dir" ] && state=present
  [ -d "$dir" ] && [ -z "$(ls -A "$dir")" ] && state=empty
  echo "$dir $state" >> "$STUB_LOG"
  touch "$dir/built-by-$1"
  printf '%s\n' "$STUB_ROW"
)
mkdir -p "$WORK/repo" "$WORK/tmp"
out=$(cd "$WORK/repo" && STUB_LOG="$WORK/log" STUB_ROW="$ROW" \
  CARGO_TARGET_DIR="$WORK/shared-target" TMPDIR="$WORK/tmp" geiger_count crate-a crate-b)
status=$?
expect "geiger_count counts every crate" 0 "$status" "$out" "crate-b: $ROW"
target=$(awk 'NR == 1 { print $1 }' "$WORK/log")
# holds TEST...: 0 when the test holds, 1 when it does not.
holds() { if "$@"; then echo 0; else echo 1; fi; }
own=1
[ "$target" != "$WORK/shared-target" ] && [ "${target#"$WORK/tmp/axess-geiger."}" != "$target" ] && own=0
expect "geiger builds in a directory of its own, not the environment's target" 0 "$own" "$target" "$WORK/tmp/axess-geiger."
expect "the directory is new and empty when geiger starts" 0 0 "$(sed -n 1p "$WORK/log")" "$target empty"
expect "every crate of the call shares it" 0 0 "$(sed -n 2p "$WORK/log")" "$target present"
expect "the directory is removed when the count ends" 0 "$(holds test ! -e "$target")" "$target" "$target"
expect "the environment's target is left untouched" 0 "$(holds test ! -e "$WORK/shared-target")" "$WORK/shared-target" "$WORK/shared-target"
: > "$WORK/log"
out=$(cd "$WORK/repo" && STUB_LOG="$WORK/log" STUB_ROW="" \
  TMPDIR="$WORK/tmp" geiger_count crate-a crate-b)
expect "a crate geiger did not count fails the call" 1 $? "$out" "crate-a: cargo geiger counted nothing"
expect "a call with a crate not counted prints no total" 1 1 "$out" "crate-a: cargo geiger counted nothing" "geiger counted 2 crate(s)"

# Every crate counted, some with geiger's warnings: the call passes and
# prints the total, and the step built on it prints OK.
geiger_run() (
  printf '%s\n' "$STUB_ROW"
  case "$1" in
    crate-a) echo "error: Found 2 warnings"; exit 1 ;;
    crate-b) exit 0 ;;
    crate-c) echo "error: Found 11 warnings"; exit 1 ;;
  esac
)
out=$(STUB_ROW="$ROW" TMPDIR="$WORK/tmp" geiger_count crate-a crate-b crate-c)
expect "every crate counted passes and totals geiger's warnings" 0 $? "$out" "geiger counted 3 crate(s); geiger warnings over them: 13"
counted_step() (
  have() { true; }
  counted() { geiger_count crate-a crate-b crate-c; }
  FAILED=()
  step "cargo geiger (unsafe usage)" informational geiger counted "the reason given"
  echo "FAILED=${#FAILED[@]}"
)
out=$(STUB_ROW="$ROW" TMPDIR="$WORK/tmp" counted_step)
expect "the step prints OK after the total when every crate counted" 0 $? "$out" "OK: cargo geiger (unsafe usage)" "FAILED (informational"

echo "supply-chain tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
