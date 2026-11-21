#!/usr/bin/env bash
# axess: crafted cases for what scripts/check-unused-dependency-lint.sh
# reads as cargo's unused-dependency lint refusing the probe crate.
#
# The predicate lives in scripts/lib/unused_dependency_lint.sh, which the
# script sources too, and runs here on crafted logs: cargo's refusal as CI
# writes it (in colour, CARGO_TERM_COLOR=always) and as a terminal without
# colour writes it, against runs that failed for another cause, a warning
# by the lint's name, an error for another crate or in another member's
# manifest, and a cargo that ignores the lint table. A widening of the
# match, or a narrowing that misses the lint's own form, fails here.
#
# Usage: ./scripts/check-unused-dependency-lint-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-unused-lint-cases.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

# shellcheck source=lib/unused_dependency_lint.sh
. "$SCRIPT_DIR/lib/unused_dependency_lint.sh"
if ! declare -f unused_dependency_lint_fires >/dev/null || ! declare -f uncoloured >/dev/null; then
  echo "FAIL: scripts/lib/unused_dependency_lint.sh does not define unused_dependency_lint_fires and uncoloured" >&2
  exit 1
fi
for line in '. "$AXESS_DIR/scripts/lib/unused_dependency_lint.sh"' \
  '  unused_dependency_lint_fires "$PROBE_CRATE" "$PROBE_MEMBER" "$probe_rc" "$WORK/probe-$name.log" && fires=yes'; do
  if ! grep -qxF -- "$line" "$SCRIPT_DIR/check-unused-dependency-lint.sh"; then
    echo "FAIL: scripts/check-unused-dependency-lint.sh lacks the line: $line" >&2
    exit 1
  fi
done

passed=0
failed=0
# case_ NAME WANT(0 fires, 1 does not) STATUS LOG [CRATE MEMBER]
case_() {
  local name="$1" want="$2" status="$3" log="$4" crate="${5:-humantime}" member="${6:-axess-rng}" rc
  local file="$WORK/$passed-$failed.log"
  printf '%s\n' "$log" > "$file"
  unused_dependency_lint_fires "$crate" "$member" "$status" "$file"
  rc=$?
  if [ "$rc" -eq "$want" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted $want, got $rc" >&2
  fi
}

# Cargo's refusal, as `cargo clippy -p axess-rng --all-targets` writes it
# with CARGO_TERM_COLOR=always: every part of the diagnostic in its colour.
E=$'\033'
COLOURED="${E}[1m${E}[91merror${E}[0m${E}[1m: unused dependency \`humantime\`${E}[0m

${E}[1m${E}[92m    Checking${E}[0m humantime v2.3.0
${E}[1m${E}[92m    Checking${E}[0m axess-rng v0.20.0 (/tmp/axess-unused-lint.bofSFX/tree/axess-rng)
${E}[1m${E}[91merror${E}[0m${E}[1m: unused dependency \`humantime\`${E}[0m
  ${E}[1m${E}[94m--> ${E}[0maxess-rng/Cargo.toml:52:1
   ${E}[1m${E}[94m|${E}[0m
${E}[1m${E}[94m52${E}[0m ${E}[1m${E}[94m|${E}[0m humantime = \"=2.3.0\"
   ${E}[1m${E}[94m|${E}[0m ${E}[1m${E}[91m^^^^^^^^^^^^^^^^^^^^${E}[0m
   ${E}[1m${E}[94m|${E}[0m
   ${E}[1m${E}[94m= ${E}[0m${E}[1mnote${E}[0m: \`cargo::unused_dependencies\` is set to \`deny\` in \`[lints]\`
${E}[1m${E}[96mhelp${E}[0m: consider removing the dependency on \`humantime\`
${E}[1m${E}[91merror${E}[0m: could not finalize \`axess-rng\` (manifest) due to 1 previous error"
case_ "the lint's refusal in colour fires" 0 101 "$COLOURED"

PLAIN="$(printf '%s\n' "$COLOURED" | sed $'s/\x1b\\[[0-9;?]*[A-Za-z]//g')"
case_ "the lint's refusal without colour fires" 0 101 "$PLAIN"
case_ "a table set to forbid fires" 0 101 "${PLAIN//set to \`deny\`/set to \`forbid\`}"
case_ "a run that exited zero did not refuse" 1 0 "$PLAIN"
case_ "the lint on another crate is not the probe's" 1 101 "${PLAIN//humantime/serde_repr}"
case_ "the lint in another member's manifest is not the probe member's" 1 101 \
  "${PLAIN//--> axess-rng\/Cargo.toml/--> axess-core/Cargo.toml}"
case_ "the probe crate inside a longer name is another crate" 1 101 "${PLAIN//humantime/humantime-serde}" humantime
case_ "the error without the lint table's note is not the lint" 1 101 \
  "$(grep -v 'cargo::unused_dependencies' <<<"$PLAIN")"

# The lint at `warn` with the run failing for another cause: the warning
# names the crate at its line, and the refusal is a compile error.
WARNED='    Checking axess-rng v0.20.0 (/tmp/axess-unused-lint.bofSFX/tree/axess-rng)
warning: unused dependency `humantime`
  --> axess-rng/Cargo.toml:52:1
   |
52 | humantime = "=2.3.0"
   | ^^^^^^^^^^^^^^^^^^^^
   |
   = note: `cargo::unused_dependencies` is set to `warn` in `[lints]`
error[E0425]: cannot find value `seed` in this scope
 --> axess-rng/src/lib.rs:40:9
  |
40 |         seed
  |         ^^^^ not found in this scope

error: could not compile `axess-rng` (lib) due to 1 previous error'
case_ "a warning by the lint's name beside another failure is not the lint refusing" 1 101 "$WARNED"
case_ "the same in colour is not either" 1 101 "${E}[1m${E}[33m${WARNED//$'\n'/$'\n'${E}[0m}${E}[0m"

# The manifest refused for another cause, at the probe crate's line.
MALFORMED='error: failed to parse manifest at `/tmp/axess-unused-lint.bofSFX/tree/axess-rng/Cargo.toml`

Caused by:
  TOML parse error at line 52, column 1
     |
  52 | humantime = "=2.3.0"
     | ^^^^^^^^^
  duplicate key'
case_ "a manifest refused for another cause at the probe line is not the lint" 1 101 "$MALFORMED"

# A cargo that does not know the lint table runs without it.
IGNORED='warning: unused manifest key: lints.cargo
    Checking axess-rng v0.20.0 (/tmp/axess-unused-lint.bofSFX/tree/axess-rng)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.52s'
case_ "a cargo that ignores the table is silent" 1 0 "$IGNORED"
case_ "a failure that names no unused dependency is not the lint" 1 101 \
  "error: could not compile \`axess-rng\` (lib test) due to 2 previous errors"

echo "check-unused-dependency-lint tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
