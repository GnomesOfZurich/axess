#!/usr/bin/env bash
# axess: crafted cases for scripts/check-release-build.sh.
#
# Each case runs the check in a copy of its scripts with a stand-in `cargo`
# first on PATH. The stand-in passes the workspace check, prints a feature
# tree with no testing node, and answers `cargo check --release -p NAME` as
# the case says: refused on the release-build gate, compiled, or failed on
# something else. So the cases prove what the check concludes from each
# answer without building the workspace.
#
# Usage: ./scripts/check-release-build-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="${GATE:-$SCRIPT_DIR/check-release-build.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-release-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case_ NAME EXPECTED_EXIT FRAGMENT ANSWERS: ANSWERS maps each example to
# refuses, compiles or breaks (`axess-example-oauth=compiles`); an example
# not named refuses.
case_() {
  local name="$1" want="$2" fragment="$3" answers="$4"
  local dir="$WORK/$passed-$failed"
  mkdir -p "$dir/scripts/lib" "$dir/bin"
  cp "$GATE" "$dir/scripts/check-release-build.sh"
  cp "$SCRIPT_DIR/lib/mock_examples.sh" "$dir/scripts/lib/mock_examples.sh"
  cat > "$dir/bin/cargo" <<STUB
#!/usr/bin/env bash
answers="$answers"
case "\$*" in
  "check --release -p "*)
    probe="\${*: -1}"
    case " \$answers " in
      *" \$probe=compiles "*) exit 0 ;;
      *" \$probe=breaks "*) echo "error[E0425]: cannot find value"; exit 101 ;;
    esac
    echo "error: the \\\`testing\\\` feature of axess-core is enabled in a release build"; exit 101 ;;
  tree*) echo "axess-core feature \"default\"" ;;
  *) exit 0 ;;
esac
STUB
  chmod +x "$dir/bin/cargo"
  local out status
  out="$(PATH="$dir/bin:$PATH" "$dir/scripts/check-release-build.sh" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$dir"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

case_ "every mock example refusing a release build passes" 0 "each refuse a release build by name" ""
case_ "the minimal example compiling in release is refused" 1 "REFUSED: axess-example-minimal compiled in release" "axess-example-minimal=compiles"
case_ "the oauth example compiling in release is refused" 1 "REFUSED: axess-example-oauth compiled in release" "axess-example-oauth=compiles"
case_ "the fapi example compiling in release is refused" 1 "REFUSED: axess-example-fapi compiled in release" "axess-example-fapi=compiles"
case_ "the fido2 example compiling in release is refused" 1 "REFUSED: axess-example-fido2 compiled in release" "axess-example-fido2=compiles"
case_ "an example failing on another error is refused" 1 "REFUSED: axess-example-fapi failed to build in release, but not on the release-build gate" "axess-example-fapi=breaks"

echo "check-release-build tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
