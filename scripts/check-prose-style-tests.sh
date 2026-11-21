#!/usr/bin/env bash
# axess: crafted cases for scripts/check-prose-style.sh.
#
# Each case runs a copy of the gate on the files git lists in a work tree of
# its own (`listed`, scripts/lib/case_harness.sh) and asserts the exit
# status and a fragment of the output. The contract: an em dash is refused
# on any line; a regression marker and a citation of a source line by its
# number are refused in a comment of a Rust, shell or Python file, in the
# Python a shell script hands to `python3`, and on any line of Markdown, and
# pass in a string literal, which is data.
#
# Usage: ./scripts/check-prose-style-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-prose-style.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-prose-style.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

OK="OK: no banned punctuation"
MARKER="(regression marker"
CITATION="(line-number citation"
DASH="$(printf '\342\200\224')"

# A clean tree.
listed "$CHECK" "a clean tree passes" 0 "$OK" "" \
  a/src/lib.rs '// Returns the stored key.
fn f() {}' s.sh '#!/usr/bin/env bash
# Prints the key.
echo key'

# Rust: the forms in a comment are refused, in a string they pass.
listed "$CHECK" "a regression marker in a line comment is refused" 1 "a/src/lib.rs:2  $MARKER" "" \
  a/src/lib.rs 'fn f() {}
// Regression: the key leaked.'
listed "$CHECK" "a line citation in a doc comment is refused" 1 "a/src/lib.rs:1  $CITATION" "" \
  a/src/lib.rs '/// Called from session/crypto.rs:343.
fn f() {}'
listed "$CHECK" "a citation on a later line of a block comment is refused" 1 "a/src/lib.rs:2  $CITATION" "" \
  a/src/lib.rs '/* The caller,
   at layer.rs:12, holds the lock. */
fn f() {}'
listed "$CHECK" "a marker in any case and spacing is refused" 1 "a/src/lib.rs:1  $MARKER" "" \
  a/src/lib.rs 'fn f() {} // regression : see the log'
listed "$CHECK" "a citation by #L is refused" 1 "a/src/lib.rs:1  $CITATION" "" \
  a/src/lib.rs '//! As in layer.rs#L12.'
listed "$CHECK" "the forms in a string literal pass" 0 "$OK" "$MARKER" \
  a/src/lib.rs 'const A: &str = "// Regression: see layer.rs:12";
const B: &str = r#"/* Regression: layer.rs:1 */"#;
const C: char = '"'"'"'"'"'; // a quote char, then a clean comment'
SQ="'"
listed "$CHECK" "a comment after an escaped quote char beside a double quote is read" 1 "a/src/lib.rs:1  $MARKER" "" \
  a/src/lib.rs "const Q: [char; 2] = [${SQ}\\${SQ}${SQ},${SQ}\"${SQ}]; // Regression: the quotes leaked.
fn f() {}"

# Shell: the comments the shell skips are read, quoted text is not.
listed "$CHECK" "a regression marker in a shell comment is refused" 1 "s.sh:2  $MARKER" "" \
  s.sh '#!/usr/bin/env bash
# Regression: the gate passed over nothing.
echo ok'
listed "$CHECK" "a citation in a comment after a command is refused" 1 "s.sh:1  $CITATION" "" \
  s.sh 'echo ok # see check.sh:20'
listed "$CHECK" "the forms in shell quotes pass, over lines too" 0 "$OK" "$CITATION" \
  s.sh 'case_ "a case" 1 '"'"'a/src/x.rs:3
# Regression: in the expected text'"'"'
echo "# see layer.rs:12"
echo x#see.rs:1'
listed "$CHECK" "a comment of the Python a heredoc hands to python3 is refused" 1 "s.sh:3  $MARKER" "" \
  s.sh 'python3 - <<'"'"'PY'"'"'
import sys
# Regression: the import failed.
PY'
listed "$CHECK" "a heredoc to another program is text" 0 "$OK" "$CITATION" \
  s.sh 'cat <<'"'"'EOF'"'"'
# see layer.rs:12
EOF'

# Python and Markdown.
listed "$CHECK" "a citation in a Python comment is refused" 1 "lib/x.py:2  $CITATION" "" \
  lib/x.py 'X = "layer.rs:12"  # a string, then a clean comment
# Called from check.py:9.'
listed "$CHECK" "the forms in a Python string pass" 0 "$OK" "$MARKER" \
  lib/x.py 'X = """Regression: layer.rs:12"""'
listed "$CHECK" "a citation on a Markdown line is refused" 1 "docs/p.md:1  $CITATION" "" \
  docs/p.md 'The counter fires in `session/crypto.rs:343`.'
listed "$CHECK" "a generated book page is exempt" 0 "$OK" "$CITATION" \
  docs/book/p.md 'The counter fires in `session/crypto.rs:343`.'

# The em dash rule is kept: on every line, a string's included.
listed "$CHECK" "an em dash in a comment is still refused" 1 "a/src/lib.rs:1  (em dash" "" \
  a/src/lib.rs "// The key ${DASH} the stored one."
listed "$CHECK" "an em dash in a string is still refused" 1 "a/src/lib.rs:1  (em dash" "" \
  a/src/lib.rs "const S: &str = \"a ${DASH} b\";"

# The files git lists: one not yet added is read, an ignored one is not.
listed "$CHECK" "an untracked file is read" 1 "a/src/new.rs:1  $MARKER" "ignored.rs" \
  a/src/new.rs '// Regression: x' a/src/ignored.rs '// Regression: x'
listed "$CHECK" "an ignored file is not read" 0 "$OK" "ignored.rs" \
  a/src/lib.rs 'fn f() {}' a/src/ignored.rs '// Regression: x'

echo "check-prose-style tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
