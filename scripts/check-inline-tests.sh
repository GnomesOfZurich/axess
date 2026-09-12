#!/usr/bin/env bash
# axess: enforce the inline-test size rule from AGENTS.md.
#
# An inline `#[cfg(test)] mod ... { … }` block inside a production file is
# fine while it is small. Past ~200 lines it drowns the logic it sits beside:
# `middleware/csrf.rs` once carried 1003 lines of tests around 698 lines of
# middleware, so five sixths of what a reader scrolled through to reach the
# code was not the code. AGENTS.md prescribes moving such a block to a sibling
# (`foo.rs` + `foo/tests.rs`, declared with `#[cfg(test)] mod tests;`).
#
# The rule triggers on a BLOCK, not a file. `session/layer/signing.rs` totals
# ~690 lines across three test mods of 98/118/191 and is compliant; measuring
# whole files would wrongly condemn it. Files that already ARE test siblings
# (`tests.rs`, anything under a `tests/` directory) are exempt: they are not
# production files drowning in tests, they are where the tests were moved to.
#
# Usage: ./scripts/check-inline-tests.sh
#   INLINE_TEST_THRESHOLD=N  override the limit (used by this script's own
#                            self-test to prove it can fail).

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR"

THRESHOLD="${INLINE_TEST_THRESHOLD:-200}"

# Only tracked files, so build output and packaged copies under target/ cannot
# contribute phantom hits.
# `mapfile` is bash 4; macOS ships 3.2, so build the list portably. Paths with
# whitespace would break the unquoted expansion below, so refuse them loudly
# rather than silently checking a subset.
FILE_LIST="$(git ls-files '*.rs' \
  | grep -v -e '/tests\.rs$' -e '^tests\.rs$' -e '/tests/' -e '^fuzz/')"

if [ -z "$FILE_LIST" ]; then
  echo "ERROR: no Rust files matched: the file selection is broken, not the tree." >&2
  exit 1
fi
if printf '%s\n' "$FILE_LIST" | grep -q '[[:space:]]'; then
  echo "ERROR: a tracked .rs path contains whitespace; this script cannot scan it." >&2
  exit 1
fi
FILE_COUNT=$(printf '%s\n' "$FILE_LIST" | grep -c .)
set -f
set -- $FILE_LIST
set +f

report=$(awk -v threshold="$THRESHOLD" '
  FNR == 1 { state = 0; pending = 0 }
  state == 0 && $0 == "#[cfg(test)]" { pending = 1; next }
  pending == 1 {
    pending = 0
    if ($0 ~ /^mod [A-Za-z0-9_]+ \{$/) {
      modname = $2; start = FNR; state = 1; checked++
    }
    next
  }
  state == 1 && $0 == "}" {
    n = FNR - start - 1
    if (n > threshold) printf "  %5d lines  %s::%s\n", n, FILENAME, modname
    state = 0
  }
  END { printf "CHECKED=%d\n", checked + 0 }
' "$@")

checked=$(printf '%s\n' "$report" | sed -n 's/^CHECKED=//p')
violations=$(printf '%s\n' "$report" | grep -v '^CHECKED=' || true)

if [ "${checked:-0}" -eq 0 ]; then
  echo "ERROR: no inline test blocks found in $FILE_COUNT files. The matcher is" >&2
  echo "       broken, not the tree, a pass here would be meaningless." >&2
  exit 1
fi

if [ -n "$violations" ]; then
  count=$(printf '%s\n' "$violations" | grep -c .)
  echo "ERROR: ${count} of ${checked} inline test blocks exceed ${THRESHOLD} lines:" >&2
  printf '%s\n' "$violations" >&2
  echo "" >&2
  echo "Move each to a sibling file per AGENTS.md: replace the block with" >&2
  echo "\`#[cfg(test)] mod <name>;\` and put the body in <file>/<name>.rs." >&2
  echo "For lib.rs / main.rs / mod.rs the sibling is <dir>/<name>.rs." >&2
  exit 1
fi

echo "OK: all ${checked} inline test blocks are within ${THRESHOLD} lines."
