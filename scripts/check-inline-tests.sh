#!/usr/bin/env bash
# axess: enforce the test-layout rule of AGENTS.md and CONTRIBUTING.md:
#
#   Tests live beside the module they test, in a sibling file declared with
#   `#[cfg(test)] mod <name>;` or in the crate's `tests/` directory. An inline
#   `#[cfg(test)] mod <name> { ... }` block in a production file is allowed
#   while its body is at most 200 lines.
#
# Past 200 lines an inline block drowns the logic it sits beside: a reader
# scrolls through more test than code to reach the code. Such a block moves
# to a sibling (`foo.rs` +
# `foo/tests.rs`, declared with `#[cfg(test)] mod tests;`).
#
# Both documents carry the rule word for word, and this gate refuses a copy
# that no longer reads so, which keeps the rule and the gate saying one thing.
#
# The rule triggers on a BLOCK, not a file. `session/layer/signing.rs` totals
# ~690 lines across three test mods of 98/118/191 and is compliant; measuring
# whole files would wrongly condemn it. Files that already ARE test siblings
# (`tests.rs`, anything under a `tests/` directory) are exempt: they are not
# production files drowning in tests, they are where the tests were moved to.
#
# A block is an inline module under any `cfg` that asks for `test`, not
# `#[cfg(test)]` alone: `#[cfg(all(test, feature = "x"))]` and
# `#[cfg(any(test, feature = "testing"))]` hold test code as well, and a
# 410-line block under the first form went unmeasured while this gate read
# only the plain attribute. scripts/lib/inline_tests.py finds the blocks and
# matches their braces on the code alone; its crafted cases are
# scripts/check-inline-tests-tests.sh.
#
# Usage: ./scripts/check-inline-tests.sh
#   INLINE_TEST_THRESHOLD=N  override the limit (used by this script's own
#                            self-test to prove it can fail).

set -uo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AXESS_DIR" || exit 1

THRESHOLD="${INLINE_TEST_THRESHOLD:-200}"

# The rule as contributors read it; the header above quotes it.
RULE='Tests live beside the module they test, in a sibling file declared with `#[cfg(test)] mod <name>;` or in the crate'"'"'s `tests/` directory. An inline `#[cfg(test)] mod <name> { ... }` block in a production file is allowed while its body is at most 200 lines.'
for doc in AGENTS.md CONTRIBUTING.md; do
  if ! grep -qF -- "$RULE" "$doc"; then
    echo "ERROR: $doc does not state the test-layout rule as this gate enforces it." >&2
    echo "       It must carry these sentences word for word:" >&2
    printf '  %s\n' "$RULE" >&2
    exit 1
  fi
done

# Tracked files and untracked ones git does not ignore, so a file not yet
# added is checked as well, and build output and packaged copies under
# target/ (ignored) cannot contribute phantom hits.
# `mapfile` is bash 4; macOS ships 3.2, so build the list portably. Paths with
# whitespace would break the unquoted expansion below, so refuse them loudly
# rather than silently checking a subset.
FILE_LIST="$(git ls-files --cached --others --exclude-standard --deduplicate '*.rs' \
  | grep -v -e '/tests\.rs$' -e '^tests\.rs$' -e '/tests/' -e '^fuzz/')"

if [ -z "$FILE_LIST" ]; then
  echo "ERROR: no Rust files matched: the file selection is broken, not the tree." >&2
  exit 1
fi
if grep -q '[[:space:]]' <<<"$FILE_LIST"; then
  echo "ERROR: a listed .rs path contains whitespace; this script cannot scan it." >&2
  exit 1
fi
FILE_COUNT=$(printf '%s\n' "$FILE_LIST" | grep -c .)
set -f
set -- $FILE_LIST
set +f

report=$(python3 -I -B "$AXESS_DIR/scripts/lib/inline_tests.py" "$THRESHOLD" "$@")
status=$?
if [ "$status" -gt 1 ]; then
  echo "ERROR: scripts/lib/inline_tests.py failed (exit $status); nothing was checked." >&2
  printf '%s\n' "$report" >&2
  exit 1
fi

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
