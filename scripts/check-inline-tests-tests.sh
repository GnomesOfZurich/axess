#!/usr/bin/env bash
# axess: crafted cases for scripts/check-inline-tests.sh.
#
# Each case runs a copy of the gate in a small git tree holding the two
# documents that state the rule and one Rust file, and asserts the exit
# status and a fragment of the output. The contract: an inline module under
# any `cfg` that asks for `test` is a block and is measured, whatever the
# predicate's form, whatever attributes stand between, at any depth and
# whether the attribute shares the `mod` line; a predicate that asks for
# `test` only under `not` is not a block, nor is an out-of-line module, an
# item that is not a module, or `test` as a feature's name; a brace inside
# a literal or a comment does not end a block.
#
# Usage: ./scripts/check-inline-tests-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="${GATE:-$SCRIPT_DIR/check-inline-tests.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-inline-tests.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

RULE='Tests live beside the module they test, in a sibling file declared with `#[cfg(test)] mod <name>;` or in the crate'"'"'s `tests/` directory. An inline `#[cfg(test)] mod <name> { ... }` block in a production file is allowed while its body is at most 200 lines.'

# body N: N lines of a test body.
body() { local i; for ((i = 0; i < $1; i++)); do printf '    let x = %d;\n' "$i"; done; }

# block ATTRIBUTE HEAD N: ATTRIBUTE on its own line, HEAD, N body lines, `}`.
block() { printf '%s\n%s\n%s\n}' "$1" "$2" "$(body "$3")"; }

# case_ NAME WANTED_EXIT FRAGMENT UNWANTED RUST_SOURCE: the gate over src/a.rs.
case_() {
  listed "$GATE" "$1" "$2" "$3" "$4" \
    AGENTS.md "$RULE" CONTRIBUTING.md "$RULE" \
    src/lib.rs 'mod a;' src/a.rs "$5"
}

OVER="201 lines  src/a.rs::tests"

case_ "a plain cfg(test) block of 200 lines passes" 0 "OK: all 1 inline test blocks are within 200 lines." "" \
  "$(block '#[cfg(test)]' 'mod tests {' 200)"
case_ "a plain cfg(test) block of 201 lines is refused" 1 "$OVER" "" \
  "$(block '#[cfg(test)]' 'mod tests {' 201)"
case_ "cfg(all(test, feature)) is a block" 1 "$OVER" "" \
  "$(block '#[cfg(all(test, feature = "default-error-response"))]' 'mod tests {' 201)"
case_ "cfg(all(feature, test)) is a block, test second" 1 "$OVER" "" \
  "$(block '#[cfg(all(feature = "x", test))]' 'mod tests {' 201)"
case_ "cfg(any(test, feature)) is a block" 1 "$OVER" "" \
  "$(block '#[cfg(any(test, feature = "testing"))]' 'mod tests {' 201)"
case_ "a nested predicate holding test is a block" 1 "$OVER" "" \
  "$(block '#[cfg(all(unix, any(feature = "x", test)))]' 'mod tests {' 201)"
case_ "test under two nots is a block" 1 "$OVER" "" \
  "$(block '#[cfg(not(not(test)))]' 'mod tests {' 201)"
case_ "cfg(not(test)) is not a block" 0 "OK: all 1 inline test blocks" "$OVER" \
  "$(block '#[cfg(not(test))]' 'mod tests {' 201)
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "test only under not inside all is not a block" 0 "OK: all 1 inline test blocks" "$OVER" \
  "$(block '#[cfg(all(unix, not(test)))]' 'mod tests {' 201)
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "test as a feature's name is not a block" 0 "OK: all 1 inline test blocks" "$OVER" \
  "$(block '#[cfg(feature = "test")]' 'mod tests {' 201)
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "an identifier that starts with test is not a block" 0 "OK: all 1 inline test blocks" "$OVER" \
  "$(block '#[cfg(testing)]' 'mod tests {' 201)
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "cfg_attr(test, ...) is not a block" 0 "OK: all 1 inline test blocks" "$OVER" \
  "$(block '#[cfg_attr(test, derive(Debug))]' 'mod tests {' 201)
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "spaces inside the attribute do not hide it" 1 "$OVER" "" \
  "$(block '#[cfg( all( test , feature = "x" ) )]' 'mod tests {' 201)"
case_ "an attribute over several lines is read whole" 1 "$OVER" "" \
  "$(block '#[cfg(all(
    test,
    feature = "x"
))]' 'mod tests {' 201)"
case_ "another attribute between the cfg and the mod does not hide it" 1 "$OVER" "" \
  "$(block '#[cfg(test)]
#[allow(clippy::unwrap_used)]' 'mod tests {' 201)"
case_ "the cfg after another attribute is read" 1 "$OVER" "" \
  "$(block '#[allow(clippy::unwrap_used)]
#[cfg(test)]' 'mod tests {' 201)"
case_ "a pub(crate) module is a block" 1 "$OVER" "" \
  "$(block '#[cfg(test)]' 'pub(crate) mod tests {' 201)"
case_ "the attribute on the mod line is read" 1 "$OVER" "" \
  "$(printf '#[cfg(test)] mod tests {\n%s\n}' "$(body 201)")"
case_ "a block nested inside a module is measured" 1 "$OVER" "" \
  "$(printf 'mod outer {\n    #[cfg(test)]\n    mod tests {\n%s\n    }\n}' "$(body 201)")"
case_ "an out-of-line module is not a block" 0 "OK: all 1 inline test blocks" "" \
  "#[cfg(test)]
mod tests;
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "a test item that is not a module is not a block" 0 "OK: all 1 inline test blocks" "$OVER" \
  "$(block '#[cfg(test)]' 'fn tests() {' 201)
$(block '#[cfg(test)]' 'mod small {' 1)"
case_ "a brace in a string, a char and a comment does not end the block" 1 "$OVER" "" \
  "$(printf '#[cfg(test)]\nmod tests {\n    let s = \"}\";\n    let c = '"'"'}'"'"';\n    // }\n%s\n}' "$(body 198)")"
case_ "the size counts the lines between the braces" 1 "202 lines  src/a.rs::tests" "" \
  "$(block '#[cfg(test)]' 'mod tests {' 202)"
case_ "a tree with no block is refused as a broken matcher" 1 "no inline test blocks found" "" \
  "fn main() {}"

echo "check-inline-tests tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
