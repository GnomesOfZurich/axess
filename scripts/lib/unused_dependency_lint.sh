#!/usr/bin/env bash
# axess: whether a cargo run was refused by cargo's unused-dependency lint.
#
# Cargo reports the lint as an error that names the crate, at the line of
# the member's manifest that declares it, with the lint table as the reason:
#
#   error: unused dependency `humantime`
#     --> axess-rng/Cargo.toml:52:1
#      |
#   52 | humantime = "=2.3.0"
#      | ^^^^^^^^^^^^^^^^^^^^
#      |
#      = note: `cargo::unused_dependencies` is set to `deny` in `[lints]`
#   help: consider removing the dependency on `humantime`
#   error: could not finalize `axess-rng` (manifest) due to 1 previous error
#
# A run fired the lint on CRATE in MEMBER when it exited non-zero and its
# log holds all four of: that error for CRATE, a location in MEMBER's
# manifest, the line that declares CRATE, and the note that the lint table
# sets `cargo::unused_dependencies` to deny (or forbid). A warning by the
# same name is not the lint refusing (the table at `warn`, the run failing
# for another cause), and neither is an error for another crate or a
# failure that names no unused dependency.
#
# The log is read without its colour codes. With CARGO_TERM_COLOR=always,
# as CI sets it, cargo wraps each part of the diagnostic in escape
# sequences, the line number and the `|` of the gutter included, so a
# pattern for `52 | humantime = ` does not match the line as written.
#
# Sourced by scripts/check-unused-dependency-lint.sh, which applies it, and
# by scripts/check-unused-dependency-lint-tests.sh, which holds it to
# crafted logs.

# uncoloured LOG: the file with every colour escape sequence removed.
uncoloured() {
  sed $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' "$1"
}

# unused_dependency_lint_fires CRATE MEMBER STATUS LOG
unused_dependency_lint_fires() {
  local crate="$1" member="$2" status="$3" plain
  [ "$status" -ne 0 ] || return 1
  plain="$(uncoloured "$4")" || return 1
  grep -qE "^error: unused dependency \`$crate\`" <<<"$plain" \
    && grep -qE "^[[:space:]]*--> $member/Cargo\\.toml:[0-9]+:[0-9]+[[:space:]]*\$" <<<"$plain" \
    && grep -qE "^[[:space:]]*[0-9]+ \\| $crate = " <<<"$plain" \
    && grep -qE "^[[:space:]]*= note: \`cargo::unused_dependencies\` is set to \`(deny|forbid)\`" <<<"$plain"
}
