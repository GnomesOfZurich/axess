# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: every cargo install carries
# --locked and an exact version for each crate. Sourced by
# scripts/check-workflow-pins-tests.sh.

# install_case NAME EXPECTED_EXIT FRAGMENT LINE: LINE as a `run: |` script,
# whose first line is line 5 of the file.
install_case() {
  case_ "$1" "$2" "$3" i.yml "jobs:
  a:
    steps:
      - run: |
          $4"
}
install_case "an install without a version or --locked is refused" 1 "line 5: cargo install without --locked" "cargo install cargo-audit"
install_case "an install without --locked is refused" 1 "cargo install without --locked" "cargo install cargo-audit@0.22.2"
install_case "an install without a version is refused" 1 "no exact version for cargo-audit" "cargo install --locked cargo-audit"
install_case "an install with a caret version is refused" 1 "no exact version for cargo-audit (^0.22 is not X.Y.Z)" "cargo install --locked cargo-audit@^0.22"
install_case "one unversioned crate among pinned ones is refused" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 cargo-deny"
install_case "a --version pin passes" 0 "OK: every action" "cargo install cargo-mutants --version 26.1.0 --locked"
install_case "the short --vers spelling of --version passes" 0 "OK: every action" "cargo install cargo-mutants --vers 26.1.0 --locked"
install_case "--frozen locks the install" 0 "OK: every action" "cargo install --frozen cargo-audit@0.22.2"
# A version is a literal X.Y.Z, with an optional pre-release suffix. A
# variable or an expression resolves on the runner, where this check does
# not run, so it is refused by name whatever it would expand to.
install_case "a --version from a variable is refused" 1 "no exact version for cargo-mutants (--version \"\$TOOL_VERSION\" is not a literal X.Y.Z)" "cargo install cargo-mutants --version \"\$TOOL_VERSION\" --locked"
install_case "a --version from an expression is refused" 1 "no exact version for cargo-mutants (--version \"\${{ inputs.version }}\" is not a literal X.Y.Z)" "cargo install cargo-mutants --version \"\${{ inputs.version }}\" --locked"
install_case "a --version= from a variable is refused" 1 "no exact version for cargo-mutants (--version \$TOOL_VERSION is not a literal X.Y.Z)" "cargo install cargo-mutants --version=\$TOOL_VERSION --locked"
install_case "a crate@version from a variable is refused" 1 "no exact version for cargo-audit (\$V is not X.Y.Z)" 'cargo install --locked cargo-audit@$V'
install_case "a quoted literal --version passes" 0 "OK: every action" "cargo install cargo-mutants --version \"26.1.0\" --locked"
install_case "a single-quoted literal --version passes" 0 "OK: every action" "cargo install cargo-mutants --version '26.1.0' --locked"
install_case "a --version= literal passes" 0 "OK: every action" "cargo install cargo-mutants --version=26.1.0 --locked"
install_case "a pre-release --version passes" 0 "OK: every action" "cargo install cargo-mutants --version 27.0.0-beta.1 --locked"
install_case "a pre-release crate@version passes" 0 "OK: every action" "cargo install --locked cargo-fuzz@0.13.2-rc.1"
install_case "a two-part --version is refused" 1 "no exact version for cargo-mutants (--version 26.1 is not a literal X.Y.Z)" "cargo install cargo-mutants --version 26.1 --locked"
install_case "a nightly install with every pin passes" 0 "OK: every action" "cargo +nightly install --locked cargo-fuzz@0.13.2"
install_case "a pinned install after a shell operator passes" 0 "OK: every action" "cargo semver-checks --version || cargo install cargo-semver-checks@0.51.0 --locked"
install_case "an install from a git url is refused" 1 "no exact version for a cargo install from --git or --path" "cargo install --locked --git https://example.invalid/tool"
install_case "an install from a path is refused whatever else it carries" 1 "no exact version for a cargo install from --git or --path" "cargo install --locked --path tools/audit --version 0.22.2"
install_case "an install from a git url with a tag is refused for its source alone" 1 "1 workflow pin problem(s)" "cargo install --locked --git https://example.invalid/tool --tag v1.0.0 tool"
install_case "an install that names no crate is refused" 1 "cargo install names no crate" "cargo install --locked"
# The crate comes from crates.io, named in the script.
install_case "an install from another registry is refused" 1 "a cargo install from another registry is not read (--registry mirror)" "cargo install --locked cargo-audit@0.22.2 --registry mirror"
install_case "an install from another registry joined by an equals sign is refused" 1 "a cargo install from another registry is not read (--registry=mirror)" "cargo install --locked cargo-audit@0.22.2 --registry=mirror"
install_case "an install from crates-io named as a registry passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 --registry crates-io"
install_case "an install from another index is refused" 1 "a cargo install from another registry is not read (--index sparse+https://example.invalid/index/)" "cargo install --locked cargo-audit@0.22.2 --index sparse+https://example.invalid/index/"
install_case "an install from another index joined by an equals sign is refused" 1 "a cargo install from another registry is not read (--index=https://example.invalid)" "cargo install --locked cargo-audit@0.22.2 --index=https://example.invalid"
install_case "a crate from a variable is refused by name" 1 'the crate of a cargo install comes from a variable or a substitution ("$TOOL")' 'cargo install --locked --version 1.0.0 "$TOOL"'
install_case "a crate from a command substitution is refused by name" 1 'the crate of a cargo install comes from a variable or a substitution ($(cat tools.txt))' 'cargo install --locked $(cat tools.txt)'
install_case "a crate from an expression is refused by name" 1 'the crate of a cargo install comes from a variable or a substitution (${{ inputs.tool }})' 'cargo install --locked --version 1.0.0 ${{ inputs.tool }}'
install_case "a flag the check does not know is refused by name" 1 "a cargo install flag the check does not read: --frobnicate" "cargo install --locked cargo-audit@0.22.2 --frobnicate"
# A toolchain selector is any text after the plus sign, and cargo takes its
# own flags, some with a value, before the subcommand. Each form is the same
# install, and a --locked among cargo's own flags locks it.
install_case "an install under a numbered toolchain is refused" 1 "cargo install without --locked" "cargo +1.98.0 install cargo-audit"
install_case "an install under a dated nightly is refused" 1 "cargo install without --locked" "cargo +nightly-2026-01-01 install cargo-fuzz"
install_case "a pinned install under a numbered toolchain passes" 0 "OK: every action" "cargo +1.98.0 install --locked cargo-audit@0.22.2"
install_case "an unversioned install after cargo's own --locked is refused" 1 "no exact version for cargo-audit" "cargo --locked install cargo-audit"
install_case "a pinned install after cargo's own --locked passes" 0 "OK: every action" "cargo --locked install cargo-audit@0.22.2"
install_case "an install after a short flag is refused" 1 "cargo install without --locked" "cargo -q install cargo-audit"
install_case "an install after a flag with a value is refused" 1 "cargo install without --locked" "cargo --color always install cargo-audit"
install_case "the value of a flag before the subcommand is not read as a crate" 0 "OK: every action" "cargo --color always install --locked cargo-audit@0.22.2"
install_case "an install after a toolchain and a flag is refused" 1 "no exact version for cargo-fuzz" "cargo +nightly -q --locked install cargo-fuzz"
install_case "an install after a flag with a double-quoted value is refused" 1 "cargo install without --locked" 'cargo --config "net.retry = 3" install cargo-audit'
install_case "an install after a flag with a single-quoted value is refused" 1 "cargo install without --locked" "cargo --config 'net.retry = 3' install cargo-audit"
install_case "an install after a flag with a quoted value joined by an equals sign is refused" 1 "cargo install without --locked" 'cargo --config="net.retry = 3" install cargo-audit'
install_case "a quoted value of a flag before the subcommand is not read as a crate" 0 "OK: every action" 'cargo --config "net.retry = 3" install --locked cargo-audit@0.22.2'
install_case "an external subcommand named install is not an install" 0 "OK: every action" "cargo install --locked cargo-xtask@1.0.0 && cargo --locked xtask install"
# Every install on a line is read, not the last one alone.
install_case "the first of two installs on a line is read" 1 "no exact version for cargo-audit" "cargo install cargo-audit && cargo install --locked cargo-deny@0.20.2"
install_case "two pinned installs on a line pass" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 && cargo --locked install cargo-deny@0.20.2"
for operator in '&&' '||' ';' '|' '&'; do
  install_case "the second of two installs joined by $operator is read" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 $operator cargo install --locked cargo-deny"
done
install_case "pins written in a shell comment pin nothing" 1 "cargo install without --locked" "cargo install cargo-audit # --locked --version 0.22.2"
install_case "a comment after a pinned install is not read as a crate" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 # the audit tool"

# The value of a flag stands as a word of its own, or joined by an equals
# sign, and is not a crate.
for flag in --features -F --root --target --target-dir --profile -j --jobs --branch --tag --rev --bin --example; do
  install_case "the value word after $flag is not read as a crate" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 $flag value"
done
install_case "the value word after --config is not read as a crate" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 --config net.retry=3"
install_case "the value of a flag is one word and the crate after it is read" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 --features fix cargo-deny"
install_case "the value of a flag joined by an equals sign passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 --bin=audit"

# Honest spellings: a quoted crate, a quoted value with a space, an
# expression as the value of a flag, alone or joined, and a redirection of
# input, are read as what they are.
install_case "a crate in double quotes passes" 0 "OK: every action" 'cargo install --locked "cargo-audit@0.22.2"'
install_case "a crate in single quotes passes" 0 "OK: every action" "cargo install --locked 'cargo-audit@0.22.2'"
install_case "a crate in quotes is held to its version" 1 "no exact version for cargo-audit" 'cargo install --locked "cargo-audit"'
install_case "a quoted value with a space after the subcommand passes" 0 "OK: every action" 'cargo install --locked cargo-audit@0.22.2 --config "net.retry = 3"'
install_case "the value of a flag as an expression is text pasted into the script" 1 'line 5: an expression the runner pastes into the script before the shell reads it (${{ matrix.target }})' 'cargo install --locked cargo-audit@0.22.2 --target ${{ matrix.target }}'
install_case "the value of a flag from a variable passes" 0 "OK: every action" 'cargo install --locked cargo-audit@0.22.2 --target "$TARGET"'
install_case "the value of a flag from a variable joined by an equals sign passes" 0 "OK: every action" 'cargo install --locked cargo-audit@0.22.2 --target="$TARGET"'
install_case "the value of a flag as a quoted variable passes" 0 "OK: every action" 'cargo install --locked cargo-audit@0.22.2 --target "$TARGET"'
install_case "a redirection of input from a file passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 < /dev/null"
install_case "a redirection of input from a word passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 <<< yes"
install_case "a redirection of input before the command passes" 0 "OK: every action" "<input.txt cargo install --locked cargo-audit@0.22.2"
install_case "a duplicated input descriptor passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 2<&1"
install_case "a descriptor of two digits passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 10>install.log"
install_case "a descriptor named by a variable passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 {log}>install.log"

# The arguments of an install end where the shell ends the command: at an
# operator, and at the parenthesis or the backtick that closes a
# substitution or a subshell the install stands in. A substitution among
# the arguments ends nothing, and what stands in it is not an argument.
install_case "the arguments of an install end at a single ampersand" 1 "cargo install without --locked" "cargo install cargo-audit & cargo install --locked --version 0.20.2 cargo-deny"
install_case "two pinned installs joined by an ampersand pass" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 & cargo install --locked cargo-deny@0.20.2 & wait"
install_case "the arguments of an install end at a semicolon" 1 "cargo install without --locked" "cargo install cargo-audit; cargo install --locked --version 0.20.2 cargo-deny"
install_case "the arguments of an install end at a pipe" 1 "cargo install without --locked" "cargo install cargo-audit | cargo install --locked --version 0.20.2 cargo-deny"
install_case "the arguments of an install end at an or" 1 "cargo install without --locked" "cargo install cargo-audit || cargo install --locked --version 0.20.2 cargo-deny"
install_case "the arguments of an install end where its command substitution closes" 1 "cargo install without --locked" 'echo $(cargo install cargo-audit) --locked --version 0.22.2'
install_case "the arguments of an install end where its backtick substitution closes" 1 "cargo install without --locked" 'echo `cargo install cargo-audit` --locked --version 0.22.2'
install_case "pins in a later backtick substitution pin nothing" 1 "cargo install without --locked" 'echo `cargo install cargo-audit` `echo --locked --version 0.22.2`'
install_case "a pinned install in a command substitution passes" 0 "OK: every action" 'out=$(cargo install --locked cargo-audit@0.22.2)'
install_case "a pinned install in a backtick substitution passes" 0 "OK: every action" 'out=`cargo install --locked cargo-audit@0.22.2`'
install_case "a pinned install in a subshell passes" 0 "OK: every action" "( cargo install --locked cargo-audit@0.22.2 )"
install_case "a pinned install in a group passes" 0 "OK: every action" "{ cargo install --locked cargo-audit@0.22.2; } 2>&1 | tee log"
install_case "a crate after a command substitution among the arguments is read" 1 "no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 --root=$(pwd | tr a b) cargo-deny'
install_case "a crate after a backtick substitution among the arguments is read" 1 "no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 --root=`pwd` cargo-deny'
install_case "a crate after a substitution inside a substitution is read" 1 "no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 --root=$(dirname $(pwd)) cargo-deny'
install_case "pins inside a substitution among the arguments pin nothing" 1 "cargo install without --locked" 'cargo install cargo-audit@0.22.2 --root=$( echo --locked )'
# Quotes are read: an operator, a parenthesis, a backtick or a `>` inside
# one ends nothing, and a pin inside one is not a word of the install.
install_case "a parenthesis in quotes does not pair with the one that ends the install" 1 "cargo install without --locked" 'echo $(cargo install tool "(") --locked --version 1.2.3'
install_case "a backtick in quotes does not end the install" 1 "no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 --root '"'"'`'"'"' cargo-deny'
install_case "an escaped backtick does not end the install" 1 "no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 --root \` cargo-deny'
install_case "a quoted greater-than sign is not a redirection" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 --root '>' cargo-deny"
install_case "an escaped parenthesis does not end the install" 1 "no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 --root \) cargo-deny'
install_case "a pin inside a quoted value is not a pin" 1 "cargo install without --locked" "cargo install cargo-audit@0.22.2 --config='a --locked --b'"
install_case "an operator inside a quoted value ends nothing" 0 "OK: every action" "cargo install cargo-audit@0.22.2 --features='a;b' --locked"

# A redirection of output is not an operator that ends the arguments, and
# neither its file descriptor nor its target is a crate or a pin.
for redirect in '2>&1 | tee install.log' '>&2' '&>install.log' '>install.log' '> /dev/null' '>>install.log' '>|install.log' '2>errors.log' '&>>install.log' '2>&-'; do
  install_case "a pinned install with the redirection $redirect passes" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2 $redirect"
done
install_case "a --version pin before a redirection and a pipe passes" 0 "OK: every action" "cargo install --locked --version 1.0.0 foo 2>&1 | tee log"
install_case "a version that a redirection follows without a space is read whole" 0 "OK: every action" "cargo install --locked cargo-audit@0.22.2>install.log"
install_case "a crate after a redirection is read" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 >install.log cargo-deny"
install_case "the target of a redirection is not a pin" 1 "cargo install without --locked" "cargo install cargo-audit@0.22.2 > --locked"
install_case "a pin after a redirection of both streams is read" 0 "OK: every action" "cargo install cargo-audit@0.22.2 &>install.log --locked"
install_case "a pin after one stream is sent to the other is read" 0 "OK: every action" "cargo install cargo-audit@0.22.2 2>&1 --locked"
install_case "an install after a redirection and an ampersand is read" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 &>install.log & cargo install --locked cargo-deny"
install_case "a crate after a redirection that overwrites is read" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 >| install.log cargo-deny"
for operator in ';' '&' '|'; do
  install_case "the target of a redirection stops at $operator" 1 "cargo install without --locked" "cargo install cargo-audit >install.log$operator echo --locked --version 0.22.2"
done
for close in ']' '(' '<' '>'; do
  install_case "the target of a redirection is one word before $close" 1 "no exact version for cargo-deny" "cargo install --locked cargo-audit@0.22.2 >log'$close' cargo-deny"
done
install_case "the target of a redirection stops where its command substitution closes" 1 "cargo install without --locked" 'echo $(cargo install cargo-audit 2>&1) --locked --version 0.22.2'
install_case "the target of a redirection stops where its backtick substitution closes" 1 "cargo install without --locked" 'echo `cargo install cargo-audit 2>/dev/null` --locked --version 0.22.2'
