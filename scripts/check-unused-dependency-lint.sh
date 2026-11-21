#!/usr/bin/env bash
# axess: cargo's unused-dependency lint fires where the gates rely on it.
#
# The workspace's lint table denies `unused_dependencies`
# ([workspace.lints.cargo] in Cargo.toml), and every member takes the table
# (scripts/check-member-lints.sh). The lint reports a normal or build
# dependency that no target of the selected build uses, with one exemption:
# a crate another dependency of the build also pulls in is never reported.
# It is silent in a build of the library alone (`--lib`), and an older
# cargo ignores the table with a warning. So a manifest that only says
# "deny" proves nothing; this runs it.
#
# The probe: a copy of the files git lists (tracked, and untracked but not
# ignored) in a temporary folder, in which PROBE_MEMBER (a member with no
# normal dependency of its own) declares PROBE_CRATE, a crate that is not in
# Cargo.lock's tree, so the exemption cannot hide it. In that copy each
# invocation below that the gates rely on (the shape of the workspace clippy
# step of CI and the release preflight, with the default and with every
# feature, and an all-targets check) must exit non-zero with an error that
# names the probe crate as unused. The same invocation on the copy without
# the probe crate must exit zero, so that a failure of another cause is not
# read as the lint. What counts as the lint refusing is decided in
# scripts/lib/unused_dependency_lint.sh: cargo's own error for the probe
# crate, at its line of the probe member's manifest, with the lint table
# named as the reason, read with any colour codes removed (CI sets
# CARGO_TERM_COLOR=always); scripts/check-unused-dependency-lint-tests.sh
# holds it to crafted logs. The `--lib` build is run and printed, to show
# where the lint is silent; it is not judged.
#
# The copy's lock file takes the probe crate from the local registry cache
# when it is there, and from the registry otherwise (a fresh CI runner).
# Builds go to $CARGO_TARGET_DIR/unused-dependency-probe
# (default target/), a folder of their own, because the copy is a workspace
# at another path.
#
# Usage: ./scripts/check-unused-dependency-lint.sh

set -uo pipefail

PROBE_MEMBER=axess-rng
PROBE_CRATE=humantime
PROBE_REQ="=2.3.0"

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ $# -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
# shellcheck source=lib/unused_dependency_lint.sh
. "$AXESS_DIR/scripts/lib/unused_dependency_lint.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-unused-lint.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT
TARGET="${CARGO_TARGET_DIR:-$AXESS_DIR/target}/unused-dependency-probe"
COPY="$WORK/tree"

# The files git lists as they stand in the working tree, the tracked ones
# and the untracked ones it does not ignore, so an uncommitted manifest
# change, or a member not yet added, is what is probed. NUL-separated on
# both sides, so no path is split.
mkdir -p "$COPY"
# Through an archive file, not a pipe: a reading tar stops at the first
# end-of-archive marker, and the writing one would die on what is left.
(cd "$AXESS_DIR" && git ls-files --cached --others --exclude-standard --deduplicate -z > "$WORK/listed" \
    && tar -cf "$WORK/listed.tar" --null -T "$WORK/listed") \
  && tar -xf "$WORK/listed.tar" -C "$COPY" && rm -f "$WORK/listed.tar" || {
  echo "ERROR: the files git lists could not be copied." >&2
  exit 1
}

if grep -qx "name = \"$PROBE_CRATE\"" "$COPY/Cargo.lock"; then
  echo "ERROR: $PROBE_CRATE is in Cargo.lock; a crate in the tree is exempt from the lint, so it proves nothing. Choose another probe crate." >&2
  exit 1
fi
if grep -qE '^\[(dependencies|build-dependencies)\]' "$COPY/$PROBE_MEMBER/Cargo.toml"; then
  echo "ERROR: $PROBE_MEMBER now has a [dependencies] table; choose a member without one, or add the probe crate to it." >&2
  exit 1
fi

# The invocations: "<name>|<required or shown>|<what it runs>", and `run_one`
# runs the one named.
INVOCATIONS="clippy-default|required|cargo clippy -p $PROBE_MEMBER --all-targets -- -D warnings
clippy-all-features|required|cargo clippy -p $PROBE_MEMBER --all-targets --all-features -- -D warnings
check-all-targets|required|cargo check -p $PROBE_MEMBER --all-targets
check-lib|shown|cargo check -p $PROBE_MEMBER --lib"

run_one() {
  case "$1" in
    clippy-default) cargo clippy -p "$PROBE_MEMBER" --all-targets -- -D warnings ;;
    clippy-all-features) cargo clippy -p "$PROBE_MEMBER" --all-targets --all-features -- -D warnings ;;
    check-all-targets) cargo check -p "$PROBE_MEMBER" --all-targets ;;
    check-lib) cargo check -p "$PROBE_MEMBER" --lib ;;
    *) echo "no invocation named $1" >&2; return 2 ;;
  esac
}

run_all() {
  local side="$1" name kind shown
  while IFS='|' read -r name kind shown; do
    (cd "$COPY" && CARGO_TARGET_DIR="$TARGET" run_one "$name") > "$WORK/$side-$name.log" 2>&1
    echo "$?" > "$WORK/$side-$name.rc"
  done <<< "$INVOCATIONS"
}

# Without the probe crate first, then with it, in the same copy.
run_all control
printf '\n[dependencies]\n%s = "%s"\n' "$PROBE_CRATE" "$PROBE_REQ" >> "$COPY/$PROBE_MEMBER/Cargo.toml"
if ! (cd "$COPY" && cargo metadata --offline --format-version 1 > /dev/null 2> "$WORK/metadata.err") \
   && ! (cd "$COPY" && cargo metadata --format-version 1 > /dev/null 2> "$WORK/metadata.err"); then
  echo "ERROR: the probe crate $PROBE_CRATE $PROBE_REQ cannot be resolved from the registry cache or the registry:" >&2
  sed 's/^/    /' "$WORK/metadata.err" >&2
  exit 1
fi
run_all probe

failed=0
while IFS='|' read -r name kind shown; do
  control_rc=$(cat "$WORK/control-$name.rc")
  probe_rc=$(cat "$WORK/probe-$name.rc")
  plain=$(uncoloured "$WORK/probe-$name.log")
  message=$(grep -m 1 -iE 'unused dependenc' <<<"$plain")
  located=$(grep -m 1 -E "^[[:space:]]*[0-9]+ \| $PROBE_CRATE = " <<<"$plain")
  fires=no
  unused_dependency_lint_fires "$PROBE_CRATE" "$PROBE_MEMBER" "$probe_rc" "$WORK/probe-$name.log" && fires=yes
  printf '%-22s control exit %s, probe exit %s, lint %s (%s)\n' \
    "$name" "$control_rc" "$probe_rc" "$([ "$fires" = yes ] && echo FIRES || echo silent)" "$shown"
  [ -n "$message" ] && printf '    %s\n    %s\n' "$message" "$located"
  [ "$kind" = required ] || continue
  if [ "$control_rc" -ne 0 ]; then
    echo "REFUSED: $name fails without the probe crate (exit $control_rc); the lint is not what is measured:" >&2
    tail -n 20 "$WORK/control-$name.log" | sed 's/^/    /' >&2
    failed=1
  elif [ "$fires" != yes ]; then
    echo "REFUSED: $name does not refuse the unused dependency $PROBE_CRATE:" >&2
    tail -n 20 "$WORK/probe-$name.log" | sed 's/^/    /' >&2
    failed=1
  fi
done <<< "$INVOCATIONS"

if grep -l "unused manifest key" "$WORK"/probe-*.log > /dev/null 2>&1; then
  echo "REFUSED: this cargo ignores a manifest key (unused manifest key); it does not run the lint table:" >&2
  grep -h "unused manifest key" "$WORK"/probe-*.log | sort -u | sed 's/^/    /' >&2
  failed=1
fi
if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "OK: the unused-dependency lint refuses $PROBE_CRATE in $PROBE_MEMBER under every invocation the gates rely on."
