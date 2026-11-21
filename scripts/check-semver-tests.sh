#!/usr/bin/env bash
# axess: crafted cases for scripts/check-semver.sh and the inventory it runs
# (scripts/lib/semver_inventory.py).
#
# The check runs `cargo semver-checks`, which builds the workspace twice; here
# a stand-in cargo, first on PATH, answers instead: `semver-checks --version`
# with the version a case names, `metadata` with a canned package list, and
# `check-release` with a canned report and exit status, recording every
# command line it is given. The check and the inventory are copied into a
# throwaway git repository (a crate at the release tag v0.19.0, a crate new
# since, the workflow line that pins the tool, the migration page a case
# writes), so the script reads that repository as its own. The reports are
# the text cargo-semver-checks 0.51.0 writes; scripts/lib/semver_inventory_tests.py
# says where in the tool's source each line was read.
#
# Usage: ./scripts/check-semver-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-semver.XXXXXX")"
# The path the script computes for itself, so that the manifest paths below
# start with it (a TMPDIR ending in a slash would double it).
WORK="$(cd "$WORK" && pwd)"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE SEMVER_PAGE

passed=0
failed=0

# The inventory's own cases first: what it reads and what it refuses.
unit_out="$(python3 -I -B "$SCRIPT_DIR/lib/semver_inventory_tests.py" 2>"$WORK/stderr")"
judge "the inventory's unit cases" 0 "0 failed" "$?" "$unit_out"

REPO="$WORK/repo"
mkdir -p "$REPO/scripts/lib" "$REPO/.github/workflows" "$REPO/axess-core" "$REPO/docs/production/migrating"
git init -q -b main "$REPO"
git -C "$REPO" config user.name cases
git -C "$REPO" config user.email cases@example.org
git -C "$REPO" config commit.gpgsign false
git -C "$REPO" config tag.gpgsign false
cp "$SCRIPT_DIR/check-semver.sh" "$REPO/scripts/check-semver.sh"
cp "$SCRIPT_DIR/lib/semver_inventory.py" "$REPO/scripts/lib/semver_inventory.py"
printf 'jobs:\n  semver:\n    steps:\n      - run: cargo install cargo-semver-checks@0.51.0 --locked\n' > "$REPO/.github/workflows/ci.yml"
printf '[package]\nname = "axess-core"\n' > "$REPO/axess-core/Cargo.toml"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "the release"
git -C "$REPO" tag v0.19.0
mkdir -p "$REPO/axess-new"
printf '[package]\nname = "axess-new"\n' > "$REPO/axess-new/Cargo.toml"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "a crate"
PAGE="$REPO/docs/production/migrating/0.19.0-to-0.20.0.md"

export STUB_LOG="$WORK/argv.log" STUB_REPORT="$WORK/report.txt"
export STUB_METADATA
STUB_METADATA="$(printf '{"packages":[{"name":"axess-core","version":"0.20.0","publish":null,"manifest_path":"%s/axess-core/Cargo.toml"},{"name":"axess-new","version":"0.20.0","publish":null,"manifest_path":"%s/axess-new/Cargo.toml"},{"name":"axess-bench","version":"0.20.0","publish":[],"manifest_path":"%s/bench/Cargo.toml"}]}' "$REPO" "$REPO" "$REPO")"
mkdir -p "$WORK/bin"
cat > "$WORK/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
case "$1 $2" in
  "semver-checks --version") echo "cargo-semver-checks ${STUB_VERSION:-0.51.0}" ;;
  "metadata --no-deps") printf '%s\n' "$STUB_METADATA" ;;
  "semver-checks check-release") cat "$STUB_REPORT"; exit "${STUB_STATUS:-0}" ;;
  *) echo "stand-in cargo: not a command the check runs: $*" >&2; exit 99 ;;
esac
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$WORK/bin/cargo-semver-checks"
chmod +x "$WORK/bin/cargo" "$WORK/bin/cargo-semver-checks"
PATH="$WORK/bin:$PATH"

CHECKING='    Checking axess-core v0.19.0 -> v0.20.0 (minor change)'
FAILED='     Checked [   0.120s] 200 checks: 199 pass, 1 fail, 0 warn, 54 skip'
CLEAN='     Checked [   0.120s] 200 checks: 200 pass, 54 skip
     Summary no semver update required'
FUNCTION_MISSING='
--- failure function_missing: pub fn removed or renamed ---

Description:
A publicly-visible function cannot be imported by its prior path. A `pub use` may have been removed, or the function itself may have been renamed or removed entirely.
        ref: https://doc.rust-lang.org/cargo/reference/semver.html#item-remove
       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.51.0/src/lints/function_missing.ron

Failed in:
  function axess_core::session::rotate_id, previously in file /w/axess-core/src/session.rs:42'
METHOD_MISSING='
--- failure inherent_method_missing: pub method removed or renamed ---

Description:
A publicly-visible method or associated fn is no longer available under its prior name. It may have been renamed or removed entirely.
        ref: https://doc.rust-lang.org/cargo/reference/semver.html#item-remove
       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.51.0/src/lints/inherent_method_missing.ron

Failed in:
  SessionStore::load, previously in file /w/axess-core/src/store.rs:7
  SessionStore::save, previously in file /w/axess-core/src/store.rs:9'
REORDERED='
--- warning partial_ord_enum_struct_variant_fields_reordered: struct variant fields reordered in #[derive(PartialOrd)] enum ---

Description:
A public enum that derives PartialOrd had fields reordered within a struct variant.
        ref: https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable
       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.51.0/src/lints/partial_ord_enum_struct_variant_fields_reordered.ron

Failed in:
  Event::Login.at moved from position 1 to 2, in /w/axess-core/src/event.rs:8'
summary() { printf '\n     Summary semver requires new major version: %s major and 0 minor checks failed' "$1"; }

# run NAME WANTED_EXIT FRAGMENT STATUS REPORT PAGE [UNWANTED]: the check on
# the throwaway repository, the stand-in answering with REPORT and STATUS;
# PAGE is the migration page's text, or "-" for no page.
run() {
  local name="$1" want="$2" fragment="$3" status="$4" report="$5" page="$6" unwanted="${7:-}"
  printf '%s\n' "$report" > "$STUB_REPORT"
  rm -f "$PAGE"
  [ "$page" = "-" ] || printf '%s\n' "$page" > "$PAGE"
  : > "$STUB_LOG"
  local out code
  out="$(cd "$WORK" && STUB_STATUS="$status" "$REPO/scripts/check-semver.sh" 2>"$WORK/stderr")"
  code=$?
  judge "$name" "$want" "$fragment" "$code" "$out" "$unwanted"
}

ONE="$CHECKING
$FAILED
$FUNCTION_MISSING
$(summary 1)"
NAMED='# Migrating from 0.19.0 to 0.20.0

### Compile breaks

- `axess_core::session::rotate_id` is gone: call `Session::rotate`.'

run "a break named on the page passes" 0 "OK: 1 breaks in 1 crates, each named on docs/production/migrating/0.19.0-to-0.20.0.md" 1 "$ONE" "$NAMED"
run "a break named by its last two segments passes" 0 "OK: 1 breaks" 1 "$ONE" 'The free function `session::rotate_id()` is gone.'
run "a break the page does not name fails and names crate, lint and item" 1 \
  "axess-core: failure function_missing: axess_core::session::rotate_id" 1 "$ONE" '# Migrating

Nothing to do.'
run "a name inside a fenced code block does not count" 1 "axess_core::session::rotate_id" 1 "$ONE" '```rust
// was `axess_core::session::rotate_id`
Session::rotate();
```'
run "a break with no migration page fails and says the page is missing" 1 "0.19.0-to-0.20.0.md, which does not exist" 1 "$ONE" -
run "a clean report passes" 0 "OK: cargo-semver-checks reports no break." 0 "$CHECKING
$CLEAN" -
TWO="$CHECKING
     Checked [   0.120s] 200 checks: 198 pass, 2 fail, 1 warn, 54 skip
$FUNCTION_MISSING
$METHOD_MISSING
$REORDERED
$(summary 2)
     Warning produced 1 major and 0 minor level warnings"
run "every place of every block is held to the page" 1 "SessionStore::save" 1 "$TWO" "$NAMED
- \`SessionStore::load\` takes a key.
- \`Login::at\` moved." "SessionStore::load ("
run "a warning block is held to the page as well" 1 "axess-core: warning partial_ord_enum_struct_variant_fields_reordered: Event::Login.at" 1 "$TWO" "$NAMED
- \`SessionStore::load\` and \`SessionStore::save\` take a key."
run "a failure header over a body the reader cannot parse is refused with exit 2" 2 \
  "no place under a \`Failed in:\` line" 1 "$CHECKING
$FAILED

--- failure function_missing: pub fn removed or renamed ---

the body of a format this reader does not know
$(summary 1)" "$NAMED"
run "a summary counting more failures than blocks is refused with exit 2" 2 "1 failure blocks, and its Summary counts 2" 1 "$CHECKING
$FAILED
$FUNCTION_MISSING
$(summary 2)" "$NAMED"
run "a failing run whose report names no crate is refused with exit 2" 2 "exited 1 and its report is not read: the report holds no Checking line" 1 \
  "error: failed to build rustdoc for crate axess-core v0.19.0" "$NAMED"
run "a failing run with a clean report is refused with exit 2" 2 "exited 101 and the report names no failure" 101 "$CHECKING
$CLEAN" "$NAMED"
run "an empty report is refused with exit 2" 2 "the report holds no Checking line" 0 "" "$NAMED"

# The tool is asked for a minor release against the tag, for the crates the
# tag holds, and with the pinned version only.
run "the tool is run with --release-type minor" 0 "OK: 1 breaks" 1 "$ONE" "$NAMED"
if grep -qxF "semver-checks check-release -p axess-core --baseline-rev v0.19.0 --release-type minor" "$STUB_LOG"; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: the check-release command line: wanted the crate at the tag, the tag as baseline and --release-type minor, got:" >&2
  sed 's/^/    /' "$STUB_LOG" >&2
fi
run "a crate new since the baseline is named and skipped" 0 "note: axess-new is new since v0.19.0 and has no semver baseline; skipped" 0 "$CHECKING
$CLEAN" -
out="$(cd "$WORK" && STUB_VERSION=0.50.0 "$REPO/scripts/check-semver.sh" 2>"$WORK/stderr")"
judge "another installed version of the tool is refused" 1 "'cargo-semver-checks 0.50.0' is installed" "$?" "$out"
printf '%s\n' "$ONE" > "$STUB_REPORT"
printf 'x\n' > "$WORK/other-page.md"
out="$(cd "$WORK" && STUB_STATUS=1 SEMVER_PAGE="$WORK/other-page.md" "$REPO/scripts/check-semver.sh" 2>"$WORK/stderr")"
judge "SEMVER_PAGE names the page" 1 "not named on $WORK/other-page.md" "$?" "$out"

# The refusals before the tool runs.
out="$(cd "$WORK" && "$REPO/scripts/check-semver.sh" v9.9.9 2>"$WORK/stderr")"
judge "a baseline that is not a commit is refused" 1 "semver baseline 'v9.9.9' is not a commit" "$?" "$out"
git -C "$REPO" tag -d v0.19.0 >/dev/null
out="$(cd "$WORK" && "$REPO/scripts/check-semver.sh" 2>"$WORK/stderr")"
judge "no release tag below HEAD is refused" 1 "no release tag v* is an ancestor of HEAD" "$?" "$out"
git -C "$REPO" tag v0.19.0 HEAD~1
mkdir -p "$WORK/bin-notool"
ln -s "$WORK/bin/cargo" "$WORK/bin-notool/cargo"
for tool in git jq python3 grep sort head mktemp tee rm cat dirname; do
  ln -s "$(command -v "$tool")" "$WORK/bin-notool/$tool"
done
out="$(cd "$WORK" && PATH="$WORK/bin-notool:/bin" "$REPO/scripts/check-semver.sh" 2>"$WORK/stderr")"
judge "a missing cargo-semver-checks is refused" 1 "cargo-semver-checks not installed (cargo install cargo-semver-checks@0.51.0 --locked)" "$?" "$out"

echo "check-semver crafted cases: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
