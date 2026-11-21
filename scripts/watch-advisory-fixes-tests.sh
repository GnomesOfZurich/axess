#!/usr/bin/env bash
# axess: crafted cases for scripts/watch-advisory-fixes.sh.
#
# Each case records the two answers the watch reads from crates.io (the
# dependent's newest stable version, and that version's dependencies) under
# a temporary directory, runs the watch against it with `--answers` and
# asserts the exit status and a fragment of the output. The contract: a
# requirement that stays below the fixed release is `hit=false`, one that
# admits it is `hit=true`, and an answer or a requirement the watch cannot
# read is a failure by name, never a silent "no change".
#
# Nothing here reaches the network, so what the cases prove is the reading
# of an answer, not that crates.io gives answers of that shape.
#
# Usage: ./scripts/watch-advisory-fixes-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-advisory-watch.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

passed=0
failed=0

# record DEPENDENT VERSION DEPENDENCIES_JSON: the two answers for one crate.
record() {
  mkdir -p "$WORK/answers/crates/$1/$2"
  printf '{"crate":{"max_stable_version":"%s"}}\n' "$2" >"$WORK/answers/crates/$1.json"
  printf '{"dependencies":%s}\n' "$3" >"$WORK/answers/crates/$1/$2/dependencies.json"
}

# dep CRATE REQ [KIND [FEATURE]]: one entry of a dependencies answer.
dep() {
  printf '{"crate_id":"%s","req":"%s","kind":"%s","optional":true,"features":[%s]}' \
    "$1" "$2" "${3:-normal}" "${4:+\"$4\"}"
}

# case_ NAME WATCH EXPECTED_EXIT FRAGMENT
case_() {
  local name="$1" watch="$2" want="$3" fragment="$4" out status
  out="$("$SCRIPT_DIR/watch-advisory-fixes.sh" "$watch" --answers "$WORK/answers" --output "$WORK/discarded" 2>&1)"
  status=$?
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" <<<"$out"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
  rm -rf "$WORK/answers"
}

OTHER="$(dep serde '^1.0')"

# ── The four watches as they stand, and as they end ───────────────
record jsonwebtoken 11.1.0 "[$OTHER,$(dep rsa '^0.9.6'),$(dep p256 '^0.13.2')]"
case_ "jsonwebtoken on rsa 0.9 is still waiting" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.1.0 "[$OTHER,$(dep rsa '^0.9.6')]"
case_ "the summary says what is required and what it stays below" jsonwebtoken-rsa 0 \
  'summary=RUSTSEC-2023-0071: jsonwebtoken 11.1.0 requires rsa `^0.9.6`, which stays below 0.10.0.'
record jsonwebtoken 12.0.0 "[$OTHER,$(dep rsa '^0.10.0')]"
case_ "jsonwebtoken on rsa 0.10 is a hit" jsonwebtoken-rsa 0 "hit=true"
record jsonwebtoken 12.0.0 "[$OTHER,$(dep rsa '^0.10.0')]"
case_ "a hit says what the fix gives" jsonwebtoken-rsa 0 \
  'requires rsa `^0.10.0`, which admits 0.10.0: RS256 under `jwt-rust-crypto` signs through the patched rsa.'
record jsonwebtoken 12.0.0 "[$OTHER]"
case_ "a dependency that is gone is a hit" jsonwebtoken-rsa 0 \
  "summary=RUSTSEC-2023-0071: jsonwebtoken 12.0.0 no longer depends on rsa."

record openidconnect 4.1.0 "[$OTHER,$(dep rsa '^0.9.2')]"
case_ "openidconnect on rsa 0.9 is still waiting" openidconnect-rsa 0 "hit=false"
record openidconnect 4.2.0 "[$OTHER,$(dep rsa '0.10')]"
case_ "a bare requirement is a caret" openidconnect-rsa 0 "hit=true"

# crypto-glue's range admits rsa 0.10.0, and cargo still cannot select it:
# the requirement asks for a feature that release dropped.
record crypto-glue 0.2.2 "[$OTHER,$(dep rsa '^0.10.0-rc.18' normal sha2)]"
case_ "a requirement that asks for a feature the fix dropped is still waiting" crypto-glue-rsa 0 \
  'summary=RUSTSEC-2023-0071: crypto-glue 0.2.2 requires rsa `^0.10.0-rc.18` with the feature `sha2`, which rsa 0.10.0 does not have.'
record crypto-glue 0.2.3 "[$OTHER,$(dep rsa '^0.10.0')]"
case_ "the same requirement without the feature is a hit" crypto-glue-rsa 0 "hit=true"
record crypto-glue 0.2.3 "[$OTHER,$(dep rsa '^0.10.0' normal pkcs5)]"
case_ "a feature the fixed release has does not hold the watch" crypto-glue-rsa 0 "hit=true"
record crypto-glue 0.2.3 "[$OTHER,$(dep rsa '^0.9' normal sha2)]"
case_ "a requirement below the fix is named for its range first" crypto-glue-rsa 0 "which stays below 0.10.0."
record jsonwebtoken 12.0.0 "[$OTHER,$(dep rsa '^0.10.0' normal sha2)]"
case_ "a watch that names no dropped feature does not look at features" jsonwebtoken-rsa 0 "hit=true"

record jsonwebtoken 11.1.0 "[$OTHER,$(dep rsa '^0.10.0'),$(dep p256 '^0.13.2')]"
case_ "each watch reads its own dependency" jsonwebtoken-p256 0 "hit=false"
record jsonwebtoken 12.0.0 "[$OTHER,$(dep p256 '^0.14')]"
case_ "jsonwebtoken on p256 0.14 is a hit" jsonwebtoken-p256 0 "hit=true"
record jsonwebtoken 12.0.0 "[$OTHER,$(dep p256 '^0.15.1')]"
case_ "a release line past the fixed one is a hit" jsonwebtoken-p256 0 "hit=true"
# crypto-bigint 0.5 comes through both curves, and each has a watch.
record jsonwebtoken 12.0.0 "[$OTHER,$(dep p256 '^0.14'),$(dep p384 '^0.13.0')]"
case_ "jsonwebtoken on p384 0.13 is still waiting when its p256 has moved" jsonwebtoken-p384 0 \
  'summary=RUSTSEC-2026-0387: jsonwebtoken 12.0.0 requires p384 `^0.13.0`, which stays below 0.14.0.'
record jsonwebtoken 12.0.0 "[$OTHER,$(dep p256 '^0.14'),$(dep p384 '^0.13.0')]"
case_ "the p256 hit says the other curve has to move too" jsonwebtoken-p256 0 \
  'crypto-bigint 0.5 leaves the tree when `jsonwebtoken-p384` is a hit too.'
record jsonwebtoken 12.0.0 "[$OTHER,$(dep p256 '^0.14'),$(dep p384 '^0.14')]"
case_ "jsonwebtoken on p384 0.14 is a hit" jsonwebtoken-p384 0 "hit=true"

record sqlx-sqlite 0.9.0 "[$OTHER,$(dep libsqlite3-sys '>=0.30.1, <0.38.0')]"
case_ "sqlx-sqlite below libsqlite3-sys 0.38 is still waiting" sqlx-sqlite-libsqlite3-sys 0 \
  'requires libsqlite3-sys `>=0.30.1, <0.38.0`, which stays below 0.39.0.'
record sqlx-sqlite 0.9.1 "[$OTHER,$(dep libsqlite3-sys '>=0.30.1, <0.39.0')]"
case_ "a range that ends at the fixed release does not admit it" sqlx-sqlite-libsqlite3-sys 0 "hit=false"
record sqlx-sqlite 0.9.1 "[$OTHER,$(dep libsqlite3-sys '>=0.30.1, <0.40.0')]"
case_ "a range that holds the fixed release is a hit" sqlx-sqlite-libsqlite3-sys 0 "hit=true"
record sqlx-sqlite 0.10.0 "[$OTHER,$(dep libsqlite3-sys '>=0.39')]"
case_ "a range with no end is a hit" sqlx-sqlite-libsqlite3-sys 0 "hit=true"

# ── How a requirement is read ─────────────────────────────────────
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '~0.9.6')]"
case_ "a tilde stays in its minor" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '=0.9.10')]"
case_ "an exact version is that version" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '0.9.*')]"
case_ "a wildcard stays in what it names" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '*')]"
case_ "a bare wildcard admits everything" jsonwebtoken-rsa 0 "hit=true"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '>0.9')]"
case_ "above a minor starts at the next" jsonwebtoken-rsa 0 "hit=true"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '<=0.9')]"
case_ "up to a minor ends with it" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '^0.10.0-rc.18')]"
case_ "a pre-release requirement admits its release" jsonwebtoken-rsa 0 "hit=true"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '=0.10.0-rc.19')]"
case_ "an exact pre-release admits no release" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '<=0.10.0-rc.19')]"
case_ "up to a pre-release stops before its release" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '>0.10.0-rc.19')]"
case_ "above a pre-release admits its release" jsonwebtoken-rsa 0 "hit=true"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '>=0.9.0, <0.10.0-rc.5')]"
case_ "below a pre-release stops before its release" jsonwebtoken-rsa 0 "hit=false"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '^0.10-rc.1')]"
case_ "a pre-release on a partial version cannot be read" jsonwebtoken-rsa 1 "cannot read requirement part '^0.10-rc.1'"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '^0.9.6' dev),$(dep rsa '^0.10.0' build)]"
case_ "only a normal dependency counts" jsonwebtoken-rsa 0 "no longer depends on rsa"
record jsonwebtoken 11.2.0 "[$OTHER,$(dep rsa '^0.9.6'),$(dep rsa '^0.10.0')]"
case_ "two requirements wait while one stays below" jsonwebtoken-rsa 0 \
  'requires rsa `^0.10.0` and `^0.9.6`, which stays below 0.10.0.'

# ── A run that could not see is a red run ─────────────────────────
mkdir -p "$WORK/answers"
case_ "a missing answer fails" jsonwebtoken-rsa 1 "no answer for crates/jsonwebtoken"
mkdir -p "$WORK/answers/crates"; echo '<html>' >"$WORK/answers/crates/jsonwebtoken.json"
case_ "an answer that is not JSON fails" jsonwebtoken-rsa 1 "no answer for crates/jsonwebtoken"
mkdir -p "$WORK/answers/crates"; echo '{"crate":{}}' >"$WORK/answers/crates/jsonwebtoken.json"
case_ "an answer without a stable version fails" jsonwebtoken-rsa 1 "no stable jsonwebtoken version in the answer"
record jsonwebtoken 11.1.0 "[]"
case_ "an empty dependency list fails" jsonwebtoken-rsa 1 "empty dependency list in the answer for jsonwebtoken 11.1.0"
record jsonwebtoken 11.1.0 "[$OTHER,$(dep rsa 'latest')]"
case_ "a requirement that cannot be read fails" jsonwebtoken-rsa 1 "cannot read requirement part 'latest'"
record jsonwebtoken 11.1.0 "[$OTHER,$(dep rsa '>=0.10, <0.9')]"
case_ "a requirement that admits nothing fails" jsonwebtoken-rsa 1 "admits no version"
mkdir -p "$WORK/answers/crates"; echo '[]' >"$WORK/answers/crates/jsonwebtoken.json"
case_ "an answer that is a JSON list fails" jsonwebtoken-rsa 1 "no answer for crates/jsonwebtoken: the body is not a JSON object"
mkdir -p "$WORK/answers/crates"; echo '{"crate":"jsonwebtoken"}' >"$WORK/answers/crates/jsonwebtoken.json"
case_ "a crate that is no object fails" jsonwebtoken-rsa 1 "no stable jsonwebtoken version in the answer"
mkdir -p "$WORK/answers/crates"; echo '{"crate":{"max_stable_version":11}}' >"$WORK/answers/crates/jsonwebtoken.json"
case_ "a version that is no string fails" jsonwebtoken-rsa 1 "no stable jsonwebtoken version in the answer"
record jsonwebtoken 11.1.0 '{"rsa":"^0.9.6"}'
case_ "dependencies that are no list fail" jsonwebtoken-rsa 1 "empty dependency list in the answer for jsonwebtoken 11.1.0"
record jsonwebtoken 11.1.0 "[$OTHER,\"rsa\"]"
case_ "a dependency that is no object fails" jsonwebtoken-rsa 1 "a dependency of jsonwebtoken 11.1.0 in the answer is not a JSON object"
record jsonwebtoken 11.1.0 "[$OTHER,{\"crate_id\":\"rsa\",\"kind\":\"normal\"}]"
case_ "a dependency without a requirement fails" jsonwebtoken-rsa 1 "a rsa dependency of jsonwebtoken 11.1.0 in the answer has no requirement"
record jsonwebtoken 11.1.0 "[$OTHER,{\"crate_id\":\"rsa\",\"kind\":\"normal\",\"req\":\"^0.10.0\",\"features\":\"sha2\"}]"
case_ "features that are no list fail" jsonwebtoken-rsa 1 "has features that are no list"
record jsonwebtoken 11.1.0 "[$OTHER,$(dep rsa '^0.9.6')]"
case_ "an unknown watch prints the usage" rsa 2 "usage: watch-advisory-fixes.sh jsonwebtoken-rsa|"

# ── Every watch at once ───────────────────────────────────────────
# all_ NAME EXPECTED_EXIT FRAGMENT HITS: run --all over the recorded answers
# and assert the `hits` output whole.
all_() {
  local name="$1" want="$2" fragment="$3" hits="$4" out status
  rm -f "$WORK/output"
  out="$("$SCRIPT_DIR/watch-advisory-fixes.sh" --all --answers "$WORK/answers" --output "$WORK/output" 2>&1)"
  status=$?
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" <<<"$out" \
     && [ "$(cat "$WORK/output")" = "hits=$hits" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment' and hits=$hits, got exit $status and $(cat "$WORK/output" 2>&1):" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
  rm -rf "$WORK/answers"
}
# record_all JSONWEBTOKEN_DEPS: every dependent, still waiting, but
# jsonwebtoken with the dependencies given.
record_all() {
  record jsonwebtoken 11.1.0 "$1"
  record openidconnect 4.1.0 "[$OTHER,$(dep rsa '^0.9.2')]"
  record crypto-glue 0.2.2 "[$OTHER,$(dep rsa '^0.10.0-rc.18' normal sha2)]"
  record sqlx-sqlite 0.9.0 "[$OTHER,$(dep libsqlite3-sys '>=0.30.1, <0.38.0')]"
}
record_all "[$OTHER,$(dep rsa '^0.9.6'),$(dep p256 '^0.13.2'),$(dep p384 '^0.13.0')]"
all_ "every watch waiting writes no hit" 0 "sqlx-sqlite-libsqlite3-sys: waiting: RUSTSEC-2026-0459" "[]"
record_all "[$OTHER,$(dep rsa '^0.10.0'),$(dep p256 '^0.13.2'),$(dep p384 '^0.13.0')]"
all_ "a hit is written with its watch and summary" 0 "jsonwebtoken-rsa: hit:" \
  '[{"watch":"jsonwebtoken-rsa","summary":"RUSTSEC-2023-0071: jsonwebtoken 11.1.0 requires rsa `^0.10.0`, which admits 0.10.0: RS256 under `jwt-rust-crypto` signs through the patched rsa."}]'
record_all "[$OTHER,$(dep rsa '^0.10.0'),$(dep p256 '^0.14'),$(dep p384 '^0.13.0')]"
all_ "two hits of one dependent are two entries" 0 "jsonwebtoken-p256: hit:" \
  '[{"watch":"jsonwebtoken-rsa","summary":"RUSTSEC-2023-0071: jsonwebtoken 11.1.0 requires rsa `^0.10.0`, which admits 0.10.0: RS256 under `jwt-rust-crypto` signs through the patched rsa."},{"watch":"jsonwebtoken-p256","summary":"RUSTSEC-2026-0387: jsonwebtoken 11.1.0 requires p256 `^0.14`, which admits 0.14.0: p256 0.14 is on crypto-bigint 0.7, patched from 0.7.6; crypto-bigint 0.5 leaves the tree when `jsonwebtoken-p384` is a hit too."}]'
# A failure of one watch that nothing foresaw: the answer for one dependent
# is JSON of another shape. The hit of another watch is still written.
record_all "[$OTHER,$(dep rsa '^0.9.6'),$(dep p256 '^0.13.2'),$(dep p384 '^0.13.0')]"
record sqlx-sqlite 0.10.0 "[$OTHER,$(dep libsqlite3-sys '>=0.39')]"
echo '[]' >"$WORK/answers/crates/openidconnect.json"
all_ "an answer of another shape fails its watch and the hits are still written" 1 \
  "watch-advisory-fixes: openidconnect-rsa: no answer for crates/openidconnect: the body is not a JSON object" \
  '[{"watch":"sqlx-sqlite-libsqlite3-sys","summary":"RUSTSEC-2026-0459: sqlx-sqlite 0.10.0 requires libsqlite3-sys `>=0.39`, which admits 0.39.0: the `sqlite` feature bundles SQLite 3.54.0 or later."}]'
record_all "[$OTHER,$(dep rsa '^0.9.6'),$(dep p256 '^0.13.2'),$(dep p384 '^0.13.0')]"
record sqlx-sqlite 0.10.0 "[$OTHER,$(dep libsqlite3-sys '>=0.39')]"
printf '{"dependencies":[%s,{"crate_id":"rsa","kind":"normal","req":["^0.9"]}]}\n' "$OTHER" >"$WORK/answers/crates/crypto-glue/0.2.2/dependencies.json"
all_ "a requirement that is no string fails its watch and the hits are still written" 1 \
  "watch-advisory-fixes: crypto-glue-rsa: a rsa dependency of crypto-glue 0.2.2 in the answer has no requirement" \
  '[{"watch":"sqlx-sqlite-libsqlite3-sys","summary":"RUSTSEC-2026-0459: sqlx-sqlite 0.10.0 requires libsqlite3-sys `>=0.39`, which admits 0.39.0: the `sqlite` feature bundles SQLite 3.54.0 or later."}]'
record_all "[$OTHER,$(dep rsa '^0.9.6'),$(dep p256 '^0.13.2'),$(dep p384 '^0.13.0')]"
record sqlx-sqlite 0.10.0 "[$OTHER,$(dep libsqlite3-sys '>=0.39')]"
rm -f "$WORK/answers/crates/openidconnect.json"
all_ "a watch that cannot read fails the run and the hits are still written" 1 \
  "watch-advisory-fixes: openidconnect-rsa: no answer for crates/openidconnect" \
  '[{"watch":"sqlx-sqlite-libsqlite3-sys","summary":"RUSTSEC-2026-0459: sqlx-sqlite 0.10.0 requires libsqlite3-sys `>=0.39`, which admits 0.39.0: the `sqlite` feature bundles SQLite 3.54.0 or later."}]'

# ── What a step of the workflow reads ─────────────────────────────
record jsonwebtoken 12.0.0 "[$OTHER,$(dep rsa '^0.10.0')]"
rm -f "$WORK/output"
"$SCRIPT_DIR/watch-advisory-fixes.sh" jsonwebtoken-rsa --answers "$WORK/answers" --output "$WORK/output" >/dev/null 2>&1
if [ "$(sed -n 1p "$WORK/output")" = "hit=true" ] && grep -q '^summary=RUSTSEC-2023-0071: ' "$WORK/output" \
   && [ "$(wc -l <"$WORK/output" | tr -d ' ')" = "2" ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: the step outputs are hit and a one-line summary:" >&2
  sed 's/^/    /' "$WORK/output" >&2
fi

# ── The step that opens the issues ────────────────────────────────
# Read out of the workflow and run as the runner runs a step that names no
# shell (`bash -e`), with a recorded `gh` first on the path: $GH_ISSUES is
# what `gh issue list` finds, and each call is appended to $GH_LOG. A small
# Python program hands the step to bash, with the variables the runner and
# the step's `env:` give it.
WORKFLOW="$SCRIPT_DIR/../.github/workflows/advisory-fix-watch.yml"
python3 -I -B - "$SCRIPT_DIR/lib" "$WORKFLOW" "$WORK" <<'PY' || { echo "FAIL: the issue step could not be read from $WORKFLOW" >&2; exit 1; }
import os, sys
sys.path.insert(0, sys.argv[1])
import workflow_yaml as yaml
doc = yaml.read(open(sys.argv[2], encoding="utf-8").read())
steps = [s for s in doc.get("jobs").get("issue").get("steps").items if s.get("run") is not None]
if len(steps) != 1 or steps[0].get("shell") is not None:
    sys.exit("expected one run step, naming no shell, in the issue job")
open(os.path.join(sys.argv[3], "issue-step.sh"), "w").write(steps[0].get("run").value)
PY
mkdir -p "$WORK/bin"
cat >"$WORK/bin/gh" <<'GH'
#!/usr/bin/env bash
printf 'gh' >>"$GH_LOG"; printf ' [%s]' "$@" >>"$GH_LOG"; printf '\n' >>"$GH_LOG"
case "$1 $2" in
  "issue list") printf '%s\n' "$GH_ISSUES" ;;
  "issue create") echo "https://github.example/issues/9" ;;
  *) echo "recorded gh: no answer for $1 $2" >&2; exit 2 ;;
esac
GH
chmod +x "$WORK/bin/gh"
export GH_LOG="$WORK/gh.log"
RSA_HIT='{"watch":"jsonwebtoken-rsa","summary":"RUSTSEC-2023-0071: jsonwebtoken 12.0.0 requires rsa `^0.10.0`, which admits 0.10.0."}'
SQLITE_HIT='{"watch":"sqlx-sqlite-libsqlite3-sys","summary":"RUSTSEC-2026-0459: fixed."}'
RSA_TITLE='An accepted advisory can be fixed: jsonwebtoken-rsa'

# issue_ NAME HITS ISSUES EXPECTED_CREATES FRAGMENT: run the step for HITS
# while `gh issue list` finds ISSUES; it opens EXPECTED_CREATES issues and
# its output or its calls hold FRAGMENT.
issue_() {
  local name="$1" creates status seen
  : >"$GH_LOG"
  HITS="$2" GH_ISSUES="$3" python3 -I -B - "$WORK" >"$WORK/issue-out" 2>&1 <<'PY'
import os, subprocess, sys
work = sys.argv[1]
env = dict(os.environ, PATH=os.path.join(work, "bin") + os.pathsep + os.environ["PATH"],
           GITHUB_REPOSITORY="owner/repository", GH_TOKEN="not-a-token")
sys.exit(subprocess.run(["bash", "-e", os.path.join(work, "issue-step.sh")], env=env).returncode)
PY
  status=$?
  creates=$(grep -c '^gh \[issue\] \[create\]' "$GH_LOG")
  # Read into a variable and searched from a here-string: `cat ... | grep -q`
  # under pipefail fails whenever grep finds the fragment in the first file
  # and exits while cat is still writing the second.
  seen="$(cat "$WORK/issue-out" "$GH_LOG")"
  if [ "$status" -eq 0 ] && [ "$creates" -eq "$4" ] && grep -qF -- "$5" <<<"$seen"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit 0, $4 issue(s) opened and '$5', got exit $status and $creates:" >&2
    cat "$WORK/issue-out" "$GH_LOG" | sed 's/^/    /' >&2
  fi
}
issue_ "a hit with no issue opens one, titled by its watch" "[$RSA_HIT]" '[]' 1 \
  "gh [issue] [create] [--repo] [owner/repository] [--title] [$RSA_TITLE] [--body] [RUSTSEC-2023-0071: jsonwebtoken 12.0.0 requires rsa \`^0.10.0\`, which admits 0.10.0."
issue_ "the issues of every state are searched, by the title" "[$RSA_HIT]" '[]' 1 \
  "gh [issue] [list] [--repo] [owner/repository] [--state] [all] [--search] [\"$RSA_TITLE\" in:title] [--json] [number,state,title]"
issue_ "an open issue is left as it is" "[$RSA_HIT]" "[{\"number\":7,\"state\":\"OPEN\",\"title\":\"$RSA_TITLE\"}]" 0 \
  "Tracking issue #7 is already open for jsonwebtoken-rsa."
issue_ "a closed issue is not opened again, and the run says so" "[$RSA_HIT]" "[{\"number\":7,\"state\":\"CLOSED\",\"title\":\"$RSA_TITLE\"}]" 0 \
  "::warning::jsonwebtoken-rsa is still a hit and its tracking issue #7 is closed. Reopen it, or remove the watch from scripts/lib/upstream_watch.py; no new issue is opened."
issue_ "an open issue counts before a closed one" "[$RSA_HIT]" \
  "[{\"number\":5,\"state\":\"CLOSED\",\"title\":\"$RSA_TITLE\"},{\"number\":8,\"state\":\"OPEN\",\"title\":\"$RSA_TITLE\"}]" 0 \
  "Tracking issue #8 is already open for jsonwebtoken-rsa."
issue_ "an issue whose title only holds the words is another issue" "[$RSA_HIT]" \
  "[{\"number\":3,\"state\":\"CLOSED\",\"title\":\"Re: $RSA_TITLE (notes)\"}]" 1 "[--title] [$RSA_TITLE]"
issue_ "each hit is judged by its own title" "[$RSA_HIT,$SQLITE_HIT]" "[{\"number\":7,\"state\":\"CLOSED\",\"title\":\"$RSA_TITLE\"}]" 1 \
  "[--title] [An accepted advisory can be fixed: sqlx-sqlite-libsqlite3-sys]"

echo "watch-advisory-fixes tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
