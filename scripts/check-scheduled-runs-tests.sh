#!/usr/bin/env bash
# axess: crafted cases for scripts/check-scheduled-runs.sh.
#
# The check reads runs through `gh api`. Here a stand-in gh, first on PATH,
# answers each endpoint the check asks for from a file a case wrote (or
# with the status and error a case names) and records what it was asked;
# nothing reaches GitHub. The commits are made in a git repository under a
# temporary root: a release branch, the squash merge of its release commit
# into main with a tag on it, and a patch line with a tag of its own. Each
# case asserts the exit status and a fragment of the output.
#
# Usage: ./scripts/check-scheduled-runs-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${CHECK:-$SCRIPT_DIR/check-scheduled-runs.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-scheduled-runs-tests.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GH_REPO GH_TOKEN GITHUB_TOKEN

passed=0
failed=0

# The stand-in gh answers `gh api [--paginate] ENDPOINT` from $FAKE_GH:
#   .../workflows/W/runs?head_sha=...    W.json      (W.status, W.err)
#   .../workflows/W/runs?branch=main...  W.main.json (W.main.status)
#   .../runs/ID/jobs...                  jobs-ID.json (jobs-ID.status)
mkdir -p "$WORK/bin" "$WORK/answers"
cat > "$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_GH/asked"
[ "$1" = api ] || { echo "the stand-in answers gh api alone" >&2; exit 64; }
shift
[ "$1" = --paginate ] && shift
case "$1" in
  */workflows/*/runs\?head_sha=*) key="${1#*/workflows/}"; key="${key%%/*}" ;;
  */workflows/*/runs\?branch=main*) key="${1#*/workflows/}"; key="${key%%/*}.main" ;;
  */runs/*/jobs*) key="${1#*/runs/}"; key="jobs-${key%%/*}" ;;
  *) echo "the stand-in does not know $1" >&2; exit 64 ;;
esac
[ -f "$FAKE_GH/$key.err" ] && cat "$FAKE_GH/$key.err" >&2
[ -f "$FAKE_GH/$key.json" ] && cat "$FAKE_GH/$key.json"
exit "$(cat "$FAKE_GH/$key.status" 2>/dev/null || echo 0)"
EOF
chmod +x "$WORK/bin/gh"
export FAKE_GH="$WORK/answers"
PATH="$WORK/bin:$PATH"

# The repository. main: M0. release/next, cut from M0: X, then the release
# commit R. main again: S, the squash merge of R (R's tree on M0). A patch
# line release/1.0.x, cut from M0: p1, then its release commit T1. Tags:
# v1.1.0 on S, v1.0.1 on T1. Y lies on no release branch.
REPO="$WORK/repo"
git init -q -b main "$REPO"
cd "$REPO" || exit 1
commit() { # commit MESSAGE: a commit on the current branch with a file of its own
  printf '%s\n' "$1" > "$1.txt"
  git add "$1.txt"
  git -c user.name=axess -c user.email=ci@example.org commit -q -m "$1"
  git rev-parse HEAD
}
M0="$(commit m0)"
git checkout -q -b next
X="$(commit x)"
R="$(commit r)"
S="$(git -c user.name=axess -c user.email=ci@example.org commit-tree "$R^{tree}" -p "$M0" -m squash)"
git checkout -q -b patch "$M0"
commit p1 >/dev/null
T1="$(commit t1)"
git checkout -q -b side "$M0"
Y="$(commit y)"
git update-ref refs/remotes/origin/main "$S"
git update-ref refs/remotes/origin/release/next "$R"
git update-ref refs/remotes/origin/release/1.0.x "$T1"
git tag v1.1.0 "$S"
git tag v1.0.1 "$T1"
git checkout -q next

URL=https://github.com/acme/axess/actions/runs
# run ID SHA EVENT STATUS CONCLUSION CREATED [HEAD_REPOSITORY]: one run, as
# the API lists it; CONCLUSION "" is null. Its address ends in ID.
run() {
  local conclusion=null
  [ -n "$5" ] && conclusion="\"$5\""
  printf '{"id":%s,"status":"%s","conclusion":%s,"event":"%s","head_sha":"%s","created_at":"%s","html_url":"%s/%s","repository":{"full_name":"acme/axess"},"head_repository":{"full_name":"%s"}}' \
    "$1" "$4" "$conclusion" "$3" "$2" "$6" "$URL" "$1" "${7:-acme/axess}"
}
ok() { run "$1" "$2" "$3" completed success "$4" "${5:-}"; }
# answer KEY RUN...: what gh answers for the key.
answer() {
  local key="$1" list="" item
  shift
  for item in "$@"; do list="${list:+$list,}$item"; done
  printf '{"total_count":%s,"workflow_runs":[%s]}\n' "$#" "$list" > "$FAKE_GH/$key.json"
}

# case_ NAME EXPECTED_EXIT FRAGMENT ARGS...: run the check on the answers
# written, then clear them.
case_() {
  local name="$1" want="$2" fragment="$3" out status
  shift 3
  out="$("$CHECK" "$@" 2>"$WORK/stderr")"
  status=$?
  judge "$name" "$want" "$fragment" "$status" "$out"
  rm -f "$FAKE_GH"/*
}
# asked NAME LINE: the stand-in was asked for that line.
asked() {
  if grep -qxF -- "$2" "$FAKE_GH/asked" 2>/dev/null; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $1: the stand-in was not asked '$2'; it was asked:" >&2
    sed 's/^/    /' "$FAKE_GH/asked" >&2 2>/dev/null
  fi
}

T='2026-11-01T03:00:00Z'
T2='2026-11-02T03:00:00Z'
T3='2026-11-03T03:00:00Z'
green() { # both workflows green on SHA
  answer hardening.yml "$(ok 1 "$1" push "$T")"
  answer mutants.yml "$(ok 2 "$1" push "$T")"
}

# The release commit itself is judged: for the squash merge of v1.1.0, R.
green "$R"
case_ "green runs on the release commit pass" 0 "OK: Mutants: $URL/2 (push, success, $T) on $R." --tag v1.1.0
green "$R"
"$CHECK" --tag v1.1.0 >/dev/null 2>&1
asked "the runs of Hardening are asked for on the release commit" "api repos/{owner}/{repo}/actions/workflows/hardening.yml/runs?head_sha=$R&per_page=100"
asked "the runs of Mutants are asked for on the release commit" "api repos/{owner}/{repo}/actions/workflows/mutants.yml/runs?head_sha=$R&per_page=100"
rm -f "$FAKE_GH"/*
green "$X"
case_ "green runs on the parent of the release commit do not count" 1 "Hardening: no run on $R that counts" --tag v1.1.0
green "$M0"
case_ "the squash merge's own parent, the release before, is not judged" 1 "Hardening: no run on $R that counts" --tag v1.1.0

for ending in failure cancelled timed_out startup_failure neutral skipped action_required; do
  answer hardening.yml "$(run 1 "$R" push completed "$ending" "$T")"
  answer mutants.yml "$(ok 2 "$R" push "$T")"
  case_ "a Hardening run that ended $ending stops with its address" 1 "Hardening: the newest run on $R ended $ending: $URL/1" --tag v1.1.0
done
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(run 2 "$R" push completed cancelled "$T")"
case_ "a cancelled Mutants run stops" 1 "Mutants: the newest run on $R ended cancelled: $URL/2" --tag v1.1.0
answer hardening.yml "$(run 1 "$R" push in_progress "" "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a Hardening run still going stops and names it" 1 "Hardening: the newest run on $R has not ended (in_progress): wait for run $URL/1" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(run 2 "$R" push queued "" "$T")"
case_ "a queued Mutants run stops and names it" 1 "wait for run $URL/2" --tag v1.1.0
answer hardening.yml "$(run 1 "$R" push completed failure "$T")"
answer mutants.yml "$(run 2 "$R" push completed failure "$T")"
"$CHECK" --tag v1.1.0 >/dev/null 2>"$WORK/stderr"
if [ "$(grep -c '^REFUSED: ' "$WORK/stderr")" -eq 2 ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: both red workflows are named: got:" >&2
  sed 's/^/    /' "$WORK/stderr" >&2
fi
rm -f "$FAKE_GH"/*

# The newest run that counts decides, and only runs that ran the commit count.
answer hardening.yml "$(ok 1 "$R" push "$T")" "$(run 3 "$R" workflow_dispatch completed failure "$T2")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a newer red run over a green push run stops" 1 "Hardening: the newest run on $R ended failure: $URL/3" --tag v1.1.0
answer hardening.yml "$(run 1 "$R" push completed failure "$T")" "$(ok 3 "$R" workflow_dispatch "$T2")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a newer green dispatched run over a red push run passes" 0 "OK: Hardening: $URL/3 (workflow_dispatch, success" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" pull_request "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a Hardening run of a pull request from this repository counts" 0 "OK: Hardening: $URL/1 (pull_request, success" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" pull_request "$T" someone/axess)"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a Hardening run of a fork's pull request does not count" 1 "Hardening: no run on $R that counts" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")" "$(run 3 "$R" pull_request completed failure "$T2" someone/axess)"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a fork's red run over a green push run is passed over" 0 "OK: Hardening: $URL/1 (push, success" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(ok 2 "$R" pull_request "$T")"
case_ "a pull request's Mutants run, a sweep of its diff, does not count" 1 "Mutants: no run on $R that counts" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" schedule "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a scheduled run does not count" 1 "Hardening: no run on $R that counts" --tag v1.1.0
answer hardening.yml "$(ok 1 "$X" push "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a run the answer gives for another commit does not count" 1 "Hardening: no run on $R that counts" --tag v1.1.0

# No run: the check says how to start one.
answer hardening.yml
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "no Hardening run says how to start one on the release branch" 1 "start one: gh workflow run hardening.yml --ref release/next" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml
case_ "no Mutants run says how to start the full sweep" 1 "start one: gh workflow run mutants.yml --ref release/next -f full_sweep=true" --tag v1.1.0
answer hardening.yml
answer mutants.yml "$(ok 2 "$T1" push "$T")"
case_ "a tag on a patch line is judged by its own commit" 1 "gh workflow run hardening.yml --ref release/1.0.x" --tag v1.0.1
answer hardening.yml "$(ok 1 "$T1" push "$T")"
answer mutants.yml "$(ok 2 "$T1" push "$T")"
case_ "green runs on a patch line's release commit pass" 0 "Release commit $T1." --tag v1.0.1

# What gh says.
green "$R"
echo 4 > "$FAKE_GH/hardening.yml.status"
echo "To get started with GitHub CLI, please run:  gh auth login" > "$FAKE_GH/hardening.yml.err"
case_ "gh not signed in stops with its status" 1 "Hardening: gh api repos/{owner}/{repo}/actions/workflows/hardening.yml/runs?head_sha=$R&per_page=100 ended with status 4" --tag v1.1.0
green "$R"
echo 4 > "$FAKE_GH/hardening.yml.status"
echo "To get started with GitHub CLI, please run:  gh auth login" > "$FAKE_GH/hardening.yml.err"
case_ "gh not signed in stops with its message" 1 "To get started with GitHub CLI, please run:  gh auth login" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
printf 'not json\n' > "$FAKE_GH/mutants.yml.json"
case_ "an answer that is not JSON stops" 1 "answered with something other than a list of runs: not json" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
printf 'not\033[2K::warning::json\n' > "$FAKE_GH/mutants.yml.json"
case_ "an answer is quoted without its control characters" 1 "list of runs: not [2K::warning::json" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
printf '[%s]\n' "$(ok 2 "$R" push "$T")" > "$FAKE_GH/mutants.yml.json"
case_ "an answer that is a bare list stops" 1 "answered with something other than a list of runs" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T" | sed 's/,"html_url":"[^"]*"//')"
case_ "a run without an address stops" 1 "answered with something other than a list of runs" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T" | sed 's/"conclusion":"success"/"conclusion":7/')"
case_ "a run whose ending is a number stops" 1 "answered with something other than a list of runs" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T" | sed 's/"conclusion":"success"/"conclusion":"success\\u001b[2K::warning::x"/')"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "an ending the API reports is printed without its control characters" 1 "ended success [2K::warning::x" --tag v1.1.0
answer hardening.yml "$(ok 1 "$R" push "$T" | sed 's/"conclusion":"success"/"conclusion":"fail\\u001fure"/')"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "a separator inside a field does not move the fields after it" 1 "Hardening: the newest run on $R ended fail ure: $URL/1" --tag v1.1.0

# The release commit.
green "$X"
case_ "--commit judges the commit itself" 0 "OK: Hardening: $URL/1 (push, success, $T) on $X." --commit "$X"
answer hardening.yml
answer mutants.yml "$(ok 2 "$X" push "$T")"
case_ "a commit no release branch has at its head says so in the command" 1 "--ref <the release branch whose head is $X>" --commit "$X"
case_ "a commit the checkout does not hold stops" 1 "no commit 0123456789abcdef0123456789abcdef01234567" --commit 0123456789abcdef0123456789abcdef01234567
case_ "a tag the checkout does not hold stops" 1 "no tag v9.9.9" --tag v9.9.9
git tag v0.0.1 "$Y"
case_ "a tag whose tree no release branch carries stops" 1 "no commit of a release branch outside main carries the tree of v0.0.1" --tag v0.0.1
# Once release/next is moved to the released squash merge, no commit outside
# main carries its tree, and the squash merge is never taken for it.
git update-ref refs/remotes/origin/release/next "$S"
case_ "a release branch moved to the squash merge does not make main's commits the release's" 1 "no commit of a release branch outside main carries the tree of v1.1.0" --tag v1.1.0
git update-ref refs/remotes/origin/release/next "$R"
git update-ref -d refs/remotes/origin/main
case_ "a checkout without origin/main stops" 1 "origin/main is not fetched" --tag v1.1.0
git update-ref refs/remotes/origin/main "$S"
git update-ref -d refs/remotes/origin/release/next
git update-ref -d refs/remotes/origin/release/1.0.x
case_ "a checkout without release branches stops" 1 "no release branch of origin is fetched" --tag v1.1.0
git update-ref refs/remotes/origin/release/next "$R"
git update-ref refs/remotes/origin/release/1.0.x "$T1"
case_ "no argument stops before anything is read" 2 "usage:"
case_ "an argument the check does not take stops" 2 "usage:" --branch main

# --mutants-report-only: Hardening is judged as before; the Mutants run is
# reported with its address and ending and never stops the check.
RO=--mutants-report-only
green "$R"
case_ "report-only: green runs pass and Mutants is still read" 0 "OK: Mutants: $URL/2 (push, success, $T) on $R." --tag v1.1.0 "$RO"
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml
case_ "report-only: no Mutants run is reported and does not stop" 0 "REPORTED, NOT REQUIRED: Mutants: no run on $R that counts. Push the release commit to its release branch, or start one: gh workflow run mutants.yml --ref release/next -f full_sweep=true" --tag v1.1.0 "$RO"
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(run 2 "$R" push in_progress "" "$T")"
case_ "report-only: a Mutants run still going is reported with its address and does not stop" 0 "REPORTED, NOT REQUIRED: Mutants: the newest run on $R has not ended (in_progress): wait for run $URL/2" --tag v1.1.0 "$RO"
for ending in failure cancelled timed_out; do
  answer hardening.yml "$(ok 1 "$R" push "$T")"
  answer mutants.yml "$(run 2 "$R" push completed "$ending" "$T")"
  case_ "report-only: a Mutants run that ended $ending is reported with its address and does not stop" 0 "REPORTED, NOT REQUIRED: Mutants: the newest run on $R ended $ending: $URL/2" --tag v1.1.0 "$RO"
done
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
echo 4 > "$FAKE_GH/mutants.yml.status"
case_ "report-only: Mutants runs gh could not read are reported and do not stop" 0 "REPORTED, NOT REQUIRED: Mutants: gh api repos/{owner}/{repo}/actions/workflows/mutants.yml/runs?head_sha=$R&per_page=100 ended with status 4" --tag v1.1.0 "$RO"
answer hardening.yml "$(run 1 "$R" push completed failure "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "report-only: a red Hardening run still stops" 1 "REFUSED: Hardening: the newest run on $R ended failure: $URL/1" --tag v1.1.0 "$RO"
answer hardening.yml
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "report-only: no Hardening run still stops" 1 "REFUSED: Hardening: no run on $R that counts" --tag v1.1.0 "$RO"
answer hardening.yml "$(run 1 "$R" push queued "" "$T")"
answer mutants.yml "$(ok 2 "$R" push "$T")"
case_ "report-only: a Hardening run not ended still stops" 1 "REFUSED: Hardening: the newest run on $R has not ended (queued)" --tag v1.1.0 "$RO"
green "$R"
echo 4 > "$FAKE_GH/hardening.yml.status"
case_ "report-only: Hardening runs gh could not read still stop" 1 "REFUSED: Hardening: gh api repos/{owner}/{repo}/actions/workflows/hardening.yml/runs?head_sha=$R&per_page=100 ended with status 4" --tag v1.1.0 "$RO"
answer mutants.yml "$(ok 2 "$R" push "$T")"
printf 'not json\n' > "$FAKE_GH/hardening.yml.json"
case_ "report-only: a Hardening answer that is not a list of runs still stops" 1 "REFUSED: Hardening: gh api repos/{owner}/{repo}/actions/workflows/hardening.yml/runs?head_sha=$R&per_page=100 answered with something other than a list of runs: not json" --tag v1.1.0 "$RO"
answer hardening.yml "$(run 1 "$R" push completed failure "$T")"
answer mutants.yml "$(run 2 "$R" push completed failure "$T")"
out="$("$CHECK" --tag v1.1.0 "$RO" 2>"$WORK/stderr")"
status=$?
if [ "$status" -eq 1 ] && [ "$(grep -c '^REFUSED: ' "$WORK/stderr")" -eq 1 ] \
   && grep -qF "REPORTED, NOT REQUIRED: Mutants: the newest run on $R ended failure: $URL/2" <<<"$out"; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: report-only: both red stops on Hardening alone and reports Mutants: got exit $status:" >&2
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  sed 's/^/    /' "$WORK/stderr" >&2
fi
rm -f "$FAKE_GH"/*
answer hardening.yml "$(ok 1 "$X" push "$T")"
answer mutants.yml "$(run 2 "$X" push completed failure "$T")"
case_ "report-only: --commit takes it too" 0 "REPORTED, NOT REQUIRED: Mutants: the newest run on $X ended failure: $URL/2" --commit "$X" "$RO"
answer hardening.yml "$(ok 1 "$R" push "$T")"
answer mutants.yml "$(run 2 "$R" push completed failure "$T")"
case_ "without report-only a red Mutants run still stops" 1 "REFUSED: Mutants: the newest run on $R ended failure: $URL/2" --tag v1.1.0
case_ "report-only before the tag stops before anything is read" 2 "usage:" "$RO" --tag v1.1.0
case_ "report-only with the report stops before anything is read" 2 "usage:" --report "$RO"
case_ "report-only alone stops before anything is read" 2 "usage:" "$RO"

# The report, for the preflight: it judges nothing and exits 0.
answer hardening.yml.main "$(ok 5 "$M0" schedule "$T")"
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
case_ "the report prints the newest ended run of each on main" 0 "hardening.yml on main: success on $T (schedule), every job passed; $URL/5" --report
answer hardening.yml.main "$(ok 5 "$M0" schedule "$T")"
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
case_ "the report says where the binding check runs" 0 "This is a report. The binding check runs in the release workflow, on the release commit." --report
answer hardening.yml.main "$(ok 5 "$M0" schedule "$T")"
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
"$CHECK" --report >/dev/null 2>&1
asked "the report asks for the newest ended run on main" "api repos/{owner}/{repo}/actions/workflows/mutants.yml/runs?branch=main&status=completed&per_page=1"
rm -f "$FAKE_GH"/*
answer hardening.yml.main "$(run 5 "$M0" schedule completed failure "$T3")"
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
printf '{"jobs":[{"name":"Supply chain","conclusion":"failure"},{"name":"Miri","conclusion":"success"}]}\n{"jobs":[{"name":"Fuzz (decode)","conclusion":"cancelled"},{"name":"Fuzz (other)","conclusion":"skipped"}]}\n' > "$FAKE_GH/jobs-5.json"
case_ "a red run names the jobs that did not pass, over every page" 0 "hardening.yml on main: failure on $T3 (schedule), jobs not passing: Supply chain, Fuzz (decode); $URL/5" --report
answer hardening.yml.main "$(run 5 "$M0" schedule completed failure "$T3")"
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
echo 1 > "$FAKE_GH/jobs-5.status"
case_ "jobs that cannot be read are said to be unread" 0 "failure on $T3 (schedule), its jobs not read" --report
answer hardening.yml.main
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
case_ "no ended run on main is said" 0 "hardening.yml on main: no ended run." --report
answer mutants.yml.main "$(ok 6 "$M0" schedule "$T2")"
echo 4 > "$FAKE_GH/hardening.yml.main.status"
case_ "a run gh could not read is said to be unread, and the report still exits 0" 0 "hardening.yml on main: not read: gh api repos/{owner}/{repo}/actions/workflows/hardening.yml/runs?branch=main&status=completed&per_page=1 ended with status 4" --report

# No gh: a PATH that holds the programs the check runs, but not gh.
mkdir -p "$WORK/bin-nogh"
for program in bash git jq tr; do
  ln -s "$(command -v "$program")" "$WORK/bin-nogh/$program"
done
out="$(PATH="$WORK/bin-nogh" "$CHECK" --tag v1.1.0 2>"$WORK/stderr")"
judge "a missing gh stops the check" 1 "gh is not installed" "$?" "$out"
out="$(PATH="$WORK/bin-nogh" "$CHECK" --report 2>"$WORK/stderr")"
judge "a missing gh is said in the report, which exits 0" 0 "not read: gh is not installed" "$?" "$out"

echo "check-scheduled-runs crafted cases: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
