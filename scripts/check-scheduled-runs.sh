#!/usr/bin/env bash
# axess: the Hardening and Mutants runs on the release commit ended in
# success.
#
# hardening.yml (the supply-chain gate, fuzzing and Miri) and mutants.yml
# (the whole-workspace mutation sweep) run beside CI, and no workflow can
# wait for another's run. Both run on a push to a release branch, which in
# this project receives one squashed commit per release: the release
# commit. The release workflow runs this script before publish, and it
# refuses unless a run of each on that exact commit ended in success, or,
# with --mutants-report-only (which the release workflow passes for now),
# unless the Hardening run did.
#
#   --tag TAG    (the release workflow) The release commit is the commit of
#                a fetched origin/release/* branch, not on origin/main, whose
#                tree is the tagged tree: for a tag on a release/X.Y.x branch
#                the tagged commit, for the squash merge into main the head
#                of the release pull request. Judged as --commit judges.
#   --commit C   Judge commit C itself. No run on a commit before it counts:
#                a red run on the commit below a release (an advisory the
#                release fixes) says nothing about the release, and a green
#                one says nothing about the code it adds.
#   --report     (the preflight) Print the newest ended run of each workflow
#                on main, with its date, the jobs that did not pass and its
#                address, and exit 0. A commit not yet pushed has no runs,
#                so the preflight cannot judge one; the release workflow
#                does.
#   --mutants-report-only
#                After --tag TAG or --commit C: Hardening is judged as
#                without it, and the Mutants run is read and reported
#                instead of judged. What would have stopped the check (a
#                run not ended, any ending but success, no run, an answer
#                gh could not give) is printed as one REPORTED line with the
#                run's address and ending, and never stops it. The release
#                workflow passes it while no full sweep has passed at the
#                shard size scripts/mutants-sweep.sh plans; the requirement
#                returns, and the release workflow drops the option, once a
#                full sweep has passed.
#
# A run counts when it ran the commit it names: a push, a dispatch, and for
# Hardening a pull request from this repository (a fork's run is not this
# repository's). A pull request's Mutants run sweeps only the lines its diff
# touches, so it does not stand for the sweep. Of the runs that count, the
# newest decides: success passes; a run not ended stops ("wait for run
# <address>"); any other ending (failure, cancelled, timed_out, ...) stops
# with the address; no run stops and says how to start one. gh missing or
# refused and an answer that is not a list of runs stop as well: the check
# never passes on what it could not read.
#
# Usage: ./scripts/check-scheduled-runs.sh --tag TAG | --commit COMMIT [--mutants-report-only] | --report
#   Needs git, jq and gh signed in with read access to the repository's
#   Actions (in a workflow: GH_TOKEN with `actions: read`). gh fills in the
#   repository from the checkout's remote, or from GH_REPO.

set -euo pipefail

usage() {
  echo "usage: $0 --tag TAG | --commit COMMIT [--mutants-report-only] | --report" >&2
  exit 2
}

# Whether the Mutants run binds: `required` (what does not pass stops the
# check, as for Hardening) or, with --mutants-report-only, `report-only`.
mutants_rule=required
case "$#:${1:-}:${3:-}" in
  2:--tag:) mode=tag; given="$2" ;;
  2:--commit:) mode=commit; given="$2" ;;
  3:--tag:--mutants-report-only) mode=tag; given="$2"; mutants_rule=report-only ;;
  3:--commit:--mutants-report-only) mode=commit; given="$2"; mutants_rule=report-only ;;
  1:--report:) mode=report ;;
  *) usage ;;
esac

refused=0
# refuse MESSAGE: one stop, printed as one line without control characters,
# so that text from the API cannot start a workflow command.
refuse() {
  printf 'REFUSED: %s\n' "$(printf '%s' "$*" | tr '\000-\037\177' ' ')" >&2
  refused=1
}
# say MESSAGE: one line of the report, without control characters.
say() {
  printf '%s\n' "$(printf '%s' "$*" | tr '\000-\037\177' ' ')"
}
# halt RULE MESSAGE: for RULE `report-only`, MESSAGE on the output stream
# as one REPORTED line, not counted as a stop (--mutants-report-only); for
# any other RULE, refuse MESSAGE.
halt() {
  if [ "$1" = report-only ]; then
    say "REPORTED, NOT REQUIRED: $2"
  else
    refuse "$2"
  fi
}

# The runs of one workflow, as `gh api` answers them, go to $answer at the
# call, which names its endpoint from a literal start (the pin check holds
# a gh api endpoint to that); what gh says when it fails goes to the error
# stream as gh wrote it.
VALID='type == "object" and (.workflow_runs | type) == "array" and all(.workflow_runs[];
  type == "object" and all(.status, .event, .head_sha, .created_at, .html_url; type == "string")
  and (.id | type) == "number" and ((.conclusion | type) == "string" or .conclusion == null)
  and (.repository.full_name | type) == "string")'
# read_runs ENDPOINT STATUS: 1, with why in $unread, when gh ended with
# STATUS other than 0 or $answer is not a list of runs.
read_runs() {
  if [ "$2" -ne 0 ]; then
    unread="gh api $1 ended with status $2; gh must be signed in with read access to Actions."
    return 1
  fi
  if ! jq -e "$VALID" <<<"$answer" >/dev/null 2>&1; then
    unread="gh api $1 answered with something other than a list of runs: ${answer:0:200}"
    return 1
  fi
}

# One line per run in $answer, newest first: id, status, conclusion, event,
# whether it ran in this repository, created_at, html_url, separated by the
# unit separator (0x1f). It is not white space to the shell, so an empty
# field (a run not ended has no conclusion) keeps its place, and no field
# holds one: every control character in a field is a space.
SEP=$'\x1f'
RUNS='.workflow_runs | sort_by(.created_at, .id) | reverse | .[]
  | [.id, .status, (.conclusion // ""), .event,
     ((.head_repository.full_name // "") == .repository.full_name), .created_at, .html_url]
  | map(tostring | gsub("[[:cntrl:]]"; " ")) | join("\u001f")'

if [ "$mode" = report ]; then
  for program in git jq gh; do
    if ! command -v "$program" >/dev/null 2>&1; then
      say "Hardening and Mutants on main: not read: $program is not installed."
      say "This is a report. The binding check runs in the release workflow, on the release commit."
      exit 0
    fi
  done
  for workflow in hardening.yml mutants.yml; do
    endpoint="repos/{owner}/{repo}/actions/workflows/$workflow/runs?branch=main&status=completed&per_page=1"
    status=0
    answer="$(gh api "repos/{owner}/{repo}/actions/workflows/$workflow/runs?branch=main&status=completed&per_page=1")" || status=$?
    if ! read_runs "$endpoint" "$status"; then
      say "$workflow on main: not read: $unread"
      continue
    fi
    if ! IFS="$SEP" read -r id status conclusion event same created url < <(jq -r "$RUNS" <<<"$answer"); then
      say "$workflow on main: no ended run."
      continue
    fi
    jobs="every job passed"
    if [ "$conclusion" != success ]; then
      if listed="$(gh api --paginate "repos/{owner}/{repo}/actions/runs/$id/jobs?per_page=100")" \
         && names="$(jq -rs '[.[] | .jobs[]? | select(.conclusion != "success" and .conclusion != "skipped") | .name]
              | if length == 0 then "none named" else join(", ") end' <<<"$listed" 2>/dev/null)"; then
        jobs="jobs not passing: $names"
      else
        jobs="its jobs not read"
      fi
    fi
    say "$workflow on main: $conclusion on $created ($event), $jobs; $url"
  done
  say "This is a report. The binding check runs in the release workflow, on the release commit."
  exit 0
fi

for program in git jq gh; do
  if ! command -v "$program" >/dev/null 2>&1; then
    refuse "$program is not installed; the check reads the runs with gh and jq, in a git checkout."
  fi
done
[ "$refused" -eq 0 ] || exit 1

# release_of_tag TAG: the commit of a release branch on origin, not on
# origin/main, that carries the tagged tree; the newest by commit date.
release_of_tag() {
  local tagged tree
  if ! tagged="$(git rev-parse --verify --quiet "refs/tags/$1^{commit}")"; then
    refuse "no tag $1 in this checkout."
    return 1
  fi
  tree="$(git rev-parse "$tagged^{tree}")"
  if ! git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null; then
    refuse "origin/main is not fetched, so the release branch commits cannot be told from main's (check out with fetch-depth: 0)."
    return 1
  fi
  if [ -z "$(git for-each-ref --count=1 --format='%(refname)' refs/remotes/origin/release/)" ]; then
    refuse "no release branch of origin is fetched (check out with fetch-depth: 0)."
    return 1
  fi
  release="$(git log --format='%H %T' --date-order --remotes='origin/release/*' --not refs/remotes/origin/main \
    | awk -v tree="$tree" '$2 == tree && !found { print $1; found = 1 }')"
  if [ -z "$release" ]; then
    refuse "no commit of a release branch outside main carries the tree of $1 ($tagged), so the release commit is unknown."
    return 1
  fi
}

if [ "$mode" = tag ]; then
  release_of_tag "$given" || exit 1
elif ! release="$(git rev-parse --verify --quiet "$given^{commit}")"; then
  refuse "no commit $given in this checkout."
  exit 1
fi
echo "Release commit $release."
# The branch of origin whose head it is, for the command that starts a run.
branch="$(git for-each-ref --points-at "$release" --format='%(refname:lstrip=3)' refs/remotes/origin/ | sed -n 1p)"

# judge NAME WORKFLOW PULL_REQUESTS_COUNT RULE [DISPATCH_FLAGS]: the newest
# run of the workflow that counts on the release commit decides; what does
# not pass goes to halt with RULE (`required` or `report-only`).
judge() {
  local id status conclusion event same created url start ended=0 rule="$4"
  answer="$(gh api "repos/{owner}/{repo}/actions/workflows/$2/runs?head_sha=$release&per_page=100")" || ended=$?
  if ! read_runs "repos/{owner}/{repo}/actions/workflows/$2/runs?head_sha=$release&per_page=100" "$ended"; then
    halt "$rule" "$1: $unread"
    return
  fi
  while IFS="$SEP" read -r id status conclusion event same created url; do
    case "$event:$same:$3" in
      push:*|workflow_dispatch:*|pull_request:true:yes) ;;
      *) continue ;;
    esac
    if [ "$status" != completed ]; then
      halt "$rule" "$1: the newest run on $release has not ended ($status): wait for run $url, then run this check again."
    elif [ "$conclusion" != success ]; then
      halt "$rule" "$1: the newest run on $release ended $conclusion: $url"
    else
      echo "OK: $1: $url ($event, success, $created) on $release."
    fi
    return
  done < <(jq -r --arg sha "$release" "(.workflow_runs |= map(select(.head_sha == \$sha))) | $RUNS" <<<"$answer")
  start="gh workflow run $2 --ref ${branch:-<the release branch whose head is $release>}${5:+ $5}"
  halt "$rule" "$1: no run on $release that counts. Push the release commit to its release branch, or start one: $start"
}

judge Hardening hardening.yml yes required
judge Mutants mutants.yml no "$mutants_rule" "-f full_sweep=true"

[ "$refused" -eq 0 ]
