#!/usr/bin/env bash
# axess: crafted cases for the publish job of .github/workflows/release.yml:
# its first step, which checks the toolchain, and its publish step.
#
# The step publishes by crates.io trusted publishing: for every crate it asks
# GitHub for the job's OIDC token, exchanges it at crates.io for a token that
# publishes, runs `cargo publish` with it, revokes it, and compares what
# crates.io's index then lists with the attested file. Its script is read
# out of the workflow (scripts/lib/workflow_yaml.py) and run as the runner
# runs a step that names no shell (`bash -e`), in a directory that holds
# the attested files where the job downloads them, with a recorded `curl`,
# `cargo`, `sleep` and `date` first on the path. A small Python program
# hands it to bash: scripts/check-workflow-pins.sh reads the step where the
# runner reads it, in release.yml, and refuses a shell that runs a file the
# repository does not hold, which the extracted copy is. Each case sets
# what they answer and asserts the exit status, a fragment of the output,
# and where it matters what was asked of them. The refusals are the
# contract: every way the exchange can fail ends the job by name before
# that crate is published, and no credential reaches the log, an argument
# list or a file that outlives the step.
#
# The recorded curl behaves as curl does where the step depends on it: an
# HTTP error is exit 22 only under --fail-with-body, a transient error is
# tried again as often as --retry says, and an answer already written to a
# pipe stays there while a named file is emptied first. It records whether
# a header or a body came from a file, and refuses a credential in its
# arguments, as the recorded cargo refuses a token in its own.
#
# Nothing here reaches the network, so what the cases prove is the step's
# handling of each answer, not that GitHub and crates.io give those answers.
#
# Usage: ./scripts/release-publish-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW="$SCRIPT_DIR/../.github/workflows/release.yml"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-release-publish.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The step's script, and the facts of its job the cases check.
python3 -I -B - "$SCRIPT_DIR/lib" "$WORKFLOW" "$WORK" <<'PY' || { echo "FAIL: the publish step could not be read from $WORKFLOW" >&2; exit 1; }
import os, sys
sys.path.insert(0, sys.argv[1])
import workflow_yaml as yaml
doc = yaml.read(open(sys.argv[2], encoding="utf-8").read())
job = doc.get("jobs").get("publish")
steps = [s for s in job.get("steps").items if s.get("name") is not None
         and s.get("name").value.startswith("Publish crates")]
if len(steps) != 1:
    sys.exit("expected one step named 'Publish crates...' in the publish job")
open(os.path.join(sys.argv[3], "step.sh"), "w").write(steps[0].get("run").value)
items = job.get("steps").items
guards = [s for s in items if s.get("name") is not None and s.get("name").value.startswith("The toolchain is")]
if len(guards) != 1:
    sys.exit("expected one step named 'The toolchain is...' in the publish job")
open(os.path.join(sys.argv[3], "guard.sh"), "w").write(guards[0].get("run").value)
perms = job.get("permissions")
uses = [s.get("uses").value for s in items if s.get("uses") is not None]
job_env = job.get("env")
after_checkout = items[1].get("name").value if len(items) > 1 and items[1].get("name") is not None else ""
facts = {
    "id-token": perms.get("id-token").value if perms.get("id-token") is not None else "",
    "env": "yes" if any(s.get("env") is not None for s in job.get("steps").items) else "no",
    "environment": job.get("environment").get("name").value,
    "shell": steps[0].get("shell").value if steps[0].get("shell") is not None else "unset",
    "actions-not-github's-own": ",".join(u for u in uses if not u.startswith("actions/")) or "none",
    "auto-install": job_env.get("RUSTUP_AUTO_INSTALL").value if job_env is not None and job_env.get("RUSTUP_AUTO_INSTALL") is not None else "unset",
    "first-step-after-checkout": "guard" if items[0].get("uses") is not None and items[0].get("uses").value.startswith("actions/checkout@") and items[1] is guards[0] else after_checkout,
    "guard-shell": guards[0].get("shell").value if guards[0].get("shell") is not None else "unset",
}
open(os.path.join(sys.argv[3], "facts"), "w").write("".join(f"{k}={v}\n" for k, v in facts.items()))
PY

CRATES="axess-strings axess-clock axess-rng axess-testing axess-identity axess-events axess-cache axess-factors axess-core axess-macros axess"
AGENT='GnomesOfZurich/axess release.yml (https://github.com/GnomesOfZurich/axess)'
export JWT='eyJhbGciOiJSUzI1NiJ9.oidc-claims.signature'
export RUNNER_REQUEST='runner-request-token'
# The instant the recorded `date` calls now, and the two dates it reads.
NOW=1767225600
AHEAD='Thu, 01 Jan 2026 00:05:00 GMT'
BEHIND='Wed, 31 Dec 2025 23:00:00 GMT'

mkdir -p "$WORK/bin"
cat >"$WORK/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -u
for arg in "$@"; do
  case "$arg" in *"$JWT"*|*"$RUNNER_REQUEST"*|*cio_tp_*)
    echo "curl credential-in-arguments" >>"$LOG"
    echo "recorded curl: a credential was passed as an argument" >&2; exit 2 ;;
  esac
done
method=GET; headers=""; data=""; url=""; agent=""; retry=0; time=""; output=""; fail=no
while [ $# -gt 0 ]; do
  case "$1" in
    --silent|--show-error) ;;
    --fail-with-body) fail=yes ;;
    --max-time) time="$2"; shift ;;
    --retry) retry="$2"; shift ;;
    --request) method="$2"; shift ;;
    --user-agent) agent="$2"; shift ;;
    --output) output="$2"; shift ;;
    --header) case "$2" in @*) headers="$headers|@$(cat "${2#@}")" ;; *) headers="$headers|$2" ;; esac; shift ;;
    --data-binary) case "$2" in @*) data="@$(cat "${2#@}")" ;; *) data="$2" ;; esac; shift ;;
    --url) url="$2"; shift ;;
    *) echo "recorded curl: $1 is not an argument the step is known to pass" >&2; exit 2 ;;
  esac
  shift
done
printf 'curl %s %s retry=[%s] time=[%s] agent=[%s] to=[%s] headers=[%s] data=[%s]\n' "$method" "$url" "$retry" "$time" "$agent" \
  "${output:+file}" "$headers" "$data" >>"$LOG"
# answer STATUS BODY [STATUS BODY]...: what the server says to each attempt.
answer() {
  local left="$retry" status body
  while [ $# -ge 2 ]; do
    status="$1"; body="$2"; shift 2
    if [ "$status" = "unreachable" ]; then echo "curl: (6) Could not resolve host" >&2; exit 6; fi
    if [ -n "$output" ]; then printf '%s' "$body" >"$output"; else printf '%s' "$body"; fi
    case "$status" in
      408|429|500|502|503|504)
        if [ "$fail" = yes ] && [ "$left" -gt 0 ] && [ $# -ge 2 ]; then left=$((left - 1)); continue; fi ;;
    esac
    if [ "$status" -ge 400 ] && [ "$fail" = yes ]; then exit 22; fi
    exit 0
  done
}
case "$method $url" in
  "GET https://github.example/oidc?x=1&audience=crates.io")
    if [ -n "${OIDC_FIRST_STATUS:-}" ]; then answer "$OIDC_FIRST_STATUS" "$OIDC_FIRST_BODY" "$OIDC_STATUS" "$OIDC_BODY"; fi
    answer "$OIDC_STATUS" "$OIDC_BODY" ;;
  "POST https://crates.io/api/v1/trusted_publishing/tokens")
    n=$(( $(cat "$COUNTER") + 1 )); echo "$n" >"$COUNTER"
    if [ "$n" -ge "${EXCHANGE_FAIL_AT:-1000}" ]; then answer "$EXCHANGE_STATUS" "$EXCHANGE_BODY"; fi
    answer 200 "${EXCHANGE_OK_BODY-{\"token\":\"cio_tp_$n\"}}" ;;
  "DELETE https://crates.io/api/v1/trusted_publishing/tokens")
    if [ -n "${REVOKE_FIRST_STATUS:-}" ]; then answer "$REVOKE_FIRST_STATUS" "$REVOKE_FIRST_BODY" "$REVOKE_STATUS" "$REVOKE_BODY"; fi
    answer "$REVOKE_STATUS" "$REVOKE_BODY" ;;
  "GET https://index.crates.io/ax/es/"*)
    # The index file of one crate: a line per version. INDEX_<crate> says
    # what it lists for this release: `ok` the attested file's checksum,
    # `other` another one, `late` nothing until the third read, `never`
    # nothing, `missing` no file at all, `garbage` a line that is not JSON.
    crate="${url##*/}"
    reads="$WORK_DIR/index-reads-$crate"; echo x >>"$reads"
    var="INDEX_$(printf '%s' "$crate" | tr '-' '_')"; mode="${!var:-ok}"
    sum=$(sha256sum -- "$WORK_DIR/checkout/attested/target/package/$crate-0.20.0.crate"); sum="${sum%% *}"
    older="{\"name\":\"$crate\",\"vers\":\"0.19.0\",\"deps\":[],\"cksum\":\"$(printf 'a%.0s' $(seq 1 64))\",\"features\":{},\"yanked\":false}"
    line() { printf '%s\n{"name":"%s","vers":"0.20.0","deps":[],"cksum":"%s","features":{},"yanked":false}\n' "$older" "$crate" "$1"; }
    case "$mode" in
      ok) answer 200 "$(line "$sum")" ;;
      other) answer 200 "$(line "$(printf 'b%.0s' $(seq 1 64))")" ;;
      late) if [ "$(wc -l <"$reads")" -ge 3 ]; then answer 200 "$(line "$sum")"; else answer 200 "$older"; fi ;;
      never) answer 200 "$older" ;;
      missing) answer 404 '{"errors":[{"detail":"Not Found"}]}' ;;
      gone) answer 410 'Gone' ;;
      withheld) answer 451 'Unavailable For Legal Reasons' ;;
      garbage) answer 200 "<html>busy</html>" ;;
      flaky) answer 503 "<html>busy</html>" 200 "$(line "$sum")" ;;
    esac ;;
  *) echo "recorded curl: no answer for $method $url" >&2; exit 2 ;;
esac
CURL
# The recorded cargo: answers `cargo publish` for each crate as
# CARGO_<crate> says, `ok` by default, and records the token it was given.
# The `limited` answers are 429 once, then a publish; `interrupted` ends the
# step with the signal a cancelled run gets and stays until it is stopped.
cat >"$WORK/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
# `cargo -vV`: the toolchain's release, as $TOOLCHAIN says (`fail` for a
# cargo that does not run, `unnamed` for one that names no release).
if [ "$*" = "-vV" ]; then
  TOOLCHAIN="${TOOLCHAIN:-1.98.0}"
  case "$TOOLCHAIN" in
    fail) echo "error: toolchain '1.98.0' is not installed" >&2; exit 1 ;;
    unnamed) printf 'cargo 1.98.0 (797e8a9bc 2026-08-05)\nhost: x86_64-unknown-linux-gnu\n' ;;
    *) printf 'cargo %s (797e8a9bc 2026-08-05)\nrelease: %s\ncommit-hash: 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d\nhost: x86_64-unknown-linux-gnu\n' "$TOOLCHAIN" "$TOOLCHAIN" ;;
  esac
  exit 0
fi
crate=""; previous=""
for arg in "$@"; do
  [ "$previous" = "-p" ] && crate="$arg"; previous="$arg"
  case "$arg" in --token|*cio_tp_*)
    echo "cargo credential-in-arguments" >>"$LOG"
    echo "recorded cargo: a token was passed as an argument" >&2; exit 2 ;;
  esac
done
echo "cargo $* token=[${CARGO_REGISTRY_TOKEN:-}]" >>"$LOG"
var="CARGO_$(printf '%s' "$crate" | tr '-' '_')"
limited() {
  if [ ! -e "$WORK_DIR/limited-$crate" ]; then
    touch "$WORK_DIR/limited-$crate"
    printf 'error: failed to publish to registry at https://crates.io\n\nCaused by:\n  the remote server responded with an error (status 429 Too Many Requests): %s\n' "$1"
    exit 101
  fi
  echo "Uploaded $crate"
}
many='You have published too many versions of this crate in the last 24 hours.'
case "${!var:-ok}" in
  ok) echo "Uploaded $crate" ;;
  uploaded) echo "error: crate version \`$crate@0.20.0\` is already uploaded"; exit 101 ;;
  exists) echo "error: crate $crate@0.20.0 already exists on crates.io index"; exit 101 ;;
  limited) limited "$many Please try again after $AHEAD or email help@crates.io to have your limit increased." ;;
  limited-behind) limited "$many Please try again after $BEHIND or email help@crates.io to have your limit increased." ;;
  limited-unnamed) limited "$many" ;;
  fail) echo "error: failed to verify package tarball"; exit 101 ;;
  forbidden) printf 'error: failed to publish %s to registry at https://crates.io\n\nCaused by:\n  the remote server responded with an error (status 403 Forbidden): not allowed\n' "$crate"; exit 101 ;;
  interrupted)
    echo $$ >"$WORK_DIR/cargo.pid"
    until [ -s "$WORK_DIR/step.pid" ]; do :; done
    kill -TERM "$(cat "$WORK_DIR/step.pid")"
    mkfifo "$WORK_DIR/never"; read -r -t 20 _ <>"$WORK_DIR/never"
    echo "cargo outlived the step" >>"$LOG" ;;
esac
CARGO
# sleep and date: recorded, so no case waits or reads the machine's clock.
printf '#!/usr/bin/env bash\necho "sleep $*" >>"$LOG"\n' >"$WORK/bin/sleep"
cat >"$WORK/bin/date" <<'DATE'
#!/usr/bin/env bash
case "$*" in
  "-u +%s") echo "$NOW" ;;
  "-u -d $AHEAD +%s") echo $((NOW + 300)) ;;
  "-u -d $BEHIND +%s") echo $((NOW - 3600)) ;;
  *) exit 1 ;;
esac
DATE
chmod +x "$WORK/bin/curl" "$WORK/bin/cargo" "$WORK/bin/sleep" "$WORK/bin/date"
export NOW AHEAD BEHIND

passed=0
failed=0

# The answers of a run in which everything works; a case changes what it is
# about.
reset() {
  export LOG="$WORK/requests.log" COUNTER="$WORK/counter" WORK_DIR="$WORK"
  : >"$LOG"; echo 0 >"$COUNTER"
  rm -rf "$WORK/runner" "$WORK/checkout" "$WORK/never" "$WORK/step.pid" "$WORK/cargo.pid" "$WORK"/limited-* "$WORK"/index-reads-*
  mkdir -p "$WORK/runner" "$WORK/checkout/attested/target/package"
  # The attested files, where the job's download step puts them.
  for c in $CRATES; do printf 'the package of %s\n' "$c" >"$WORK/checkout/attested/target/package/$c-0.20.0.crate"; done
  # What the runner hands a job with `id-token: write`, given to the step
  # under its own names by the Python program that runs it.
  export OIDC_URL='https://github.example/oidc?x=1' OIDC_REQUEST="$RUNNER_REQUEST"
  export OIDC_STATUS=200 OIDC_BODY="{\"count\":1,\"value\":\"$JWT\"}"
  export EXCHANGE_STATUS=400 EXCHANGE_BODY='' REVOKE_STATUS=204 REVOKE_BODY=''
  unset EXCHANGE_FAIL_AT EXCHANGE_OK_BODY OIDC_FIRST_STATUS OIDC_FIRST_BODY REVOKE_FIRST_STATUS REVOKE_FIRST_BODY
  for c in $CRATES; do unset "CARGO_$(printf '%s' "$c" | tr '-' '_')" "INDEX_$(printf '%s' "$c" | tr '-' '_')"; done
}

# run_ NAME EXPECTED_EXIT FRAGMENT: run the step and judge its output.
run_() {
  local name="$1" want="$2" fragment="$3" status
  python3 -I -B - "$WORK" >"$WORK/out" 2>&1 <<'PY'
import os, subprocess, sys
work = sys.argv[1]
env = dict(os.environ, PATH=os.path.join(work, "bin") + os.pathsep + os.environ["PATH"],
           RUNNER_TEMP=os.path.join(work, "runner"))
for name, source in (("ACTIONS_ID_TOKEN_REQUEST_URL", "OIDC_URL"), ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OIDC_REQUEST")):
    env.pop(name, None)
    if source in env:
        env[name] = env[source]
# A step that names no shell is run by the runner as `bash -e {0}`.
step = subprocess.Popen(["bash", "-e", os.path.join(work, "step.sh")], env=env,
                        cwd=os.path.join(work, "checkout"))
open(os.path.join(work, "step.pid"), "w").write(str(step.pid))
code = step.wait()
# A step the signal killed is not a step that left with the signal's status.
sys.exit(code if code >= 0 else 99)
PY
  status=$?
  if [ "$status" -ne "$want" ] || ! grep -qF -- "$fragment" "$WORK/out"; then
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    sed 's/^/    /' "$WORK/out" >&2
    return
  fi
  # A credential appears in the log only where the runner is told to mask it.
  if grep -qE "cio_tp_|$JWT|$RUNNER_REQUEST" <<<"$(grep -v '^::add-mask::' "$WORK/out")"; then
    failed=$((failed + 1))
    echo "FAIL: $name: a credential reached the log unmasked" >&2
    return
  fi
  # No credential was an argument of curl or cargo.
  if grep -q 'credential-in-arguments' "$LOG"; then
    failed=$((failed + 1))
    echo "FAIL: $name: a credential was passed as an argument" >&2
    return
  fi
  # No credential, answer or output stays in the runner's temporary directory.
  if [ -n "$(ls -A "$WORK/runner")" ]; then
    failed=$((failed + 1))
    echo "FAIL: $name: files left in RUNNER_TEMP: $(ls -A "$WORK/runner")" >&2
    return
  fi
  passed=$((passed + 1))
}

# logged_ NAME FRAGMENT [COUNT]: the requests hold FRAGMENT (COUNT times).
logged_() {
  local count
  count=$(grep -cF -- "$2" "$LOG")
  if { [ $# -eq 3 ] && [ "$count" -eq "$3" ]; } || { [ $# -eq 2 ] && [ "$count" -gt 0 ]; }; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $1: '$2' requested $count time(s)${3:+, wanted $3}:" >&2
    sed 's/^/    /' "$LOG" >&2
  fi
}

# printed_ NAME FRAGMENT: the output of the last run holds FRAGMENT.
printed_() {
  if grep -qF -- "$2" "$WORK/out"; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL: $1: the output does not hold '$2'" >&2
  fi
}

# quiet_ NAME FRAGMENT: the output of the last run does not hold FRAGMENT.
quiet_() {
  if grep -qF -- "$2" "$WORK/out"; then
    failed=$((failed + 1)); echo "FAIL: $1: the output holds '$2'" >&2
  else passed=$((passed + 1)); fi
}

# ── The job ───────────────────────────────────────────────────────
fact_() {
  if grep -qxF -- "$2" "$WORK/facts"; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL: $1: the publish job does not have $2:" >&2; sed 's/^/    /' "$WORK/facts" >&2
  fi
}
fact_ "the publish job may ask for an OIDC token" "id-token=write"
fact_ "it runs in the environment the crates' settings name" "environment=crates-io"
fact_ "no step of it is handed a stored secret through env" "env=no"
fact_ "the step names no shell, so the runner's is bash -e, as here" "shell=unset"
fact_ "every action of the job is GitHub's own" "actions-not-github's-own=none"
fact_ "the job overrides a runner whose rustup does not install a pinned toolchain" "auto-install=1"
fact_ "the toolchain is checked by the first step after the checkout" "first-step-after-checkout=guard"
fact_ "the toolchain step names no shell either" "guard-shell=unset"
if grep -qE 'secrets\.|\$\{\{' "$WORK/step.sh"; then
  failed=$((failed + 1)); echo "FAIL: the publish step names an expression or a secret" >&2
else passed=$((passed + 1)); fi

# ── The toolchain is the release rust-toolchain.toml pins ─────────
# guard_ NAME EXIT FRAGMENT FILE: run the first step in a checkout whose
# rust-toolchain.toml holds FILE (none when FILE is `-`), with the recorded
# cargo answering `cargo -vV` as $TOOLCHAIN says.
guard_() {
  local name="$1" want="$2" fragment="$3" status
  rm -f "$WORK/checkout/rust-toolchain.toml"
  if [ "$4" != "-" ]; then printf '%s\n' "$4" >"$WORK/checkout/rust-toolchain.toml"; fi
  python3 -I -B - "$WORK" >"$WORK/out" 2>&1 <<'PY'
import os, subprocess, sys
work = sys.argv[1]
env = dict(os.environ, PATH=os.path.join(work, "bin") + os.pathsep + os.environ["PATH"],
           RUNNER_TEMP=os.path.join(work, "runner"))
sys.exit(subprocess.run(["bash", "-e", os.path.join(work, "guard.sh")], env=env,
                        cwd=os.path.join(work, "checkout")).returncode)
PY
  status=$?
  if [ "$status" -eq "$want" ] && grep -qF -- "$fragment" "$WORK/out"; then passed=$((passed + 1)); else
    failed=$((failed + 1))
    echo "FAIL: $name: wanted exit $want with '$fragment', got exit $status:" >&2
    sed 's/^/    /' "$WORK/out" >&2
  fi
}
PINNED='[toolchain]
channel = "1.98.0"
components = ["clippy", "rustfmt"]'
reset; unset TOOLCHAIN
guard_ "the pinned release passes" 0 "OK: the toolchain is 1.98.0, the release rust-toolchain.toml pins." "$PINNED"
printed_ "and what cargo says is in the log" "release: 1.98.0"
reset; export TOOLCHAIN=1.97.3
guard_ "the release is read from the file, not written in the step" 0 "OK: the toolchain is 1.97.3" '[toolchain]
channel = "1.97.3"'
reset; export TOOLCHAIN=1.97.0
guard_ "another release stops the job by name" 1 "::error::refused: the toolchain is 1.97.0 and rust-toolchain.toml pins 1.98.0; nothing was packaged or published." "$PINNED"
reset; export TOOLCHAIN=fail
guard_ "a toolchain that is not installed stops the job by name" 1 "::error::refused: cargo did not run, so the toolchain 1.98.0 is not installed" "$PINNED"
reset; export TOOLCHAIN=unnamed
guard_ "a cargo that names no release stops the job" 1 "refused: the toolchain is of no release cargo names and rust-toolchain.toml pins 1.98.0" "$PINNED"
reset; unset TOOLCHAIN
guard_ "a channel that is no exact release stops the job" 1 "::error::refused: rust-toolchain.toml names no exact release" '[toolchain]
channel = "stable"'
guard_ "a checkout with no rust-toolchain.toml stops the job" 1 "names no exact release" -
guard_ "a release in a comment is not the channel" 1 "names no exact release" '[toolchain]
# channel = "1.98.0"
channel = "beta"'
unset TOOLCHAIN

# ── Every crate, each with a token of its own ─────────────────────
reset
run_ "a release publishes every crate" 0 "Uploaded axess"
logged_ "each crate is published once" "cargo publish --locked --no-verify -p" 11
logged_ "each publish has a token of its own" "curl POST https://crates.io/api/v1/trusted_publishing/tokens" 11
logged_ "each token is revoked" "curl DELETE https://crates.io/api/v1/trusted_publishing/tokens" 11
logged_ "the first crate gets the first token" "cargo publish --locked --no-verify -p axess-strings token=[cio_tp_1]" 1
logged_ "the last crate gets the eleventh" "cargo publish --locked --no-verify -p axess token=[cio_tp_11]" 1
logged_ "GitHub is asked for the crates.io audience with the runner's token, from a file" \
  "curl GET https://github.example/oidc?x=1&audience=crates.io retry=[2] time=[30] agent=[] to=[file] headers=[|@Authorization: bearer $RUNNER_REQUEST]"
logged_ "crates.io is handed GitHub's token as jwt from a file, told who asks, and asked once" \
  "curl POST https://crates.io/api/v1/trusted_publishing/tokens retry=[0] time=[30] agent=[$AGENT] to=[] headers=[|Content-Type: application/json] data=[@{"
logged_ "a crate is published with what package verified, building nothing" "cargo publish --locked --no-verify -p axess-strings" 1
logged_ "the body is the JSON crates.io reads" "\"jwt\": \"$JWT\""
logged_ "a token is revoked by presenting it, from a file, and crates.io is told who asks" \
  "curl DELETE https://crates.io/api/v1/trusted_publishing/tokens retry=[2] time=[30] agent=[$AGENT] to=[file] headers=[|@Authorization: Bearer cio_tp_1]" 1
# The order for one crate: exchange, publish, revoke, compare.
if [ "$(grep -nE 'tokens retry|cargo publish|index.crates.io' "$LOG" | sed -n '1,4p' | cut -d' ' -f2 | tr '\n' ' ')" = "POST publish DELETE GET " ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1)); echo "FAIL: a crate's token is not issued, used and revoked, and the crate then compared, in that order:" >&2; sed -n '1,8p' "$LOG" | sed 's/^/    /' >&2
fi
logged_ "crates are 30 seconds apart" "sleep 30" 11
first=$(grep -n 'cargo publish' "$LOG" | cut -d: -f2 | awk '{print $6}' | tr '\n' ' ')
if [ "$first" = "$(printf '%s ' $CRATES)" ]; then passed=$((passed + 1)); else
  failed=$((failed + 1)); echo "FAIL: crates published out of order: $first" >&2; fi

# ── An exchange that fails ends the job before that crate ─────────
reset; unset OIDC_URL
run_ "a job without the OIDC permission is refused" 1 "::error::refused: this job cannot ask GitHub for an OIDC token; it needs 'permissions: id-token: write'."
logged_ "and publishes nothing" "cargo publish" 0
logged_ "and asks nobody" "curl" 0
reset; export OIDC_REQUEST=''
run_ "an empty request token is refused" 1 "this job cannot ask GitHub for an OIDC token"

reset; export OIDC_STATUS=unreachable
run_ "GitHub unreachable is named" 1 "::error::refused: GitHub gave this job no OIDC token (curl exit 6)"
logged_ "and crates.io is not asked" "curl POST" 0
printed_ "the crate it stopped at is named" "::error::axess-strings was not published, and no crate after it."
reset; export OIDC_STATUS=403 OIDC_BODY='{"message":"forbidden"}'
run_ "a refusal by GitHub is named with its answer" 1 'GitHub gave this job no OIDC token (curl exit 22): {"message":"forbidden"}'
logged_ "and crates.io is not asked" "curl POST" 0
reset; export OIDC_BODY='{"count":0}'
run_ "an answer from GitHub without a token is named" 1 "::error::refused: GitHub's answer to the OIDC token request holds no token."
reset; export OIDC_BODY='{"value":""}'
run_ "an empty token from GitHub is named" 1 "holds no token"
reset; export OIDC_BODY='{"value":42}'
run_ "a token from GitHub that is not a string is named" 1 "holds no token"
reset; export OIDC_BODY='<html>rate limited</html>'
run_ "an answer from GitHub that is not JSON is named" 1 "holds no token"
logged_ "and crates.io is not asked" "curl POST" 0
# curl tries a 503 again. The answer of the attempt that failed is not read
# in front of the token: it is neither JSON nor short.
reset; export OIDC_FIRST_STATUS=503 OIDC_FIRST_BODY='<html>upstream connect error</html>'
run_ "an answer from GitHub that came at the second attempt is read alone" 0 "Uploaded axess"
logged_ "and every crate is published" "cargo publish" 11
reset; export OIDC_FIRST_STATUS=503 OIDC_FIRST_BODY='{"value":"not-the-token"}'
run_ "a failed attempt that looks like an answer is not the answer" 0 "Uploaded axess"
logged_ "the token sent to crates.io is the second attempt's" "\"jwt\": \"$JWT\"" 11
logged_ "and never the first's" "not-the-token" 0

reset; export EXCHANGE_FAIL_AT=1 EXCHANGE_STATUS=unreachable
run_ "crates.io unreachable is named" 1 "::error::refused: crates.io issued no trusted-publishing token (curl exit 6)"
reset; export EXCHANGE_FAIL_AT=1 EXCHANGE_BODY='{"errors":[{"detail":"No matching Trusted Publishing config found"}]}'
run_ "a refusal by crates.io is named with its reason" 1 \
  "refused: crates.io issued no trusted-publishing token (curl exit 22): No matching Trusted Publishing config found."
printed_ "a refusal points at the settings" "(docs/project/publishing.md, settings step 5)."
logged_ "and nothing is published" "cargo publish" 0
reset; export EXCHANGE_FAIL_AT=1 EXCHANGE_BODY='{"errors":[{"detail":"first"},{"detail":"second"}]}'
run_ "every reason crates.io gives is printed" 1 "(curl exit 22): first; second."
reset; export EXCHANGE_FAIL_AT=1 EXCHANGE_STATUS=502 EXCHANGE_BODY='<html>Bad Gateway</html>'
run_ "an answer that is not JSON is printed as it stands" 1 "(curl exit 22): <html>Bad Gateway</html>."
logged_ "and the exchange is not tried again" "curl POST" 1
reset; export EXCHANGE_FAIL_AT=1 EXCHANGE_BODY=$'{"errors":[{"detail":"no\\n::add-mask::x\\u001b[31m"}]}'
run_ "a reason is one line of printable text" 1 "(curl exit 22): no ::add-mask::x [31m."
long_reason="$(printf 'x%.0s' $(seq 1 400))"
reset; export EXCHANGE_FAIL_AT=1 EXCHANGE_BODY="{\"errors\":[{\"detail\":\"$long_reason\"}]}"
run_ "a long reason is cut" 1 "(curl exit 22): $(printf 'x%.0s' $(seq 1 300)). Each crate"
reset; export EXCHANGE_OK_BODY='{"ok":true}'
run_ "a 200 from crates.io without a token is named" 1 "::error::refused: crates.io answered the token exchange with no token."
reset; export EXCHANGE_OK_BODY='{"token":["a"]}'
run_ "a token from crates.io that is not a string is named" 1 "answered the token exchange with no token"

reset; export EXCHANGE_FAIL_AT=4 EXCHANGE_BODY='{"errors":[{"detail":"No matching Trusted Publishing config found"}]}'
run_ "a refusal part-way names the crate it stopped at" 1 "::error::axess-testing was not published, and no crate after it."
logged_ "the crates before it are published" "cargo publish" 3
logged_ "and none after it" "cargo publish --locked --no-verify -p axess-identity" 0

# ── What cargo answers ────────────────────────────────────────────
reset; export CARGO_axess_rng=uploaded
run_ "a crate already uploaded is skipped" 0 "::notice::axess-rng already published; skipping"
logged_ "and its token is revoked" "curl DELETE" 11
# A second run of the same tag, after a release that stopped part-way: the
# crates already at this version are skipped, whichever of the two wordings
# says so (the registry's, or cargo's own check of the index), and the rest
# are published in order. The run does not fail on the first of them.
reset
export CARGO_axess_strings=uploaded CARGO_axess_clock=uploaded CARGO_axess_rng=uploaded CARGO_axess_testing=uploaded
export CARGO_axess_identity=exists CARGO_axess_events=exists CARGO_axess_cache=exists CARGO_axess_factors=exists
run_ "a second run of a tag skips what is published and publishes the rest" 0 "Uploaded axess-core"
printed_ "the first crate is skipped, not a failure" "::notice::axess-strings already published; skipping"
printed_ "cargo's own wording is a skip too" "::notice::axess-factors already published; skipping"
printed_ "the last crate is published" "Uploaded axess"
logged_ "every crate is asked of cargo once, in order" "cargo publish --locked --no-verify -p" 11
logged_ "every token of the run is revoked" "curl DELETE" 11
logged_ "a skipped crate is compared with its attested file too" "curl GET https://index.crates.io/ax/es/axess-strings" 1
quiet_ "a second run of a tag prints no error" "::error::"

# crates.io names the time a rate limit ends; the recorded clock stands 300
# seconds before it, and the step adds ten.
reset; export CARGO_axess_core=limited
run_ "a rate limit waits until the time crates.io names" 0 "::notice::axess-core rate-limited; sleeping 310s"
logged_ "with a token of its own" "cargo publish --locked --no-verify -p axess-core token=[cio_tp_10]" 1
logged_ "after the wait" "sleep 310" 1
logged_ "both tokens are revoked" "curl DELETE" 12
printed_ "and cargo's answer is in the log" "Please try again after $AHEAD or email"
reset; export CARGO_axess_core=limited-behind
run_ "a named time that has passed waits two minutes" 0 "::notice::axess-core rate-limited; sleeping 120s"
logged_ "after the wait" "sleep 120" 1
reset; export CARGO_axess_core=limited-unnamed
run_ "a rate limit that names no time waits two minutes" 0 "::notice::axess-core rate-limited; sleeping 120s"
logged_ "after the wait" "sleep 120" 1
reset; export CARGO_axess_events=fail
run_ "a failed publish stops the job by name" 1 "::error::publishing axess-events failed"
logged_ "its token is revoked" "curl DELETE" 6
logged_ "and no crate after it is published" "cargo publish --locked --no-verify -p axess-cache" 0
# A crate left out of settings step 5: the exchange succeeds (another crate
# trusts the workflow) and crates.io refuses the upload.
reset; export CARGO_axess_core=forbidden
run_ "a crate that does not trust the workflow stops the job by name" 1 \
  "::error::crates.io refused the token for axess-core: its Trusted Publishing settings may not name this repository"
printed_ "and cargo's answer is in the log" "(status 403 Forbidden): not allowed"
logged_ "the crates before it are published" "cargo publish" 9
logged_ "and none after it" "cargo publish --locked --no-verify -p axess-macros" 0
logged_ "its token is revoked" "curl DELETE" 9

# ── A token that outlives nothing ─────────────────────────────────
reset; export REVOKE_STATUS=401 REVOKE_BODY='{"errors":[{"detail":"Invalid authorization header"}]}'
run_ "a token that is not revoked is a warning, not a stop" 0 \
  "::warning::the token issued to publish axess-strings was not revoked (curl exit 22): Invalid authorization header; it ends by itself when its short lifetime runs out."
logged_ "and every crate is published" "cargo publish" 11
reset; export REVOKE_FIRST_STATUS=503 REVOKE_FIRST_BODY='<html>busy</html>'
run_ "a revocation that works at the second attempt is no warning" 0 "Uploaded axess"
quiet_ "nothing is warned of" "::warning::"
# A run cancelled, or stopped by a timeout, while cargo uploads: the runner
# signals the step, and the token issued for that upload is revoked on the
# way out.
reset; export CARGO_axess_rng=interrupted
run_ "a run stopped in the middle of an upload leaves with the signal's status" 143 "OK: crates.io holds the attested axess-clock 0.20.0"
if kill -0 "$(cat "$WORK/cargo.pid")" 2>/dev/null; then
  failed=$((failed + 1)); echo "FAIL: cargo is stopped with the step: it is still running" >&2
  kill "$(cat "$WORK/cargo.pid")"
else passed=$((passed + 1)); fi
logged_ "the token of the upload under way is revoked, asked once and briefly" \
  "curl DELETE https://crates.io/api/v1/trusted_publishing/tokens retry=[0] time=[5] agent=[$AGENT] to=[file] headers=[|@Authorization: Bearer cio_tp_3]" 1
logged_ "every token issued is revoked" "curl DELETE" 3
logged_ "and the step did not wait for cargo to end by itself" "cargo outlived the step" 0
logged_ "and nothing after it is published" "cargo publish" 3
reset; export CARGO_axess_rng=interrupted REVOKE_STATUS=500 REVOKE_BODY='<html>busy</html>'
run_ "a stopped run whose token is not revoked says so" 143 \
  "::warning::the token issued to publish axess-rng was not revoked on the way out; it ends by itself when its short lifetime runs out."

# ── What crates.io holds is the attested file ─────────────────────
reset
run_ "every crate is compared with its attested file" 0 "OK: crates.io holds the attested axess 0.20.0 ($(sha256sum -- "$WORK/checkout/attested/target/package/axess-0.20.0.crate" | cut -d' ' -f1))."
logged_ "the index is read once for each crate" "curl GET https://index.crates.io/ax/es/" 11
logged_ "at the crate's own file, and told who asks" \
  "curl GET https://index.crates.io/ax/es/axess-core retry=[2] time=[30] agent=[$AGENT] to=[file] headers=[] data=[]" 1
reset; export INDEX_axess_events=other
run_ "a published crate that is not the attested file stops the job by name" 1 \
  "::error::refused: crates.io holds axess-events 0.20.0 with SHA-256 $(printf 'b%.0s' $(seq 1 64)), and the attested file has $(sha256sum -- "$WORK/checkout/attested/target/package/axess-events-0.20.0.crate" | cut -d' ' -f1). They are not the same file."
logged_ "the crate itself was uploaded" "cargo publish --locked --no-verify -p axess-events" 1
logged_ "and no crate after it" "cargo publish --locked --no-verify -p axess-cache" 0
reset; export CARGO_axess_strings=uploaded INDEX_axess_strings=other
run_ "a crate already there that is not the attested file stops the job by name" 1 \
  "::error::refused: crates.io holds axess-strings 0.20.0 with SHA-256 $(printf 'b%.0s' $(seq 1 64))"
printed_ "after cargo said it was there" "::notice::axess-strings already published; skipping"
logged_ "and no crate after it is published" "cargo publish" 1
reset; export CARGO_axess_strings=exists INDEX_axess_strings=other
run_ "under cargo's own wording too" 1 "::error::refused: crates.io holds axess-strings 0.20.0 with SHA-256"
reset; export INDEX_axess_clock=late
run_ "a version the index lists a moment later is waited for" 0 "OK: crates.io holds the attested axess-clock 0.20.0"
logged_ "it is read until it lists the version" "curl GET https://index.crates.io/ax/es/axess-clock" 3
logged_ "30 seconds apart" "sleep 30" 13
reset; export INDEX_axess_clock=never
run_ "a version the index never lists stops the job by name" 1 \
  "::error::refused: crates.io's index did not list axess-clock 0.20.0 in 10 reads (curl exit 0)"
logged_ "after ten reads" "curl GET https://index.crates.io/ax/es/axess-clock" 10
logged_ "and no crate after it is published" "cargo publish" 2
reset; export INDEX_axess_strings=missing
run_ "a crate the index does not know stops the job by name" 1 "did not list axess-strings 0.20.0 in 10 reads (curl exit 22)"
reset; export INDEX_axess_strings=gone
run_ "a crate the index answers is gone is not compared and stops the job" 1 "did not list axess-strings 0.20.0 in 10 reads (curl exit 22)"
reset; export INDEX_axess_strings=withheld
run_ "a crate the index withholds is not compared and stops the job" 1 "did not list axess-strings 0.20.0 in 10 reads (curl exit 22)"
reset; export INDEX_axess_strings=garbage
run_ "an index answer that is not the index stops the job by name" 1 "did not list axess-strings 0.20.0 in 10 reads (curl exit 0)"
reset; export INDEX_axess_strings=flaky
run_ "an index answer that came at the second attempt is read alone" 0 "OK: crates.io holds the attested axess-strings 0.20.0"
logged_ "in one call" "curl GET https://index.crates.io/ax/es/axess-strings" 1
# The attested files are all there before anything is published.
reset; rm "$WORK/checkout/attested/target/package/axess-core-0.20.0.crate"
run_ "a crate with no attested file is refused before the first publish" 1 "::error::refused: the attested files hold 0 packages of axess-core, not one."
logged_ "nothing is published" "cargo publish" 0
logged_ "and nobody is asked" "curl" 0
reset; printf 'another\n' >"$WORK/checkout/attested/target/package/axess-0.20.1.crate"
run_ "two attested versions of a crate are refused" 1 "::error::refused: the attested files hold 2 packages of axess, not one."
logged_ "nothing is published" "cargo publish" 0

echo "release-publish tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
