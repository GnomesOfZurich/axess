# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: what a script runs in a job that
# names a secret, may ask for an OIDC token or holds a token that can write.
# Such a job runs only what the check reads. Sourced by
# scripts/check-workflow-pins-tests.sh.

HELD_FILES=(scripts/check.sh '#!/usr/bin/env bash
echo checked')

# A program the check does not name may run its arguments, write a file or
# be one a step put on the path.
UNNAMED="$HELD, line 7: a program the check does not name"
held_case "a container beside a secret is refused" 1 "$UNNAMED (docker)" 'docker run --rm "$IMAGE" "$COMMAND"'
held_case "an editor that runs a command beside a secret is refused" 1 "$UNNAMED (vim)" 'vim -c "!cargo build" -c q'
held_case "a program that runs its arguments beside a secret is refused" 1 "$UNNAMED (setsid)" 'setsid "$COMMAND"'
held_case "a program that copies a file beside a secret is refused" 1 "$UNNAMED (cp)" 'cp tool "$HOME/.cargo/bin/cargo-publish"'
held_case "a program that makes a file runnable beside a secret is refused" 1 "$UNNAMED (chmod)" 'chmod +x tool'
held_case "a program that unpacks an archive beside a secret is refused" 1 "$UNNAMED (tar)" 'tar -xf tools.tar --to-command=sh'
held_case "a program that writes its input to a file beside a secret is refused" 1 "$UNNAMED (tee)" 'echo x | sudo tee /usr/local/bin/git'
held_case "a download beside a secret is refused" 1 "$UNNAMED (wget)" 'wget https://example.invalid/tool'
held_case "rustup beside a secret is refused" 1 "$UNNAMED (rustup)" 'rustup component add clippy'
held_case "a compiler beside a secret is refused" 1 "$UNNAMED (rustc)" 'rustc tool.rs'
held_case "an unnamed program in the middle of a pipeline is refused" 1 "$UNNAMED (frob)" 'echo a | frob | cat'
held_case "an unnamed program after sudo is refused" 1 "$UNNAMED (dockerd)" 'sudo -E dockerd'
held_case "an unnamed program in a substitution is refused" 1 "$UNNAMED (frob)" 'value=$(frob)'
held_case "an unnamed program in the string of a trap is refused" 1 "$UNNAMED (frob)" 'trap "frob" EXIT'
held_case "an unnamed program named by a path of the image is refused" 1 "$UNNAMED (docker)" '/usr/bin/docker ps'
held_case "a word of the grammar written in quotes is a program" 1 "$UNNAMED (fi)" '"fi" now'
held_case "a second refusal names its own line" 1 "$HELD, line 8: a program the check does not name (frob)" 'echo one' 'frob'
free_case "a container in a job that holds nothing passes" 'docker run --rm "$IMAGE" "$COMMAND"'
free_case "a copy and a checked download in a job that holds nothing pass" 'set -e' 'curl -sSfL -o tool https://example.invalid/tool' 'echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  tool" | sha256sum --check -' 'chmod +x tool' 'cp tool target/tool'
held_case "the builtins, filters and readers of a release pass beside a secret" 0 "OK: every action" \
  'set -euo pipefail' \
  'attempt=0' \
  'while [ "$attempt" -lt 10 ]; do attempt=$((attempt + 1)); done' \
  'if out=$(cargo publish --locked -p "$crate" 2>&1); then echo "$out"; fi' \
  'if printf "%s" "$out" | grep -qiE "already uploaded|already exists"; then echo skip; fi' \
  'after=$(printf "%s" "$out" | grep -oiE "try again after [^.]*GMT" | sed -E "s/.*after //I")' \
  'target=$(date -u -d "$after" +%s 2>/dev/null || echo 0)' \
  'sleep "$wait"; [ -n "$after" ] || { echo "::error::none"; exit 1; }' \
  'case "$GITHUB_REF" in refs/tags/v*) ;; *) exit 1 ;; esac' \
  'for c in axess-strings axess; do echo "$c"; done' \
  'version=$(sed -n "s/^version *= *\"\\(.*\\)\".*/\\1/p" Cargo.toml | head -1 | tr -d " " | cut -d. -f1)' \
  'count=$(awk -v start="$n" "NR > start { n++ } END { print n + 0 }" CHANGELOG.md | wc -l)' \
  'auth=$(printf "x-access-token:%s" "$TOKEN" | base64 | tr -d "\n")' \
  'jq -r --arg c "$crate" ".crate" <<<"$answer" >/dev/null' \
  'mkdir -p "$RUNNER_TEMP/out"; work=$(mktemp -d); trap "rm -rf \"\$work\"" EXIT' \
  'sha256sum -- target/package/*.crate | sort -u | uniq -c' \
  'diff -u attested/crates.sha256 "$RUNNER_TEMP/here.sha256"' \
  '/usr/bin/git status --short'
held_case "a function of the script is not a program" 0 "OK: every action" 'publish() { cargo publish --locked -p "$1"; }' 'publish axess'
held_case "a function named as an unnamed program is the function" 0 "OK: every action" 'docker() { echo "docker $*"; }' 'docker ps'
held_case "a function behind the command builtin is a program" 1 "$HELD, line 8: a program the check does not name (docker)" 'docker() { echo skipped; }' 'command docker ps'
held_case "a function behind env is a program" 1 "$HELD, line 8: a program the check does not name (docker)" 'docker() { echo skipped; }' 'env docker ps'
held_case "a function removed by unset leaves the program" 1 "$HELD, line 8: a function removed with unset: the program of its name runs after it" 'docker() { echo skipped; }' 'unset -f docker' 'docker ps'

# The rule holds for a token that can write, a token with the repository's
# default permissions and a job that may ask for an OIDC token.
permission_case() { # permission_case NAME FRAGMENT PERMISSIONS
  TRAILER='' case_ "$1" 1 "$2" p.yml "jobs:
  a:$3
    steps:
      - run: docker ps"
}
permission_case "an unnamed program under a token that can write is refused" "a job whose token can write runs what the check does not read: job a, line 6: a program the check does not name (docker) (give the job read permissions)" "
    permissions:
      contents: write"
permission_case "an unnamed program under an OIDC permission is refused" "a job that may ask for an OIDC token runs what the check does not read: job a, line 6: a program the check does not name (docker)" "
    permissions:
      id-token: write"
permission_case "an unnamed program under the default permissions is refused" "a job whose token has the repository's default permissions runs what the check does not read: job a, line 4: a program the check does not name (docker) (declare permissions: contents: read)" ""

# A repository file is the file the check read when it is named from the
# repository's root: by its path, or under $GITHUB_WORKSPACE.
held_case "a repository script by its path passes beside a secret" 0 "OK: every action" './scripts/check.sh' 'bash scripts/check.sh' '. scripts/check.sh'
held_case "a repository script under the workspace passes beside a secret" 0 "OK: every action" '"$GITHUB_WORKSPACE/scripts/check.sh"' 'bash "${GITHUB_WORKSPACE}/scripts/check.sh"'
THROUGH="a repository file named through a variable"
held_case "a repository script named through a variable is refused" 1 "$HELD, line 7: $THROUGH (\"\$DIR/scripts/check.sh\")" '"$DIR/scripts/check.sh"'
held_case "a script of the repository's name in the temporary directory is refused" 1 "$HELD, line 8: $THROUGH (\"\$RUNNER_TEMP/check.sh\")" 'curl -sSf https://example.invalid/check.sh > "$RUNNER_TEMP/check.sh"' 'bash "$RUNNER_TEMP/check.sh"'
held_case "a script sourced through a variable is refused" 1 "$HELD, line 7: $THROUGH (\"\$DIR/scripts/check.sh\")" '. "$DIR/scripts/check.sh"'
free_case "a repository script named through a variable in a job that holds nothing passes" '"$DIR/scripts/check.sh"'
AFTER_CD="a repository file run after a change of directory"
held_case "a repository script after a change of directory is refused" 1 "$HELD, line 7: $AFTER_CD (./scripts/check.sh)" 'cd "$RUNNER_TEMP/unpacked" && ./scripts/check.sh'
held_case "a repository script after pushd is refused" 1 "$HELD, line 8: $AFTER_CD (scripts/check.sh)" 'pushd unpacked' 'bash scripts/check.sh'
held_case "a repository script in the text of sh -c after a change of directory is refused" 1 "$HELD, line 8: $AFTER_CD (./scripts/check.sh)" 'cd unpacked' 'sh -c "./scripts/check.sh"'
held_case "a repository script after a change of directory in a function is refused" 1 "$HELD, line 8: $AFTER_CD (./scripts/check.sh)" 'enter() { cd unpacked; }' 'enter; ./scripts/check.sh'
held_case "a change of directory in a subshell moves the subshell alone" 0 "OK: every action" '(cd target/package && sha256sum -- *.crate) > "$RUNNER_TEMP/sums"' './scripts/check.sh'
held_case "a change of directory in a substitution moves the substitution alone" 0 "OK: every action" 'here="$(cd "$(dirname "$0")" && pwd)"' './scripts/check.sh'
held_case "a script in a subshell after its change of directory is refused" 1 "$HELD, line 7: $AFTER_CD (./scripts/check.sh)" '(cd unpacked && ./scripts/check.sh)'
held_case "a return to the workspace puts paths back at the root" 0 "OK: every action" 'cd unpacked' 'ls' 'cd "$GITHUB_WORKSPACE"' './scripts/check.sh'
held_case "a repository script under the workspace after a change of directory passes" 0 "OK: every action" 'cd unpacked' '"$GITHUB_WORKSPACE/scripts/check.sh"'
case_ "a repository script in a step with a working directory is refused" 1 "$HELD, line 7: $AFTER_CD (./scripts/check.sh)" h.yml "jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - working-directory: unpacked
        run: ./scripts/check.sh" "${HELD_FILES[@]}"
case_ "a repository script under a default working directory is refused" 1 "$HELD, line 9: $AFTER_CD (./scripts/check.sh)" h.yml "jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    defaults:
      run:
        working-directory: unpacked
    steps:
      - run: ./scripts/check.sh" "${HELD_FILES[@]}"
HELD_FILES=(scripts/check.sh '#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")/.."
./scripts/inner.sh' scripts/inner.sh 'echo inner')
held_case "a script that returns to the root by its own directory runs another by its path" 0 "OK: every action" './scripts/check.sh'
HELD_FILES=(scripts/check.sh '#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"
./scripts/inner.sh' scripts/inner.sh 'echo inner')
held_case "a script that moves to its own directory does not run another by a path from the root" 1 "$HELD, scripts/check.sh line 3: $AFTER_CD (./scripts/inner.sh)" './scripts/check.sh'
HELD_FILES=(scripts/tool '#!/usr/bin/env node
require("child_process").execSync("npm install -g tool")')
held_case "a repository program in another language is refused" 1 "$HELD, scripts/tool line 1: a repository program that is neither a shell nor a Python script" './scripts/tool'
free_case "a repository program in another language in a job that holds nothing passes" './scripts/tool'
HELD_FILES=(scripts/lib.sh 'helper() { echo helped; }' scripts/check.sh 'echo checked')
held_case "a function of a sourced repository script is not a program" 0 "OK: every action" '. scripts/lib.sh' 'helper now'
held_case "a function that no sourced script defines is a program" 1 "$HELD, line 8: a program the check does not name (helper)" '. scripts/check.sh' 'helper now'
HELD_FILES=(scripts/check.sh 'echo checked')

# A signal is the shell's own to send.
held_case "a signal sent from a trap passes" 0 "OK: every action" "trap 'kill 0' EXIT"
held_case "git by its path in the image passes" 0 "OK: every action" '/usr/bin/git status'
