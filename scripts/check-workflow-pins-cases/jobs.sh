# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: no job that names a secret, may
# ask for an OIDC token or holds a token that can write installs a tool, and
# a workflow that publishes builds with an exact toolchain. Sourced by
# scripts/check-workflow-pins-tests.sh.

SECRET_MESSAGE="a job that names a secret installs a tool on the same runner"
OIDC_MESSAGE="a job that may ask for an OIDC token installs a tool on the same runner"

case_ "a job that names a secret and installs a tool is refused" 1 "$SECRET_MESSAGE: job publish, cargo install at line 9" release.yml "jobs:
  publish:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
      - name: Audit
        run: |
          cargo install cargo-audit@0.22.2 --locked
          cargo audit
      - name: Publish
        env:
          CARGO_REGISTRY_TOKEN: \${{ secrets.CARGO_REGISTRY_TOKEN }}
        run: cargo publish --locked"
case_ "the install in a job of its own passes" 0 "OK: every action" release.yml "jobs:
  audit:
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked
  publish:
    needs: [audit]
    steps:
      - name: Publish
        env:
          CARGO_REGISTRY_TOKEN: \${{ secrets.CARGO_REGISTRY_TOKEN }}
        run: cargo publish --locked"
# The release workflow's shape: the audit at release in a job with no
# secret, the registry token in a publish job that installs nothing.
case_ "the audit at release in the job that publishes is refused" 1 "$SECRET_MESSAGE: job publish, cargo install at line 5" release.yml "jobs:
  publish:
    steps:
      - run: |
          cargo install cargo-audit@0.22.2 --locked
          cargo audit --file Cargo.lock --deny warnings
      - env:
          CARGO_REGISTRY_TOKEN: \${{ secrets.CARGO_REGISTRY_TOKEN }}
        run: cargo publish --locked -p axess"
case_ "a repository script a secret job runs is read for installs" 1 "$SECRET_MESSAGE: job publish, cargo install at line 4 (scripts/tools.sh, line 1)" release.yml "jobs:
  publish:
    steps:
      - run: scripts/tools.sh
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked" scripts/tools.sh "cargo install --locked cargo-audit@0.22.2"

# secret_case NAME EXPRESSION [INSTALL LINE]: an expression in a later step's env.
secret_case() {
  case_ "$1" 1 "$SECRET_MESSAGE: job publish, cargo install at line 4" s.yml "jobs:
  publish:
    steps:
      - run: ${3:-cargo install cargo-audit@0.22.2 --locked}
      - env:
          TOKEN: \${{ $2 }}
        run: cargo publish --locked"
}
# not_secret_case NAME EXPRESSION: the same, and the job passes.
not_secret_case() {
  case_ "$1" 0 "OK: every action" s.yml "jobs:
  publish:
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked
      - env:
          VALUE: \${{ $2 }}
        run: cargo audit"
}
secret_case "a secret named by a dot is seen" "secrets.TOKEN"
secret_case "a secret named by a single-quoted index is seen" "secrets['TOKEN']"
secret_case "a secret named in another case is seen" "SECRETS.TOKEN"
secret_case "an index after a space is seen" "secrets ['TOKEN']"
secret_case "the whole secrets context handed to a function is seen" "toJSON(secrets)"
secret_case "the secrets context as the first of two arguments is seen" "contains(secrets, 'x')"
secret_case "the secrets context named whole is seen" "secrets"
secret_case "the object filter on the secrets context is seen" "toJSON(secrets.*)"
secret_case "the secrets context between operators is seen" "toJSON(1 && secrets || 0)"
secret_case "an install under a numbered toolchain is seen beside a secret" "secrets.TOKEN" "cargo +1.98.0 install --locked cargo-audit@0.22.2"
secret_case "an install after cargo's own flag is seen beside a secret" "secrets.TOKEN" "cargo --locked install cargo-audit@0.22.2"
secret_case "an install by the quoted CARGO variable is seen beside a secret" "secrets.TOKEN" 'command "$CARGO" install --locked cargo-audit@0.22.2'
# A command the check cannot read counts as an install beside a secret.
for script in '$c' '$CARGO $SUB cargo-audit' '"${tools[@]}"' '$(echo cargo) install --locked cargo-audit@0.22.2'; do
  case_ "the command $script is refused beside a secret" 1 "$SECRET_MESSAGE: job publish, a command it cannot read at line 4" s.yml "jobs:
  publish:
    steps:
      - run: $script
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"
done
# A quoted program whose name a variable fills in may be a shell, eval, an
# interpreter or a task runner, whose script is then not read: beside a
# secret it counts as an install.
for script in '"$c" -c "cargo install cargo-audit"' '"$c" "cargo install cargo-audit"' '"$c" default stable' \
  '"${CARGO:-cargo}" build' '"$X"sh -c true' '"$(command -v make)" tools' 'command "$f" "${@:1}"'; do
  case_ "the program of $script is refused beside a secret" 1 "$SECRET_MESSAGE: job publish, a program whose name comes from a variable" s.yml "jobs:
  publish:
    steps:
      - run: |
          $script
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"
done
case_ "a quoted program from a variable passes in a job with a read-only token" 0 "OK: every action" s.yml 'jobs:
  test:
    steps:
      - run: |
          CHECK="${CHECK:-scripts/check.sh}"
          "$CHECK" "$dir"'
case_ "a program named by its path after an expansion is read by its name" 1 "line 5: cargo install without --locked" s.yml 'jobs:
  test:
    steps:
      - run: |
          "$X/bash" -c "cargo install cargo-audit"'
# A program that hands a string to a shell is read as `sh -c` text; a git
# setting, an awk or sed program or a variable that runs another program,
# and a command composer, are refused by name.
for script in "env -S 'cargo install cargo-audit'" "flock /tmp/lock -c 'cargo install cargo-audit'" \
  "su -c 'cargo install cargo-audit'" "script -qc 'cargo install cargo-audit' /dev/null" \
  "watch -n1 'cargo install cargo-audit'" "trap 'cargo install cargo-audit' EXIT" \
  "ssh -p 22 localhost 'cargo install cargo-audit'"; do
  case_ "the string of $script is read beside a secret" 1 "$SECRET_MESSAGE: job publish, cargo install at line 5" s.yml "jobs:
  publish:
    steps:
      - run: |
          $script
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"
done
for pair in "git config alias.t '!cargo install cargo-audit'|a git setting that can run a program is not read: alias.t" \
  "git -c core.hooksPath=hooks commit|a git setting that can run a program is not read: core.hooksPath" \
  "awk 'BEGIN { system(\"cargo install cargo-audit\") }'|an awk program that runs another program" \
  "sed -n '1e cargo install cargo-audit' Cargo.toml|a sed program that runs a command" \
  "sed 's/^/cargo install /e' tools.txt|a sed program that runs a command" \
  "parallel ::: 'cargo install cargo-audit'|parallel builds the commands it runs from its input"; do
  case_ "the command ${pair%%|*} is refused beside a secret" 1 "line 5: ${pair#*|}" s.yml "jobs:
  publish:
    steps:
      - run: |
          ${pair%%|*}
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"
done
for variable in BASH_ENV PS4 PROMPT_COMMAND GIT_SSH_COMMAND LD_PRELOAD; do
  case_ "the variable $variable in an env is refused" 1 "line 4: $variable makes a program run another one" s.yml "jobs:
  test:
    env:
      $variable: x
    steps:
      - run: cargo test --locked"
  block_case "the variable $variable in a script is refused" 1 "line 5: $variable makes a program run another one" "$variable=x bash -c true"
done
case_ "honest uses of git, awk, sed and trap pass beside a secret" 0 "OK: every action" s.yml 'jobs:
  publish:
    steps:
      - run: |
          git config user.name "bot"
          git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $auth" push
          w=$(awk -v w="$width" '"'"'BEGIN { printf "%.1f", w / 2 }'"'"')
          v=$(sed -n '"'"'s/^version *= *"\([^"]*\)".*/\1/p'"'"' Cargo.toml | head -1)
          trap '"'"'rm -rf "$WORK"'"'"' EXIT
      - env:
          TOKEN: ${{ secrets.TOKEN }}
        run: cargo publish --locked'
# What a step writes to $GITHUB_ENV is held to the rules on variables, and
# a directory a step puts on the path counts as an install beside a secret.
for pair in 'echo "BASH_ENV=./setup.sh" >> "$GITHUB_ENV"=>line 5: BASH_ENV makes a program run another one' \
  'echo "CARGO_HOME=./home" >> "$GITHUB_ENV"=>line 5: CARGO_HOME changes what cargo installs or runs' \
  'echo "$NAME=x" >> "$GITHUB_ENV"=>line 5: a write to $GITHUB_ENV the check cannot read' \
  'echo X=1 | tee -a "$GITHUB_ENV"=>line 5: a write to $GITHUB_ENV the check cannot read' \
  'echo "$PWD/bin" >> "$GITHUB_PATH"=>job publish, a directory put on the path at line 5' \
  'export PATH="$PWD/bin:$PATH"=>job publish, a directory put on the path at line 5' \
  'hash -p ./bin/tool cargo=>job publish, a directory put on the path at line 5'; do
  case_ "the line ${pair%%=>*} is refused beside a secret" 1 "${pair#*=>}" s.yml "jobs:
  publish:
    steps:
      - run: |
          ${pair%%=>*}
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"
done
for pair in 'env BASH_ENV=./setup.sh bash -c true=>line 5: BASH_ENV makes a program run another one' \
  'sudo -E RUSTC_WRAPPER=./wrap cargo build=>line 5: RUSTC_WRAPPER changes what cargo installs or runs' \
  'enable -f ./builtin.so cargo=>line 5: a builtin loaded from a file is not read (enable -f)'; do
  case_ "the line ${pair%%=>*} is refused beside a secret" 1 "${pair#*=>}" s.yml "jobs:
  publish:
    steps:
      - run: |
          ${pair%%=>*}
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"
done
case_ "a floating toolchain written for the later steps beside a publish is refused" 1 "line 5: a toolchain that is not an exact version (stable)" s.yml 'jobs:
  publish:
    steps:
      - run: |
          echo "RUSTUP_TOOLCHAIN=stable" >> "$GITHUB_ENV"
      - env:
          TOKEN: ${{ secrets.TOKEN }}
        run: cargo publish --locked'
case_ "a plain variable written for the later steps passes beside a secret" 0 "OK: every action" s.yml 'jobs:
  publish:
    steps:
      - run: |
          echo "PCT=75" >> "$GITHUB_ENV"
          printf "VERSION=1.2.3\n" >> "$GITHUB_ENV"
      - env:
          TOKEN: ${{ secrets.TOKEN }}
        run: cargo publish --locked'
case_ "a directory put on the path passes in a job with a read-only token" 0 "OK: every action" s.yml 'jobs:
  test:
    steps:
      - run: |
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
          PATH="$PWD/bin:$PATH" cargo test --locked'
secret_case "an install with a quoted subcommand is seen beside a secret" "secrets.TOKEN" 'cargo "install" --locked cargo-audit@0.22.2'
secret_case "the job token named by a dot is seen" "github.token"
secret_case "the job token named by an index is seen" "github['token']"
secret_case "the job token named in another case is seen" "GitHub.Token"
secret_case "the job token after a space before the dot is seen" "github .token"
secret_case "the whole github context handed to a function is seen" "toJSON(github)"
secret_case "the github context at the start of an expression is seen" "github"
secret_case "the github context after a space and a parenthesis is seen" "toJSON (github)"
secret_case "the github context between spaces in a function is seen" "toJSON( github )"
secret_case "the github context as the first of two arguments is seen" "contains(github, 'x')"
secret_case "the github context as a later argument is seen" "format('{0}', 1, github, 2)"
secret_case "the github context before an or is seen" "toJSON(github || 0)"
secret_case "the github context after an and is seen" "toJSON(true&&github)"
secret_case "the github context right after a negation is seen" "toJSON(!github)"
secret_case "the github context right after a comparison is seen" "toJSON(1==github)"
secret_case "the github context right after a less-than sign is seen" "toJSON(1<github)"
secret_case "the github context in brackets is seen" "toJSON(fromJSON('{}')[github])"
secret_case "the github context in parentheses of its own is seen" "toJSON((github))"
secret_case "the github context after a tab is seen" "toJSON(	github)"
secret_case "the object filter on the github context is seen" "toJSON(github.*)"
not_secret_case "a property of the github context that is not the token names nothing" "github.ref"
not_secret_case "a property of a property of the github context names nothing" "github.event.sender.login"
not_secret_case "a property named github of another object names nothing" "toJSON(matrix.github)"
not_secret_case "a property named github of another object before .token names nothing" "x.github.token"
not_secret_case "a property named secrets of another object names nothing" "steps.secrets.outputs.value"
not_secret_case "a string that holds the word names nothing" "format('{0}', 'secrets.TOKEN')"
not_secret_case "a function named like a context names nothing" "github(1)"
# A character the grammar does not hold leaves the expression unread, and
# an unread expression counts as one that names a secret.
for spelling in '{github}' '$github' '"github"' 'x:github' '+github' '@github' '~github'; do
  case_ "the expression toJSON($spelling) is refused as unread" 1 "an expression the check cannot read" s.yml "jobs:
  publish:
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked
      - env:
          VALUE: \${{ toJSON($spelling) }}
        run: cargo audit"
done
case_ "an expression that does not close is refused" 1 "an expression the check cannot read: an expression that does not close" s.yml "jobs:
  publish:
    steps:
      - run: echo \${{ github.ref"

# Text outside an expression names nothing: a step name, a script, a
# trailing comment, a directory, a sentence.
prose_case() { # prose_case NAME STEP_NAME SCRIPT_LINE
  case_ "$1" 0 "OK: every action" p.yml "jobs:
  audit:
    steps:
      - name: $2
        run: |
          cargo install --locked cargo-audit@0.22.2
          $3"
}
prose_case "a step name that reads like the secrets context names nothing" "Audit (no secrets)" "true"
prose_case "a step name that reads like the github context names nothing" "Publish the notes (GitHub)" "true"
prose_case "a sentence that ends in the word names nothing" "Audit" "echo Released on GitHub && true"
for line in 'cd .github && ls' 'cd src/github && ls' 'x=$(ls .github)' 'ls github/workflows || true' 'cd secrets && ls' 'x=$(ls .secrets)' 'cat config/secrets || true' 'echo secrets, github, done'; do
  prose_case "the script line $line names nothing" "Audit" "$line"
done
case_ "a trailing comment that reads like a secret names nothing" 0 "OK: every action" p.yml "jobs:
  audit:
    steps:
      - run: cargo install --locked cargo-audit@0.22.2 # holds no secrets.TOKEN"
case_ "a secret in an expression in a script comment is seen" 1 "$SECRET_MESSAGE: job publish, cargo install at line 6" c.yml "jobs:
  publish:
    steps:
      - run: |
          # curl -H \"Authorization: Bearer \${{ secrets.TOKEN }}\" https://example.invalid
          cargo install --locked cargo-audit@0.22.2"
case_ "a secret in a step name expression is seen" 1 "$SECRET_MESSAGE: job publish, cargo install at line 5" c.yml "jobs:
  publish:
    steps:
      - name: Install for \${{ secrets.WHO }}
        run: cargo install --locked cargo-audit@0.22.2"
case_ "a secret in an if is seen without the braces" 1 "$SECRET_MESSAGE: job publish, cargo install at line 6" c.yml "jobs:
  publish:
    steps:
      - if: secrets.TOKEN != ''
        run: |
          cargo install --locked cargo-audit@0.22.2"
case_ "an if on the github context that names no token arms nothing" 0 "OK: every action" c.yml "jobs:
  audit:
    if: github.actor != 'github-actions[bot]' && github.event_name == 'push'
    steps:
      - run: cargo install --locked cargo-audit@0.22.2"
case_ "an expression over two lines is read" 1 "$SECRET_MESSAGE: job publish, cargo install at line 8" u.yml "jobs:
  publish:
    env:
      TOKEN: >-
        \${{ secrets
        .TOKEN }}
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
case_ "the github context right after a YAML escape is read" 1 "$SECRET_MESSAGE: job publish, cargo install at line 6" u.yml "jobs:
  publish:
    env:
      TOKEN: \"\${{ toJSON(\\tgithub) }}\"
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
case_ "a parenthesis written as a YAML escape is read" 1 "$SECRET_MESSAGE: job publish, cargo install at line 6" u.yml "jobs:
  publish:
    env:
      TOKEN: \"\${{ toJSON\\x28github) }}\"
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
case_ "a secret a job takes through an alias to another job is seen" 1 "$SECRET_MESSAGE: job audit, cargo install at line 10" u.yml "jobs:
  publish:
    env: &env
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: cargo publish --locked
  audit:
    env: *env
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
case_ "a secret in the workflow's own env counts for every job" 1 "$SECRET_MESSAGE: job audit, cargo install at line 6" shared.yml "env:
  TOKEN: \${{ secrets.TOKEN }}
jobs:
  audit:
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
case_ "a secret named only in a YAML comment arms nothing" 0 "OK: every action" comment.yml "# the publish job reads \${{ secrets.TOKEN }} in release.yml
jobs:
  audit:
    steps:
      # no \${{ secrets.TOKEN }} on this runner
      - run: cargo install cargo-audit@0.22.2 --locked"
for key in '"jobs":' "'jobs':" 'jobs :'; do
  case_ "the jobs key $key is the jobs key" 1 "$SECRET_MESSAGE: job publish, cargo install at line 6" j.yml "$key
  publish:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: cargo install --locked cargo-audit@0.22.2"
done
case_ "jobs indented four spaces are read as jobs" 1 "$SECRET_MESSAGE: job publish, cargo install at line 4" deep.yml "jobs:
    publish:
        steps:
            - run: cargo install cargo-audit@0.22.2 --locked
            - env:
                  TOKEN: \${{ secrets.TOKEN }}
              run: cargo publish --locked"

# A job that may ask for an OIDC token, whose token can write, or whose
# permissions are not declared installs no tool: every step that uses an
# action can reach the job's token without naming it.
TRAILER='' case_ "a job that may ask for an OIDC token and installs a tool is refused" 1 "$OIDC_MESSAGE: job attest, cargo install at line 6" o.yml "jobs:
  attest:
    permissions:
      id-token: write
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a quoted OIDC permission with a quoted value is the same permission" 1 "$OIDC_MESSAGE: job attest, cargo install at line 6" o.yml "jobs:
  attest:
    permissions:
      \"id-token\": \"write\"
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "every permission at once carries the OIDC one" 1 "$OIDC_MESSAGE: job audit, cargo install at line 5" o.yml "jobs:
  audit:
    permissions: write-all
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a permission whose value stands on the line after its key is read" 1 "$OIDC_MESSAGE: job attest, cargo install at line 7" o.yml "jobs:
  attest:
    permissions:
      id-token:
        write
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a permission behind a tag is refused by name" 1 "not read as YAML: a YAML tag" o.yml "jobs:
  attest:
    permissions:
      id-token: !!str write
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a job that names a secret and may ask for an OIDC token is refused for its secret" 1 "$SECRET_MESSAGE: job attest, cargo install at line 8" o.yml "jobs:
  attest:
    permissions:
      id-token: write
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a job whose token can write and installs a tool is refused" 1 "a job whose token can write installs a tool on the same runner: job audit, cargo install at line 6" o.yml "jobs:
  audit:
    permissions:
      contents: write
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a job with undeclared permissions that installs a tool is refused" 1 "a job whose token has the repository's default permissions installs a tool on the same runner: job audit, cargo install at line 4" o.yml "jobs:
  audit:
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a job's own permissions replace the workflow's" 0 "OK: every action" o.yml "permissions:
  contents: write
jobs:
  audit:
    permissions:
      contents: read
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "the workflow's permissions hold for a job with none" 1 "a job whose token can write installs a tool" o.yml "permissions:
  contents: write
jobs:
  audit:
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"
TRAILER='' case_ "a job without the OIDC permission installs its tool" 0 "OK: every action" o.yml "jobs:
  audit:
    permissions:
      contents: read
      id-token: none
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked
  attest:
    permissions:
      id-token: write
    steps:
      - run: echo attest"
TRAILER='' case_ "a permission level the check does not read is refused" 1 "a permission the check does not read: contents" o.yml "jobs:
  audit:
    permissions:
      contents: \${{ inputs.level }}
    steps:
      - run: cargo audit"
TRAILER='' case_ "the OIDC permission on the whole workflow is refused" 1 "line 3: the OIDC permission stands on the whole workflow" o.yml "permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - run: echo deploy"
TRAILER='' case_ "every permission on the whole workflow is refused" 1 "line 1: every permission, the OIDC one included, stands on the whole workflow" o.yml "permissions: write-all
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - run: echo deploy"
case_ "the OIDC permission in a YAML comment arms nothing" 0 "OK: every action" o.yml "jobs:
  audit:
    # id-token: write
    steps:
      - run: cargo install cargo-audit@0.22.2 --locked"

# In a workflow with a job that names a secret or may ask for an OIDC
# token, every toolchain is an exact release.
TOOLCHAIN_MESSAGE="a toolchain that is not an exact version"
toolchain_case() { # toolchain_case NAME EXPECTED_EXIT FRAGMENT TOOLCHAIN [PUBLISH_ENV]
  case_ "$1" "$2" "$3" t.yml "jobs:
  package:
    steps:
      - uses: dtolnay/rust-toolchain@$SHA # master
        with:
          toolchain: $4
      - run: cargo package --locked
  publish:
    steps:
      - env:
          TOKEN: \${{ ${5:-secrets.TOKEN} }}
        run: cargo publish --locked"
}
toolchain_case "a floating toolchain beside a publish is refused" 1 "line 6: $TOOLCHAIN_MESSAGE (stable)" stable
toolchain_case "a two-part toolchain beside a publish is refused" 1 "line 6: $TOOLCHAIN_MESSAGE (1.98)" 1.98
toolchain_case "an exact toolchain beside a publish passes" 0 "OK: every action" 1.98.0
toolchain_case "a dated nightly beside a publish passes" 0 "OK: every action" nightly-2026-01-01
toolchain_case "a floating toolchain in a workflow that holds no secret passes" 0 "OK: every action" stable github.ref
case_ "a rust-toolchain step that names no toolchain beside a publish is refused" 1 "$TOOLCHAIN_MESSAGE (none named)" t.yml "jobs:
  package:
    steps:
      - uses: dtolnay/rust-toolchain@$SHA # master
  publish:
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: echo done"
case_ "a floating toolchain selector beside a publish is refused" 1 "line 5: $TOOLCHAIN_MESSAGE (stable)" t.yml "jobs:
  package:
    steps:
      - run: |
          cargo +stable package --locked
  publish:
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: echo done"
for command in 'rustup toolchain install stable' 'rustup install beta' 'rustup default stable' 'rustup override set nightly' 'rustup run stable cargo build'; do
  case_ "the toolchain of $command beside a publish is refused" 1 "line 5: $TOOLCHAIN_MESSAGE" t.yml "jobs:
  package:
    steps:
      - run: |
          $command
  publish:
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: echo done"
done
case_ "an exact toolchain rustup installs beside a publish passes" 0 "OK: every action" t.yml "jobs:
  package:
    steps:
      - run: |
          rustup toolchain install 1.98.0 --profile minimal
  publish:
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: echo done"

# The toolchains of what the workflow runs are its own: a repository script,
# a local action, a RUSTUP_TOOLCHAIN in an env or a script, and the
# repository's toolchain file, which rustup takes over its default toolchain.
PUBLISH="  publish:
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: echo done"
case_ "a floating toolchain a repository script selects beside a publish is refused" 1 "t.yml: scripts/tc.sh, line 2: $TOOLCHAIN_MESSAGE (stable)" t.yml "jobs:
  package:
    steps:
      - run: ./scripts/tc.sh
$PUBLISH" scripts/tc.sh '#!/bin/sh
rustup default stable'
case_ "a script another workflow read first is held in this one too" 1 "u.yml: scripts/tc.sh, line 2: $TOOLCHAIN_MESSAGE (stable)" t.yml "jobs:
  package:
    steps:
      - run: ./scripts/tc.sh" u.yml "jobs:
  package:
    steps:
      - run: ./scripts/tc.sh
$PUBLISH" scripts/tc.sh '#!/bin/sh
cargo +stable build'
case_ "a floating toolchain in a local action beside a publish is refused" 1 "t.yml: act/action.yml, line 6: $TOOLCHAIN_MESSAGE (stable)" t.yml "jobs:
  package:
    steps:
      - uses: ./act
$PUBLISH" act/action.yml "runs:
  using: composite
  steps:
    - uses: dtolnay/rust-toolchain@$SHA # master
      with:
        toolchain: stable"
case_ "a floating toolchain a local action's script selects beside a publish is refused" 1 "t.yml: act/action.yml, line 4: $TOOLCHAIN_MESSAGE (beta)" t.yml "jobs:
  package:
    steps:
      - uses: ./act
$PUBLISH" act/action.yml "runs:
  using: composite
  steps:
    - run: rustup default beta
      shell: bash"
case_ "an exact toolchain in a local action beside a publish passes" 0 "OK: every action" t.yml "jobs:
  package:
    steps:
      - uses: ./act
$PUBLISH" act/action.yml "runs:
  using: composite
  steps:
    - uses: dtolnay/rust-toolchain@$SHA # master
      with:
        toolchain: 1.98.0"
case_ "a floating RUSTUP_TOOLCHAIN in a job's env beside a publish is refused" 1 "line 4: $TOOLCHAIN_MESSAGE (stable)" t.yml "jobs:
  package:
    env:
      RUSTUP_TOOLCHAIN: stable
    steps:
      - run: cargo package --locked
$PUBLISH"
case_ "a floating RUSTUP_TOOLCHAIN in the workflow's env beside a publish is refused" 1 "line 2: $TOOLCHAIN_MESSAGE (nightly)" t.yml "env:
  RUSTUP_TOOLCHAIN: nightly
jobs:
$PUBLISH"
case_ "a floating RUSTUP_TOOLCHAIN a script exports beside a publish is refused" 1 "line 5: $TOOLCHAIN_MESSAGE (stable)" t.yml "jobs:
  package:
    steps:
      - run: |
          export RUSTUP_TOOLCHAIN=stable
$PUBLISH"
case_ "a RUSTUP_TOOLCHAIN from a variable beside a publish is refused" 1 "line 5: $TOOLCHAIN_MESSAGE (\"\$T\")" t.yml "jobs:
  package:
    steps:
      - run: |
          RUSTUP_TOOLCHAIN=\"\$T\" cargo build
$PUBLISH"
case_ "an exact RUSTUP_TOOLCHAIN beside a publish passes" 0 "OK: every action" t.yml "jobs:
  package:
    env:
      RUSTUP_TOOLCHAIN: 1.98.0
    steps:
      - run: RUSTUP_TOOLCHAIN=1.98.0 cargo package --locked
$PUBLISH"
case_ "a floating channel in the toolchain file beside a publish is refused" 1 "rust-toolchain.toml names a toolchain that is not an exact version (stable)" t.yml "jobs:
$PUBLISH" rust-toolchain.toml '[toolchain]
channel = "stable"'
case_ "a floating legacy toolchain file beside a publish is refused" 1 "rust-toolchain names a toolchain that is not an exact version (nightly)" t.yml "jobs:
$PUBLISH" ./rust-toolchain 'nightly'
case_ "an exact channel in the toolchain file beside a publish passes" 0 "OK: every action" t.yml "jobs:
$PUBLISH" rust-toolchain.toml '[toolchain]
channel = "1.98.0"
components = ["clippy"]'
case_ "a floating channel in the toolchain file with no secret passes" 0 "OK: every action" t.yml "jobs:
  a:
    steps:
      - run: cargo build" rust-toolchain.toml '[toolchain]
channel = "stable"'

# A workflow another one calls may be handed a secret as an input, so its
# `inputs` count as a secret; a workflow a person starts takes them as typed.
case_ "a secret handed to a called workflow as an input is seen" 1 "called.yml: $SECRET_MESSAGE: job build, cargo install at line 12" caller.yml "jobs:
  call:
    uses: ./called.yml
    with:
      tok: \${{ secrets.TOKEN }}" called.yml "on:
  workflow_call:
    inputs:
      tok:
        type: string
jobs:
  build:
    env:
      TOK: \${{ inputs.tok }}
    steps:
      - run: |
          cargo install --locked cargo-audit@0.22.2"
case_ "the inputs of a workflow a person starts name nothing" 0 "OK: every action" started.yml "on:
  workflow_dispatch:
    inputs:
      full:
        type: boolean
jobs:
  build:
    if: \${{ inputs.full }}
    steps:
      - run: cargo install --locked cargo-audit@0.22.2"
