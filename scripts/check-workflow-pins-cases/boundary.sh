# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: the boundary between a job that
# holds nothing and a job beside a secret. The first builds and tests with
# programs the check does not name, so what it makes is not read; the
# second takes its artifact, its cache or its outputs as data, and runs,
# sources or builds none of it. Sourced by
# scripts/check-workflow-pins-tests.sh.

# boundary_case NAME EXPECTED_EXIT FRAGMENT STEPS: a job that holds nothing
# hands an artifact and an output to a job that names a secret, which has
# checked out its own commit and unpacked the artifact into `handed/`.
# STEPS are the steps after that; the first stands on line 23.
boundary_case() {
  case_ "$1" "$2" "$3" b.yml "jobs:
  build:
    outputs:
      value: \${{ steps.made.outputs.value }}
    steps:
      - id: made
        run: |
          docker run --rm builder > out/tool
          echo \"value=\$(cat out/name)\" >> \"\$GITHUB_OUTPUT\"
      - uses: actions/upload-artifact@$SHA # v7.0.2
  publish:
    needs: build
    env:
      TOKEN: \${{ secrets.TOKEN }}
      VALUE: \${{ needs.build.outputs.value }}
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          path: handed
$4" scripts/check.sh 'echo checked'
}
# run_case NAME EXPECTED_EXIT FRAGMENT LINE [LINE...]: the lines as the
# script of the step after the download; the first is line 24.
run_case() {
  local name="$1" want="$2" fragment="$3" body="" line
  shift 3
  for line in "$@"; do
    body="$body
          $line"
  done
  boundary_case "$name" "$want" "$fragment" "      - run: |$body"
}
BESIDE="a job that names a secret runs what the check does not read: job publish"
INSTALLS="a job that names a secret installs a tool on the same runner: job publish"

# The artifact: no file of it is run, sourced, built or made a setting.
run_case "a program of the artifact run by its path is refused" 1 "line 24: a program run by a path the repository does not hold is not read: ./handed/tool" './handed/tool --version'
run_case "a script of the artifact a shell runs is refused" 1 "line 24: a script the check cannot read is run by bash: handed/setup.sh" 'bash handed/setup.sh'
run_case "a script of the artifact sourced is refused" 1 "line 24: a script the check cannot read is run by .: handed/env.sh" '. handed/env.sh'
run_case "a script of the artifact on the input of a shell is refused" 1 "line 24: a script the check cannot read is run by sh: handed/setup.sh" 'sh < handed/setup.sh'
run_case "a script of the artifact piped into a shell is refused" 1 "line 24: a script piped into sh is not read" 'cat handed/setup.sh | sh'
run_case "the text of the artifact handed to eval is refused" 1 "line 24: the script eval runs comes from a variable or a substitution" 'eval "$(cat handed/commands)"'
run_case "the text of the artifact as a command is refused" 1 "line 24: a command from an expansion that splits into words is not read: \$(cat handed/command)" '$(cat handed/command)'
run_case "the lines of the artifact as scripts of a shell are refused" 1 "line 24: the script sh -c runs comes from a variable or a substitution" 'xargs -a handed/commands -I{} sh -c "{}"'
run_case "the text of the artifact sourced through a substitution is refused" 1 "line 24: a script the check cannot read is run by source" 'source <(cat handed/env)'
run_case "a Python program of the artifact is refused" 1 "line 24: a script the check cannot read is run by python3: handed/tool.py" 'python3 handed/tool.py'
run_case "a sed program of the artifact is refused" 1 "line 24: a sed program from a file is not read: -f" 'sed -f handed/edit.sed Cargo.toml'
run_case "an awk program of the artifact is refused" 1 "line 24: an awk program from a file is not read: -f" 'awk -f handed/report.awk Cargo.toml'
run_case "a package of the artifact built by its manifest is refused" 1 "$BESIDE, line 24: a cargo manifest the repository does not hold (handed/Cargo.toml)" 'cargo build --locked --manifest-path handed/Cargo.toml'
run_case "a package of the artifact built in its directory is refused" 1 "$BESIDE, line 24: cargo build after a change of directory" 'cd handed && cargo build --locked'
run_case "a cargo configuration of the artifact is refused" 1 "line 24: a --config that names a file is not read: handed/config.toml" 'cargo publish --locked --config handed/config.toml'
run_case "the variables of the artifact set for the later steps are refused" 1 "line 24: a write to \$GITHUB_ENV the check cannot read" 'cat handed/env >> "$GITHUB_ENV"'
run_case "a directory of the artifact put on the path for the later steps is refused" 1 "$INSTALLS, a directory put on the path at line 24" 'echo "$PWD/handed" >> "$GITHUB_PATH"'
run_case "a directory of the artifact put on the path of a command is refused" 1 "$INSTALLS, a directory put on the path at line 24" 'PATH="$PWD/handed:$PATH" cargo publish --locked'
run_case "a program of the artifact copied onto the path is refused" 1 "$BESIDE, line 24: a program the check does not name (cp)" 'cp handed/tool "$HOME/.cargo/bin/cargo-publish"'
run_case "a file of the artifact written over a repository script is refused" 1 "$BESIDE, line 24: a file a script writes outside the runner's temporary directory (scripts/check.sh)" 'cat handed/setup.sh > scripts/check.sh' './scripts/check.sh'
run_case "a patch of the artifact applied before a build is refused" 1 "a job that names a secret changes its checkout and runs code from it, which is not the code the check read: job publish, line 24: git apply, and line 25: cargo publish" 'git apply handed/fix.patch' 'cargo publish --locked'
case_ "an artifact unpacked over the checkout before a repository script is refused" 1 "job publish, line 13: an artifact unpacked over the checkout, and line 14: ./scripts/check.sh" b.yml "jobs:
  build:
    steps:
      - uses: actions/upload-artifact@$SHA # v7.0.2
  publish:
    needs: build
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/download-artifact@$SHA # v8.0.2
      - run: ./scripts/check.sh" scripts/check.sh 'echo checked'

# The cache: what an earlier run made is restored into no job beside a secret.
boundary_case "a cache restored beside a secret is refused" 1 "$BESIDE, line 23: an action that may run in no job beside a secret (Swatinem/rust-cache)" "      - uses: Swatinem/rust-cache@$SHA # v2.9.3
      - run: cargo publish --locked"
boundary_case "a cache restored by an action off the list is refused" 1 "line 23: an action that is not on the list (actions/cache)" "      - uses: actions/cache@$SHA # v4.2.0
        with:
          path: ~/.cargo/bin
          key: tools"

# The outputs: a value of the other job is data. It is no word of a
# script, no command, no script of another shell, and no place to run in.
run_case "an output pasted into the script is refused" 1 "line 24: an expression the runner pastes into the script before the shell reads it (\${{ needs.build.outputs.value }})" 'echo ${{ needs.build.outputs.value }}'
run_case "an output run as a command is refused" 1 "$INSTALLS, a program whose name comes from a variable (\"\$VALUE\") at line 24" '"$VALUE" --version'
run_case "an output run as a command and its arguments is refused" 1 "line 24: a command from an expansion that splits into words is not read: \$VALUE" '$VALUE'
run_case "an output handed to eval is refused" 1 "line 24: the script eval runs comes from a variable or a substitution" 'eval "$VALUE"'
run_case "an output as the script of a shell is refused" 1 "line 24: the script sh -c runs comes from a variable or a substitution" 'sh -c "$VALUE"'
run_case "an output pasted into the script of a shell is refused" 1 "$BESIDE, line 24: a value pasted into the script sh -c runs" 'sh -c "echo $VALUE"'
run_case "an output as the name of a script is refused" 1 "line 24: a script the check cannot read is run by bash: \"\$VALUE\"" 'bash "$VALUE"'
run_case "an output written for the later steps is refused" 1 "$BESIDE, line 24: a value from a variable written to \$GITHUB_ENV (NAME)" 'echo "NAME=$VALUE" >> "$GITHUB_ENV"'
run_case "an output as an argument of a build is refused" 1 "$BESIDE, line 24: a cargo argument a variable fills in (\$VALUE)" 'cargo publish --locked $VALUE'
run_case "an output as an argument of git fetch is refused" 1 "$BESIDE, line 24: an argument of git fetch that a variable fills in and that may be an option (\"\$VALUE\")" 'git fetch "$VALUE"'
boundary_case "an output as the shell of a step is refused" 1 "line 23: a run step in a shell the check does not read: \${{ needs.build.outputs.value }}" "      - shell: \${{ needs.build.outputs.value }}
        run: echo done"
boundary_case "an output as the directory of a step that runs a repository script is refused" 1 "$BESIDE, line 24: a repository file run after a change of directory (./scripts/check.sh)" "      - working-directory: \${{ needs.build.outputs.value }}
        run: ./scripts/check.sh"
case_ "an output as the ref of a checkout before a build is refused" 1 "job publish, line 13: a checkout of another repository or ref, and line 17: cargo publish" b.yml "jobs:
  build:
    outputs:
      value: \${{ steps.made.outputs.value }}
    steps:
      - id: made
        run: echo \"value=main\" >> \"\$GITHUB_OUTPUT\"
  publish:
    needs: build
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
          ref: \${{ needs.build.outputs.value }}
      - run: cargo publish --locked"

# What a job beside a secret does with what it is handed: it reads it,
# compares it, uploads it, and names a package by it.
run_case "the files of an artifact and an output used as data pass" 0 "OK: every action" \
  'set -eu' \
  'cargo package --workspace --locked' \
  '(cd target/package && sha256sum -- *.crate) > "$RUNNER_TEMP/here.sha256"' \
  'diff -u handed/crates.sha256 "$RUNNER_TEMP/here.sha256"' \
  'grep -c . handed/crates.sha256; jq -r .name handed/sbom.cdx.json; cat handed/notes' \
  'if [ "$VALUE" = "true" ]; then echo "tag: $VALUE"; fi' \
  'cargo publish --locked -p "$VALUE"' \
  'gh release upload "$VALUE" handed/axess.crate' \
  'echo "tag=$VALUE" >> "$GITHUB_OUTPUT"'
