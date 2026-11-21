# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: the steps of a job that names a
# secret, may ask for an OIDC token or holds a token that can write. Such a
# job uses the actions the check names, and does not both change its
# checkout and run code from it. Sourced by
# scripts/check-workflow-pins-tests.sh.

# steps_case NAME EXPECTED_EXIT FRAGMENT STEPS [FILE CONTENT...]: the steps
# of a job that names a secret; the first stands on line 6 of the file.
steps_case() {
  local name="$1" want="$2" fragment="$3" steps="$4"
  shift 4
  case_ "$name" "$want" "$fragment" s.yml "jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
$steps" scripts/check.sh 'echo checked' "$@"
}
CHECKOUT="      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false"

# An action is pinned to a commit and not read, so every job uses the
# actions of the list (scripts/lib/workflow_actions.txt), and a job beside
# a secret those the list lets run there.
UNLISTED="an action that is not on the list"
steps_case "an action that installs a tool is refused beside a secret" 1 "s.yml: line 6: $UNLISTED (taiki-e/install-action)" "      - uses: taiki-e/install-action@$SHA # v2.62.0
        with:
          tool: cargo-audit"
steps_case "an action that runs a script it is given is refused" 1 "line 6: $UNLISTED (actions/github-script): what its pinned commit runs is not read" "      - uses: actions/github-script@$SHA # v8.0.0
        with:
          script: require('child_process').execSync('cargo install cargo-audit')"
steps_case "an action in a directory of a repository is named by the repository" 1 "line 6: $UNLISTED (github/codeql-action/init)" "      - uses: github/codeql-action/init@$SHA # v4.0.0"
case_ "an action that is not on the list is refused in a job that holds nothing" 1 "line 7: $UNLISTED (taiki-e/install-action)" s.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
      - uses: taiki-e/install-action@$SHA # v2.62.0"
TRAILER='' case_ "an action that is not on the list is refused under a token that can write" 1 "line 6: $UNLISTED (peter-evans/create-pull-request)" s.yml "jobs:
  a:
    permissions:
      contents: write
    steps:
      - uses: peter-evans/create-pull-request@$SHA # v7.0.0"
NO_SECRET="an action that may run in no job beside a secret"
steps_case "an action that restores a cache beside a secret is refused" 1 "$HELD, line 6: $NO_SECRET (Swatinem/rust-cache)" "      - uses: Swatinem/rust-cache@$SHA # v2.9.3"
TRAILER='' case_ "an action that restores a cache under an OIDC permission is refused" 1 "a job that may ask for an OIDC token runs what the check does not read: job a, line 6: $NO_SECRET (Swatinem/rust-cache)" s.yml "jobs:
  a:
    permissions:
      id-token: write
    steps:
      - uses: Swatinem/rust-cache@$SHA # v2.9.3"
case_ "an action that restores a cache in a job that holds nothing passes" 0 "OK: every action" s.yml "jobs:
  a:
    steps:
      - uses: Swatinem/rust-cache@$SHA # v2.9.3
      - run: cargo test --locked"
steps_case "an image run as a step beside a secret is refused" 1 "$HELD, line 6: an image run as a step (docker://example.invalid/tools)" "      - uses: docker://example.invalid/tools@$DIGEST
        with:
          args: publish"
case_ "an image run as a step in a job that holds nothing passes" 0 "OK: every action" s.yml "jobs:
  a:
    steps:
      - uses: docker://example.invalid/tools@$DIGEST"
steps_case "the actions of the release, tag and pages jobs pass beside a secret" 0 "OK: every action" "$CHECKOUT
      - uses: dtolnay/rust-toolchain@$SHA # master
        with:
          toolchain: 1.98.0
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          name: release-files
          path: attested
      - uses: actions/upload-artifact@$SHA # v7.0.2
      - uses: actions/attest-build-provenance@$SHA # v4.2.2
      - uses: softprops/action-gh-release@$SHA # v3.0.4
      - uses: actions/configure-pages@$SHA # v6.0.0
      - uses: actions/upload-pages-artifact@$SHA # v5.0.0
      - uses: actions/deploy-pages@$SHA # v5.0.1
      - run: cargo publish --locked" rust-toolchain.toml 'channel = "1.98.0"'

# A workflow of another repository is pinned and not read either: it is on
# the list or it is refused, whatever the job hands it.
case_ "a workflow of another repository handed every secret is refused" 1 "line 3: $UNLISTED (owner/repo/.github/workflows/publish.yml)" s.yml "jobs:
  a:
    uses: owner/repo/.github/workflows/publish.yml@$SHA # v1.0.0
    secrets: inherit"
case_ "a workflow of another repository handed nothing is refused" 1 "line 3: $UNLISTED (owner/repo/.github/workflows/lint.yml)" s.yml "jobs:
  a:
    uses: owner/repo/.github/workflows/lint.yml@$SHA # v1.0.0"
case_ "a workflow of the repository handed every secret is held as its own" 0 "OK: every action" s.yml "jobs:
  a:
    uses: ./.github/workflows/ci.yml
    secrets: inherit" .github/workflows/ci.yml "on: workflow_call
permissions:
  contents: read
jobs:
  test:
    steps:
      - run: cargo test --locked"

# A job beside a secret runs the code the check read: it does not change
# its checkout and run a repository script, a local action or a build.
CHANGED="a job that names a secret changes its checkout and runs code from it, which is not the code the check read: job a"
steps_case "the head of a pull request checked out and run beside a secret is refused" 1 "$CHANGED, line 6: a checkout of another repository or ref, and line 10: ./scripts/check.sh" "      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
          ref: \${{ github.event.pull_request.head.sha }}
      - run: ./scripts/check.sh"
steps_case "another repository checked out and built beside a secret is refused" 1 "$CHANGED, line 6: a checkout of another repository or ref, and line 10: cargo test" "      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
          repository: owner/other
      - run: cargo test --locked"
steps_case "another ref checked out beside a local action is refused" 1 "$CHANGED, line 6: a checkout of another repository or ref, and line 10: ./.github/actions/tools" "      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
          ref: main
      - uses: ./.github/actions/tools" .github/actions/tools/action.yml "name: tools
runs:
  using: composite
  steps:
    - shell: bash
      run: echo tools"
steps_case "another ref checked out for git alone passes" 0 "OK: every action" "      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
          ref: main
      - run: |
          git fetch --no-tags origin '+refs/heads/main:refs/remotes/origin/main'
          git checkout -b release/next origin/main
          git merge --no-ff --no-edit origin/main"
steps_case "the job's own commit checked out and run passes" 0 "OK: every action" "$CHECKOUT
      - run: ./scripts/check.sh"
steps_case "an artifact unpacked over the checkout and a build are refused" 1 "$CHANGED, line 9: an artifact unpacked over the checkout, and line 10: cargo publish" "$CHECKOUT
      - uses: actions/download-artifact@$SHA # v8.0.2
      - run: cargo publish --locked"
steps_case "an artifact unpacked into a directory of the repository is refused" 1 "$CHANGED, line 9: an artifact unpacked over the checkout, and line 12: ./scripts/check.sh" "$CHECKOUT
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          path: scripts/generated
      - run: ./scripts/check.sh"
steps_case "an artifact unpacked into a directory from an expression is refused" 1 "$CHANGED, line 9: an artifact unpacked over the checkout" "$CHECKOUT
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          path: \${{ inputs.where }}
      - run: ./scripts/check.sh"
steps_case "an artifact unpacked above its directory is refused" 1 "$CHANGED, line 9: an artifact unpacked over the checkout" "$CHECKOUT
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          path: attested/../scripts
      - run: ./scripts/check.sh"
steps_case "an artifact unpacked beside the checkout and a build pass" 0 "OK: every action" "$CHECKOUT
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          path: attested
      - run: cargo publish --locked"
steps_case "an artifact unpacked into the temporary directory and a build pass" 0 "OK: every action" "$CHECKOUT
      - uses: actions/download-artifact@$SHA # v8.0.2
        with:
          path: \${{ runner.temp }}/attested
      - run: cargo publish --locked"
steps_case "an artifact unpacked with no checkout and no code passes" 0 "OK: every action" "      - uses: actions/download-artifact@$SHA # v8.0.2
      - uses: softprops/action-gh-release@$SHA # v3.0.4"
steps_case "a branch checked out by git and a script run are refused" 1 "$CHANGED, line 8: git checkout, and line 9: ./scripts/check.sh" "      - run: |
          git fetch origin main
          git checkout FETCH_HEAD
          ./scripts/check.sh"
steps_case "a patch applied and a build are refused" 1 "$CHANGED, line 7: git apply, and line 8: cargo publish" "      - run: |
          git apply attested/fix.patch
          cargo publish --locked"
case_ "a branch checked out and a script run in a job that holds nothing pass" 0 "OK: every action" s.yml "jobs:
  a:
    steps:
      - run: |
          git checkout other
          ./scripts/check.sh" scripts/check.sh 'echo checked'

# A local action a job beside a secret uses is held as the job's own steps.
ACTION_HEAD="name: tools
runs:
  using: composite
  steps:"
USES_LOCAL="      - uses: ./.github/actions/tools"
steps_case "an unnamed program in the script of a local action is refused" 1 "$HELD, .github/actions/tools/action.yml line 6: a program the check does not name (docker)" "$USES_LOCAL" .github/actions/tools/action.yml "$ACTION_HEAD
    - shell: bash
      run: docker ps"
steps_case "an action for jobs that hold no secret in a local action is refused" 1 "$HELD, .github/actions/tools/action.yml line 5: $NO_SECRET (Swatinem/rust-cache)" "$USES_LOCAL" .github/actions/tools/action.yml "$ACTION_HEAD
    - uses: Swatinem/rust-cache@$SHA # v2.9.3"
steps_case "an unnamed program in a local action another one uses is refused" 1 "$HELD, .github/actions/inner/action.yml line 6: a program the check does not name (docker)" "$USES_LOCAL" .github/actions/tools/action.yml "$ACTION_HEAD
    - uses: ./.github/actions/inner" .github/actions/inner/action.yml "$ACTION_HEAD
    - shell: bash
      run: docker ps"
steps_case "a local action with a working directory is held to it" 1 "$HELD, .github/actions/tools/action.yml line 7: a repository file run after a change of directory (./scripts/check.sh)" "$USES_LOCAL" .github/actions/tools/action.yml "$ACTION_HEAD
    - shell: bash
      working-directory: unpacked
      run: ./scripts/check.sh"
steps_case "a local action that checks the runner passes beside a secret" 0 "OK: every action" "$USES_LOCAL
$USES_LOCAL" .github/actions/tools/action.yml "$ACTION_HEAD
    - if: runner.os == 'Linux'
      shell: bash
      run: |
        set -euo pipefail
        [ -n \"\${LIBCLANG_PATH:-}\" ] || echo \"::warning::no libclang\"
        ./scripts/check.sh"
