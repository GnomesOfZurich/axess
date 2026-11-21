# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: actions, images, checkouts, and
# the YAML they are written in. Sourced by scripts/check-workflow-pins-tests.sh.

PINNED="jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/local
      - name: Install a tool
        run: cargo install cargo-audit@0.22.2 --locked"
LOCAL_ACTION="runs:
  using: composite
  steps:
    - run: echo local
      shell: bash"
case_ "a pinned block-style workflow passes" 0 "OK: every action" a.yml "$PINNED" .github/actions/local/action.yml "$LOCAL_ACTION"
case_ "a local action the repository does not hold is refused" 1 "a local action or workflow the repository does not hold: ./.github/actions/local (job a)" a.yml "$PINNED"

# A checkout that lost its workflows has nothing to pass.
case_ "a directory with no workflow file is refused" 1 "no workflow file (*.yml, *.yaml)"
case_ "a directory with no workflow file among other files is refused" 1 "no workflow file (*.yml, *.yaml)" notes/README.md "nothing here"
missing_out="$("$CHECK" "$WORK/no-such-directory" 2>&1)"; missing_status=$?
if [ "$missing_status" -eq 1 ] && grep -qF "no workflow directory" <<<"$missing_out"; then
  passed=$((passed + 1))
else
  failed=$((failed + 1))
  echo "FAIL: a missing workflow directory is refused: got exit $missing_status: $missing_out" >&2
fi

FLOW="jobs:
  a:
    steps:
      - {uses: actions/upload-artifact@v1}"
BLOCK_YAML="jobs:
  a:
    steps:
      - uses: actions/upload-artifact@v1"
case_ "a flow-style {uses: ...} is refused" 1 "flow-style mapping" a.yml "$FLOW"
case_ "a .yaml workflow is read" 1 "not pinned to a full commit SHA" x.yaml "$BLOCK_YAML"
case_ "both files together are refused" 1 "2 workflow pin problem(s)" a.yml "$FLOW" x.yaml "$BLOCK_YAML"
case_ "a quoted tag is refused" 1 "not pinned to a full commit SHA" b.yaml "jobs:
  a:
    steps:
      - name: x
        uses: \"actions/upload-artifact@v1\""
case_ "a quoted commit with its version comment passes" 0 "OK: every action" c.yml "jobs:
  a:
    steps:
      - name: x
        uses: \"actions/upload-artifact@$SHA\" # v1.2.3"
case_ "a commit with no version comment is refused" 1 "not pinned to a full commit SHA with a version comment: 4:" c.yml "jobs:
  a:
    steps:
      - uses: actions/upload-artifact@$SHA"
case_ "a commit with a comment that names no version is refused" 1 "not pinned to a full commit SHA with a version comment" c.yml "jobs:
  a:
    steps:
      - uses: actions/upload-artifact@$SHA # pinned"
case_ "a commit with the branch it was read from passes" 0 "OK: every action" c.yml "jobs:
  a:
    steps:
      - uses: actions/upload-artifact@$SHA # master"
case_ "a short commit is refused" 1 "not pinned to a full commit SHA" c.yml "jobs:
  a:
    steps:
      - uses: actions/upload-artifact@${SHA:0:12} # v1.2.3"
case_ "a flow-style image is refused" 1 "flow-style mapping" d.yml "jobs:
  a:
    services: {db: {image: postgres:17}}"
case_ "a flow-style checkout is refused" 1 "flow-style mapping" e.yml "jobs:
  a:
    steps:
      - {uses: actions/checkout@$SHA, with: {persist-credentials: false}}"
case_ "a reusable workflow named by tag is refused" 1 "not pinned to a full commit SHA" r.yml "jobs:
  call:
    uses: acme/flows/.github/workflows/build.yml@v2"
case_ "a local reusable workflow needs no pin" 0 "OK: every action" r.yml "jobs:
  call:
    uses: ./.github/workflows/build.yml" .github/workflows/build.yml "on: workflow_call"
case_ "a local reusable workflow the repository does not hold is refused" 1 "a local action or workflow the repository does not hold: ./.github/workflows/build.yml (job call)" r.yml "jobs:
  call:
    uses: ./.github/workflows/build.yml"

# Every image carries a digest: a service, a container, the short form of a
# container and a docker action.
case_ "a service image by tag is refused" 1 "image not pinned by an @sha256 digest: 5:" i.yml "jobs:
  a:
    services:
      db:
        image: postgres:17"
case_ "a service image by digest passes" 0 "OK: every action" i.yml "jobs:
  a:
    services:
      db:
        image: postgres:17@$DIGEST"
case_ "a container named by tag in the short form is refused" 1 "image not pinned by an @sha256 digest: 3:" i.yml "jobs:
  a:
    container: node:22"
case_ "a container by digest in the short form passes" 0 "OK: every action" i.yml "jobs:
  a:
    container: node:22@$DIGEST"
case_ "a docker action by tag is refused" 1 "image not pinned by an @sha256 digest" i.yml "jobs:
  a:
    steps:
      - uses: docker://alpine:3.20"
case_ "a docker action by digest passes" 0 "OK: every action" i.yml "jobs:
  a:
    steps:
      - uses: docker://alpine:3.20@$DIGEST"

# Every checkout drops its credentials, in its own with: block.
case_ "a checkout without persist-credentials is refused" 1 "checkout at line 4 does not set persist-credentials: false" k.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
case_ "a checkout that keeps its credentials is refused" 1 "checkout at line 4 does not set persist-credentials: false" k.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: true"
case_ "persist-credentials on the next step does not count for a checkout" 1 "checkout at line 4 does not set persist-credentials: false" k.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
      - uses: actions/upload-artifact@$SHA # v1.0.0
        with:
          persist-credentials: false"
case_ "a quoted false drops the credentials" 0 "OK: every action" k.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: 'false'"

# A key may be quoted, and white space may stand before its colon. Either
# way it is the same key to the runner.
QUOTED_KEYS="jobs:
  a:
    steps:
      - \"uses\": actions/upload-artifact@v1
      - name: x
        \"uses\": actions/checkout@v4"
case_ "a double-quoted uses key is refused" 1 "not pinned to a full commit SHA with a version comment: 4:" q.yml "$QUOTED_KEYS"
case_ "a double-quoted checkout key is refused" 1 "not pinned to a full commit SHA with a version comment: 6:" q.yml "$QUOTED_KEYS"
case_ "a double-quoted checkout key without persist-credentials is refused" 1 "checkout at line 6 does not set persist-credentials: false" q.yml "$QUOTED_KEYS"
case_ "a single-quoted uses key is refused" 1 "not pinned to a full commit SHA" q.yml "jobs:
  a:
    steps:
      - 'uses': actions/upload-artifact@v1"
case_ "a quoted pinned checkout with a quoted persist-credentials key passes" 0 "OK: every action" q.yml "jobs:
  a:
    steps:
      - \"uses\": actions/checkout@$SHA # v7.0.1
        with:
          \"persist-credentials\": false"
case_ "a quoted image key is refused" 1 "image not pinned by an @sha256 digest" q.yml "jobs:
  a:
    services:
      db:
        \"image\": postgres:17"
case_ "a uses key before a space is read" 1 "not pinned to a full commit SHA with a version comment: 4:" k.yml "jobs:
  a:
    steps:
      - uses : actions/upload-artifact@v1"
case_ "a quoted uses key before a space is read" 1 "not pinned to a full commit SHA" k.yml "jobs:
  a:
    steps:
      - \"uses\"  : actions/upload-artifact@v1"
case_ "an image key before a space is read" 1 "image not pinned by an @sha256 digest" k.yml "jobs:
  a:
    container:
      image : postgres:17"
case_ "a checkout key before a space is held to its credentials" 1 "checkout at line 4 does not set persist-credentials: false" k.yml "jobs:
  a:
    steps:
      - uses : actions/checkout@$SHA # v7.0.1"
case_ "a uses key written as an explicit key is refused by name" 1 "not read as YAML: an explicit key" k.yml "jobs:
  a:
    steps:
      - ? uses
        : actions/upload-artifact@v1"
case_ "an image key written as an explicit key is refused by name" 1 "not read as YAML: an explicit key" k.yml "jobs:
  a:
    container:
      ? image
      : postgres:17"
case_ "an explicit key in flow style is refused by name" 1 "not read as YAML: an explicit key" k.yml "jobs:
  a:
    container: {? image : postgres:17}"

# What YAML writes in other ways is read as the runner reads it, and a form
# the reader does not take is refused by name.
case_ "a tag is refused by name" 1 "not read as YAML: a YAML tag" t.yml "jobs:
  a:
    steps:
      - uses: !!str actions/upload-artifact@v1"
case_ "a key written twice is refused by name" 1 "not read as YAML: the key uses twice" t.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        uses: actions/upload-artifact@v1"
case_ "a merge key is refused by name" 1 "not read as YAML: a merge key" t.yml "jobs:
  a:
    <<: {steps: []}"
case_ "a second document is refused by name" 1 "not read as YAML: more than one YAML document" t.yml "jobs: {}
---
jobs: {}"
case_ "a tab in the indentation is refused by name" 1 "not read as YAML: a tab in the indentation" t.yml "jobs:
	a: {}"
case_ "text that is not YAML is refused by name" 1 "not read as YAML: a colon and a space inside a plain value" t.yml "jobs:
  a:
    steps:
      - run: echo a: b"
case_ "an action behind an alias is read where the alias stands" 1 "not pinned to a full commit SHA" t.yml "x-step: &step
  uses: actions/upload-artifact@v1
jobs:
  a:
    steps:
      - *step"
case_ "a uses value behind a YAML escape is decoded" 1 "not pinned to a full commit SHA" t.yml "jobs:
  a:
    steps:
      - uses: \"actions/upload-artifact\\x40v1\""
case_ "a checkout written with escapes is held to its credentials" 1 "does not set persist-credentials: false" t.yml "jobs:
  a:
    steps:
      - uses: \"actions\\x2fcheckout@$SHA\" # v7.0.1"
