# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: a file a job downloads is
# checked against a SHA-256 the repository writes, before it is run or
# unpacked, and a program run by a path the repository does not hold is a
# checked download or lies in the directory a checked archive was unpacked
# into. Sourced by scripts/check-workflow-pins-tests.sh.

HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
URL=https://example.invalid/tool-1.0.0-linux.tar.gz
UNCHECKED="a downloaded file is unpacked before it is checked against a SHA-256 the repository writes"
NOT_CHECKED="a download that is not checked against a SHA-256 the repository writes"
PATH_RUN="a program run by a path the repository does not hold is not read"

# The passing fixture: downloaded, checked against a digest written in the
# script, unpacked into a directory of its own, and run from there.
block_case "a download checked before it is unpacked, and run from where it was unpacked, passes" 0 "OK: every action" \
  'set -euo pipefail' \
  'archive="$RUNNER_TEMP/tool.tar.gz"' \
  "curl -fsSL -o \"\$archive\" $URL" \
  "echo \"$HEX  \$archive\" | sha256sum --check --strict -" \
  'mkdir "$RUNNER_TEMP/tool"' \
  'tar -xzf "$archive" -C "$RUNNER_TEMP/tool"' \
  '"$RUNNER_TEMP/tool/bin/tool" --version'
case_ "a digest in the env: of the job passes" 0 "OK: every action" e.yml "jobs:
  a:
    env:
      TOOL_SHA256: $HEX
    steps:
      - run: |
          set -euo pipefail
          curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL
          echo \"\${TOOL_SHA256}  \${RUNNER_TEMP}/tool.tar.gz\" | sha256sum --check -
          tar -xzf \"\$RUNNER_TEMP/tool.tar.gz\""
block_case "a check of a here-string, by a digest the script sets, passes" 0 "OK: every action" \
  'set -e' \
  "sha=$HEX" \
  "wget -q -O \"\$RUNNER_TEMP/tool.zip\" $URL" \
  'sha256sum --check <<<"$sha  $RUNNER_TEMP/tool.zip"' \
  'unzip "$RUNNER_TEMP/tool.zip" -d "$RUNNER_TEMP/tool"'
block_case "a check by shasum of what printf prints passes" 0 "OK: every action" \
  'set -eu' \
  "curl -fsSLo \"\$RUNNER_TEMP/tool\" $URL" \
  "printf '%s  %s\\n' $HEX \"\$RUNNER_TEMP/tool\" | shasum -a 256 -c -" \
  'chmod +x "$RUNNER_TEMP/tool"' \
  '"$RUNNER_TEMP/tool" --version'
block_case "a download read only as data needs no check" 0 "OK: every action" \
  'curl -fsS -o "$RUNNER_TEMP/answer.json" https://example.invalid/api/answer' \
  'jq -r .version "$RUNNER_TEMP/answer.json"'
case_ "a repository script run on the directory a checked archive was unpacked into passes" 0 "OK: every action" s.yml "jobs:
  a:
    steps:
      - run: |
          set -euo pipefail
          curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL
          echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -
          mkdir \"\$RUNNER_TEMP/tool\"
          tar -xzf \"\$RUNNER_TEMP/tool.tar.gz\" -C \"\$RUNNER_TEMP/tool\"
      - run: ./scripts/run.sh \"\$RUNNER_TEMP/tool/bin\"" scripts/run.sh '#!/usr/bin/env bash
set -eu
bin="$1"
"$bin/tool" --version'

# The failing fixtures.
block_case "a download unpacked with no check is refused" 1 "line 7: $UNCHECKED: \$RUNNER_TEMP/tool.tar.gz, downloaded at line 6" \
  'set -euo pipefail' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz" -C "$RUNNER_TEMP"'
block_case "an archive downloaded and checked by nothing is refused" 1 "line 5: $NOT_CHECKED: \"\$RUNNER_TEMP/tool.tar.gz\"" \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL"
block_case "a check after the download is unpacked is refused" 1 "line 7: $UNCHECKED" \
  'set -euo pipefail' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz" -C "$RUNNER_TEMP/tool"' \
  "echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -"
block_case "a check after the download is run is refused" 1 "line 7: a downloaded file is run before it is checked" \
  'set -euo pipefail' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool\" $URL" \
  '"$RUNNER_TEMP/tool" --version' \
  "echo \"$HEX  \$RUNNER_TEMP/tool\" | sha256sum --check -"
block_case "a digest fetched from the network is refused" 1 "the check at line 8 does not count: its digest \$digest is not written out in the repository" \
  'set -euo pipefail' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "digest=\"\$(curl -fsSL $URL.sha256)\"" \
  'echo "$digest  $RUNNER_TEMP/tool.tar.gz" | sha256sum --check -' \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz"'
block_case "a digest file fetched from the network is refused" 1 "line 9: $UNCHECKED" \
  'set -euo pipefail' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.sha256\" $URL.sha256" \
  'sha256sum --check "$RUNNER_TEMP/tool.sha256"' \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz"'
case_ "a digest a step writes to GITHUB_ENV is refused" 1 "its digest \$TOOL_SHA256 is set by no env: to a SHA-256 written out" g.yml "jobs:
  a:
    env:
      TOOL_SHA256: $HEX
    steps:
      - run: echo \"TOOL_SHA256=$HEX\" >> \"\$GITHUB_ENV\"
      - run: |
          set -euo pipefail
          curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL
          echo \"\$TOOL_SHA256  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -
          tar -xzf \"\$RUNNER_TEMP/tool.tar.gz\""
block_case "a check in a script that does not stop on a failure is refused" 1 "the script does not stop when it fails: set -e before it" \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz"'
block_case "a check whose failure goes on to another command is refused" 1 "it is joined to the command after it by ||" \
  'set -e' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check - || echo mismatch" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz"'
block_case "a check in a subshell is refused" 1 "it runs in a subshell or a substitution" \
  'set -e' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "(echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -)" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz"'
block_case "a download written over after its check is refused" 1 "(line 8 writes it again after its check)" \
  'set -e' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -" \
  'cp "$RUNNER_TEMP/other.tar.gz" "$RUNNER_TEMP/tool.tar.gz"' \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz"'
block_case "a download unpacked from its stream is refused" 1 "line 5: a download unpacked from its stream, before any digest can be checked: curl | tar" \
  "curl -fsSL $URL | tar -xz -C \"\$RUNNER_TEMP\""
block_case "a download unpacked through a process substitution is refused" 1 "line 5: a download unpacked from its stream" \
  "tar -xzf <(curl -fsSL $URL)"
block_case "a wget with no output file is refused" 1 "line 5: a wget whose file the check cannot name" "wget $URL"
block_case "a gh release download with no output file is refused" 1 "line 5: a gh release download whose files the release names" 'gh release download v1.0.0 --pattern "*.tar.gz"'
block_case "a curl whose file the server names is refused" 1 "line 5: a curl whose file or options the check cannot name (-J)" "curl -fsSLOJ $URL"
case_ "an action handed a URL is refused" 1 "line 7: an action is handed a URL as its input archive-url ($URL)" u.yml "jobs:
  a:
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
          archive-url: $URL"
block_case "a program run from where an unchecked archive was unpacked is refused" 1 "line 7: $PATH_RUN: \"\$RUNNER_TEMP/tool/bin/tool\"" \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz" -C "$RUNNER_TEMP/tool"' \
  '"$RUNNER_TEMP/tool/bin/tool" --version'
block_case "a program run from the temporary directory with no download is refused" 1 "line 5: $PATH_RUN: \"\$RUNNER_TEMP/tool\"" '"$RUNNER_TEMP/tool" --version'
block_case "a program run from the temporary directory itself, where a checked archive was unpacked, is refused" 1 "line 9: $PATH_RUN: \"\$RUNNER_TEMP/bin/tool\"" \
  'set -e' \
  "curl -fsSL -o \"\$RUNNER_TEMP/tool.tar.gz\" $URL" \
  "echo \"$HEX  \$RUNNER_TEMP/tool.tar.gz\" | sha256sum --check -" \
  'tar -xzf "$RUNNER_TEMP/tool.tar.gz" -C "$RUNNER_TEMP"' \
  '"$RUNNER_TEMP/bin/tool" --version'
case_ "a repository script run on a directory no checked archive was unpacked into is refused" 1 "scripts/run.sh: line 4: $PATH_RUN: \"\$bin/tool\"" r.yml "jobs:
  a:
    steps:
      - run: ./scripts/run.sh \"\$RUNNER_TEMP/tool/bin\"" scripts/run.sh '#!/usr/bin/env bash
set -eu
bin="$1"
"$bin/tool" --version'
