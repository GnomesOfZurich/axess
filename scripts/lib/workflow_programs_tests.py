"""Crafted cases for scripts/lib/workflow_programs.py, run by
scripts/check-workflow-pins-tests.sh.

Each case lexes one command and pins what the reader of its program
returns: the reasons a job beside a secret may not run it, in order, and
for git whether it changes the checkout, for cargo whether it builds. Run
with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words
import workflow_programs as P

OPTION = "an option of %s that writes a file or runs a program (%s)"
HIDDEN = "an argument of %s that a variable fills in and that may be an option (%s): put it after --"
REMOTE = "a git remote other than origin (%s): a job beside a secret talks to the repository's own"
CURL = "a curl option the check does not name (%s): it may write a file or read options from one"
CURL_URL = "a curl argument that a variable fills in and that may be an option (%s): give it to --url"
UNLOCKED = "cargo %s without --locked: it builds what the registry serves on the day, not the lockfile"
REWRITES = "cargo %s without --locked: it may rewrite the lockfile a later build reads"
OWN = "cargo %s, which changes the sources or the lockfile or is not needed beside a secret"
FLAG = "a cargo flag that changes where or how it runs (%s)"
MANIFEST = "a cargo manifest the repository does not hold (%s)"
WRITES = "a file a script writes outside the runner's temporary directory (%s)"


def words(line):
    return shell_words.lex(line, lambda offset: 1).commands[0].words


def args(line):
    return words(line)[1:]


PURE = [
  ("grep -rn x .", []), ("jq -r --arg c \"$crate\" .x", []), ("date -u -d \"$after\" +%s", []),
  ("sleep \"$wait\"", []), ("rm -rf \"$work\"", []), ("cat \"$file\"", []),
  ("sort -u input", []), ("sort -k1,1 -t: input", []), ("sort --month-sort input", []),
  ("sort -o out input", [OPTION % ("sort", "-o")]), ("sort -uo out input", [OPTION % ("sort", "-uo")]),
  ("sort -oout input", [OPTION % ("sort", "-oout")]), ("sort --output=out input", [OPTION % ("sort", "--output=out")]),
  ("sort --out out input", [OPTION % ("sort", "--out")]),
  ("sort --compress-program ./tool input", [OPTION % ("sort", "--compress-program")]),
  ("sort --comp=./tool input", [OPTION % ("sort", "--comp=./tool")]),
  ("sort -o\"$OUT\" input", [OPTION % ("sort", '-o"$OUT"')]),
  ("sort \"$LIST\"", [HIDDEN % ("sort", '"$LIST"')]), ("sort $LIST", [HIDDEN % ("sort", "$LIST")]),
  ("sort -u -- \"$LIST\"", []), ("sort -- -o", []), ("sort \"a$LIST\"", []),
  ("base64 -d input", []), ("base64 -w0", []), ("base64 -o out", [OPTION % ("base64", "-o")]),
  ("base64 --output=out", [OPTION % ("base64", "--output=out")]), ("base64 -do out", [OPTION % ("base64", "-do")]),
  ("uniq -c", []), ("uniq input", []), ("uniq input out", ["a file uniq writes (its second operand)"]),
  ("uniq \"$IN\"", [HIDDEN % ("uniq", '"$IN"')]),
]
GIT = [
  ("git status", ([], False, "status")), ("git", ([], False, None)), ("git --version", ([], False, None)),
  ("git rev-parse \"$next^{tree}\"", ([], False, "rev-parse")), ("git merge-base --is-ancestor \"$a\" \"$b\"", ([], False, "merge-base")),
  ("git checkout -b release/next \"$next\"", ([], True, "checkout")), ("git merge --no-ff \"$main\"", ([], True, "merge")),
  ("git -c user.name=bot commit -m x", ([], False, "commit")), ("git -c a=b -c c=d push origin main", ([], False, "push")),
  ("git frob", (["a git subcommand the check does not name (git frob)"], False, "frob")),
  ("git lfs pull", (["a git subcommand the check does not name (git lfs)"], False, "lfs")),
  ("git archive -o out HEAD", (["a git subcommand the check does not name (git archive)"], False, "archive")),
  ("git \"$SUB\"", (['a git subcommand from a variable ("$SUB")'], False, None)),
  ("git -C sub status", (["git in another directory or repository (-C)"], False, "status")),
  ("git --git-dir=x/.git log", (["git in another directory or repository (--git-dir)"], False, "log")),
  ("git --work-tree x status", (["git in another directory or repository (--work-tree)"], False, "status")),
  ("git diff --output=out", (["a git option that writes a file (--output=out)"], False, "diff")),
  ("git log --out out", (["a git option that writes a file (--out)"], False, "log")),
  ("git clone --template=t u", (["a git option that writes a file (--template=t)", "a clone of another repository beside a secret"], True, "clone")),
  ("git log --oneline --no-tags", ([], False, "log")), ("git log -- --output=x", ([], False, "log")),
  ("git fetch \"$REMOTE\"", ([HIDDEN % ("git fetch", '"$REMOTE"'), REMOTE % '"$REMOTE"'], False, "fetch")),
  ("git fetch origin \"$REF\"", ([HIDDEN % ("git fetch", '"$REF"')], False, "fetch")),
  ("git fetch origin -- \"$REF\"", ([], False, "fetch")), ("git fetch origin \"refs/tags/$TAG\"", ([], False, "fetch")),
  ("git push \"$@\"", ([HIDDEN % ("git push", '"$@"'), REMOTE % '"$@"'], False, "push")),
  ("git push --force-with-lease=\"refs/heads/x:$next\" origin a:b", ([], False, "push")),
  ("git pull $REMOTE", ([HIDDEN % ("git pull", "$REMOTE"), REMOTE % "$REMOTE"], True, "pull")),
  ("git push https://example.invalid/r main", ([REMOTE % "https://example.invalid/r"], False, "push")),
  ("git push upstream main", ([REMOTE % "upstream"], False, "push")),
  ("git fetch --depth 1 origin main", ([], False, "fetch")), ("git fetch --depth 1 mirror", ([REMOTE % "mirror"], False, "fetch")),
  ("git push --repo=https://example.invalid/r", (["a git remote named by --repo (--repo=https://example.invalid/r): a job beside a secret talks to origin"], False, "push")),
  ("git push -o ci.skip origin main", ([], False, "push")), ("git push", ([], False, "push")), ("git ls-remote --tags origin x", ([], False, "ls-remote")),
  ("git remote add evil u", (["a change to the remotes of the checkout (git remote add)"], False, "remote")),
  ("git remote set-url origin u", (["a change to the remotes of the checkout (git remote set-url)"], False, "remote")),
  ("git remote -v", ([], False, "remote")), ("git remote get-url origin", ([], False, "remote")),
  ("git ls-remote --tags origin \"refs/tags/${TAG}\"", ([], False, "ls-remote")),
  ("git branch -f release/next \"$main\"", ([], False, "branch")),
]
GH = [
  ("gh api repos/o/r", []), ("gh api -X POST \"repos/$R/git/refs\" -f ref=\"$T\"", []),
  ("gh issue create --title \"$t\" --body \"$b\"", []), ("gh workflow run release.yml --ref \"$TAG\"", []),
  ("gh release upload \"$TAG\" a.crate", []), ("gh auth status", []), ("gh status", []),
  ("gh api \"repos/{owner}/{repo}/actions/workflows/$2/runs?head_sha=$release&per_page=100\"", []),
  ("gh api --paginate \"repos/{owner}/{repo}/actions/runs/$id/jobs?per_page=100\"", []),
  ("gh api \"$1\"", ['a gh api endpoint that may be a URL of another host ("$1")']),
  ("gh run list --repo \"$REPO\" --workflow hardening.yml",
   ["a gh repository that may name another host (\"$REPO\"): name OWNER/REPO, or $GITHUB_REPOSITORY"]),
  ("gh", ["a gh command from a variable"]), ("gh \"$C\"", ["a gh command from a variable"]),
  ("gh tool", ["a gh command the check does not name (gh tool)"]),
  ("gh extension install o/r", ["a gh command the check does not name (gh extension)"]),
  ("gh release download v1", ["a gh command the check does not name (gh release download)"]),
  ("gh run download 1", ["a gh command the check does not name (gh run download)"]),
  ("gh pr checkout 7", ["a gh command the check does not name (gh pr checkout)"]),
  ("gh repo clone o/r", ["a gh command the check does not name (gh repo clone)"]),
  ("gh issue", ["a gh command the check does not name (gh issue)"]),
  ("gh issue \"$VERB\"", ['a gh command the check does not name (gh issue "$VERB")']),
]
HOST = "a curl address of a host the check does not name (%s): a job beside a secret talks to crates.io and GitHub"
UNWRITTEN = "a curl address whose host is not written out (%s): the job's credentials may go to any host"
CURLS = [
  ("curl https://crates.io/x", []), ("curl -fsSL https://api.github.com/x", []), ("curl https://github.com", []),
  ("curl --fail --silent --show-error --retry 3 --max-time 30 --user-agent \"$UA\" --url https://crates.io/api/v1/x", []),
  ("curl -H \"Authorization: Bearer $T\" -X POST -d \"$body\" https://uploads.github.com/x", []),
  ("curl -sSH \"X: $v\" https://crates.io/x", []), ("curl -m 30 -A agent https://crates.io/x", []),
  ("curl -o /dev/null https://crates.io/x", []), ("curl --output \"$RUNNER_TEMP/a.json\" https://crates.io/x", []),
  ("curl -w '%{http_code}' https://crates.io/x", []), ("curl --header=x https://crates.io/x", []), ("curl -H\"$H\" https://crates.io/x", []), ("curl -H\"Authorization: $T\" https://crates.io/x", []), ("curl -m30 https://crates.io/x", []),
  ("curl https://example.invalid/x", [HOST % "example.invalid"]), ("curl https://crates.io.example.invalid/x", [HOST % "crates.io.example.invalid"]),
  ("curl -o out https://crates.io/x", ["a file curl writes outside the runner's temporary directory (out)"]),
  ("curl -fsSLo out https://crates.io/x", ["a file curl writes outside the runner's temporary directory (out)"]),
  ("curl --output=out https://crates.io/x", ["a file curl writes outside the runner's temporary directory (out)"]),
  ("curl -o\"$OUT\" https://crates.io/x", ["a file curl writes outside the runner's temporary directory ($OUT)"]),
  ("curl -w '%output{f}' https://crates.io/x", ["a curl output format that is not written out, or that writes a file ('%output{f}')"]),
  ("curl -O https://crates.io/x", [CURL % "-O"]), ("curl -K file https://crates.io/x", [CURL % "-K"]), ("curl --config file", [CURL % "--config"]),
  ("curl -D headers u", [CURL % "-D"]), ("curl -c jar u", [CURL % "-c"]), ("curl --libcurl f u", [CURL % "--libcurl"]),
  ("curl -x proxy https://crates.io/x", [CURL % "-x"]), ("curl --resolve crates.io:443:1.2.3.4 https://crates.io/x", [CURL % "--resolve"]),
  ("curl \"$OPT\" https://crates.io/x", [UNWRITTEN % "\"$OPT\""]), ("curl -fsS \"$URL\"", [UNWRITTEN % "\"$URL\""]), ("curl $URL", [UNWRITTEN % "$URL"]),
  ("curl \"https://crates.io/$path\"", []), ("curl \"https://crates.io$path\"", [UNWRITTEN % "\"https://crates.io$path\""]),
  ("curl --url \"$URL\" --retry \"$n\"", [UNWRITTEN % "\"$URL\""]), ("curl u", [UNWRITTEN % "u"]),
  ("curl -L -H \"Authorization: $T\" https://api.github.com/x", ["a curl that follows a redirect with a header or a credential a variable fills in (\"Authorization: $T\"): the next host gets it"]),
  ("curl -sSLu \"$U\" https://api.github.com/x", ["a curl that follows a redirect with a header or a credential a variable fills in (\"$U\"): the next host gets it"]),
  ("curl -L -H 'Accept: x' https://api.github.com/x", []),
]
SEDS = [
  ("sed -n 1p file", []), ("sed -E 's/.*after //I'", []), ("sed -n '/a/,/b/p' -- \"$0\"", []),
  ("sed -e 's/a/b/' -e 's/c/d/' file", []), ("sed 's/wide/narrow/g' file", []),
  ("sed -i 's/a/b/' file", ["a sed command that edits a file in place"]),
  ("sed -i.bak 's/a/b/' file", ["a sed command that edits a file in place"]),
  ("sed -Ei 's/a/b/' file", ["a sed command that edits a file in place"]),
  ("sed --in-place 's/a/b/' file", ["a sed command that edits a file in place"]),
  ("sed --in-pl=.bak 's/a/b/' file", ["a sed command that edits a file in place"]),
  ("sed -n 'w out' file", ["a sed program that writes a file (the w command or flag)"]),
  ("sed -n '/x/W out' file", ["a sed program that writes a file (the w command or flag)"]),
  ("sed 's/a/b/w out' file", ["a sed program that writes a file (the w command or flag)"]),
  ("sed 's/a/b/gw out' file", ["a sed program that writes a file (the w command or flag)"]),
  ("sed -e p -e 'w out' file", ["a sed program that writes a file (the w command or flag)"]),
  ("sed -n 1p \"$FILE\"", [HIDDEN % ("sed", '"$FILE"')]), ("sed -n 1p $FILE", [HIDDEN % ("sed", "$FILE")]),
  ("sed -n -e 1p \"$FILE\"", [HIDDEN % ("sed", '"$FILE"')]), ("sed -n -e 1p -- \"$FILE\"", []),
  ("sed -l \"$n\" -n l file", []), ("sed -n 1p \"dir/$FILE\"", []),
]
AWKS = [
  ("awk '{ print $1 }' file", []), ("awk -v s=\"$1\" 'NR > s && /^## / { exit } END { print n + 0 }' \"$F\"", []),
  ("awk '$1 > 2 { print }' file", []), ("awk '{ print \">\" }' file", []),
  ("awk '{ print > \"out\" }' file", ["an awk program that writes a file (print > file)"]),
  ("awk '{ print $1 >> \"out\" }' file", ["an awk program that writes a file (print > file)"]),
  ("awk '{ printf \"%s\", $1 > \"out\" }' file", ["an awk program that writes a file (print > file)"]),
  ("awk 'BEGIN { x = 1 } { print x > f }' file", ["an awk program that writes a file (print > file)"]),
]
FINDS = [
  ("find . -name '*.rs' -type f", []), ("find . -name x -delete", []),
  ("find . -fprint out", ["a find action that writes a file (-fprint)"]),
  ("find . -fprintf out %p", ["a find action that writes a file (-fprintf)"]),
  ("find . -fls out", ["a find action that writes a file (-fls)"]),
  ("find \"$dir\" -name x", [HIDDEN % ("find", '"$dir"')]), ("find \"src/$dir\" -name x", []),
]
# (line, the index of the subcommand among the words, expected reasons, builds)
CARGOS = [
  ("cargo build --locked", 1, [], True), ("cargo publish --locked -p \"$crate\"", 1, [], True),
  ("cargo package --workspace --exclude \"axess-example-*\" --locked", 1, [], True),
  ("cargo test --frozen", 1, [], True), ("cargo metadata --locked --format-version 1", 1, [], False),
  ("cargo version", 1, [], False), ("cargo search axess", 1, [], False), ("cargo clean", 1, [], False),
  ("cargo owner --add x axess", 1, [OWN % "owner"], False), ("cargo yank --version 1.0.0 axess", 1, [OWN % "yank"], False),
  ("cargo login", 1, [OWN % "login"], False), ("cargo logout", 1, [OWN % "logout"], False),
  ("cargo publish --locked --registry mirror", 1, ["a cargo registry named by --registry: a job beside a secret publishes to crates.io, cargo's default, alone"], True),
  ("cargo search --index=https://example.invalid x", 1, ["a cargo registry named by --index: a job beside a secret publishes to crates.io, cargo's default, alone"], False),
  ("cargo build", 1, [UNLOCKED % "build"], True), ("cargo publish -p axess", 1, [UNLOCKED % "publish"], True),
  ("cargo tree -e normal", 1, [REWRITES % "tree"], False), ("cargo fetch", 1, [REWRITES % "fetch"], False),
  ("cargo metadata --format-version 1", 1, [REWRITES % "metadata"], False), ("cargo pkgid", 1, [REWRITES % "pkgid"], False),
  ("cargo update", 1, [OWN % "update"], False), ("cargo fmt --check", 1, [OWN % "fmt"], False),
  ("cargo generate-lockfile", 1, [OWN % "generate-lockfile"], False), ("cargo clippy --locked", 1, [OWN % "clippy"], False),
  ("cargo xtask publish", 1, [], False), ("cargo audit", 1, [], False), ("cargo tools/build.rs", 1, [], False),
  ("cargo -Zscript run --locked", 2, [FLAG % "-Zscript"], True), ("cargo -Z unstable-options build --locked", 3, [FLAG % "-Z"], True),
  ("cargo -C dir build --locked", 3, [FLAG % "-C"], True), ("cargo +1.98.0 build --locked", 2, [], True),
  ("cargo build --locked -Zbuild-std", 1, [FLAG % "-Zbuild-std"], True),
  ("cargo build --locked --manifest-path held/Cargo.toml", 1, [], True),
  ("cargo build --locked --manifest-path other/Cargo.toml", 1, [MANIFEST % "other/Cargo.toml"], True),
  ("cargo build --locked --manifest-path=other/Cargo.toml", 1, [MANIFEST % "--manifest-path=other/Cargo.toml"], True),
  ("cargo build --locked --manifest-path \"$M\"", 1, [MANIFEST % '"$M"'], True),
  ("cargo build --locked --manifest-path=\"$M\"", 1, [MANIFEST % '--manifest-path="$M"'], True),
  ("cargo test --locked \"$FILTER\"", 1, ['a cargo argument a variable fills in ("$FILTER"): name it, or give it as the value of an option'], True),
  ("cargo test --locked $ARGS", 1, ["a cargo argument a variable fills in ($ARGS): name it, or give it as the value of an option"], True),
  ("cargo test --locked -p \"$crate\" --features \"$f\" -- \"$FILTER\" $ARGS", 1, [], True),
  ("cargo run --locked --bin \"$bin\" --features=\"$f\"", 1, [], True),
]
# (operator, target, expected reasons)
REDIRECTS = [
  (">", "/dev/null", []), ("2>", "/dev/null", []), (">", "/dev/stderr", []), (">&", "2", []), ("2>&", "1", []),
  (">&", "-", []), ("&>", "/dev/null", []), (">", "/dev/fd/3", []), (">>", '"$GITHUB_OUTPUT"', []),
  (">>", "$GITHUB_STEP_SUMMARY", []), (">>", '"${GITHUB_ENV}"', []), (">>", '"$GITHUB_PATH"', []),
  (">", '"$RUNNER_TEMP/sums"', []), (">>", '"${RUNNER_TEMP}/a/b.log"', []), (">", "$RUNNER_TEMP/x", []),
  ("<", "input", []), ("<<<", '"$text"', []), ("<&", "3", []),
  (">", "out", [WRITES % "out"]), (">>", "Cargo.toml", [WRITES % "Cargo.toml"]), ("&>", "log", [WRITES % "log"]),
  (">|", "out", [WRITES % "out"]), ("<>", "/dev/tcp/h/80", [WRITES % "/dev/tcp/h/80"]), (">", '"$OUT"', [WRITES % '"$OUT"']),
  (">", '"$RUNNER_TEMP"', [WRITES % '"$RUNNER_TEMP"']), (">", '"$RUNNER_TEMP/../x"', [WRITES % '"$RUNNER_TEMP/../x"']),
  (">", '"$RUNNER_TEMP/$name"', [WRITES % '"$RUNNER_TEMP/$name"']), (">", '"$GITHUB_OUTPUT.bak"', [WRITES % '"$GITHUB_OUTPUT.bak"']),
  (">", '"$HOME/.cargo/bin/cargo"', [WRITES % '"$HOME/.cargo/bin/cargo"']), (">", "/tmp/x", [WRITES % "/tmp/x"]),
  (">&", "out", [WRITES % "out"]),
]


def external(sub):
    """Whether a subcommand of the cases is one cargo does not hold itself."""
    return sub in ("xtask", "audit", "tools/build.rs")


def main():
    failures = []

    def check(what, line, got, want):
        if got != want:
            failures.append("%s %r: %r, wanted %r" % (what, line, got, want))
    for line, want in PURE:
        check("pure", line, P.pure(words(line)[0].literal(), args(line)), want)
    for line, want in GIT:
        check("git", line, P.git(args(line)), want)
    for line, want in GH:
        check("gh", line, P.gh(args(line)), want)
    for line, want in CURLS:
        check("curl", line, P.curl(args(line)), want)
    for line, want in SEDS:
        check("sed", line, P.sed(args(line)), want)
    for line, want in AWKS:
        check("awk", line, P.awk(args(line)), want)
    for line, want in FINDS:
        check("find", line, P.find(args(line)), want)
    for line, at, want, builds in CARGOS:
        w = words(line)
        locked = any(x.literal() in ("--locked", "--frozen") for x in w[1:at])
        check("cargo", line, P.cargo(w[at].literal(), w[1:at], w[at + 1:], locked, lambda path: path == "held/Cargo.toml"), (want, builds, external(w[at].literal())))
    for op, target, want in REDIRECTS:
        command = shell_words.lex("x %s %s" % (op, target), lambda offset: 1).commands[0]
        got = [r for o, t in command.redirects for r in P.redirect(o, t)]
        check("redirect", "%s %s" % (op, target), got, want)
    # Every name of the tables is a program the check names; a name in no table is not.
    tables = sorted(P.BUILTINS | P.READ | set(P.PURE))
    for name in tables:
        if not P.named(name):
            failures.append("%s is not named" % name)
    for name in ("docker", "cp", "tee", "chmod", "python3", "rustup", "make", "wget", "tar", "fi"):
        if P.named(name):
            failures.append("%s is named" % name)
    for name in sorted(P.PURE):
        if P.PURE[name] is None and P.pure(name, args("x -o out --output=out \"$X\"")):
            failures.append("%s has an option that writes" % name)
    for flag, names, want in (("--comp", ("--compress-program",), True), ("--compress-program", ("--compress-program",), True),
                              ("--c", ("--compress-program", "--check"), True), ("--", ("--output",), False),
                              ("-o", ("--output",), False), ("--outputs", ("--output",), False)):
        if P.abbreviates(flag, names) is not want:
            failures.append("abbreviates(%r, %r) is not %r" % (flag, names, want))
    for failure in failures:
        print("FAIL: workflow_programs: " + failure, file=sys.stderr)
    total = (len(PURE) + len(GIT) + len(GH) + len(CURLS) + len(SEDS) + len(AWKS) + len(FINDS) + len(CARGOS)
             + len(REDIRECTS) + len(tables) + 10 + len(P.PURE) + 6)
    print("workflow_programs tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
