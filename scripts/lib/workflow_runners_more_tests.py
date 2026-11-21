"""More crafted cases for scripts/lib/workflow_runners.py, run by
scripts/check-workflow-pins-tests.sh: the long options a prefix names, the
git and gh commands that run a program, the awk and sed options that name
a program, the builtins that run a command or assign a variable, and the
variables that say where a program finds its files. Each pins what the
reader returns. Run with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words
import workflow_runners as R
from workflow_runners_tests import args, shown

RUNS = "a git command that runs a program it is given is not read: git %s"
OPTION = "a git option that runs a program is not read: git %s"
SETTING = "a git setting that can run a program is not read: %s"
AWK = "an awk program, a file of one or a library given by an option is not read: %s"
SED_FILE = "a sed program from a file is not read: %s"
SED_RUNS = "a sed program that runs a command (the e command or flag) is not read"
CALLBACK = "a command %s runs through an option is not read: write the command out"
REFERENCE = "a name reference is not read (%s -n): assign the variable by its own name"
PLACE = "%s says where a program finds its settings or the job its files, and the runner sets it: a script or an env: that sets it is not read"
LOADS = "%s makes a program run another one or load code before the command it is given, which is not read"

LONG = [
  ("--command", ("-c", "--command"), "--command"), ("--comm", ("-c", "--command"), "--command"), ("--c", ("-c", "--command"), "--command"),
  ("-c", ("-c", "--command"), "-c"), ("--", ("--command",), None), ("-", ("--command",), None), ("--commands", ("--command",), None),
  ("--session", ("--command", "--session-command"), "--session-command"), ("--x", ("--command",), None),
]
SCRIPTS = [
  ("flock f --comm 'a b'", ["a b"]), ("flock --co='a b' f", ["a b"]), ("flock --timeout 5 f true", []), ("flock --timeo 5 --c x f", ["x"]),
  ("su --session 'a b' u", ["a b"]), ("runuser --comm=x u", ["x"]), ("script --comm 'a b' out", ["a b"]),
  ("env --split 'a b' c", ["a b", "c"]), ("env --split-s='a b'", ["a b"]), ("env -iS 'a b'", ["a b"]), ("env -i0vS'a b' c", ["a b", "c"]),
  ("env --unset X a", []), ("env --uns X -S 'a b'", ["a b"]), ("env --chdir d a", []), ("env -i a", []), ("env --ignore-environment a", []),
]
GITS = [
  ("git bisect run ./t", RUNS % "bisect run"), ("git bisect start", None), ("git submodule foreach 'x'", RUNS % "submodule foreach"),
  ("git submodule update --init", None), ("git filter-branch --tree-filter x", RUNS % "filter-branch"), ("git difftool", RUNS % "difftool"),
  ("git mergetool", RUNS % "mergetool"), ("git rebase -x 'c' m", OPTION % "rebase -x"), ("git rebase -ix c", OPTION % "rebase -ix"),
  ("git rebase --exec=c m", OPTION % "rebase --exec"), ("git rebase --ex c m", OPTION % "rebase --exec"), ("git rebase main", None),
  ("git fetch --upload-pack=./x o", OPTION % "fetch --upload-pack"), ("git fetch --upload-p ./x o", OPTION % "fetch --upload-pack"),
  ("git ls-remote --upload-pack ./x o", OPTION % "ls-remote --upload-pack"), ("git push --receive-pack=./x o", OPTION % "push --receive-pack"),
  ("git push --exec=./x o", OPTION % "push --exec"), ("git push -u origin x", None), ("git push --force-with-lease=a:b o", None),
  ("git clone -u ./x u", OPTION % "clone -u"), ("git clone --upload-pack ./x u", OPTION % "clone --upload-pack"), ("git clone --depth 1 u", None),
  ("git clone -c core.fsmonitor=x u", SETTING % "core.fsmonitor"), ("git clone --config core.pager=x u", SETTING % "core.pager"),
  ("git clone --config=core.pager=x u", SETTING % "core.pager"), ("git clone --conf=alias.x=y u", SETTING % "alias.x"),
  ("git clone -c user.name=x u", None), ("git clone --config=user.email=x u", None), ('git clone -c "$S" u', SETTING % '"$S"'),
  ("git grep -Oless a", OPTION % "grep -Oless"), ("git grep --open-files-in-pager a", OPTION % "grep --open-files-in-pager"), ("git grep -n a", None),
  ("git difftool --extcmd=x", RUNS % "difftool"), ("git log --oneline -- --exec", None), ("git commit -m --exec=x", OPTION % "commit --exec"),
  ("git -C d bisect run x", RUNS % "bisect run"), ("git --namespace n fetch --upload-pack=x", OPTION % "fetch --upload-pack"),
  ("git fetch origin", None), ("git status", None),
]
GHS = [
  ("gh extension install o/r", "an install route the check does not read: gh extension (a program installed from a repository, with no pin)"),
  ("gh ext exec x", "an install route the check does not read: gh extension (a program installed from a repository, with no pin)"),
  ("gh extensions list", "an install route the check does not read: gh extension (a program installed from a repository, with no pin)"),
  ("gh alias set a b", "a gh alias is not read: write the command out"), ("gh alias import f", "a gh alias is not read: write the command out"),
  ("gh alias list", None), ("gh alias", None), ("gh api x", None), ("gh", None), ('gh "$X"', None),
]
AWKS = [
  ("awk --source='BEGIN{}' f", AWK % "--source"), ("awk --sou 'BEGIN{}' f", AWK % "--sou"), ("awk -e 'p' f", AWK % "-e"),
  ("awk -E f", AWK % "-E"), ("awk --exec f", AWK % "--exec"), ("awk -i inplace '{print}' f", AWK % "-i"), ("awk --include=x p", AWK % "--include"),
  ("awk -l lib p", AWK % "-l"), ("awk --load lib p", AWK % "--load"), ("awk -v a=1 '{print}' f", None), ("awk -F: '{print $1}' f", None),
  ("awk --field-separator : p f", None), ("awk --posix p f", None),
]
SEDS = [
  ("sed -Ef a x", SED_FILE % "-Ef"), ("sed -nf a x", SED_FILE % "-nf"), ("sed -f a x", SED_FILE % "-f"), ("sed --file=a x", SED_FILE % "--file=a"),
  ("sed --fil a x", SED_FILE % "--fil"), ("sed --expr='1e id' -e p x", SED_RUNS), ("sed --expression '1e id' x", SED_RUNS),
  ("sed -ne '1e id' x", SED_RUNS), ("sed -n -e1eid x", SED_RUNS), ("sed -Ee p -e '1e id' x", SED_RUNS), ("sed -s -n '$p' a b", None),
  ("sed --sandbox p x", None), ("sed -i.fbak p x", None), ("sed -l 5 -n l x", None), ("sed --line-length=5 -n l x", None),
  ("sed -n p -- x", None), ("sed -- p x", None), ("sed -- '1e id' x", SED_RUNS), ("sed -En 's/a/b/p' x", None),
]
# (line, (the words that hold the program, edits in place))
SED_PROGRAMS = [
  ("sed -n 1p f", (["1p"], False)), ("sed -e a -e b f", (["a", "b"], False)), ("sed -nea f", (["a"], False)), ("sed --expr=a f", (["a"], False)),
  ("sed -i p f", (["p"], True)), ("sed -ni.bak p f", (["p"], True)), ("sed --in-place=.b p f", (["p"], True)), ("sed --in-pl p f", (["p"], True)),
  ("sed -l 5 p f", (["p"], False)), ("sed -l5 p f", (["p"], False)), ("sed -- p f", (["p"], False)), ("sed -e a -- f", (["a"], False)),
  ('sed "$P" f', (["[$P]"], False)), ('sed -e"$P" f', (["[$P]"], False)), ("sed -e", ([], False)), ("sed", ([], False)),
]
# (program, (runs a command, writes a file))
SED_SCANS = [
  ("p", (False, False)), ("s/a/b/g", (False, False)), ("w out", (False, True)), ("/x/W out", (False, True)), ("s/a/b/w out", (False, True)),
  ("s/a/b/gw out", (False, True)), ("1e id", (True, True)), ("s/a/b/e", (True, True)), ("s/w/x/", (False, False)), ("a\\\ntext w", (False, False)),
  ("r in", (False, False)), ("s/a/b", (True, True)), ("?", (True, True)), ("1p;2w out;3d", (False, True)),
]
BUILTINS = [
  ("mapfile -C cb -c 1 a", CALLBACK % "mapfile"), ("mapfile -tC cb a", CALLBACK % "mapfile"), ("readarray -C cb a", CALLBACK % "readarray"),
  ("mapfile -t a", None), ("mapfile -c 1 a", None), ("compgen -C cmd", CALLBACK % "compgen"), ("compgen -G 'a*'", None),
  ("complete -C cmd x", CALLBACK % "complete"), ("complete -F fn x", CALLBACK % "complete"), ("complete -W 'a b' x", None),
  ("bind -x '\"a\": cmd'", CALLBACK % "bind"), ("bind -l", None), ("declare -n r=X", REFERENCE % "declare"), ("declare -gn r=X", REFERENCE % "declare"),
  ("local -n r=$1", REFERENCE % "local"), ("typeset -n r", REFERENCE % "typeset"), ("declare -i n=1", None), ("declare -A map", None),
  ("local name=$1", None), ("export -n X", None), ("echo -n x", None),
]
# (line, (the names assigned, the operand a variable names))
ASSIGNED = [
  ("for PATH in a b", (["PATH"], None)), ("select X in a b", (["X"], None)), ("for x", (["x"], None)), ("for", ([], None)),
  ("read -r a b", (["a", "b"], None)), ("read -ra ARR", (["ARR"], None)), ("read -p prompt -t 5 X", (["X"], None)), ("read", ([], None)),
  ("read -d '' -r X", (["X"], None)), ('read -r "$name"', ([], '"$name"')), ('read -p "$prompt" X', (["X"], None)), ("read -u 3 X", (["X"], None)),
  ("mapfile -t LINES", (["LINES"], None)), ("mapfile -d '' -n 5 A", (["A"], None)), ('readarray "$A"', ([], '"$A"')),
  ("getopts ab OPT", (["OPT"], None)), ('getopts "$spec" OPT', (["OPT"], None)), ('getopts ab "$V"', ([], '"$V"')), ("getopts ab", ([], None)),
  ("printf -v OUT %s x", (["OUT"], None)), ('printf -v "$N" %s x', ([], '"$N"')), ('printf "%s" "$x"', ([], None)), ("printf -v", ([], None)),
  ("wait -p PID -n", (["PID"], None)), ("wait 5", ([], None)),
  ("export A=1 B", ([], None)), ('export "$PAIR"', ([], '"$PAIR"')), ('declare "$n=$v"', ([], '"$n=$v"')), ('local "x=$v"', ([], None)),
  ('readonly X"$s"=1', ([], 'X"$s"=1')), ('export -n "$X"', ([], '"$X"')), ('declare -a "arr=($x)"', ([], None)), ('typeset "$x"', ([], '"$x"')),
  (': "${A:=x}" ${B=y} "${C:-z}"', (["A", "B"], None)), ('X="${PATH:=x}"', (["PATH"], None)), ('echo "${X:-${Y:=z}}"', (["Y"], None)),
  ("echo a b", ([], None)), ('"$cmd" a', ([], None)),
]
EXPANSIONS = [
  ('echo "${p@P}"', "an expansion that runs the commands in the value of a variable is not read: ${p@P}"),
  ("echo ${p@P}", "an expansion that runs the commands in the value of a variable is not read: ${p@P}"),
  ('X="${a[0]@P}"', "an expansion that runs the commands in the value of a variable is not read: ${a[0]@P}"),
  ('echo "${p@Q}" "${p@E}" "${p@A}"', None), ("echo '${p@P}'", None), ('echo "$p" ${p}', None),
]
ENV = [(name, PLACE % name) for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "GITHUB_WORKSPACE", "RUNNER_TEMP",
                                         "GITHUB_ENV", "GITHUB_PATH")]
ENV += [(name, LOADS % name) for name in (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONBREAKPOINT", "PYTHONWARNINGS",
    "PERL5LIB", "PERLLIB", "PERL5OPT", "RUBYLIB", "RUBYOPT", "NODE_OPTIONS", "NODE_PATH", "AWKPATH", "AWKLIBPATH", "CURL_HOME",
    "LESSOPEN", "LESSCLOSE", "MANPAGER", "BROWSER", "TAR_OPTIONS", "SHELL", "CDPATH", "GH_BROWSER", "GH_EDITOR", "GH_PAGER",
    "GH_CONFIG_DIR", "RUSTUP_HOME", "RUSTUP_DIST_SERVER", "RUSTUP_UPDATE_ROOT")]
SUDO = [
  ("sudo -s", True), ("sudo -i", True), ("sudo -u builder -i", True), ("sudo -Es", True), ("sudo --shell", True), ("sudo --login", True),
  ("env X=1 sudo -s", True), ("sudo", False), ("sudo -E", False), ("sudo -u builder", False), ("sudo -n", False), ("echo -s", False),
  ("sudo --preserve-env=X", False),
]
BUILD = [
  ("CC", True), ("CXX", True), ("AR", True), ("LD", True), ("NM", True), ("RANLIB", True), ("TARGET_CC", True), ("HOST_CXX", True),
  ("CC_x86_64_unknown_linux_gnu", True), ("CXX_aarch64-apple-darwin", True), ("CMAKE", True), ("PKG_CONFIG", True),
  ("PKG_CONFIG_PATH", True), ("PKG_CONFIG_LIBDIR", True), ("PKG_CONFIG_SYSROOT_DIR", True), ("PROTOC", True),
  ("LIBCLANG_PATH", True), ("CLANG_PATH", True), ("LLVM_CONFIG_PATH", True), ("CCACHE_DIR", False), ("CFLAGS", False),
  ("ARCH", False), ("LDFLAGS", False), ("MY_CC", False), ("CARGO", False), ("PKG_CONFIG_ALLOW_CROSS", False), ("CMAKE_GENERATOR", False),
]
HOST = "%s points a program at another host, or changes which hosts it trusts, with the job's credentials, which is not read"
ENV += [(name, HOST % name) for name in (
    "GH_HOST", "GH_REPO", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GITHUB_API_URL", "GITHUB_SERVER_URL", "GITHUB_GRAPHQL_URL",
    "GITHUB_REPOSITORY", "ACTIONS_RUNTIME_URL", "ACTIONS_CACHE_URL", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
    "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO")]
ENV += [(name, None) for name in ("HOMEBREW_PREFIX", "MY_HOME", "GITHUB_REF", "GITHUB_SHA", "RUNNER_OS", "TMPDIR", "PYTHONUNBUFFERED",
                                  "GH_TOKEN", "RUSTUP_TOOLCHAIN", "NO_PROXY", "GITHUB_REF_NAME", "ACTIONS",
                                  "GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY", "ACTIONS_ID_TOKEN_REQUEST_URL",
                                  "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GIT_AUTHOR_NAME", "SHELLCHECK_OPTS", "TAG")]


def words(line):
    return shell_words.lex(line, lambda offset: 1).commands[0].words


def main():
    failures = []

    def check(what, line, got, want):
        if got != want:
            failures.append("%s %r: %r, wanted %r" % (what, line, got, want))
    for flag, names, want in LONG:
        check("long option", (flag, names), R.long_option(flag, names), want)
    for line, want in SCRIPTS:
        name, rest = args(line)
        check("script of", line, shown(R.script_of(name, rest)), want)
    for line, want in GITS:
        check("git", line, R.git_problem(args(line)[1]), want)
    for line, want in GHS:
        check("gh", line, R.gh_problem(args(line)[1]), want)
    for line, want in AWKS:
        check("awk", line, R.awk_problem(args(line)[1]), want)
    for line, want in SEDS:
        check("sed", line, R.sed_problem(args(line)[1]), want)
    for line, want in SED_PROGRAMS:
        programs, _, in_place = R.sed_programs(args(line)[1])
        check("sed programs", line, (shown(programs), in_place), want)
    for program, want in SED_SCANS:
        check("sed scan", program, R.sed_scan(program), want)
    for line, want in BUILTINS:
        name, rest = args(line)
        check("builtin", line, R.builtin_problem(name, rest), want)
    for line, want in ASSIGNED:
        w = words(line)
        start = None if "=" in w[0].raw and w[0].raw[0] != '"' else 0
        names, unread = R.assigned(w, start)
        check("assigned", line, (names, unread.raw if unread is not None else None), want)
    for line, want in EXPANSIONS:
        check("expansion", line, R.expansion_problem(words(line)), want)
    for name, want in ENV:
        check("variable", name, R.env_problem(name), want)
    for line, want in SUDO:
        check("a sudo that starts a shell", line, R.sudo_shell(words(line)), want)
    STAND_IN = "a stand-in for the runner (%s): a job beside a secret takes the runner's own"
    for name, want in (("ACTIONS_ID_TOKEN_REQUEST_URL", True), ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", True), ("GITHUB_OUTPUT", True),
                       ("GITHUB_STATE", True), ("GITHUB_STEP_SUMMARY", True), ("ACTIONS_ID_TOKEN_REQUEST_URLX", False),
                       ("ACTIONS_RUNTIME_URL", False), ("GITHUB_ENV", False), ("GITHUB_OUTPUTS", False)):
        check("a stand-in for the runner", name, R.stand_in(name), STAND_IN % name if want else None)
    for name, want in BUILD:
        check("a variable a build script runs a program by", name, R.BUILD_ENV.fullmatch(name) is not None, want)
    for failure in failures:
        print("FAIL: workflow_runners_more: " + failure, file=sys.stderr)
    total = (len(LONG) + len(SCRIPTS) + len(GITS) + len(GHS) + len(AWKS) + len(SEDS) + len(SED_PROGRAMS) + len(SED_SCANS)
             + len(BUILTINS) + len(ASSIGNED) + len(EXPANSIONS) + len(ENV) + len(SUDO) + len(BUILD) + 9)
    print("workflow_runners_more tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
