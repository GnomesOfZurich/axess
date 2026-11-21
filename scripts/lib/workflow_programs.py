"""The programs a job runs beside a secret, for scripts/check-workflow-pins.sh.

A job that names a secret, may ask for an OIDC token or holds a token that
can write runs only what the check reads: the shell's own words and
builtins, the functions of the script, a script the repository holds, and
the programs of the runner's image named here. A named program is one of
three kinds. One runs no program and writes no file, whatever its
arguments (`grep`, `cut`, `jq`). One does so only through options listed
beside it (`sort -o`, `base64 --output`), which are refused. One is read
by a reader of its own: `git`, `gh`, `cargo`, `curl`, `sed`, `awk` and
`find` here, the shells and the programs that hand a string to one in
scripts/lib/workflow_installs.py.

Every function returns the reasons a command is not held, as noun phrases
that end the sentence "a job that names a secret runs what the check does
not read: job J, ...". An empty list: the command is held.

An option hides in a variable: `git fetch "$X"` runs a program when X is
`--upload-pack=./tool`. So where a program has an option that writes a
file or runs a program, an argument that begins with an expansion is
refused unless it stands after `--` or is the value of an option the
reader knows to take one.
"""

import re

import workflow_runners
import workflow_values

# The shell's grammar: a word that opens, joins or closes a compound
# command, when written bare.
SYNTAX = {"if", "then", "else", "elif", "fi", "for", "select", "while", "until", "do", "done",
          "case", "in", "esac", "function", "{", "}", "!", "[[", "]]", "time", "coproc"}
# Builtins that run no program. `eval`, `source`, `trap`, `alias` and
# `enable` are read or refused by scripts/lib/workflow_installs.py.
BUILTINS = {":", "[", "test", "true", "false", "echo", "printf", "read", "cd", "pushd", "popd",
            "dirs", "pwd", "set", "shopt", "unset", "export", "declare", "typeset", "local",
            "readonly", "return", "exit", "break", "continue", "shift", "wait", "kill", "type", "hash",
            "umask", "ulimit", "let", "getopts", "times", "jobs", "disown", "unalias", "mapfile",
            "readarray", "compgen", "caller", "command", "builtin", "exec", "eval", ".", "source",
            "trap", "alias", "enable"}
# Programs read elsewhere: named, and judged by their own reader.
READ = {"sh", "bash", "dash", "git", "gh", "cargo", "curl", "sed", "gsed", "awk", "gawk", "mawk",
        "nawk", "find", "xargs", "env", "sudo", "nice", "nohup", "stdbuf", "timeout"}
# Programs of the runner's image that run no program and write nothing into
# a file (`mkdir`, `mktemp` and `rm` make and remove, and write no text):
# None, or the options (short letters, long names) through which one does.
PURE = {
    "cat": None, "cut": None, "tr": None, "head": None, "tail": None, "wc": None, "grep": None,
    "egrep": None, "fgrep": None, "diff": None, "cmp": None, "comm": None, "sha256sum": None,
    "sha512sum": None, "sha1sum": None, "md5sum": None, "cksum": None, "date": None,
    "sleep": None, "dirname": None, "basename": None, "realpath": None, "readlink": None,
    "ls": None, "stat": None, "du": None, "df": None, "uname": None, "id": None, "whoami": None,
    "nproc": None, "printenv": None, "seq": None, "expr": None, "tac": None, "rev": None,
    "nl": None, "paste": None, "fold": None, "column": None, "od": None, "jq": None,
    "which": None, "mkdir": None, "mktemp": None, "rm": None, "rmdir": None,
    "sort": ("o", ("--output", "--compress-program")),
    "base64": ("o", ("--output",)),
    "uniq": ("", ()),
}

# git subcommands that run no program they are given and write no file of
# the checkout, and those that change the files of the checkout.
GIT_READS = {"status", "log", "show", "diff", "rev-parse", "rev-list", "merge-base", "ls-remote",
             "ls-files", "ls-tree", "cat-file", "for-each-ref", "show-ref", "describe", "tag",
             "branch", "remote", "fetch", "push", "config", "symbolic-ref", "name-rev",
             "shortlog", "blame", "grep", "count-objects", "check-ignore", "check-attr", "var",
             "version", "diff-tree", "diff-index", "diff-files", "update-ref", "add", "commit"}
GIT_TREE = {"checkout", "switch", "restore", "reset", "merge", "pull", "rebase", "cherry-pick",
            "revert", "apply", "am", "stash", "clone", "submodule", "worktree", "read-tree",
            "checkout-index", "clean", "mv", "rm", "sparse-checkout"}
# git subcommands with an option that runs a program or writes a file
# (`--upload-pack`, `--receive-pack`, `--exec`, `--output`, `--template`).
GIT_RISK = {"fetch", "pull", "push", "ls-remote", "clone", "rebase", "grep", "diff", "log", "show",
            "submodule", "diff-tree", "diff-index", "diff-files", "shortlog", "blame", "worktree"}
GIT_WRITES = ("--output", "--template", "--separate-git-dir")
GIT_GLOBAL_VALUES = {"-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--attr-source"}
# gh commands that call the API and neither run a program, download a file
# nor change the checkout.
GH = {
    "api": None, "status": None, "search": None,
    "issue": {"list", "view", "create", "comment", "edit", "close", "reopen", "status", "lock",
              "unlock", "pin", "unpin", "delete", "transfer"},
    "pr": {"list", "view", "create", "comment", "edit", "close", "reopen", "merge", "ready",
           "review", "status", "checks", "diff"},
    "release": {"list", "view", "create", "edit", "upload", "delete", "delete-asset"},
    "workflow": {"list", "view", "run", "enable", "disable"},
    "run": {"list", "view", "watch", "rerun", "cancel", "delete"},
    "label": {"list", "create", "edit", "delete", "clone"},
    "repo": {"view", "list"}, "auth": {"status", "token"},
    "variable": {"list", "get", "set", "delete"}, "cache": {"list", "delete"},
    "ruleset": {"list", "view", "check"},
}
# cargo's own subcommands that build or resolve from the lockfile, and
# those that do neither.
CARGO_LOCKED = {"build", "b", "check", "c", "test", "t", "bench", "doc", "d", "run", "r", "rustc",
                "rustdoc", "package", "publish", "metadata", "tree", "fetch", "pkgid"}
CARGO_BUILDS = CARGO_LOCKED - {"metadata", "tree", "fetch", "pkgid"}
CARGO_PLAIN = {"version", "help", "search", "locate-project", "read-manifest", "clean", "report"}
# The rest of cargo's own subcommands, and the toolchain's: they change the
# sources or the lockfile, act on a crate's owners or releases with the
# job's registry token, or are not needed beside a secret.
CARGO_OWN = {"owner", "yank", "login", "logout",
             "add", "remove", "rm", "update", "generate-lockfile", "new", "init", "vendor", "fix",
             "fmt", "clippy", "miri", "install", "uninstall", "config", "info", "verify-project"}
# Every subcommand cargo holds itself, whose words are cargo's.
CARGO_SUBCOMMANDS = CARGO_LOCKED | CARGO_PLAIN | CARGO_OWN
CARGO_VALUES = {"-p", "--package", "--exclude", "--features", "-F", "--target", "--bin", "--example",
                "--test", "--bench", "--profile", "-j", "--jobs", "--color", "--message-format",
                "--target-dir", "--registry", "--index", "--config", "--manifest-path",
                "--lockfile-path", "--format-version", "--filter-platform", "-e", "--edges",
                "-i", "--invert", "--prefix", "--format", "--depth", "--token"}
# curl options that neither write a file nor read options from one: those
# that stand alone (short letters and long names) and those that take a value.
CURL_SHORT = set("fsSLiIvgNGq46")
CURL_FLAGS = {"--fail", "--fail-with-body", "--silent", "--show-error", "--location", "--include",
              "--head", "--verbose", "--globoff", "--compressed", "--tlsv1.2", "--tlsv1.3",
              "--http1.1", "--http2", "--retry-connrefused", "--retry-all-errors",
              "--no-progress-meter", "--no-buffer", "--get", "--disable", "--ipv4", "--ipv6"}
# curl options whose value is a file curl writes, or a format it prints.
CURL_OUTPUT = {"-o", "--output", "-w", "--write-out"}
# curl options whose value goes to the host as a header, a credential or a
# cookie, and with -L to the next host too.
CURL_CARRIES = {"-H", "--header", "-u", "--user", "--oauth2-bearer", "-b", "--cookie", "-e", "--referer", "-A", "--user-agent"}
# The hosts a job beside a secret may talk to: crates.io, GitHub, and the
# runner's own services, whose URLs the runner sets (scripts/lib/workflow_values.py).
HOSTS = {"crates.io", "static.crates.io", "index.crates.io", "github.com", "api.github.com", "uploads.github.com",
         "the runner's OIDC token service"}
CURL_VALUES = {"--retry", "--retry-delay", "--retry-max-time", "-m", "--max-time",
               "--connect-timeout", "-A", "--user-agent", "-H", "--header", "-X", "--request",
               "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-u", "--user",
               "--proto", "--proto-redir", "--max-redirs", "-e", "--referer", "--url", "--json",
               "--max-filesize", "--oauth2-bearer", "-F", "--form"}
# Directories of the runner's image: a program named by a path into one is
# the program of that name.
SYSTEM = ("/bin/", "/usr/bin/", "/usr/local/bin/", "/sbin/", "/usr/sbin/")
# Where a script may write: the runner's own files and its temporary directory.
RUNNER_FILE = re.compile(r"\$\{?GITHUB_(OUTPUT|STEP_SUMMARY|STATE|ENV|PATH)\}?")
RUNNER_TEMP = re.compile(r"\$\{?RUNNER_TEMP\}?")
DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr"}


def pieces(word):
    """The parts of a word, the literal text between two expansions as one."""
    out = []
    for kind, text in word.parts:
        if kind == "lit" and out and out[-1][0] == "lit":
            out[-1] = ("lit", out[-1][1] + text)
        else:
            out.append((kind, text))
    return out


def variable_first(word):
    """Whether a word begins with an expansion, so that its value may be an option."""
    return word.literal() is None and not word.head()


def abbreviates(flag, names):
    """Whether a long option is one of `names` or a prefix of one, as
    getopt_long takes it (`--comp` for `--compress-program`)."""
    return flag.startswith("--") and len(flag) > 2 and any(n.startswith(flag) for n in names)


def hidden(name, args, values=()):
    """The first argument before `--` that begins with an expansion and is
    not the value of an option in `values`: an option the check cannot see."""
    after_value = False
    for w in args:
        if w.literal() == "--":
            return None
        if after_value:
            after_value = False
            continue
        if variable_first(w):
            return "an argument of %s that a variable fills in and that may be an option (%s): put it after --" % (name, w.raw)
        after_value = w.literal() in values
    return None


def pure(name, args):
    """A program of PURE: its options that write a file or run a program."""
    spec = PURE[name]
    if spec is None:
        return []
    letters, longs = spec
    operands = 0
    for w in args:
        head = w.head()
        if w.literal() == "--":
            break
        flag = head.partition("=")[0]
        if abbreviates(flag, longs) or (letters and re.fullmatch(r"-[A-Za-z0-9]*[%s].*" % letters, head)):
            return ["an option of %s that writes a file or runs a program (%s)" % (name, w.raw)]
        operands += not head.startswith("-")
    if name == "uniq" and operands > 1:
        return ["a file uniq writes (its second operand)"]
    problem = hidden(name, args)
    return [problem] if problem else []


def git(args):
    """(reasons, changes the checkout, subcommand) for a git command."""
    k = 0
    reasons = []
    while k < len(args):
        t = args[k].literal()
        head = args[k].head().partition("=")[0]
        if head in ("-C", "--git-dir", "--work-tree"):
            reasons.append("git in another directory or repository (%s)" % head)
        if t is None or not t.startswith("-"):
            break
        k += 2 if t in GIT_GLOBAL_VALUES or t == "-c" else 1
    if k >= len(args):
        return reasons, False, None
    sub = args[k].literal()
    rest = args[k + 1:]
    if sub is None:
        return reasons + ["a git subcommand from a variable (%s)" % args[k].raw], False, None
    if sub not in GIT_READS and sub not in GIT_TREE:
        return reasons + ["a git subcommand the check does not name (git %s)" % sub], False, sub
    for w in rest:
        if w.literal() == "--":
            break
        flag = w.head().partition("=")[0]
        if abbreviates(flag, GIT_WRITES):
            reasons.append("a git option that writes a file (%s)" % w.raw)
    if sub in GIT_RISK:
        problem = hidden("git " + sub, rest)
        if problem:
            reasons.append(problem)
    reasons.extend(git_remote(sub, rest))
    return reasons, sub in GIT_TREE, sub


def gh(args):
    """A gh command: one of GH, named by literal words."""
    words = [w.literal() for w in args[:2]] + [None, None]
    group, sub = words[0], words[1]
    if group is None:
        return ["a gh command from a variable"]
    if group not in GH:
        return ["a gh command the check does not name (gh %s)" % group]
    if GH[group] is not None and sub not in GH[group]:
        shown = sub if sub is not None else (args[1].raw if len(args) > 1 else "")
        return ["a gh command the check does not name (%s)" % " ".join(p for p in ("gh", group, shown) if p)]
    return gh_hosts(group, args[1:])


def gh_hosts(group, args):
    """gh talks to github.com: no `--hostname`, no repository named with a
    host (`HOST/OWNER/REPO`) or by a variable other than the runner's
    `$GITHUB_REPOSITORY`, and no `gh api` endpoint that is a URL."""
    for k, w in enumerate(args):
        if w.literal() == "--":
            break
        flag, eq, _ = w.head().partition("=")
        value = cut_joined(w, len(flag) + 1) if eq else (args[k + 1] if k + 1 < len(args) else None)
        if flag == "--hostname":
            return ["gh pointed at another host (%s)" % w.raw]
        if flag in ("-R", "--repo") and value is not None:
            literal = value.literal()
            runner = re.fullmatch(r"\$\{?GITHUB_REPOSITORY\}?", "".join(text for _, text in value.parts) if len(value.parts) == 1 else "")
            if (literal is None and not runner) or (literal is not None and literal.count("/") != 1):
                return ["a gh repository that may name another host (%s): name OWNER/REPO, or $GITHUB_REPOSITORY" % value.raw]
    if group == "api":
        endpoints = [w for w in args if not w.head().startswith("-")]
        for w in endpoints[:1]:
            if variable_first(w) or re.match(r"[A-Za-z]+:|//", w.head()):
                return ["a gh api endpoint that may be a URL of another host (%s)" % w.raw]
    return []


# git subcommands that talk to a remote, and their options that take a
# value as the next word.
GIT_REMOTE_VALUES = {
    "push": {"-o", "--push-option", "--signed"}, "fetch": {"-j", "--jobs", "--depth", "--deepen", "--shallow-since",
    "--shallow-exclude", "--negotiation-tip", "-o", "--server-option", "--refmap", "--filter"},
    "pull": {"-j", "--jobs", "--depth", "--deepen", "--shallow-since", "--shallow-exclude", "-o", "--server-option",
             "-s", "--strategy", "-X", "--strategy-option"},
    "ls-remote": {"--sort", "-o", "--server-option"},
}


def git_remote(sub, rest):
    """A job beside a secret talks to the repository's own remote alone:
    `origin`, or the one a branch tracks, which only a setting this check
    refuses could change. A URL, another remote, `--repo`, a clone and a
    change to the remotes are refused."""
    if sub == "clone":
        return ["a clone of another repository beside a secret"]
    if sub == "remote":
        verbs = [w.literal() for w in rest if not (w.literal() or "-").startswith("-")]
        if verbs[:1] and verbs[0] not in ("show", "get-url"):
            return ["a change to the remotes of the checkout (git remote %s)" % verbs[0]]
        return []
    if sub not in GIT_REMOTE_VALUES:
        return []
    skip = False
    for w in rest:
        literal = w.literal()
        if skip:
            skip = False
            continue
        if literal == "--":
            break
        flag = w.head().partition("=")[0]
        if flag == "--repo":
            return ["a git remote named by --repo (%s): a job beside a secret talks to origin" % w.raw]
        if w.head().startswith("-"):
            skip = flag in GIT_REMOTE_VALUES[sub] and "=" not in w.head()
            continue
        if literal != "origin":
            return ["a git remote other than origin (%s): a job beside a secret talks to the repository's own" % w.raw]
        break
    return []


def cargo(sub, flags, rest, locked, holds):
    """A cargo command other than install: `sub` its subcommand, `flags`
    the words before it and `rest` those after; `holds(path)` tells whether
    the repository holds a file. Returns (reasons, builds, external):
    `external` for a subcommand that is not cargo's own, which every job
    is held to install (scripts/lib/workflow_pins.py)."""
    reasons = []
    for w in flags:
        if w.head() in ("-C", "-Z") or w.head().startswith("-Z"):
            reasons.append("a cargo flag that changes where or how it runs (%s)" % w.raw)
    for w in flags + rest:
        if w.literal() == "--":
            break
        if w.head().partition("=")[0] in ("--registry", "--index"):
            reasons.append("a cargo registry named by %s: a job beside a secret publishes to crates.io, cargo's default, alone" % w.head().partition("=")[0])
    if sub in CARGO_PLAIN:
        return reasons, False, False
    if sub in CARGO_OWN:
        return reasons + ["cargo %s, which changes the sources or the lockfile or is not needed beside a secret" % sub], False, False
    if sub not in CARGO_LOCKED:
        return reasons, False, True
    after_value = None
    for w in rest:
        literal = w.literal()
        if literal == "--":
            break
        if after_value == "--manifest-path" and not (literal is not None and holds(literal)):
            reasons.append("a cargo manifest the repository does not hold (%s)" % w.raw)
        if after_value:
            after_value = None
            continue
        head = w.head()
        flag, eq, value = head.partition("=")
        if flag in ("--locked", "--frozen"):
            locked = True
        elif flag == "--manifest-path" and eq and not (literal is not None and holds(value)):
            reasons.append("a cargo manifest the repository does not hold (%s)" % w.raw)
        elif flag == "-Z" or flag.startswith("-Z"):
            reasons.append("a cargo flag that changes where or how it runs (%s)" % w.raw)
        elif literal is None and not flag.startswith("-"):
            reasons.append("a cargo argument a variable fills in (%s): name it, or give it as the value of an option" % w.raw)
        after_value = flag if flag in CARGO_VALUES and not eq else None
    if not locked and sub in CARGO_BUILDS:
        reasons.append("cargo %s without --locked: it builds what the registry serves on the day, not the lockfile" % sub)
    elif not locked:
        reasons.append("cargo %s without --locked: it may rewrite the lockfile a later build reads" % sub)
    return reasons, sub in CARGO_BUILDS, False


class Unknown:
    """A place that knows nothing of a script's variables: a host is the
    one a word writes out."""

    @staticmethod
    def host(word):
        head = word.head()
        return workflow_values.host_of(head, word.literal() is not None) if head else None


def curl(args, place=Unknown):
    """A curl command: every option is one that neither writes a file nor
    reads options from one, its output goes to a file of the runner's
    temporary directory, and every
    address is one of HOSTS, written out to its host or named by a variable
    the script set to such a text (`place` knows the script's values). A
    redirect is followed only when no header a variable fills in goes with
    it to the next host."""
    k, reasons, follows, carried = 0, [], False, None
    while k < len(args):
        w = args[k]
        head = w.head()
        literal = w.literal()
        k += 1
        flag = head.partition("=")[0]
        joined = "=" in head and flag.startswith("--")
        value = None
        if not head.startswith("-"):
            reasons.extend(curl_address(w, place))
            continue
        if literal is not None and (literal in CURL_FLAGS or (re.fullmatch(r"-[A-Za-z0-9]+", literal) and set(literal[1:]) <= CURL_SHORT)):
            follows = follows or literal in ("-L", "--location") or (not literal.startswith("--") and "L" in literal)
            continue
        if flag in CURL_VALUES or flag in CURL_OUTPUT or flag == "--url":
            name = flag
        elif not head.startswith("--") and head[:2] in CURL_VALUES | CURL_OUTPUT:
            name = head[:2]
        elif literal is not None and re.fullmatch(r"-[A-Za-z0-9]+", literal) and set(literal[1:-1]) <= CURL_SHORT and "-" + literal[-1] in CURL_VALUES | CURL_OUTPUT:
            name = "-" + literal[-1]
            follows = follows or "L" in literal[1:-1]
        else:
            return ["a curl option the check does not name (%s): it may write a file or read options from one" % w.raw]
        attached = not head.startswith("--") and len(head) > len(name) and head.startswith(name)
        if joined:
            value = cut_joined(w, len(flag) + 1)
        elif attached or (not head.startswith("--") and literal is None and head == name):
            value = cut_joined(w, len(name))
        elif k < len(args):
            value, k = args[k], k + 1
        if value is None:
            continue
        shown = "".join(text for _, text in value.parts) if value.raw == w.raw else value.raw
        if name in ("-o", "--output") and not (value.literal() in DEVICES or runner_temp(value)):
            reasons.append("a file curl writes outside the runner's temporary directory (%s)" % shown)
        elif name in ("-w", "--write-out") and (value.literal() is None or "%output{" in value.literal()):
            reasons.append("a curl output format that is not written out, or that writes a file (%s)" % shown)
        elif name == "--url":
            reasons.extend(curl_address(value, place))
        elif name in CURL_CARRIES and value.literal() is None and carried is None:
            carried = shown
    if follows and carried is not None:
        reasons.append("a curl that follows a redirect with a header or a credential a variable fills in (%s): the next host gets it" % carried)
    return reasons


def curl_address(word, place):
    host = place.host(word)
    if host is None:
        return ["a curl address whose host is not written out (%s): the job's credentials may go to any host" % word.raw]
    if host not in HOSTS:
        return ["a curl address of a host the check does not name (%s): a job beside a secret talks to crates.io and GitHub" % host]
    return []


def cut_joined(word, n):
    """The value of a long option joined to it by `=`."""
    return workflow_runners.cut(word, n)


def runner_temp(word):
    parts = pieces(word)
    return (len(parts) == 2 and parts[0][0] == "exp" and RUNNER_TEMP.fullmatch(parts[0][1]) is not None and parts[1][0] == "lit"
            and parts[1][1].startswith("/") and ".." not in parts[1][1].split("/"))


def sed(args):
    """A sed command: it edits no file in place, its program writes none
    and no operand of it may be an option."""
    programs, _, in_place = workflow_runners.sed_programs(args)
    reasons = ["a sed command that edits a file in place"] if in_place else []
    if any(w.literal() is not None and workflow_runners.sed_scan(w.literal())[1] for w in programs):
        reasons.append("a sed program that writes a file (the w command or flag)")
    problem = hidden("sed", [w for w in args if not any(w is p for p in programs)], {"-l", "--line-length"})
    return reasons + ([problem] if problem else [])


def awk(args):
    """An awk command: its program redirects no output to a file."""
    for w in args:
        literal = w.literal()
        if literal is None:
            continue
        stripped = re.sub(r'"(\\.|[^"\\])*"', '""', literal)
        if re.search(r"\b(print|printf)\b[^;}\n]*>", stripped):
            return ["an awk program that writes a file (print > file)"]
    return []


def find(args):
    """A find command: no action of it writes a file."""
    reasons = ["a find action that writes a file (%s)" % w.raw for w in args
               if w.literal() in ("-fprint", "-fprint0", "-fprintf", "-fls")]
    problem = hidden("find", args)
    return reasons + ([problem] if problem else [])


def redirect(op, target):
    """A redirection that writes: its file is one of the runner's own, a
    device or a file of the runner's temporary directory."""
    if ">" not in op or target is None or op in (">&", "<&") and re.fullmatch(r"\d+|-", target.literal() or ""):
        return []
    literal = target.literal()
    if literal is not None:
        if literal in DEVICES or re.fullmatch(r"/dev/fd/\d+", literal) or (op in (">&", "&>", "&>>") and re.fullmatch(r"\d+|-", literal)):
            return []
        return ["a file a script writes outside the runner's temporary directory (%s)" % target.raw]
    parts = pieces(target)
    if len(parts) == 1 and parts[0][0] == "exp" and RUNNER_FILE.fullmatch(parts[0][1]):
        return []
    if runner_temp(target):
        return []
    return ["a file a script writes outside the runner's temporary directory (%s)" % target.raw]


def named(name):
    """Whether the check names the program: one of the lists above."""
    return name in BUILTINS or name in READ or name in PURE
