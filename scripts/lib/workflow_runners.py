"""Programs that run another program from a string, a setting or the
environment, for scripts/check-workflow-pins.sh.

A command can run `cargo install` without the words standing in it: as the
string `env -S`, `flock -c`, `su -c`, `script -c`, `watch`, `trap` or `ssh`
hands to a shell, as a git alias or another git setting that names a
program, as an awk program that calls `system` or a pipe, as the sed `e`
command, or through a variable the shell or git reads before it runs
anything (`BASH_ENV`, `PS4`, `GIT_SSH_COMMAND`, ...). `script_of` returns
the string such a program runs, so that the caller reads it as `sh -c`
text; the `*_problem` functions name what the check does not read. A long
option is taken as getopt_long takes it, by any prefix that names it
(`--comm` is `--command`).
"""

import re

import shell_words

# Variables through which a program runs another one, or loads code, before
# or beside the command it is given.
RUN_ENV = re.compile(
    r"BASH_ENV|ENV|PROMPT_COMMAND|PS4|SHELLOPTS|BASHOPTS|BASH_FUNC_.*|"
    r"LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH|DYLD_.*|"
    r"GIT_SSH|GIT_SSH_COMMAND|GIT_PROXY_COMMAND|GIT_ASKPASS|SSH_ASKPASS|GIT_PAGER|PAGER|"
    r"GIT_EDITOR|GIT_SEQUENCE_EDITOR|EDITOR|VISUAL|GIT_EXTERNAL_DIFF|GIT_EXEC_PATH|"
    r"GIT_TEMPLATE_DIR|GIT_CONFIG|GIT_CONFIG_.*|"
    r"GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_COMMON_DIR|GIT_OBJECT_DIRECTORY|"
    r"GIT_ALTERNATE_OBJECT_DIRECTORIES|GIT_NAMESPACE|"
    r"PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|PYTHONUSERBASE|PYTHONBREAKPOINT|PYTHONWARNINGS|"
    r"PERL5LIB|PERLLIB|PERL5OPT|RUBYLIB|RUBYOPT|NODE_OPTIONS|NODE_PATH|AWKPATH|AWKLIBPATH|"
    r"CURL_HOME|LESSOPEN|LESSCLOSE|MANPAGER|BROWSER|TAR_OPTIONS|SHELL|CDPATH|"
    r"GH_BROWSER|GH_EDITOR|GH_PAGER|GH_CONFIG_DIR|"
    r"RUSTUP_HOME|RUSTUP_DIST_SERVER|RUSTUP_UPDATE_ROOT")
# Variables that say where a program finds its own files, its settings or
# the files of the job: a value other than the runner's points a program
# at files the check did not read.
PLACE_ENV = re.compile(r"HOME|XDG_CONFIG_HOME|XDG_DATA_HOME|XDG_CACHE_HOME|GITHUB_WORKSPACE|RUNNER_TEMP|"
                       r"GITHUB_ENV|GITHUB_PATH")
# Variables that send what a program sends to another host, or change which
# hosts it trusts: the runner's own service URLs, gh's host and repository,
# a proxy, a certificate store and the switches that turn its checks off.
HOST_ENV = re.compile(r"GH_HOST|GH_REPO|GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN|GITHUB_(API|SERVER|GRAPHQL)_URL|"
                      r"GITHUB_REPOSITORY|ACTIONS_(?!ID_TOKEN_REQUEST_(URL|TOKEN)$)[A-Z0-9_]+|(HTTPS?|ALL|FTP)_PROXY|(https?|all|ftp)_proxy|"
                      r"SSL_CERT_(FILE|DIR)|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS|"
                      r"NODE_TLS_REJECT_UNAUTHORIZED|GIT_SSL_(NO_VERIFY|CAINFO|CAPATH)")
# Variables by which the build script of a dependency finds a program to
# run or a library to load (the cc, cmake, pkg-config and bindgen crates).
BUILD_ENV = re.compile(r"(TARGET_|HOST_)?(CC|CXX|AR|LD|NM|RANLIB)(_[A-Za-z0-9_-]+)?|CMAKE|PKG_CONFIG(_PATH|_LIBDIR|_SYSROOT_DIR)?|"
                       r"PROTOC|LIBCLANG_PATH|CLANG_PATH|LLVM_CONFIG_PATH")
# Programs that hand a string to a shell: the options that name it, and the
# options of the program that take a value.
STRING_OPTIONS = {
    "flock": ({"-c", "--command"}, {"-w", "--timeout", "-E", "--conflict-exit-code"}),
    "su": ({"-c", "--command", "--session-command"}, {"-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w", "--whitelist-environment"}),
    "runuser": ({"-c", "--command", "--session-command"}, {"-s", "--shell", "-g", "--group", "-G", "--supp-group", "-u", "--user", "-w", "--whitelist-environment"}),
    "script": ({"-c", "--command"}, {"-E", "--echo", "-I", "--log-in", "-O", "--log-out", "-B", "--log-io", "-T", "--log-timing", "-m", "--logging-format", "-o", "--output-limit"}),
}
# Programs that run the words after their options as one shell string.
JOINED = {
    "watch": {"-n", "--interval", "-d", "-q", "--equexit", "-s", "--shotsfile"},
    "ssh": {"-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
            "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w"},
}
# Programs that build the commands they run from their input, which is not read.
COMPOSERS = {"parallel", "sem"}
# git settings that run no program; any other setting a script makes is refused.
GIT_SAFE = re.compile(
    r"user\.(name|email|signingkey)|http\.(.*\.)?extraheader|safe\.directory|init\.defaultbranch|"
    r"advice\.[a-z]+|color\.[a-z.]+|core\.(autocrlf|quotepath|longpaths|filemode|safecrlf)|"
    r"pull\.rebase|push\.default|fetch\.prune|commit\.gpgsign|tag\.gpgsign|gc\.auto", re.I)
# The actions of `git config` that set nothing.
GIT_READS = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--unset",
             "--unset-all", "--remove-section", "get", "list", "unset"}
AWKS = {"awk", "gawk", "mawk", "nawk", "busybox-awk"}
AWK_VALUE_OPTIONS = {"-F", "-v", "--field-separator", "--assign"}
# awk options that name a program, a file of one or a library to load.
AWK_PROGRAM_OPTIONS = ("--file", "--source", "--exec", "--include", "--load")
# git subcommands that run a program they are given, and the options
# through which another one does.
GIT_RUNS = {"filter-branch": "", "difftool": "", "mergetool": "", "bisect": "run", "submodule": "foreach"}
GIT_RUN_OPTIONS = ("--upload-pack", "--receive-pack", "--exec", "--extcmd", "--open-files-in-pager")
GIT_GLOBAL_VALUES = {"-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--attr-source"}


# Variables a test script sets to stand in for the runner: the runner's OIDC
# token service and the files of a step's outputs, state and summary. In a
# job that holds nothing they redirect nothing of value: there is no token
# to request, and nothing such a job makes is run, sourced or built by a
# job beside a secret. Beside a secret they are the runner's alone.
STAND_IN_ENV = re.compile(r"ACTIONS_ID_TOKEN_REQUEST_(URL|TOKEN)|GITHUB_(OUTPUT|STATE|STEP_SUMMARY)")


def stand_in(name):
    """The note of a variable a job beside a secret may not set, for a
    test's stand-in for the runner; None for any other variable."""
    if STAND_IN_ENV.fullmatch(name):
        return "a stand-in for the runner (%s): a job beside a secret takes the runner's own" % name
    return None


def env_problem(name):
    """Why setting the variable `name` hides a program the check cannot read."""
    if RUN_ENV.fullmatch(name):
        return "%s makes a program run another one or load code before the command it is given, which is not read" % name
    if PLACE_ENV.fullmatch(name):
        return "%s says where a program finds its settings or the job its files, and the runner sets it: a script or an env: that sets it is not read" % name
    if HOST_ENV.fullmatch(name):
        return "%s points a program at another host, or changes which hosts it trusts, with the job's credentials, which is not read" % name
    return None


def sudo_shell(words):
    """Whether the words are a `sudo -s` or `sudo -i` with no command: a
    shell that reads its script from its input."""
    names = [text(w) for w in words]
    if "sudo" not in names:
        return False
    return any(re.fullmatch(r"-[A-Za-z]*[si][A-Za-z]*|--shell|--login", t or "") for t in names[names.index("sudo") + 1:])


def long_option(flag, names):
    """The option of `names` a flag is: itself, or the long option it is a
    prefix of, as getopt_long takes it (`--comm` is `--command`). None for
    any other flag."""
    if flag in names:
        return flag
    if flag.startswith("--") and len(flag) > 2:
        return next((n for n in sorted(names) if n.startswith(flag)), None)
    return None


def text(word):
    """The literal text of a word, or None when an expansion fills it in."""
    return word.literal()


def head(word):
    """The literal text of a word before its first expansion: where an
    option stands, even when its value holds an expansion (`-c"$X"`)."""
    return word.head()


def cut(word, n):
    """The word without the first `n` characters of its literal head: the
    value of an option joined to it (`-c'cargo ...'`, `--command=...`)."""
    out = shell_words.Word(word.line)
    out.raw = word.raw
    out.splits = word.splits
    for kind, part in word.parts:
        if kind == "lit":
            part, n = part[n:], max(n - len(part), 0)
        if part:
            out.parts.append((kind, part))
    return out


def script_of(name, args):
    """The words a program hands to a shell as one string, or None when the
    program is not one of these. An empty list: the program runs no string."""
    if name == "trap":
        rest = [w for w in args if text(w) != "--"]
        return rest[:1] if rest and text(rest[0]) not in ("-p", "-l", "-P") else []
    if name in STRING_OPTIONS:
        names, values = STRING_OPTIONS[name]
        k = 0
        files = 0
        while k < len(args):
            t = head(args[k])
            flag, eq, _ = t.partition("=")
            files += not t.startswith("-")
            if name == "flock" and files > 1:
                return []
            if long_option(flag, names):
                return [cut(args[k], len(flag) + 1)] if eq else args[k + 1:k + 2]
            if flag.startswith("-") and not flag.startswith("--") and "-c" in names and "c" in flag[1:]:
                at = flag.index("c", 1) + 1
                return [cut(args[k], at)] if at < len(t) else args[k + 1:k + 2]
            k += 2 if long_option(flag, values) and not eq else 1
        return []
    if name in JOINED:
        k = 0
        while k < len(args):
            t = text(args[k]) or ""
            if t == "--":
                k += 1
                break
            if not t.startswith("-"):
                break
            k += 2 if t in JOINED[name] else 1
        return args[k + 1:] if name == "ssh" else args[k:]
    if name == "env":
        k = 0
        while k < len(args):
            w = args[k]
            t = head(w)
            if not t.startswith("-"):
                return []
            flag, eq, _ = t.partition("=")
            if t == "-S" or (not eq and long_option(flag, ("--split-string",))):
                return args[k + 1:]
            if eq and long_option(flag, ("--split-string",)):
                return [cut(w, len(flag) + 1)] + args[k + 1:]
            cluster = re.fullmatch(r"-[i0v]*S(.*)", t)
            if cluster:
                return ([cut(w, len(t) - len(cluster.group(1)))] if cluster.group(1) else []) + args[k + 1:]
            k += 2 if t in ("-u", "-C") or (not eq and long_option(flag, ("--unset", "--chdir"))) else 1
        return []
    return None


def git_problem(args):
    """Why a git command makes a setting the check does not read: an alias,
    a program in place of ssh, the pager, a hook path, an included file, ..."""
    k = 0
    while k < len(args):
        t = text(args[k])
        if t is None:
            return "a git option from a variable is not read: %s" % args[k].raw
        if t == "-c" or t.startswith("--config-env"):
            if t.startswith("--config-env"):
                return "a git setting from the environment is not read: %s" % t
            setting = args[k + 1] if k + 1 < len(args) else None
            if setting is None:
                return None
            key, eq, _ = setting.head().partition("=")
            if not eq:
                return "a git setting from a variable is not read: %s" % setting.raw
            if not GIT_SAFE.fullmatch(key):
                return "a git setting that can run a program is not read: %s" % key
            k += 2
            continue
        if t.startswith("--exec-path"):
            return "a git exec path is not read: %s" % t
        if t in GIT_GLOBAL_VALUES:
            k += 2
            continue
        if t.startswith("-"):
            k += 1
            continue
        if t == "config":
            return config_problem(args[k + 1:])
        return subcommand_problem(t, args[k + 1:])
    return None


def subcommand_problem(sub, args):
    """Why a git subcommand runs a program the check does not read: one it
    is given (`bisect run`, `submodule foreach`, `rebase --exec`, a filter,
    a diff or merge tool, a pager), a program in place of the one the
    other end of a transfer runs (`--upload-pack`, `--receive-pack`), or a
    setting a clone is given (`clone -c`)."""
    literals = [text(w) for w in args]
    if sub in GIT_RUNS and (not GIT_RUNS[sub] or GIT_RUNS[sub] in literals):
        return "a git command that runs a program it is given is not read: git %s" % " ".join(p for p in (sub, GIT_RUNS[sub]) if p)
    for k, w in enumerate(args):
        t = head(w)
        if t == "--":
            break
        flag = t.partition("=")[0]
        named = long_option(flag, GIT_RUN_OPTIONS)
        if named or (sub == "rebase" and re.fullmatch(r"-[a-zA-Z]*x.*", t)) or (
                sub == "clone" and re.fullmatch(r"-[a-zA-Z]*u.*", t)) or (sub == "grep" and t.startswith("-O")):
            return "a git option that runs a program is not read: git %s %s" % (sub, named or flag)
        if sub == "clone" and (t == "-c" or long_option(flag, ("--config",))):
            setting = w if "=" in t and t != "-c" else (args[k + 1] if k + 1 < len(args) else None)
            given = head(setting)[len(flag) + 1 if setting is w else 0:] if setting is not None else ""
            key = given.partition("=")[0]
            if not GIT_SAFE.fullmatch(key):
                return "a git setting that can run a program is not read: %s" % (key or (setting.raw if setting is not None else t))
    return None


def gh_problem(args):
    """Why a gh command is not read: an extension is a program installed
    from a repository with no pin, and an alias is a command the check does
    not see where it runs."""
    group = text(args[0]) if args else None
    if group in ("extension", "ext", "extensions"):
        return "an install route the check does not read: gh extension (a program installed from a repository, with no pin)"
    if group == "alias" and len(args) > 1 and text(args[1]) in ("set", "import"):
        return "a gh alias is not read: write the command out"
    return None


def config_problem(args):
    """Why `git config` with these arguments sets something that can run a program."""
    positions = []
    for w in args:
        t = text(w)
        if t in GIT_READS:
            return None
        if t in ("-f", "--file", "--blob") or (t or "").startswith(("--file=", "--blob=")):
            return "a git configuration file is not read: %s" % t
        if t == "set" or (t or "").startswith("-"):
            continue
        positions.append(w)
    if len(positions) < 2:
        return None
    key = text(positions[0])
    if key is None:
        return "a git setting from a variable is not read: %s" % positions[0].raw
    if not GIT_SAFE.fullmatch(key):
        return "a git setting that can run a program is not read: %s" % key
    return None


def awk_problem(args):
    """Why an awk program is not read: it can run another program (`system`,
    a pipe to or from a command), comes from a file or a variable."""
    k = 0
    while k < len(args):
        t = text(args[k])
        if t is None:
            return "an awk program with an expansion in it is not read: %s (pass the value with -v)" % args[k].raw
        if t in ("-f", "--file") or (t.startswith("-f") and len(t) > 2):
            return "an awk program from a file is not read: %s" % t
        if re.fullmatch(r"-[eEil].*", t) or long_option(t.partition("=")[0], AWK_PROGRAM_OPTIONS):
            return "an awk program, a file of one or a library given by an option is not read: %s" % t.partition("=")[0]
        if t in AWK_VALUE_OPTIONS:
            k += 2
            continue
        if t == "--":
            k += 1
            break
        if t.startswith("-") and len(t) > 1:
            k += 1
            continue
        break
    if k >= len(args):
        return None
    program = args[k].literal()
    if program is None:
        return "an awk program with an expansion in it is not read: %s (pass the value with -v)" % args[k].raw
    stripped = re.sub(r'"(\\.|[^"\\])*"', '""', program).replace("||", "")
    if re.search(r"\bsystem\s*\(", stripped) or "|" in stripped:
        return "an awk program that runs another program (system or a pipe) is not read"
    return None


def sed_programs(args):
    """(the words that hold the program of a sed command, the problem with
    an option that names a file of one, whether it edits a file in place).
    With `-e` or `--expression` every operand is a file; without, the first
    is the program. A cluster of short options is read letter by letter:
    `-ne` takes a program, `-Ef` a file of one, `-i.bak` a suffix."""
    programs, given, inplace, k = [], False, False, 0
    while k < len(args):
        w, t = args[k], head(args[k])
        flag, eq, _ = t.partition("=")
        named = long_option(flag, ("--expression", "--file", "--in-place", "--line-length")) if t.startswith("--") else None
        if text(w) == "--":
            programs.extend([] if given else args[k + 1:k + 2])
            break
        if named == "--file":
            return programs, "a sed program from a file is not read: %s" % t, inplace
        if named == "--expression":
            programs.extend([cut(w, len(flag) + 1)] if eq else args[k + 1:k + 2])
            given = True
            k += 0 if eq else 1
        elif named == "--in-place":
            inplace = True
        elif named == "--line-length":
            k += 0 if eq else 1
        elif t.startswith("-") and len(t) > 1 and not t.startswith("--"):
            for at, letter in enumerate(t[1:], 2):
                if letter == "f":
                    return programs, "a sed program from a file is not read: %s" % t, inplace
                if letter == "e":
                    joined = cut(w, at)
                    programs.extend([joined] if joined.parts else args[k + 1:k + 2])
                    given = True
                    k += 0 if joined.parts else 1
                    break
                if letter in "il":
                    inplace = inplace or letter == "i"
                    k += 1 if letter == "l" and at == len(t) else 0
                    break
        elif not t.startswith("--") and not given:
            programs.append(w)
            given = True
        k += 1
    return programs, None, inplace


def sed_problem(args):
    """Why a sed program is not read: the `e` command or the `e` flag of `s`
    runs a command, and a program from a file or a variable is not read."""
    programs, problem, _ = sed_programs(args)
    if problem:
        return problem
    for w in programs:
        if text(w) is None:
            return "a sed program from a variable is not read: %s" % w.raw
        if sed_runs(text(w)):
            return "a sed program that runs a command (the e command or flag) is not read"
    return None


def sed_runs(program):
    """Whether a sed program holds the `e` command or an `s` with the `e` flag."""
    return sed_scan(program)[0]


def sed_scan(program):
    """(runs a command, writes a file) for a sed program: the `e` command
    or an `s` with the `e` flag, and the `w` or `W` command or an `s` with
    the `w` flag. A program this reader cannot follow counts as one that
    does both."""
    i, n = 0, len(program)
    writes = False
    while i < n:
        c = program[i]
        if c in " \t\n;{}!$,~+IM" or c.isdigit() or c in "=dDgGhHnNpPxzF":
            i += 1
        elif c == "/":
            i = skip_delimited(program, i + 1, "/")
        elif c == "\\":
            i = skip_delimited(program, i + 2, program[i + 1:i + 2])
        elif c in "#aicrRwW":
            writes = writes or c in "wW"
            i = until(program, i, "\n")
        elif c in "btTvqQlL:":
            i = until(program, i, ";\n")
        elif c in "sy":
            delim = program[i + 1:i + 2]
            i = skip_delimited(program, skip_delimited(program, i + 2, delim), delim)
            if i is None:
                return True, True
            flags = re.match(r"[^;\n}w]*", program[i:]).group(0) if c == "s" else ""
            if "e" in flags:
                return True, True
            i += len(flags)
        else:
            return True, True
        if i is None:
            return True, True
    return False, writes


def until(program, i, stops):
    """The index of the first of `stops` at or after i, or the end."""
    m = re.compile("[%s]" % stops).search(program, i)
    return m.start() if m else len(program)


def skip_delimited(program, i, delim):
    """The index after the unescaped `delim` that closes a part at `i`; None
    when it does not close on its line, or when `i` is None."""
    while i is not None and i < len(program) and delim:
        if program[i] == "\\":
            i += 2
        elif program[i] == delim:
            return i + 1
        elif program[i] == "\n":
            return None
        else:
            i += 1
    return None


# The runner's files a step writes for the steps after it.
RUNNER_FILES = re.compile(r"\$\{?GITHUB_(ENV|PATH)\}?")
# Programs that name a runner file without writing to it.
READS_ONLY = {"echo", "printf", "test", "[", "[[", ":", "cat", "grep", "wc", "head", "tail", "true"}


def runner_file(word):
    """`ENV` or `PATH` for a word that expands $GITHUB_ENV or $GITHUB_PATH."""
    for kind, text in word.parts:
        m = RUNNER_FILES.fullmatch(text) if kind == "exp" else None
        if m:
            return m.group(1)
    return None


def named_files(name, args):
    """The runner files the arguments of a program name as files it may
    write; none for a program that only reads or prints them."""
    if name in READS_ONLY:
        return []
    return [f for f in map(runner_file, args) if f]


def env_lines(name, args, bodies):
    """The (NAME, value) pairs echo, printf (its format, each conversion
    standing as a value) or a here-document into cat writes to $GITHUB_ENV,
    an expansion standing as NUL; None when another program writes, or a
    line is not NAME=value or NAME<<DELIMITER."""
    if name in ("echo", "printf"):
        words = [w for w in args if not (name == "echo" and w.literal() in ("-n", "-e", "-E", "-ne", "-en"))]
        texts = ["".join(t if kind == "lit" else "\0" for kind, t in w.parts) for w in words]
        if name == "printf":
            texts = [re.sub(r"%[-+ #0-9.]*[a-zA-Z]", "\0", texts[0])] if texts else []
        text = " ".join(texts).replace("\\n", "\n")
    elif name == "cat" and bodies and not args:
        text = "".join(bodies)
    else:
        return None
    pairs = []
    delimiter = None
    for line in text.split("\n"):
        line = line.strip()
        if delimiter is not None:
            delimiter = None if line == delimiter else delimiter
            continue
        if not line:
            continue
        m = re.match(r"([^=<\s]*)(=|<<)(.*)", line)
        if not m or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", m.group(1)):
            return None
        if m.group(2) == "<<":
            delimiter = m.group(3)
        pairs.append((m.group(1), m.group(3) if m.group(2) == "=" else None))
    return pairs


# Builtins that run a command they are given by an option.
BUILTIN_RUNS = {"mapfile": "C", "readarray": "C", "compgen": "C", "complete": "CF", "bind": "x"}
# Builtins that assign the variables their operands name, and their options
# that take a value which is not one.
ASSIGNERS = {"read": {"-d", "-i", "-n", "-N", "-p", "-t", "-u"},
             "mapfile": {"-d", "-n", "-O", "-s", "-u", "-C", "-c"},
             "readarray": {"-d", "-n", "-O", "-s", "-u", "-C", "-c"}}
DECLARERS = {"export", "declare", "typeset", "readonly", "local"}
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# `${NAME:=value}` and `${NAME=value}` assign as they expand.
ASSIGNING_EXPANSION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?=")
# `${NAME@P}` expands the value of NAME as a prompt: a `$(...)` in it runs.
PROMPT_EXPANSION = re.compile(r"\$\{[^}]*@P\}")


def builtin_problem(name, args):
    """Why a builtin runs a command the check does not read: a callback
    (`mapfile -C`), a command whose output completes a word (`compgen -C`,
    `complete -C`, `complete -F`) or a key bound to one (`bind -x`)."""
    letters = BUILTIN_RUNS.get(name)
    if letters and any(re.fullmatch(r"-[A-Za-z]*[%s].*" % letters, head(w)) for w in args):
        return "a command %s runs through an option is not read: write the command out" % name
    if name in ("declare", "typeset", "local") and any(re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", head(w)) for w in args):
        return "a name reference is not read (%s -n): assign the variable by its own name" % name
    return None


def assigned(words, start):
    """(the variables a command assigns other than by `NAME=value`, the
    first operand that names one through a variable). The variable of a
    `for` or a `select`, the operands of `read` and `mapfile`, the
    variable of `getopts`, `printf -v` and `wait -p`, and each
    `${NAME:=value}` in a word are assigned by name; `export "$X"` and
    `read "$X"` assign whatever X names, which the check cannot read.
    `start`: the index of the word the shell runs, or None."""
    names = []
    for w in words:
        for kind, part in w.parts:
            if kind == "exp":
                names.extend(ASSIGNING_EXPANSION.findall(part))
    if start is None:
        return names, None
    program, rest = text(words[start]), words[start + 1:]
    operands = []
    if words[start].bare() in ("for", "select"):
        operands = rest[:1]
    elif program in ASSIGNERS:
        k = 0
        while k < len(rest):
            t = head(rest[k])
            if t in ASSIGNERS[program]:
                k += 1
            elif not t.startswith("-"):
                operands.append(rest[k])
            k += 1
    elif program == "getopts":
        operands = rest[1:2]
    elif program in ("printf", "wait"):
        option = "-v" if program == "printf" else "-p"
        operands = [rest[k + 1] for k, w in enumerate(rest[:-1]) if text(w) == option][:1]
    elif program in DECLARERS:
        unread = next((w for w in rest if text(w) is None and not head(w).startswith("-") and "=" not in head(w)), None)
        return names, unread
    names.extend(text(w) for w in operands if text(w) is not None and NAME.fullmatch(text(w)))
    return names, next((w for w in operands if text(w) is None), None)


def expansion_problem(words):
    """Why a word expands to more than a value: `${NAME@P}` runs the
    commands written in the value of NAME."""
    for w in words:
        for kind, part in w.parts:
            if kind == "exp" and PROMPT_EXPANSION.search(part):
                return "an expansion that runs the commands in the value of a variable is not read: %s" % part
    return None
