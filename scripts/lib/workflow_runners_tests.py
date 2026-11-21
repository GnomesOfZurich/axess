"""Crafted cases for scripts/lib/workflow_runners.py, run by
scripts/check-workflow-pins-tests.sh.

Each case lexes one command and pins what the reader returns: the string a
program hands to a shell, or the problem with a variable, a git setting, an
awk program or a sed program. Run with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words
import workflow_runners as R

RUNS = "makes a program run another one or load code before the command it is given, which is not read"
GIT = "a git setting that can run a program is not read: %s"
GIT_VAR = "a git setting from a variable is not read: %s"
AWK = "an awk program that runs another program (system or a pipe) is not read"
AWK_VAR = "an awk program with an expansion in it is not read: %s (pass the value with -v)"
SED = "a sed program that runs a command (the e command or flag) is not read"
SED_VAR = "a sed program from a variable is not read: %s"


def args(line):
    """The program's name and the words after it, as the shell lexes them."""
    words = shell_words.lex(line, lambda offset: 1).commands[0].words
    return words[0].literal(), words[1:]


def shown(words):
    """A word list as text, an expansion standing in brackets."""
    if words is None:
        return None
    return ["".join(text if kind == "lit" else "[%s]" % text for kind, text in w.parts) for w in words]


ENV = [
  ("BASH_ENV", True), ("ENV", True), ("PROMPT_COMMAND", True), ("PS4", True), ("SHELLOPTS", True),
  ("BASHOPTS", True), ("BASH_FUNC_cargo%%", True), ("LD_PRELOAD", True), ("LD_AUDIT", True),
  ("LD_LIBRARY_PATH", True), ("DYLD_INSERT_LIBRARIES", True), ("GIT_SSH", True), ("GIT_SSH_COMMAND", True),
  ("GIT_PROXY_COMMAND", True), ("GIT_ASKPASS", True), ("SSH_ASKPASS", True), ("GIT_PAGER", True),
  ("PAGER", True), ("GIT_EDITOR", True), ("GIT_SEQUENCE_EDITOR", True), ("EDITOR", True), ("VISUAL", True),
  ("GIT_EXTERNAL_DIFF", True), ("GIT_EXEC_PATH", True), ("GIT_TEMPLATE_DIR", True), ("GIT_CONFIG", True),
  ("GIT_CONFIG_COUNT", True), ("GIT_CONFIG_KEY_0", True), ("GIT_CONFIG_PARAMETERS", True),
  ("ENVIRONMENT", False), ("MY_ENV", False), ("PS1", False), ("PATH", False), ("RUSTFLAGS", False),
  ("GITHUB_TOKEN", False), ("GIT_AUTHOR_NAME", False), ("XPAGER", False),
]

SCRIPTS = [
  ("trap runs its first argument", "trap 'cargo install x' EXIT", ["cargo install x"]),
  ("trap after --", "trap -- 'rm -f y' EXIT", ["rm -f y"]),
  ("trap -p lists", "trap -p", []),
  ("trap -l lists", "trap -l", []),
  ("trap -P lists", "trap -P EXIT", []),
  ("trap with nothing", "trap", []),
  ("flock -c", "flock /tmp/l -c 'cargo install x'", ["cargo install x"]),
  ("flock --command=", "flock /tmp/l --command='cargo install x'", ["cargo install x"]),
  ("flock --command", "flock /tmp/l --command 'cargo install x'", ["cargo install x"]),
  ("flock -w value is not the command", "flock -w -c /tmp/l -c 'x y'", ["x y"]),
  ("flock --timeout= value", "flock --timeout=5 /tmp/l -c 'x y'", ["x y"]),
  ("flock running its arguments", "flock /tmp/l cargo build", []),
  ("flock running a program given -c", "flock /tmp/l python3 -c 'x'", []),
  ("flock with -c before its file", "flock -c 'a b' /tmp/l", ["a b"]),
  ("su running -c after its user", "su user -c 'a b'", ["a b"]),
  ("su -c", "su -c 'cargo install x' user", ["cargo install x"]),
  ("su -s value then -c", "su -s /bin/sh -c 'a b'", ["a b"]),
  ("su --session-command", "su --session-command 'a b'", ["a b"]),
  ("runuser -u value then -c", "runuser -u -c -c 'a b'", ["a b"]),
  ("script -c", "script -c 'cargo install x' /dev/null", ["cargo install x"]),
  ("script -qc cluster", "script -qc 'cargo install x' /dev/null", ["cargo install x"]),
  ("script -qccmd joined", "script -qc'a b' /dev/null", ["a b"]),
  ("script -c joined", "script -c'a b' /dev/null", ["a b"]),
  ("script with no command", "script -q /dev/null", []),
  ("a -c in an expansion", 'flock /tmp/l -c "$X"', ["[$X]"]),
  ("watch joins its words", "watch -n 1 cargo install x", ["cargo", "install", "x"]),
  ("watch joined interval", "watch -n1 'cargo install x'", ["cargo install x"]),
  ("watch after --", "watch -- -n x", ["-n", "x"]),
  ("watch -d takes a value", "watch -d x y", ["y"]),
  ("watch with nothing", "watch -n 1", []),
  ("ssh skips the host", "ssh -p 22 host cargo install x", ["cargo", "install", "x"]),
  ("ssh -o value", "ssh -o X=1 host 'a b'", ["a b"]),
  ("ssh with no command", "ssh host", []),
  ("env -S", "env -S 'cargo install x'", ["cargo install x"]),
  ("env -S joined", "env -S'cargo install x' y", ["cargo install x", "y"]),
  ("env --split-string", "env --split-string 'a b' c", ["a b", "c"]),
  ("env --split-string=", "env --split-string='a b'", ["a b"]),
  ("env -i then -S", "env -i -S 'a b'", ["a b"]),
  ("env with no split", "env -i A=1 cargo build", []),
  ("env with a variable option", 'env "$O" -S x', []),
  ("env -u then -S", "env -u X -S 'a b'", ["a b"]),
  ("env with only options", "env -i -u X", []),
  ("env -C then -S", "env -C -S -S 'a b'", ["a b"]),
  ("env -S joined after an option", "env -i -S'a b' c", ["a b", "c"]),
  ("env --split-string= then words", "env --split-string='a b' c d", ["a b", "c", "d"]),
  ("env -S with an expansion", 'env -S"cargo install $x"', ["cargo install [$x]"]),
  ("flock -c with an expansion", 'flock /tmp/l -c"a $X"\' z\'', ["a [$X] z"]),
  ("su --command= with an expansion", 'su --command="a $X"b', ["a [$X]b"]),
  ("a -c option from a variable", 'flock /tmp/l "$o" x', []),
  ("another program", "cargo build", None),
]

GITS = [
  ("an alias by -c", "git -c alias.x='!cargo install y' x", GIT % "alias.x"),
  ("a hook path by -c", "git -c core.hooksPath=h commit", GIT % "core.hooksPath"),
  ("an extra header by -c", 'git -c "http.https://h/.extraheader=AUTHORIZATION: basic $a" push', None),
  ("a key from a variable by -c", 'git -c "$kv" push', GIT_VAR % '"$kv"'),
  ("a key after a variable by -c", 'git -c "$k=1" push', GIT_VAR % '"$k=1"'),
  ("-c with nothing after it", "git -c", None),
  ("-c with a setting and nothing after it", "git -c alias.x=1", GIT % "alias.x"),
  ("config after a safe -c", "git -c user.name=x config alias.x y", GIT % "alias.x"),
  ("config after an option", "git --no-pager config alias.x y", GIT % "alias.x"),
  ("config after --work-tree", "git --work-tree w config alias.x y", GIT % "alias.x"),
  ("config after --namespace", "git --namespace n config alias.x y", GIT % "alias.x"),
  ("config after -C", "git -C d config alias.x y", GIT % "alias.x"),
  ("--exec-path spaced", "git --exec-path", "a git exec path is not read: --exec-path"),
  ("--config-env", "git --config-env=alias.x=V x", "a git setting from the environment is not read: --config-env=alias.x=V"),
  ("--exec-path", "git --exec-path=d x", "a git exec path is not read: --exec-path=d"),
  ("-C then config", "git -C dir config alias.x y", GIT % "alias.x"),
  ("--git-dir then config", "git --git-dir d config alias.x y", GIT % "alias.x"),
  ("an option from a variable", 'git "$O" status', "a git option from a variable is not read: \"$O\""),
  ("another option", "git --no-pager log", None),
  ("config user.name", 'git config user.name "$N"', None),
  ("config user.email", "git config --global user.email a@b", None),
  ("config an alias", "git config alias.x '!cargo install y'", GIT % "alias.x"),
  ("config set an alias", "git config set alias.x y", GIT % "alias.x"),
  ("config a pager", "git config --global core.pager less", GIT % "core.pager"),
  ("config a key from a variable", 'git config "$k" x', GIT_VAR % '"$k"'),
  ("config a typed alias", "git config --bool alias.x y", GIT % "alias.x"),
  ("config an alias with its origin shown", "git config --show-origin -z alias.x y", GIT % "alias.x"),
  ("config a typed alias by a spaced type", "git config --type bool alias.x y", GIT % "bool"),
  ("config --get", "git config --get alias.x", None),
  ("config get", "git config get alias.x", None),
  ("config --list", "git config -l", None),
  ("config --get-all", "git config --get-all alias.x y", None),
  ("config --get-regexp", "git config --get-regexp alias y", None),
  ("config --get-urlmatch", "git config --get-urlmatch http https://x", None),
  ("config --list by name", "git config --list x y", None),
  ("config --unset-all", "git config --unset-all alias.x y", None),
  ("config --remove-section", "git config --remove-section alias y", None),
  ("config list", "git config list x y", None),
  ("config unset", "git config unset alias.x y", None),
  ("config --unset", "git config --unset alias.x", None),
  ("config one word", "git config alias.x", None),
  ("config --file", "git config --file f alias.x y", "a git configuration file is not read: --file"),
  ("config -f", "git config -f f user.name y", "a git configuration file is not read: -f"),
  ("config --file=", "git config --file=f user.name y", "a git configuration file is not read: --file=f"),
  ("config --blob=", "git config --blob=b user.name y", "a git configuration file is not read: --blob=b"),
  ("config --blob", "git config --blob b user.name y", "a git configuration file is not read: --blob"),
  ("config --file spaced", "git config --file f user.name y", "a git configuration file is not read: --file"),
  ("another command", "git push origin main", None),
  ("nothing", "git", None),
]

AWKS = [
  ("system", "awk 'BEGIN{system(\"cargo install x\")}'", AWK),
  ("system with a space", "awk 'BEGIN{system (\"x\")}'", AWK),
  ("print to a command", "awk '{print | \"sh\"}'", AWK),
  ("getline from a command", "awk 'BEGIN{\"date\" | getline d}'", AWK),
  ("an or", "awk '$1 || $2 {print}'", None),
  ("a bar in a string", "awk '{print \"a|b\"}'", None),
  ("an escaped quote before a bar", "awk '{print \"a\\\"|\"}'", None),
  ("a field separator", "awk -F: '{print $1}' f", None),
  ("a value by -v", 'awk -v w="$x" \'BEGIN{print w}\'', None),
  ("a value by --assign", 'awk --assign w="$x" \'BEGIN{print w}\'', None),
  ("a joined option", "awk -F, '{print}'", None),
  ("after --", "awk -- '{print | \"sh\"}'", AWK),
  ("a program with an expansion", 'awk "BEGIN{print $w}"', AWK_VAR % '"BEGIN{print $w}"'),
  ("a program file", "awk -f prog.awk", "an awk program from a file is not read: -f"),
  ("a joined program file", "awk -fprog.awk", "an awk program from a file is not read: -fprog.awk"),
  ("a --file", "awk --file prog.awk", "an awk program from a file is not read: --file"),
  ("only options", "awk -F:", None),
  ("a program from a variable after --", 'awk -- "$p"', AWK_VAR % '"$p"'),
  ("a short program file", "awk -fp", "an awk program from a file is not read: -fp"),
  ("system after a value option", "awk -v x=1 'BEGIN{system(1)}'", AWK),
  ("system after a flag", "awk -b 'BEGIN{system(1)}'", AWK),
  ("system after a flag and --", "awk -b -- 'BEGIN{system(1)}'", AWK),
  ("a dash as the program", "awk - 'BEGIN{system(1)}'", None),
  ("gawk system", "gawk 'BEGIN{system(\"x\")}'", AWK),
  ("mawk system", "mawk 'BEGIN{system(\"x\")}'", AWK),
  ("nawk system", "nawk 'BEGIN{system(\"x\")}'", AWK),
  ("busybox-awk system", "busybox-awk 'BEGIN{system(\"x\")}'", AWK),
]

SEDS = [
  ("the e command", "sed '1e cargo install x' f", SED),
  ("the e command alone", "sed e f", SED),
  ("the e flag", "sed 's/x/cargo install y/e' f", SED),
  ("the e flag among others", "sed 's/x/y/ge' f", SED),
  ("the e flag after a semicolon", "sed 's/a/b/;s/x/y/e' f", SED),
  ("the e command after a brace", "sed '/x/{e date\n}' f", SED),
  ("the e command under an address range", "sed '1,$e date' f", SED),
  ("the e command after a regex", "sed '/^a/e date' f", SED),
  ("the e command after a custom delimiter", "sed '\\%a%e date' f", SED),
  ("the e command after a regex flag", "sed '/a/Ie date' f", SED),
  ("the e command after a comment", "sed '# e\ne date' f", SED),
  ("the e command after a label", "sed ':a;e date' f", SED),
  ("the e command by -e", "sed -n -e p -e 'e date' f", SED),
  ("the e command by --expression=", "sed --expression='e date' f", SED),
  ("the e command joined to -e", "sed -e'e date' f", SED),
  ("a print", "sed -n 's/^total=//p' f", None),
  ("an escaped delimiter", "sed 's/a\\/e/b/' f", None),
  ("y", "sed 'y/abc/xyz/' f", None),
  ("an e in a regex", "sed '/the end/d' f", None),
  ("an e in the replacement", "sed 's/x/the end/' f", None),
  ("a w flag", "sed -n 's/x/y/w out' f", None),
  ("a w flag then a line", "sed 's/x/y/w out\np' f", None),
  ("an address range and print", "sed -n '/^\\[a\\]/,/^\\[/p' f", None),
  ("an insert", "sed '1i text with e' f", None),
  ("an append to the end", "sed '$a e' f", None),
  ("a branch", "sed ':a;N;$!ba;s/\\n/ /g' f", None),
  ("a branch to the end of a line", "sed 'b end\n:end' f", None),
  ("a quit", "sed 3q f", None),
  ("a step", "sed -n '0~2p' f", None),
  ("an offset", "sed '/a/,+2d' f", None),
  ("a regex flag", "sed -E 's/.*after //I' f", None),
  ("hold commands", "sed -n 'h;G;x;H;g;=;l;D;P;n;z;F' f", None),
  ("a line length", "sed -l 5 l f", None),
  ("a regex that does not close", "sed '/a' f", SED),
  ("an s that does not close", "sed 's/a/b' f", SED),
  ("an s at the end", "sed s", SED),
  ("a command the reader does not take", "sed 'k' f", SED),
  ("a program from a variable", 'sed "$P" f', SED_VAR % '"$P"'),
  ("a program by -e from a variable", 'sed -e "$P" f', SED_VAR % '"$P"'),
  ("a file after the program", 'sed p "$F"', None),
  ("a file after -e", 'sed -e p "$F"', None),
  ("a program from a file", "sed -f prog.sed f", "a sed program from a file is not read: -f"),
  ("a program from --file=", "sed --file=prog.sed f", "a sed program from a file is not read: --file=prog.sed"),
  ("a program from a joined file", "sed -fprog.sed f", "a sed program from a file is not read: -fprog.sed"),
  ("after --", "sed -- 'e date' f", SED),
  ("a file named like the e command", "sed p e", None),
  ("only options", "sed -n", None),
  ("-e with nothing after it", "sed -e", None),
  ("the e command by --expression", "sed --expression 'e date' p", SED),
  ("the e command by --expression= before a file p", "sed --expression='e date' p", SED),
  ("the e command joined to -e before a file p", "sed -e'e date' p", SED),
  ("an -e value that looks like a file option", "sed -e -fx", SED),
  ("an operand after a joined -e is a file", "sed -ep 'e x'", None),
  ("a regex flag I then print", "sed -n '/a/Ip' f", None),
  ("a regex flag M then print", "sed -n '/a/Mp' f", None),
  ("an empty regex", "sed -n '//p' f", None),
  ("an empty custom-delimited regex", "sed -n '\\%%p' f", None),
  ("an s with an empty pattern", "sed 's//x/' f", None),
  ("an s whose pattern does not close", "sed 's/a' f", SED),
  ("a regex over a line break", "sed '/a\nb/p' f", SED),
  ("a custom delimiter that does not close", "sed '\\%a' f", SED),
  ("an --expression value that looks like a file option", "sed --expression -fx", SED),
  ("the e command after an s flag i", "sed 's/a/b/i;e date' f", SED),
  ("an insert after a y", "sed 'y/a/b/ie' f", None),
  ("a custom-delimited regex then print", "sed -n '\\%a%p' f", None),
]

ENV_LINES = [
  ("echo", 'echo "A=1"', [("A", "1")]),
  ("echo -n", "echo -n A=1", [("A", "1")]),
  ("echo -e", "echo -e 'A=1\\nB=2'", [("A", "1"), ("B", "2")]),
  ("echo -ne", "echo -ne A=1", [("A", "1")]),
  ("echo -en", "echo -en A=1", [("A", "1")]),
  ("echo -E", "echo -E A=1", [("A", "1")]),
  ("printf with a format", 'printf "%s\\n" "A=1"', None),
  ("printf of a pair", 'printf "A=%s\\n" "$v"', [("A", "\0")]),
  ("printf with no format", "printf", []),
  ("printf of a literal format", "printf 'A=1\\nB=%5.2f' 3", [("A", "1"), ("B", "\0")]),
  ("a value from a variable", 'echo "A=$v"', [("A", "\0")]),
  ("a name from a variable", 'echo "$N=1"', None),
  ("a delimited value", "printf 'A<<END\\nB=x\\nEND\\nC=2'", [("A", None), ("C", "2")]),
  ("blank lines", "printf 'A=1\\n\\n'", [("A", "1")]),
  ("a line that is not a pair", "echo 'x y'", None),
  ("a name that is not one", "echo '1A=x'", None),
  ("a space before the name", "echo ' A=1'", [("A", "1")]),
  ("cat of a here-document", "cat", "BASH_ENV=x\n"),
  ("cat of a file", "cat f", None),
  ("tee", "tee -a f", None),
]


# The tables the reader holds, as the cases hold them: a case runs each entry.
HELD_STRING_OPTIONS = {
    'flock': ({'--command', '-c'}, {'--conflict-exit-code', '--timeout', '-E', '-w'}),
    'runuser': ({'--command', '--session-command', '-c'}, {'--group', '--shell', '--supp-group', '--user', '--whitelist-environment', '-G', '-g', '-s', '-u', '-w'}),
    'script': ({'--command', '-c'}, {'--echo', '--log-in', '--log-io', '--log-out', '--log-timing', '--logging-format', '--output-limit', '-B', '-E', '-I', '-O', '-T', '-m', '-o'}),
    'su': ({'--command', '--session-command', '-c'}, {'--group', '--shell', '--supp-group', '--whitelist-environment', '-G', '-g', '-s', '-w'}),
}
HELD_JOINED = {
    'ssh': {'-B', '-D', '-E', '-F', '-I', '-J', '-L', '-O', '-P', '-Q', '-R', '-S', '-W', '-b', '-c', '-e', '-i', '-l', '-m', '-o', '-p', '-w'},
    'watch': {'--equexit', '--interval', '--shotsfile', '-d', '-n', '-q', '-s'},
}
HELD_COMPOSERS = {'parallel', 'sem'}
HELD_GIT_READS = {'--get', '--get-all', '--get-regexp', '--get-urlmatch', '--list', '--remove-section', '--unset', '--unset-all', '-l', 'get', 'list', 'unset'}
HELD_AWKS = {'awk', 'busybox-awk', 'gawk', 'mawk', 'nawk'}
HELD_AWK_VALUE_OPTIONS = {'--assign', '--field-separator', '-F', '-v'}
HELD_SED_VALUE_OPTIONS = {'--line-length', '-l'}
HELD_READS_ONLY = {':', '[', '[[', 'cat', 'echo', 'grep', 'head', 'printf', 'tail', 'test', 'true', 'wc'}


def main():
    failures = []
    for name, want in ENV:
        got = R.env_problem(name) is not None
        if got != want:
            failures.append("variable %s refused: %r, wanted %r" % (name, got, want))
    if R.env_problem("BASH_ENV") != "BASH_ENV " + RUNS:
        failures.append("variable message: %r" % R.env_problem("BASH_ENV"))
    for name, line, want in SCRIPTS:
        program, words = args(line)
        got = shown(R.script_of(program, words))
        if got != want:
            failures.append("%s: %r, wanted %r" % (name, got, want))
    for table, read in ((GITS, R.git_problem), (AWKS, R.awk_problem), (SEDS, R.sed_problem)):
        for name, line, want in table:
            got = read(args(line)[1])
            if got != want:
                failures.append("%s: %r, wanted %r" % (name, got, want))
    for name, line, want in ENV_LINES:
        program, words = args(line)
        if isinstance(want, str):
            got, want = R.env_lines(program, words, [want]), [("BASH_ENV", "x")]
        else:
            got = R.env_lines(program, words, [])
        if got != want:
            failures.append("variables written by %s: %r, wanted %r" % (name, got, want))
    for program, want in (("p", False), ("e", True), ("", False), ("s/a/b/w f", False), ("y", True), ("\\", True)):
        if R.sed_runs(program) is not want:
            failures.append("sed program %r runs a command: %r" % (program, R.sed_runs(program)))
    if R.env_lines("cat", [], []) is not None:
        failures.append("cat with no here-document writes variables")
    for line, want in (('"$GITHUB_ENV"', "ENV"), ("${GITHUB_PATH}", "PATH"), ("$GITHUB_ENVX", None), ("$GITHUB_OUTPUT", None),
                      ("'$GITHUB_ENV'", None), ("x$GITHUB_ENV", "ENV")):
        got = R.runner_file(args("x " + line)[1][0])
        if got != want:
            failures.append("runner file of %s: %r, wanted %r" % (line, got, want))
    tables = 0
    for name, table, held in (
            ("STRING_OPTIONS", R.STRING_OPTIONS, HELD_STRING_OPTIONS), ("JOINED", R.JOINED, HELD_JOINED),
            ("COMPOSERS", R.COMPOSERS, HELD_COMPOSERS), ("GIT_READS", R.GIT_READS, HELD_GIT_READS),
            ("AWKS", R.AWKS, HELD_AWKS), ("AWK_VALUE_OPTIONS", R.AWK_VALUE_OPTIONS, HELD_AWK_VALUE_OPTIONS),
            ("READS_ONLY", R.READS_ONLY, HELD_READS_ONLY)):
        tables += 1
        if table != held:
            failures.append("%s is not the table the cases hold" % name)
    for action in sorted(HELD_GIT_READS):
        tables += 1
        if R.git_problem(args("git config %s alias.x y" % action)[1]) is not None:
            failures.append("git config %s sets a value" % action)
    # Each value option of a program that takes a string: a value that looks
    # like the string's option is skipped.
    for program, (options, _) in sorted(HELD_STRING_OPTIONS.items()):
        for option in sorted(options):
            got = shown(R.script_of(program, args("x %s 'a b'" % option)[1]))
            tables += 1
            if got != ["a b"]:
                failures.append("%s %s names the string: %r" % (program, option, got))
    for program, (_, values) in sorted(HELD_STRING_OPTIONS.items()):
        for value in values:
            got = shown(R.script_of(program, args("x %s -c -c 'a b'" % value)[1]))
            tables += 1
            if got != ["a b"]:
                failures.append("%s %s takes a value: %r" % (program, value, got))
    for program, values in sorted(HELD_JOINED.items()):
        for value in values:
            got = shown(R.script_of(program, args("x %s v h a b" % value)[1]))
            tables += 1
            if got != (["a", "b"] if program == "ssh" else ["h", "a", "b"]):
                failures.append("%s %s takes a value: %r" % (program, value, got))
    for value in sorted(HELD_AWK_VALUE_OPTIONS):
        got = R.awk_problem(args("x %s 'system(1)' '{print}'" % value)[1])
        tables += 1
        if got is not None:
            failures.append("awk %s takes a value: %r" % (value, got))
    for value in sorted(HELD_SED_VALUE_OPTIONS):
        got = R.sed_problem(args("x %s e p" % value)[1])
        tables += 1
        if got is not None:
            failures.append("sed %s takes a value: %r" % (value, got))
    for reader in sorted(HELD_READS_ONLY):
        tables += 1
        if R.named_files(reader, args('x "$GITHUB_ENV" $GITHUB_PATH')[1]) != []:
            failures.append("%s writes a runner file" % reader)
    if R.named_files("tee", args('x -a "$GITHUB_ENV" $GITHUB_PATH y')[1]) != ["ENV", "PATH"]:
        failures.append("tee writes no runner file")
    for name in ("unset", "chdir"):
        got = shown(R.script_of("env", args("x --%s -S -S 'a b'" % name)[1]))
        tables += 1
        if got != ["a b"]:
            failures.append("env --%s takes a value: %r" % (name, got))
    for failure in failures:
        print("FAIL: workflow_runners: " + failure, file=sys.stderr)
    total = len(ENV) + 1 + len(SCRIPTS) + len(GITS) + len(AWKS) + len(SEDS) + len(ENV_LINES) + 14 + tables
    print("workflow_runners tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
