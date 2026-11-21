"""The files a job downloads, held to a digest the repository writes, for
scripts/check-workflow-pins.sh.

A program or an archive a step downloads (`curl`, `wget`, `gh release
download`) is whatever the server sends that day. The job holds it to what
the repository reviewed only by checking it against a SHA-256 written out in
the repository, before it is run or unpacked: `echo "<sha256>  <file>" |
sha256sum --check -` (or `shasum -a 256 -c`, a here-string or a
here-document), where the digest is a literal of 64 hex digits, a variable
the same script sets to one, or a variable an `env:` of the workflow, the
job, a step or a local action sets to one and no script of the job sets
otherwise or writes to `$GITHUB_ENV`. The check stands where its failure
stops the script: at the top level of a script that set `-e` before it, not
in a function, a subshell, a substitution or a condition, and not joined to
what follows by `&&`, `||`, `|` or `&`.

The reader of scripts (`Downloads`, mixed into scripts/lib/
workflow_installs.py) notes each fact in the order the job meets it: a
download (`fetch`), a check (`check`), every other command that names a
file (`use`), a program run by a path that may lie in a checked download
(`path`, `path-arg`), the arguments a repository script is run with (`call`,
`return`), the variables each script sets (`assigns`) and those a step
writes to `$GITHUB_ENV` (`env-write`). `judge` then holds the notes of one
job:

  - a downloaded file named by anything but a program that only names a
    file (`ls`, `test`, `rm`, the checksum programs) or reads it as data
    (`jq`, `grep`, `diff`, ...) before its check is refused, and so is one
    written again after its check and named after that;
  - a download no check covers is refused when its name or its URL says
    it is an archive or a program (`.tar.gz`, `.zip`, `.deb`, `.sh`, ...;
    every `gh release download`), and one the job runs, unpacks or makes
    executable is refused at that use;
  - a program run by a path the repository does not hold is the checked
    download itself, or lies under the directory of `$RUNNER_TEMP` a checked
    archive was unpacked into (`tar -C`, `unzip -d`); in a repository
    script the path may come through a variable whose one value is a
    positional parameter, read from the word its caller passed. Any other
    such program is refused, as in every job.

A download the check cannot name is refused by name when it is read: an
output from the server (`-J`, `--remote-name-all`), options from a file
(`curl -K`, `wget -e`, `wget -i`), a `wget` or a `gh release download`
without an output file, and a stream unpacked as it arrives (`curl ... |
tar -x`, `tar -xf <(curl ...)`). An action handed a URL as an input
fetches it where no step can check it first, and is refused by name.
"""

import re

import shell_words
import workflow_runners
from workflow_held import program_name

HEX = re.compile(r"[0-9A-Fa-f]{64}")
SIMPLE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*|[1-9])\}?")
URL_INPUT = re.compile(r"\s*(https?|ftps?)://", re.I)
CODE_NAME = re.compile(r"\.(tar|tgz|tbz2?|txz|tzst|zip|gz|xz|bz2|zst|7z|deb|rpm|apk|pkg|dmg|msi|exe|appimage|"
                       r"sh|bash|py|bin|run|whl|jar|so|dylib)$", re.I)
UNPACKERS = {"tar", "bsdtar", "gtar", "unzip", "gunzip", "gzip", "zcat", "xz", "unxz", "xzcat", "bunzip2",
             "bzip2", "zstd", "unzstd", "7z", "7za", "cpio", "dpkg", "dpkg-deb", "rpm", "rpm2cpio",
             "installer", "hdiutil", "msiexec", "jar", "ar"}
RUNNERS = {"sh", "bash", "dash", "zsh", "ksh", "source", ".", "python", "python3", "perl", "ruby", "node", "exec"}
# Programs that name a file without running, unpacking or changing it.
NAMES_ONLY = {"ls", "stat", "test", "[", "[[", "echo", "printf", "file", "wc", "du", "rm",
              "sha256sum", "shasum", "sha512sum", "sha1sum", "md5sum", "b2sum", "cksum"}
# Programs that read a file as data.
DATA = {"jq", "grep", "egrep", "fgrep", "diff", "cmp", "comm", "head", "tail", "cut", "sort", "uniq", "tr",
        "yq", "xmllint"}
# Programs whose last operand is the file they write.
COPIERS = {"cp", "mv", "ln", "install", "rsync"}
CURL_SHORT_VALUES = set("AbcCdDeEFHmoPQrtTuUwxXYyz")
CURL_LONG_VALUES = {
    "--header", "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--data", "--data-raw",
    "--data-binary", "--data-urlencode", "--form", "--request", "--max-time", "--connect-timeout", "--retry",
    "--retry-delay", "--retry-max-time", "--write-out", "--proto", "--proto-redir", "--proto-default",
    "--cacert", "--capath", "--cert", "--key", "--resolve", "--connect-to", "--upload-file", "--proxy",
    "--range", "--limit-rate", "--max-filesize", "--oauth2-bearer", "--dns-servers", "--interface",
    "--continue-at", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--ciphers", "--tls-max",
    "--expect100-timeout", "--keepalive-time", "--max-redirs", "--speed-limit", "--speed-time", "--pinnedpubkey",
}
WGET_SHORT_VALUES = set("OoatTwUQPlARDBI")
WGET_VALUES = {"--output-file", "--append-output", "--tries", "--timeout", "--wait", "--user-agent", "--header",
               "--user", "--password", "--quota", "--post-data", "--body-data", "--method", "--ca-certificate",
               "--certificate", "--private-key", "--limit-rate", "--directory-prefix"}
GH_VALUES = {"-p", "--pattern", "-A", "--archive", "-R", "--repo", "-D", "--dir"}
PATH_REFUSAL = "line %d: a program run by a path the repository does not hold is not read: %s (a file a step made or downloaded)"


def marker(text):
    """An expansion inside a key, so that no literal text can equal it."""
    return "\x01" + text + "\x02"


TEMP = marker("RUNNER_TEMP") + "/"


def shown(key):
    """A key as a reader writes it."""
    return re.sub("\x01([^\x02]*)\x02", lambda m: "$" + m.group(1) if SIMPLE.fullmatch("$" + m.group(1)) else m.group(1), key)


def code_like(text):
    return text is not None and CODE_NAME.search(text.split("?")[0].split("#")[0]) is not None


def literal_tail(word):
    """The literal text after a word's last expansion."""
    return word.tail() if word.parts else ""


# What a download command writes.

def next_word(words, k):
    """(the word at k, the index after it), or (None, k) past the end."""
    return (words[k], k + 1) if k < len(words) else (None, k)


def curl_outputs(args):
    """(output words, URL words, a problem or None) of a curl command. An
    output of `-` is the standard output."""
    outputs, urls, remote, directory = [], [], False, None
    k = 0
    while k < len(args):
        w = args[k]
        head = w.head()
        k += 1
        if head == "--" and w.literal() == "--":
            urls.extend(args[k:])
            break
        if head.startswith("--"):
            name = head.split("=")[0]
            joined = "=" in head
            if name in ("--remote-name-all", "--remote-header-name"):
                return [], urls, "a curl whose file the server or the URL names (%s): name the file with -o" % name
            if name == "--config":
                return [], urls, "a curl that reads its options from a file (--config)"
            if name == "--remote-name":
                remote = True
            elif name in ("--output", "--output-dir", "--url") or name in CURL_LONG_VALUES:
                value, k = (workflow_runners.cut(w, len(name) + 1), k) if joined else next_word(args, k)
                if value is None:
                    continue
                if name == "--output":
                    outputs.append(value)
                elif name == "--output-dir":
                    directory = value
                elif name == "--url":
                    urls.append(value)
            continue
        if head.startswith("-") and len(head) > 1:
            for i, letter in enumerate(head[1:], 1):
                if letter in "JK":
                    return [], urls, "a curl whose file or options the check cannot name (-%s): name the file with -o" % letter
                if letter == "O":
                    remote = True
                elif letter in CURL_SHORT_VALUES:
                    # The value is the rest of the word, or the next word.
                    value, k = (workflow_runners.cut(w, i + 1), k) if len(head) > i + 1 or w.literal() is None else next_word(args, k)
                    if letter == "o" and value is not None:
                        outputs.append(value)
                    break
            continue
        urls.append(w)
    if remote:
        for url in urls:
            tail = literal_tail(url)
            name = tail.split("?")[0].rsplit("/", 1)[-1] if "/" in tail else ""
            if not name:
                return outputs, urls, "a curl -O whose file the check cannot name (%s): name the file with -o" % url.raw
            named = shell_words.Word(url.line)
            named.lit(name)
            named.raw = name
            outputs.append(named)
    if directory is not None:
        outputs = [o if (o.literal() or "").startswith("/") or o.literal() == "-" else joined_path(directory, o) for o in outputs]
    return outputs, urls, None


def joined_path(directory, word):
    out = shell_words.Word(word.line)
    out.parts = list(directory.parts) + [("lit", "/")] + list(word.parts)
    out.raw = directory.raw + "/" + word.raw
    return out


def wget_outputs(args):
    """(output words, URL words, a problem or None) of a wget command. Short
    options cluster (`-qO-`), as getopt reads them."""
    outputs, urls = [], []
    k = 0
    while k < len(args):
        w = args[k]
        head = w.head()
        k += 1
        if head.startswith("--"):
            name = head.split("=")[0]
            joined = "=" in head
            if name in ("--input-file", "--execute", "--recursive", "--mirror"):
                return [], urls, "a wget whose files or settings the check cannot name (%s): name one file with -O" % name
            if name == "--output-document":
                value, k = (workflow_runners.cut(w, len(name) + 1), k) if joined else next_word(args, k)
                if value is not None:
                    outputs.append(value)
            elif name in WGET_VALUES and not joined:
                k += 1
            continue
        if head.startswith("-") and len(head) > 1:
            for i, letter in enumerate(head[1:], 1):
                if letter in "iemr":
                    return [], urls, "a wget whose files or settings the check cannot name (-%s): name one file with -O" % letter
                if letter in WGET_SHORT_VALUES:
                    value, k = (workflow_runners.cut(w, i + 1), k) if len(head) > i + 1 or w.literal() is None else next_word(args, k)
                    if letter == "O" and value is not None:
                        outputs.append(value)
                    break
            continue
        urls.append(w)
    if not outputs:
        return [], urls, "a wget whose file the check cannot name: name it with -O FILE"
    return outputs, urls, None


def gh_outputs(args):
    """(output words, a problem or None) of `gh release download`."""
    outputs = []
    k = 0
    while k < len(args):
        w = args[k]
        head = w.head()
        k += 1
        if head.startswith("--output="):
            outputs.append(workflow_runners.cut(w, len("--output=")))
        elif head in ("-O", "--output"):
            value, k = next_word(args, k)
            if value is not None:
                outputs.append(value)
        elif head in GH_VALUES:
            k += 1
    if not outputs:
        return [], "a gh release download whose files the release names: name the file with --output"
    return outputs, None


def check_lines(template, exps):
    """(digest, file template, exps) for each `<sha256>  <file>` line of an
    input the checksum program reads; the digest is hex text or an
    expansion's text."""
    found = []
    for line in template.split("\n"):
        m = re.fullmatch(r"(\x01(\d+)\x02|[0-9A-Fa-f]{64}) [ *](.+)", line)
        if m:
            digest = exps[int(m.group(2))] if m.group(2) is not None else m.group(1)
            found.append((digest, m.group(3)))
    return found


def template_of(words):
    """The text of words joined by spaces, each expansion standing as a
    numbered marker, and the expansions' texts."""
    out, exps = [], []
    for w in words:
        piece = []
        for kind, text in w.parts:
            if kind == "lit":
                piece.append(text)
            else:
                piece.append("\x01%d\x02" % len(exps))
                exps.append(text)
        out.append("".join(piece))
    return " ".join(out), exps


def printed(name, args):
    """(template, exps) of what `echo` or `printf` prints, or None when the
    check cannot tell."""
    if name == "echo":
        k = 0
        while k < len(args) and re.fullmatch(r"-[neE]+", args[k].literal() or ""):
            k += 1
        text, exps = template_of(args[k:])
        if any(re.fullmatch(r"-[neE]*e[neE]*", a.literal() or "") for a in args[:k]):
            text = text.replace("\\n", "\n")
        return text, exps
    if not args or args[0].literal() is None:
        return None
    fmt = args[0].literal().replace("\\n", "\n").replace("%%", "\x00")
    if re.search(r"%(?!s)", fmt):
        return None
    rest = args[1:]
    count = fmt.count("%s")
    out, exps = [], []
    while True:
        pieces = fmt.split("%s")
        for i, piece in enumerate(pieces):
            out.append(piece.replace("\x00", "%"))
            if i < len(pieces) - 1:
                arg = rest.pop(0) if rest else None
                if arg is not None:
                    text, inner = template_of([arg])
                    out.append(re.sub("\x01(\\d+)\x02", lambda m: "\x01%d\x02" % (int(m.group(1)) + len(exps)), text))
                    exps.extend(inner)
        if not rest or count == 0:
            break
    return "".join(out), exps


def heredoc_template(body):
    """(template, exps) of a here-document body, or None when it holds a
    substitution."""
    if "$(" in body or "`" in body:
        return None
    exps = []

    def mark(m):
        exps.append(m.group(0))
        return "\x01%d\x02" % (len(exps) - 1)
    return re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*", mark, body), exps


def word_of(template, exps, line):
    """A word made of the text of a template and the expansions it marks."""
    w = shell_words.Word(line)
    for i, piece in enumerate(re.split("\x01(\\d+)\x02", template)):
        if i % 2:
            w.exp(exps[int(piece)])
        else:
            w.lit(piece)
    w.raw = re.sub("\x01(\\d+)\x02", lambda m: exps[int(m.group(1))], template)
    return w


def checksum_reads_input(name, args):
    """Whether the command is a SHA-256 check that reads its lines from its
    input: `sha256sum --check` or `shasum -a 256 --check`, with no file
    operand but `-`."""
    literals = [w.literal() for w in args]
    if any(x is None for x in literals):
        return False
    checks = any(x == "--check" or re.fullmatch(r"-[bctzw]*c[bctzw]*", x) for x in literals)
    if name == "shasum":
        joined = " ".join(literals)
        if not re.search(r"(^| )(-a ?256|--algorithm[= ]256)( |$)", joined):
            return False
        literals = [x for i, x in enumerate(literals) if x not in ("-a", "--algorithm") and not (i and literals[i - 1] in ("-a", "--algorithm"))]
    operands = [x for x in literals if not x.startswith("-") or x == "-"]
    return checks and all(x == "-" for x in operands)


class Downloads:
    """The notes of the reader of scripts about downloads; mixed into it.
    The reader holds `notes`, `values`, `refuse` and `note`."""

    def file_key(self, word, depth=0):
        """The file a word names: its literal text, each simple expansion
        standing as its name, and a variable the script gives one value of
        literal text and simple expansions standing as that value. None
        when a variable it names has more than one value."""
        out = []
        for kind, text in word.parts:
            if kind == "lit":
                out.append(text)
                continue
            m = SIMPLE.fullmatch(text)
            if m is None:
                out.append(marker(text))
                continue
            name = m.group(1)
            given = self.values.assigned.get(name) if self.values is not None else None
            if not given:
                out.append(marker(name))
                continue
            if len(given) != 1 or given[0] is None:
                return None
            value = given[0]
            if depth < 4 and value and all(k == "lit" or SIMPLE.fullmatch(t) for k, t in value):
                inner = shell_words.Word(word.line)
                inner.parts = list(value)
                sub = self.file_key(inner, depth + 1)
                if sub is None:
                    return None
                out.append(sub)
            else:
                out.append(marker(name))
        return "".join(out)

    def script_assigns(self, path):
        """Note the variables the script sets, and whether every value of
        each is a SHA-256 written out."""
        given = {}
        for name, values in self.values.assigned.items():
            literals = self.values.literals(name)
            given[name] = literals is not None and all(HEX.fullmatch(v) for v in literals)
        self.note("assigns", path, 0, given)

    def env_written(self, path, line, variable):
        self.note("env-write", path, line, variable)

    def neighbour(self, command, lexed, step):
        """The command before (`step` -1) or after (+1) this one in the same
        subshell or substitution, or None."""
        commands = lexed.commands
        index = next((k for k, c in enumerate(commands) if c is command), None)
        if index is None:
            return None
        k = index + step
        while 0 <= k < len(commands):
            other = commands[k]
            if other.scope == command.scope:
                return other
            if other.scope[:len(command.scope)] != command.scope:
                return None
            k += step
        return None

    def downloads(self, command, words, start, lexed, path):
        """Note what the command at words[start] downloads, checks or names."""
        name = program_name(words[start])
        args = words[start + 1:]
        if name in ("curl", "wget") or (name == "gh" and [a.literal() for a in args[:2]] == ["release", "download"]):
            self.fetch(command, name, args, lexed, path)
            return
        if name in ("sha256sum", "shasum") and checksum_reads_input(name, args):
            self.check(command, lexed, path)
            return
        self.streams(command, name, words[start:], path)
        reads, writes, into = [], [], None
        run = self.file_key(words[start])
        for i, w in enumerate(words[start:]):
            head = w.head()
            if head.startswith("--") and "=" in head:
                w = workflow_runners.cut(w, head.index("=") + 1)
            key = self.file_key(w)
            if key is None:
                continue
            if name in UNPACKERS and i and (words[start + i - 1].literal() in ("-C", "--directory", "-d") or head.startswith("--directory=")):
                into = key
            if name in COPIERS and i == len(words) - start - 1:
                writes.append(key)
            elif name == "tee" and i:
                writes.append(key)
            else:
                reads.append(key)
        for op, target in command.redirects:
            key = self.file_key(target) if target is not None else None
            if key is not None:
                (writes if ">" in op else reads).append(key)
        if reads or writes:
            self.note("use", path, command.line, (name, reads, writes, into, run))

    def streams(self, command, name, words, path):
        """Refuse a download unpacked from its stream through a process
        substitution (`tar -xf <(curl ...)`). One a shell runs from its
        stream is refused as a script the check cannot read."""
        if name not in UNPACKERS:
            return
        for w in words:
            for kind, text in w.parts:
                if kind == "exp" and text.startswith("<(") and re.search(r"\b(curl|wget|gh)\b", text):
                    self.refuse(path, "line %d: a download unpacked from its stream, before any digest can be checked: %s (write it to a file and check it first)" % (
                        command.line, w.raw))

    def fetch(self, command, name, args, lexed, path):
        if name == "curl":
            outputs, urls, problem = curl_outputs(args)
        elif name == "wget":
            outputs, urls, problem = wget_outputs(args)
        else:
            (outputs, problem), urls = gh_outputs(args[2:]), []
        if problem:
            self.refuse(path, "line %d: %s" % (command.line, problem))
            return
        files = [o for o in outputs if o.literal() != "-"]
        if not files:
            files = [t for op, t in command.redirects if op in (">", ">>", ">|", "&>", "&>>") and t is not None]
        if not files:
            files = self.stream_files(command, name, lexed, path)
        code = name == "gh" or any(code_like(literal_tail(u)) for u in urls)
        for w in files:
            if w.literal() in ("/dev/null", "/dev/stdout", "/dev/stderr"):
                continue
            key = self.file_key(w)
            if key is None:
                self.refuse(path, "line %d: a download into a file the check cannot name: %s (a variable with more than one value)" % (command.line, w.raw))
                continue
            self.note("fetch", path, command.line, (key, w.raw, code or code_like(key)))

    def stream_files(self, command, name, lexed, path):
        """The files `tee` writes from a download's output, after refusing a
        stream that goes on into an unpacker."""
        files = []
        after = self.neighbour(command, lexed, 1)
        while after is not None and after.joined_by == "|":
            start = self.command_word(after.words)
            run = program_name(after.words[start]) if start is not None else None
            if run in UNPACKERS:
                self.refuse(path, "line %d: a download unpacked from its stream, before any digest can be checked: %s | %s (write it to a file and check it first)" % (command.line, name, run))
            if run == "tee":
                files.extend(w for w in after.words[start + 1:] if not (w.literal() or "").startswith("-"))
            after = self.neighbour(after, lexed, 1)
        return files

    def check(self, command, lexed, path):
        """Note the files a SHA-256 check covers, with each digest and, when
        a failure of the check does not stop the script, why."""
        texts = []
        for op, target in command.redirects:
            if op == "<<<" and target is not None:
                texts.append(template_of([target]))
        for body, _ in lexed.bodies_of(command):
            found = heredoc_template(body)
            if found is not None:
                texts.append(found)
        before = self.neighbour(command, lexed, -1) if command.joined_by == "|" else None
        if before is not None:
            start = self.command_word(before.words)
            run = program_name(before.words[start]) if start is not None else None
            found = printed(run, before.words[start + 1:]) if run in ("echo", "printf") else None
            if found is not None:
                texts.append(found)
        covered = []
        for template, exps in texts:
            for digest, rest in check_lines(template, exps):
                key = self.file_key(word_of(rest, exps, command.line))
                if key is not None:
                    covered.append((key, self.digest(digest)))
        if covered:
            self.note("check", path, command.line, (covered, self.standing(command, lexed, before)))

    def digest(self, text):
        """("hex",), ("name", NAME) for a variable of the environment, or
        ("unwritten", what) for a digest the repository does not write."""
        if HEX.fullmatch(text):
            return ("hex",)
        m = SIMPLE.fullmatch(text)
        if m is None:
            return ("unwritten", text)
        name = m.group(1)
        if self.values.assigned.get(name):
            literals = self.values.literals(name)
            if literals and all(HEX.fullmatch(v) for v in literals):
                return ("hex",)
            return ("unwritten", text)
        return ("name", name)

    def standing(self, command, lexed, before):
        """None when a failure of the check stops the script; else why not."""
        head = before if before is not None else command
        while head.joined_by == "|":
            prior = self.neighbour(head, lexed, -1)
            if prior is None:
                break
            head = prior
        if command.scope:
            return "it runs in a subshell or a substitution, whose failure does not stop the script"
        if any(c is command or c is head for body in self.values.functions.values() for c in body):
            return "it runs in a function, which a caller may run where a failure does not stop it"
        if any(w.bare() in ("if", "elif", "while", "until", "!") for c in (head, command) for w in c.words[:self.command_word(c.words) or 0]):
            return "it is a condition, whose failure does not stop the script"
        if head.joined_by in ("&&", "||"):
            return "it runs only after the command before it, joined by %s" % head.joined_by
        after = self.neighbour(command, lexed, 1)
        if after is not None and after.joined_by in ("&&", "||", "|", "&"):
            return "it is joined to the command after it by %s, so its failure does not stop the script" % after.joined_by
        index = next((k for k, c in enumerate(lexed.commands) if c is head), None)
        if index is None:
            return "the check cannot tell where it stands in the script"
        on = False
        for other in lexed.commands[:index]:
            if other.scope or any(c is other for body in self.values.functions.values() for c in body):
                continue
            start = self.command_word(other.words)
            if start is None or other.words[start].bare() != "set":
                continue
            options = [w.literal() or "" for w in other.words[start + 1:]]
            for i, option in enumerate(options):
                if re.fullmatch(r"[-+][a-zA-Z]*e[a-zA-Z]*", option):
                    on = option.startswith("-")
                elif option in ("-o", "+o") and options[i + 1:i + 2] == ["errexit"]:
                    on = option == "-o"
        return None if on else "the script does not stop when it fails: set -e before it"

    def unpacked_path(self, run, command, path):
        """Note a program run by a path that may lie in a checked download,
        for the job to judge; False for any other path."""
        key = self.file_key(run)
        if key is None:
            return False
        if key.startswith(TEMP) and len(key) > len(TEMP):
            self.note("path", path, command.line, (run.raw, key))
            return True
        m = re.fullmatch("\x01([1-9])\x02(/.*)?", key)
        if m and not self.in_function(command, run):
            self.note("path-arg", path, command.line, (run.raw, int(m.group(1)), m.group(2) or ""))
            return True
        return False

    def in_function(self, command, run):
        """Whether the positional parameter a word reads is a function's: the
        one assignment of the variable it reads stands in a body, or the
        word reads the parameter itself and stands in one."""
        bodies = {id(c) for body in self.values.functions.values() for c in body}
        m = SIMPLE.fullmatch(run.parts[0][1]) if run.parts and run.parts[0][0] == "exp" else None
        if m is not None and not m.group(1).isdigit():
            return any(id(c) in bodies for c in self.values.first.get(m.group(1), []))
        return id(command) in bodies

    def call_note(self, path, line, args):
        self.note("call", path, line, [self.file_key(w) for w in args])


def env_digests(owners):
    """{name: whether every value an `env:` of `owners` gives it is a SHA-256
    written out}."""
    found = {}
    for owner in owners:
        env = owner.get("env") if hasattr(owner, "get") else None
        for key, value in env.pairs if env is not None and hasattr(env, "pairs") else []:
            text = getattr(value, "value", None)
            ok = isinstance(text, str) and HEX.fullmatch(text) is not None
            found[key.value] = found.get(key.value, True) and ok
    return found


def judge(notes, digests, refuse, at):
    """Refuse, for one job, a downloaded file used before its check, a
    download no check covers, and a program run by a path that lies in no
    checked download. `digests` is `env_digests` of the job's `env:`s,
    `refuse(where, message)` and `at(where, line)` names a place."""
    unsettled = {n for kind, _, _, what in notes if kind == "assigns" for n, ok in what.items() if not ok}
    unsettled |= {what for kind, _, _, what in notes if kind == "env-write"}
    files, fetches, directories, calls = {}, [], [], []
    for kind, where, line, what in notes:
        if kind == "call":
            calls.append(what)
        elif kind == "return" and calls:
            calls.pop()
        elif kind == "fetch":
            key, raw, code = what
            record = {"key": key, "raw": raw, "code": code, "at": at(where, line), "where": where, "line": line,
                      "checked": False, "why": "", "done": False}
            files[key] = record
            fetches.append(record)
        elif kind == "check":
            covered, why = what
            for key, digest in covered:
                record = files.get(key)
                if record is None:
                    continue
                if why is None and digest[0] == "name" and (not digests.get(digest[1]) or digest[1] in unsettled):
                    why = "its digest $%s is set by no env: to a SHA-256 written out, or set otherwise by the job" % digest[1]
                elif why is None and digest[0] == "unwritten":
                    why = "its digest %s is not written out in the repository" % digest[1]
                record["checked"], record["why"] = why is None, "" if why is None else " (the check at %s does not count: %s)" % (at(where, line), why)
        elif kind == "use":
            use(files, directories, where, line, what, refuse)
        elif kind in ("path", "path-arg"):
            raw, key = what[0], what[1]
            if kind == "path-arg":
                given = calls[-1] if calls else []
                key = given[what[1] - 1] + what[2] if len(given) >= what[1] and given[what[1] - 1] is not None else None
            record = files.get(key)
            if key is None or not ((record is not None and record["checked"]) or any(key.startswith(d + "/") for d in directories)):
                refuse(where, PATH_REFUSAL % (line, raw))
    for record in fetches:
        if record["checked"] or record["done"] or not record["code"]:
            continue
        refuse(record["where"], "line %d: a download that is not checked against a SHA-256 the repository writes: %s%s (check it with sha256sum --check against a digest written in the workflow or the script, before it is run or unpacked)" % (
            record["line"], record["raw"], record["why"]))


def use(files, directories, where, line, what, refuse):
    """Judge one command that names files: a downloaded file it runs,
    unpacks or changes before its check is refused; one it writes again is
    no longer checked; a checked archive it unpacks under $RUNNER_TEMP adds
    the directory its programs may be run from."""
    name, reads, writes, into, run = what
    for key in writes:
        record = files.get(key)
        if record is not None and record["checked"]:
            record["checked"], record["why"] = False, " (line %d writes it again after its check)" % line
    for key in reads:
        record = files.get(key)
        if record is None or name in NAMES_ONLY:
            continue
        if name in DATA and not record["code"]:
            continue
        if not record["checked"]:
            if not record["done"]:
                record["done"] = True
                verb = ("run" if key == run or name in RUNNERS else "unpacked" if name in UNPACKERS
                        else "made executable" if name == "chmod" else "used by %s" % name)
                refuse(where, "line %d: a downloaded file is %s before it is checked against a SHA-256 the repository writes: %s, downloaded at %s%s (check it with sha256sum --check first)" % (
                    line, verb, shown(key), record["at"], record["why"]))
        elif name in UNPACKERS and into is not None and into.startswith(TEMP) and len(into) > len(TEMP):
            directories.append(into)


def action_urls(steps):
    """(line, input name, value) of each `with:` input of a step that uses
    an action and is handed a URL."""
    found = []
    for step in steps:
        uses = step.get("uses") if hasattr(step, "get") else None
        given = step.get("with") if uses is not None else None
        if not hasattr(given, "pairs") or getattr(uses, "value", "").startswith(("./", "docker://")):
            continue
        for key, value in given.pairs:
            text = getattr(value, "value", None)
            if isinstance(text, str) and URL_INPUT.match(text):
                found.append((key.line, key.value, text.strip()))
    return found

