"""Crafted cases for scripts/lib/workflow_downloads.py, run by
scripts/check-workflow-pins-tests.sh.

The readers of a download's output, of a checksum line and of what echo
and printf print are pinned word by word, and `judge` note by note: each
refusal it makes with its file and line, and the programs it lets run.
Run with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words
import workflow_downloads as D

HEX = "0123456789abcdef" * 4
TEMP = D.marker("RUNNER_TEMP")


def words(text):
    return shell_words.lex(text, lambda offset: 1).commands[0].words


def raws(found):
    return [w.raw for w in found]


OUTPUTS = [
    # (program, arguments, (outputs, problem or None))
    ("curl", '-fsSL -o "$f" https://example.invalid/a.tgz', (['"$f"'], None)),
    ("curl", "-fsSLo out https://example.invalid/a", (["out"], None)),
    ("curl", "--output=out https://example.invalid/a", (["--output=out"], None)),
    ("curl", '-o"$f" https://example.invalid/a', (['-o"$f"'], None)),
    ("curl", "-H 'X: y' -O 'https://example.invalid/dir/tool.tar.gz?x=1'", (["tool.tar.gz"], None)),
    ("curl", "-O https://example.invalid/dir/tool?x=1", ([], "a curl -O whose file the check cannot name (https://example.invalid/dir/tool?x=1): name the file with -o")),
    ("curl", "--output-dir d -o out https://example.invalid/a", (["d/out"], None)),
    ("curl", "-fsS https://example.invalid/a", ([], None)),
    ("curl", "-O \"$URL\"", ([], "a curl -O whose file the check cannot name (\"$URL\"): name the file with -o")),
    ("curl", "-LJO https://example.invalid/a", ([], "a curl whose file or options the check cannot name (-J): name the file with -o")),
    ("curl", "-K opts", ([], "a curl whose file or options the check cannot name (-K): name the file with -o")),
    ("curl", "--remote-name-all https://example.invalid/a", ([], "a curl whose file the server or the URL names (--remote-name-all): name the file with -o")),
    ("wget", "-q -O out https://example.invalid/a", (["out"], None)),
    ("wget", "-qO- https://example.invalid/a", (["-qO-"], None)),
    ("wget", "--output-document=out https://example.invalid/a", (["--output-document=out"], None)),
    ("wget", "https://example.invalid/a", ([], "a wget whose file the check cannot name: name it with -O FILE")),
    ("wget", "-nv --tries 3 -O out https://example.invalid/a", (["out"], None)),
    ("wget", "-r https://example.invalid/a", ([], "a wget whose files or settings the check cannot name (-r): name one file with -O")),
    ("wget", "-i list", ([], "a wget whose files or settings the check cannot name (-i): name one file with -O")),
    ("gh", "v1 -p '*.tgz' -O out", (["out"], None)),
    ("gh", "v1 --output=out", (["--output=out"], None)),
    ("gh", "v1 -D dir", ([], "a gh release download whose files the release names: name the file with --output")),
]

LINES = [
    # (what a checksum program reads, [(digest, file template)])
    ("%s  a.tgz" % HEX, [(HEX, "a.tgz")]),
    ("%s *a.tgz" % HEX, [(HEX, "a.tgz")]),
    ("\x010\x02  \x011\x02", [("$D", "\x011\x02")]),
    ("%s a.tgz" % HEX, []),
    ("%s  a.tgz" % HEX[:-1], []),
]

PRINTED = [
    # (command, (template, expansions) or None)
    ('echo "$D  $F"', ("\x010\x02  \x011\x02", ["$D", "$F"])),
    ("echo -n x", ("x", [])),
    ("printf '%s  %s\\n' \"$D\" f", ("\x010\x02  f\n", ["$D"])),
    ("printf '%d\\n' 1", None),
    ('printf "$F"', None),
]


def judged(notes, digests=None):
    refused = []
    D.judge(notes, digests or {}, lambda where, message: refused.append((where, message)), lambda where, line: "line %d" % line)
    return refused


ARCHIVE = TEMP + "/a.tgz"
FETCH = ("fetch", "w.yml", 1, (ARCHIVE, '"$RUNNER_TEMP/a.tgz"', True))
CHECK = ("check", "w.yml", 2, ([(ARCHIVE, ("hex",))], None))
UNPACK = ("use", "w.yml", 3, ("tar", ["tar", "-xzf", ARCHIVE], [], TEMP + "/a", "tar"))
RUN = ("path", "w.yml", 4, ('"$RUNNER_TEMP/a/bin/x"', TEMP + "/a/bin/x"))
PATH = D.PATH_REFUSAL % (4, '"$RUNNER_TEMP/a/bin/x"')
UNPACKED = "line 3: a downloaded file is unpacked before it is checked against a SHA-256 the repository writes: $RUNNER_TEMP/a.tgz, downloaded at line 1"
NOT_CHECKED = "line 1: a download that is not checked against a SHA-256 the repository writes: \"$RUNNER_TEMP/a.tgz\""

JUDGED = [
    # (name, notes, digests, [(file, the start of each refusal)])
    ("checked, unpacked, run", [FETCH, CHECK, UNPACK, RUN], {}, []),
    ("unpacked unchecked", [FETCH, UNPACK, RUN], {}, [("w.yml", UNPACKED), ("w.yml", PATH)]),
    ("checked after the unpack", [FETCH, UNPACK, CHECK, RUN], {}, [("w.yml", UNPACKED), ("w.yml", PATH)]),
    ("never checked", [FETCH], {}, [("w.yml", NOT_CHECKED)]),
    ("data never checked", [("fetch", "w.yml", 1, ("f", "f", False))], {}, []),
    ("data read as data", [("fetch", "w.yml", 1, ("f", "f", False)), ("use", "w.yml", 2, ("jq", ["jq", ".", "f"], [], None, "jq"))], {}, []),
    ("data unpacked", [("fetch", "w.yml", 1, ("f", "f", False)), ("use", "w.yml", 2, ("tar", ["tar", "-xf", "f"], [], None, "tar"))], {},
     [("w.yml", "line 2: a downloaded file is unpacked before it is checked")]),
    ("a digest of an env", [FETCH, ("check", "w.yml", 2, ([(ARCHIVE, ("name", "SHA"))], None)), UNPACK], {"SHA": True}, []),
    ("a digest no env writes", [FETCH, ("check", "w.yml", 2, ([(ARCHIVE, ("name", "SHA"))], None)), UNPACK], {},
     [("w.yml", UNPACKED + " (the check at line 2 does not count: its digest $SHA is set by no env:")]),
    ("a digest a step writes", [("env-write", "w.yml", 1, "SHA"), FETCH, ("check", "w.yml", 2, ([(ARCHIVE, ("name", "SHA"))], None)), UNPACK], {"SHA": True},
     [("w.yml", UNPACKED)]),
    ("a digest a script sets otherwise", [("assigns", "s.sh", 0, {"SHA": False}), FETCH, ("check", "w.yml", 2, ([(ARCHIVE, ("name", "SHA"))], None)), UNPACK], {"SHA": True},
     [("w.yml", UNPACKED)]),
    ("a check that does not stop", [FETCH, ("check", "w.yml", 2, ([(ARCHIVE, ("hex",))], "it is a condition")), UNPACK], {},
     [("w.yml", UNPACKED + " (the check at line 2 does not count: it is a condition)")]),
    ("written again", [FETCH, CHECK, ("use", "w.yml", 3, ("cp", ["cp", "x"], [ARCHIVE], None, "cp")), ("use", "w.yml", 4, ("tar", ["tar", ARCHIVE], [], None, "tar"))], {},
     [("w.yml", "line 4: a downloaded file is unpacked before it is checked against a SHA-256 the repository writes: $RUNNER_TEMP/a.tgz, downloaded at line 1 (line 3 writes it again")]),
    ("unpacked into the temporary directory itself", [FETCH, CHECK, ("use", "w.yml", 3, ("tar", ["tar", ARCHIVE], [], TEMP, "tar")), RUN], {}, [("w.yml", PATH)]),
    ("the checked file run in place", [FETCH, CHECK, ("path", "w.yml", 4, ('"$RUNNER_TEMP/a/bin/x"', ARCHIVE))], {}, []),
    ("a script given the directory", [FETCH, CHECK, UNPACK, ("call", "w.yml", 4, [TEMP + "/a/bin"]), ("path-arg", "s.sh", 3, ('"$bin/x"', 1, "/x")), ("return", "w.yml", 4, None)], {}, []),
    ("a script given another directory", [FETCH, CHECK, UNPACK, ("call", "w.yml", 4, [TEMP + "/b"]), ("path-arg", "s.sh", 3, ('"$bin/x"', 1, "/x")), ("return", "w.yml", 4, None)], {},
     [("s.sh", D.PATH_REFUSAL % (3, '"$bin/x"'))]),
    ("a script run with no word", [FETCH, CHECK, UNPACK, ("path-arg", "s.sh", 3, ('"$bin/x"', 1, "/x"))], {}, [("s.sh", D.PATH_REFUSAL % (3, '"$bin/x"'))]),
]


def main():
    failures = []
    for name, text, want in OUTPUTS:
        args = words(text)
        if name == "gh":
            found, problem = D.gh_outputs(args)
        else:
            found, _, problem = (D.curl_outputs if name == "curl" else D.wget_outputs)(args)
        got = (raws(found), problem)
        if got != want:
            failures.append("%s %s: %r, wanted %r" % (name, text, got, want))
    for text, want in LINES:
        exps = ["$D", "$F"]
        got = D.check_lines(text, exps)
        if got != want:
            failures.append("check line %r: %r, wanted %r" % (text, got, want))
    for text, want in PRINTED:
        w = words(text)
        got = D.printed(w[0].literal(), w[1:])
        if got != want:
            failures.append("printed %s: %r, wanted %r" % (text, got, want))
    for text, want in (("sha256sum --check -", True), ("sha256sum -c", True), ("sha256sum --strict -c -", True),
                       ("sha256sum -c sums", False), ("sha256sum f", False), ("shasum -a 256 -c -", True),
                       ("shasum -a256 --check", True), ("shasum -c -", False), ('sha256sum -c "$S"', False)):
        w = words(text)
        if D.checksum_reads_input(w[0].literal(), w[1:]) != want:
            failures.append("%s reads its input: %r" % (text, not want))
    for text, want in (("a.tar.gz", True), ("x/a.TGZ", True), ("a.zip?x=1", True), ("tool", False), ("a.json", False), (None, False)):
        if D.code_like(text) != want:
            failures.append("code_like(%r): %r" % (text, not want))
    if D.env_digests([]) != {}:
        failures.append("no env: names no digest")
    for name, notes, digests, want in JUDGED:
        got = judged(notes, digests)
        if len(got) != len(want) or any(g[0] != w[0] or not g[1].startswith(w[1]) for g, w in zip(got, want)):
            failures.append("judge, %s: %r, wanted %r" % (name, got, want))
    for failure in failures:
        print("FAIL: workflow_downloads: " + failure, file=sys.stderr)
    total = len(OUTPUTS) + len(LINES) + len(PRINTED) + 9 + 6 + 1 + len(JUDGED)
    print("workflow_downloads tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
