"""The breaks cargo-semver-checks reports, each named on the migration page,
for scripts/check-semver.sh.

The report is the text `cargo semver-checks check-release` writes to its two
streams together, read as version 0.51.0 writes it (src/check_release.rs and
src/config.rs of that release):

    Checking <crate> v<old> -> v<new> (<kind of change>)     (stderr)
    --- failure <lint id>: <lint name> ---                    (stdout)
    Description: ... / ref: ... / impl: ...
    Failed in:
      <one line per place, from the lint's template>
    --- warning <lint id>: <lint name> ---                    (the same shape)
    Summary semver requires new <major|minor> version: M major and N minor checks failed
    Summary no semver update required
    Warning produced M major and N minor level warnings

A failure is a lint at the deny level that found something; a warning is one
at the warn level. Both are breaks the tool sees, and both are inventoried:
a warning is the tool saying a break may be there, and the page is where an
adopter reads it.

The report must account for itself, or it is not read (exit 2): every block
has a `Failed in:` line and at least one place under it, every place names
an item, every crate with a block has a Summary, and per crate the failure
blocks number M + N of its Summary line and the warning blocks M + N of its
Warning line (the tool prints one block per lint that found something, and
counts the same lints). A line that holds `--- failure` or `--- warning` but
is not a header, a tool status other than zero with no failure block, a zero
status with one, and a report with no Checking line at all are refused the
same way. So a changed format, a crashed run or an empty capture can never
read as a pass.

Naming. The item of a place is its first path (identifiers joined by `::`,
`.` or a lone `:`; `<` and `>` dropped), or with no path its first word that
is not a kind word (`struct`, `enum`, `feature`, ...), after the location
(`in file src/x.rs:12`, `, previously in ...`, `in the package's Cargo.toml`)
is cut off. A break is named when the page holds, inside backticks outside a
fenced code block, a span that ends with the item's last two segments (the
last one, for an item of one segment), after the span's trailing argument
list and generic arguments are dropped and its `.` read as `::`. So the full
path names it, and so does `Type::method`. There is no allowlist: a break the
tool reports and the release means is named on the page; one the release
does not mean is fixed in the code.

Run with `python3 -I -B semver_inventory.py --report FILE --page FILE
--status N`. Exit 0: every break named (or none). Exit 1: the breaks not
named, listed. Exit 2: a report this does not read.
"""

import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CHECKING = re.compile(r"\s*Checking\s+(\S+)\s+v\S+\s+->\s+v\S+")
HEADER = re.compile(r"--- (failure|warning) ([A-Za-z0-9_]+): (.*) ---")
SUMMARY = re.compile(r"\s*Summary\s+semver requires new (?:major|minor) version: ([0-9]+) major and ([0-9]+) minor checks failed")
CLEAN = re.compile(r"\s*Summary\s+no semver update required")
WARNED = re.compile(r"\s*Warning\s+produced ([0-9]+) major and ([0-9]+) minor level warnings")
STATUS = re.compile(r"\s{3,}[A-Z][a-z]+\s")
PLACE = re.compile(r"  (\S.*)")
LOCATION = re.compile(r"(?:(?:^|,?\s+)(?:previously\s+)?(?:in|at)\s+(?:file\s+)?\S+?(?::[0-9]+)?|\s+in the package's Cargo\.toml)\s*$")
PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:(?:::|:|\.)[A-Za-z_][A-Za-z0-9_]*)*")
KIND = {"struct", "enum", "trait", "method", "function", "fn", "field", "variant", "macro", "proc", "feature",
        "constant", "const", "type", "union", "static", "module", "mod", "impl", "associated", "attribute",
        "derive", "tuple", "unit", "plain"}
SPAN = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)")


class Unread(Exception):
    """A report this reader cannot account for."""


def printable(text):
    return re.sub(r"[^\x20-\x7e]", "?", text)


def segments(path):
    """The parts of a path, its separators read as `::`."""
    flat = path.replace("<", "").replace(">", "")
    flat = re.sub(r"(?<!:):(?!:)", "::", flat).replace(".", "::")
    return [part for part in flat.split("::") if part]


def item_of(place):
    """The item a place names, or None."""
    subject = LOCATION.sub("", place).replace("<", "").replace(">", "")
    words = PATH.findall(subject)
    for word in words:
        if re.search(r"::|:|\.", word):
            return word
    for word in words:
        if word.lower() not in KIND:
            return word
    return None


def parse(text):
    """[(crate, kind, lint, place, item)] of a report, or Unread."""
    breaks, blocks, crate, block = [], [], None, None
    summaries, warnings = {}, {}
    for number, raw in enumerate(ANSI.sub("", text).replace("\r", "").split("\n"), 1):
        line = raw.rstrip()
        header = HEADER.fullmatch(line)
        if header:
            if crate is None:
                raise Unread("line %d: a %s block before any Checking line" % (number, header.group(1)))
            block = {"crate": crate, "kind": header.group(1), "lint": header.group(2), "line": number,
                     "failed_in": False, "places": []}
            blocks.append(block)
            continue
        if "--- failure" in line or "--- warning" in line:
            raise Unread("line %d: a block header this does not read: %s" % (number, printable(line.strip())))
        checking = CHECKING.match(line)
        summary, clean, warned = SUMMARY.match(line), CLEAN.match(line), WARNED.match(line)
        if checking or summary or clean or warned or STATUS.match(line):
            block = None
        if checking:
            crate = checking.group(1)
        elif summary or clean:
            if crate is None:
                raise Unread("line %d: a Summary before any Checking line" % number)
            summaries[crate] = int(summary.group(1)) + int(summary.group(2)) if summary else 0
        elif warned and crate is not None:
            warnings[crate] = int(warned.group(1)) + int(warned.group(2))
        elif block is not None:
            if line.strip() == "Failed in:":
                block["failed_in"] = True
            elif block["failed_in"]:
                place = PLACE.fullmatch(line)
                if place:
                    block["places"].append((number, place.group(1)))
    if crate is None:
        raise Unread("the report holds no Checking line: no crate was checked")
    for block in blocks:
        where = "line %d: %s %s of %s" % (block["line"], block["kind"], block["lint"], block["crate"])
        if not block["failed_in"] or not block["places"]:
            raise Unread("%s: no place under a `Failed in:` line" % where)
        for number, place in block["places"]:
            item = item_of(place)
            if item is None:
                raise Unread("line %d: a place of %s that names no item: %s" % (number, block["lint"], printable(place)))
            breaks.append((block["crate"], block["kind"], block["lint"], place, item))
    crates = {block["crate"] for block in blocks}
    for name in sorted(crates | set(summaries)):
        failures = sum(1 for b in blocks if b["crate"] == name and b["kind"] == "failure")
        warned = sum(1 for b in blocks if b["crate"] == name and b["kind"] == "warning")
        if name not in summaries:
            raise Unread("%s has blocks and no Summary line" % name)
        if failures != summaries[name]:
            raise Unread("%s: %d failure blocks, and its Summary counts %d failed checks" % (name, failures, summaries[name]))
        if warned != warnings.get(name, 0):
            raise Unread("%s: %d warning blocks, and its Warning line counts %d" % (name, warned, warnings.get(name, 0)))
    return breaks


def spans(page):
    """The normalized segment lists of the backtick spans of a page, fenced
    code blocks left out."""
    found, fenced = [], False
    for line in page.split("\n"):
        if re.match(r"\s*(```|~~~)", line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for m in SPAN.finditer(line):
            text = m.group(2).strip()
            text = re.sub(r"\([^()]*\)$", "", text)
            while re.search(r"<[^<>]*>", text):
                text = re.sub(r"<[^<>]*>", "", text)
            parts = segments(text)
            if parts:
                found.append(parts)
    return found


def named(item, page_spans):
    want = segments(item)
    k = min(2, len(want))
    return any(len(parts) >= k and parts[-k:] == want[-k:] for parts in page_spans)


def main(argv):
    args = dict(zip(argv[0::2], argv[1::2]))
    if len(argv) % 2 or set(args) != {"--report", "--page", "--status"} or not re.fullmatch(r"[0-9]+", args["--status"]):
        print("usage: semver_inventory.py --report FILE --page FILE --status N", file=sys.stderr)
        return 2
    status = int(args["--status"])
    try:
        with open(args["--report"], encoding="utf-8", errors="replace") as handle:
            report = handle.read()
        try:
            breaks = parse(report)
        except Unread as error:
            if status != 0:
                raise Unread("cargo-semver-checks exited %d and its report is not read: %s" % (status, error))
            raise
        failures = [b for b in breaks if b[1] == "failure"]
        if status != 0 and not failures:
            raise Unread("cargo-semver-checks exited %d and the report names no failure; its output above says why" % status)
        if status == 0 and failures:
            raise Unread("cargo-semver-checks exited 0 and the report holds %d failure places" % len(failures))
    except (Unread, OSError) as error:
        print("ERROR: the semver report is not read: %s" % error, file=sys.stderr)
        return 2
    if not breaks:
        print("OK: cargo-semver-checks reports no break.")
        return 0
    try:
        with open(args["--page"], encoding="utf-8") as handle:
            page = handle.read()
    except OSError:
        page = None
    page_spans = spans(page) if page is not None else []
    missing = [b for b in breaks if not named(b[4], page_spans)]
    crates = len({b[0] for b in breaks})
    if not missing:
        print("OK: %d breaks in %d crates, each named on %s." % (len(breaks), crates, args["--page"]))
        return 0
    where = args["--page"] if page is not None else "%s, which does not exist" % args["--page"]
    print("ERROR: %d of the %d breaks cargo-semver-checks reports are not named on %s:" % (len(missing), len(breaks), where),
          file=sys.stderr)
    for crate, kind, lint, place, item in missing:
        print("  %s: %s %s: %s (%s)" % (crate, kind, lint, item, printable(place)), file=sys.stderr)
    print("Name each in backticks on the page (its full path, or its last two segments), under the compile breaks, "
          "with what an adopter does about it.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
