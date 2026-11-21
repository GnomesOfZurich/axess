"""What rustdoc reported for the workspace, crate by crate.

Used by scripts/check-doc-links.sh, which documents every member with
`cargo doc --keep-going --message-format=json`: with `--keep-going` cargo
documents every member it can, so a member whose docs fail does not hide
the errors of the members after it (rustdoc of one member reads the
metadata of the members it uses, not their docs), and the JSON messages
name the package each diagnostic belongs to.

Run as `python3 -I -B doc_links.py MESSAGES METADATA DOC_ROOT STATUS
[SENTINEL]`: MESSAGES is cargo's standard output, METADATA the output of
`cargo metadata --no-deps --format-version 1`, DOC_ROOT the directory the
pages are rendered into, STATUS cargo's exit status, and SENTINEL a crate
name whose page must exist too (the gate's self-test). It prints every
error and warning with its crate and exits 1 if there is one, if cargo
failed without one, or if a member that reported nothing has no page.

Some diagnostics carry no file or line. rustdoc reads the docs of a module
written in two places, outer docs on its `mod` line and inner docs in its
own file, as one text resolved where the `mod` line stands, and since 1.100
it reports a link there (a redundant explicit target, an unresolved one)
with no location: it cannot point into one of two files. For such a
diagnostic of rustdoc the report names the places it can come from: the
lines of the crate that hold the text rustdoc quotes ("the link appears in
this line"), and every explicit link in the docs of a module of that crate
documented in both places, those whose label is named in the file of the
`mod` line first.
"""

import json
import os
import re
import sys

LINK = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
MOD = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')


def members(metadata):
    """{package id: (name, directory, the lib target's source or None)}."""
    out = {}
    for package in metadata["packages"]:
        lib = next((t["src_path"] for t in package["targets"]
                    if set(t["kind"]) & {"lib", "proc-macro", "rlib", "dylib", "cdylib", "staticlib"}), None)
        out[package["id"]] = (package["name"], os.path.dirname(package["manifest_path"]), lib)
    return out


def diagnostics(lines, ids):
    """(crate, level, rendered text, whether it has a location, lint code)
    of every error and warning in cargo's JSON messages. The closing
    summaries ("aborting due to ...", "N warnings emitted") are not one."""
    found = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        inner = msg.get("message") or {}
        level = inner.get("level")
        text = inner.get("message") or ""
        if level not in ("error", "warning"):
            continue
        if text.startswith("aborting due to") or re.fullmatch(r"\d+ warnings? emitted", text) \
                or re.match(r"\d+ warnings? generated", text):
            continue
        crate = ids.get(msg.get("package_id"), (msg.get("package_id") or "an unknown package",))[0]
        code = (inner.get("code") or {}).get("code")
        rendered = (inner.get("rendered") or text).rstrip("\n")
        # Located when the reader is shown a file and line: rustdoc can hand
        # a span of a module's docs and still print none (the docs stand in
        # two files).
        located = bool(inner.get("spans")) and re.search(r"^\s*--> \S+:\d+", rendered, re.M) is not None
        found.append((crate, level, rendered, located, code))
    return found


def outer_docs(lines, i):
    """The `///` lines above line i, past the attributes between them."""
    docs, j, attrs = [], i - 1, []
    while j >= 0:
        stripped = lines[j].strip()
        if stripped.startswith("///"):
            docs.append(j)
        elif stripped.startswith("#["):
            attrs.append(lines[j])
        else:
            break
        j -= 1
    return sorted(docs), attrs


def child_file(path, name, attrs):
    here = os.path.dirname(path)
    for attr in attrs:
        m = PATH_ATTR.search(attr)
        if m:
            return os.path.normpath(os.path.join(here, m.group(1)))
    base = here if os.path.basename(path) in ("lib.rs", "mod.rs", "main.rs") else path[:-3]
    for candidate in (os.path.join(base, name + ".rs"), os.path.join(base, name, "mod.rs")):
        if os.path.isfile(candidate):
            return candidate
    return None


def explicit(line):
    """The explicit intra-doc links of a doc line: a target that is a path,
    not a URL or an anchor."""
    return [m.group(0) for m in LINK.finditer(line)
            if "://" not in m.group(2) and not m.group(2).startswith(("#", "mailto:"))]


def two_place_links(src_root, root):
    """(named in the parent, place, link, module) of each explicit link in
    the docs of a module documented on its `mod` line and in its own file,
    for every module under src_root. Places are relative to root."""
    found = []
    for directory, _, names in sorted(os.walk(src_root)):
        for file_name in sorted(names):
            if not file_name.endswith(".rs"):
                continue
            path = os.path.join(directory, file_name)
            with open(path, encoding="utf-8") as f:
                lines = f.read().split("\n")
            for i, line in enumerate(lines):
                m = MOD.match(line)
                if not m:
                    continue
                docs, attrs = outer_docs(lines, i)
                if not docs:
                    continue
                child = child_file(path, m.group(1), attrs)
                if child is None:
                    continue
                with open(child, encoding="utf-8") as f:
                    inner = [(n, l) for n, l in enumerate(f.read().split("\n")) if l.strip().startswith("//!")]
                if not inner:
                    continue
                places = [(path, n, lines[n]) for n in docs] + [(child, n, l) for n, l in inner]
                for where, n, text in places:
                    for link in explicit(text):
                        label = LINK.match(link).group(1).strip("`").rstrip("()").split("::")[-1]
                        named = re.search(r"\b%s\b" % re.escape(label), "\n".join(
                            l for k, l in enumerate(lines) if k not in docs and not l.strip().startswith("//"))) is not None
                        found.append((named, "%s:%d" % (os.path.relpath(where, root), n + 1), link, m.group(1)))
    found.sort(key=lambda item: (not item[0], item[1]))
    return found


def quoted_line(rendered):
    """The doc text rustdoc quotes after "the link appears in this line", or None."""
    lines = rendered.split("\n")
    for i, line in enumerate(lines):
        if "the link appears in this line" in line:
            for after in lines[i + 1:]:
                text = after.strip().lstrip("=").strip()
                if text and not text.startswith(("^", "note:", "help:")):
                    return text
    return None


def lines_holding(src_root, text, root):
    """file:line of every line under src_root that holds `text`."""
    found = []
    for directory, _, names in sorted(os.walk(src_root)):
        for file_name in sorted(names):
            if not file_name.endswith((".rs", ".md")):
                continue
            path = os.path.join(directory, file_name)
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    if text in line:
                        found.append("%s:%d" % (os.path.relpath(path, root), n))
    return found


def report(messages_path, metadata_path, doc_root, status, sentinel, out=sys.stdout, err=sys.stderr):
    with open(metadata_path, encoding="utf-8") as f:
        metadata = json.load(f)
    ids = members(metadata)
    root = metadata.get("workspace_root") or os.path.commonpath([d for _, d, _ in ids.values()])
    with open(messages_path, encoding="utf-8") as f:
        found = diagnostics(f, ids)
    names = [name for name, _, _ in ids.values()]
    if not names:
        print("ERROR: cargo metadata listed no workspace members: the member query is broken, not the tree.", file=err)
        return 1
    by_crate = {}
    for crate, level, rendered, located, code in found:
        by_crate.setdefault(crate, []).append((level, rendered, located, code))
    for crate in sorted(by_crate):
        for level, rendered, located, code in by_crate[crate]:
            print("%s: %s" % (crate, rendered.replace("\n", "\n%s  " % (" " * len(crate)))), file=err)
            if located:
                continue
            print("%s  rustdoc gives no file or line for this %s." % (" " * len(crate), level), file=err)
            if not (code or "").startswith("rustdoc::"):
                continue
            lib = next((src for name, _, src in ids.values() if name == crate), None)
            quoted = quoted_line(rendered)
            if lib and quoted:
                holding = lines_holding(os.path.dirname(lib), quoted, root)
                if holding:
                    print("%s  The line rustdoc quotes stands at: %s" % (" " * len(crate), ", ".join(holding)), file=err)
            places = two_place_links(os.path.dirname(lib), root) if lib else []
            if not places:
                print("%s  No module of %s is documented both on its mod line and in its own file with an explicit link." % (" " * len(crate), crate), file=err)
                continue
            print("%s  It comes from the docs of a module written in two places (its mod line and its own file),"
                  " read where the mod line stands; a link there whose label already names its target is the one."
                  " Links in such docs, those whose label the mod line's file names first:" % (" " * len(crate)), file=err)
            for named, place, link, module in places:
                print("%s    %s: %s (module %s)%s" % (" " * len(crate), place, link, module,
                                                     "" if named else ", label not named there"), file=err)
    missing = []
    for name in names + ([sentinel] if sentinel else []):
        if name in by_crate:
            continue
        page = os.path.join(doc_root, name.replace("-", "_"), "index.html")
        if not os.path.isfile(page):
            missing.append((name, page))
    for name, page in missing:
        print("ERROR: no rendered docs for workspace member '%s' (%s)" % (name, page), file=err)
    if by_crate:
        count = sum(len(v) for v in by_crate.values())
        print("ERROR: rustdoc reported %d diagnostic(s), fatal under -D warnings, in %d crate(s): %s."
              % (count, len(by_crate), ", ".join(sorted(by_crate))), file=err)
        print("       An unresolved link renders as literal text on docs.rs. Qualify it with a"
              " `crate::`-absolute path, or drop the link and keep the backticks if the target"
              " is not reachable from a docs build; a link whose label already resolves needs no target.", file=err)
    elif status != 0:
        print("ERROR: cargo doc exited %d and reported no diagnostic; read its output above." % status, file=err)
    if missing and not by_crate:
        print("ERROR: rustdoc exited %d but %d of %d workspace members have no rendered page."
              " The invocation documented less than the workspace." % (status, len(missing), len(names) + (1 if sentinel else 0)), file=err)
    if by_crate or missing or status != 0:
        return 1
    print("OK: %d workspace members documented, no link warnings." % len(names), file=out)
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) not in (4, 5):
        sys.exit("usage: doc_links.py MESSAGES METADATA DOC_ROOT STATUS [SENTINEL]")
    sys.exit(report(args[0], args[1], args[2], int(args[3]), args[4] if len(args) == 5 else ""))
