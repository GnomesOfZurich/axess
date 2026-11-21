"""The rules of scripts/check-chrono-edges.sh: where chrono may be named.

`text_rule` is the rule over library code: the name `chrono` stands only in
the files of `BOUNDARY`, and there in no public item. `manifest_rule` is the
rule over the manifests and the lock files: the edges of `ADMITTED` and no
other, and no chrono-tz. Both print what they refuse and return the exit
status. The header of the script says why each admitted place is admitted.

The text rule reads code with its comments and literals taken out and its
test code removed (scripts/lib/rust_source.py). It sees a name, not a type.
"""

import json
import re
import sys

from rust_source import declared_for_tests, integration_test, production_lines

# The private conversion beside the upstream crate that hands chrono values.
BOUNDARY = {"axess-factors/src/oauth/provider.rs"}

# crate -> the one edge to chrono it may have: the kind of the dependency
# (None is a normal one), whether it is optional, and the features that may
# name it.
ADMITTED = {
    "axess-factors": {"kind": None, "optional": True, "features": {"oauth"}},
    "axess-clock": {"kind": "dev", "optional": False, "features": set()},
}

NAME = re.compile(r"\bchrono\b")
# The start of a public item: `pub` with no restriction, then what it is.
ITEM = re.compile(
    r"\bpub\s+(?:(?:async|const|unsafe|default)\s+|extern\s+\"\"\s+)*"
    r"(?:fn|struct|enum|union|type|const|static|trait|use|mod|extern)\b"
)
FIELD = re.compile(r"^\s*pub\s+(?:r#)?\w+\s*:")


def library(path):
    """Whether a path is library code of a crate of the workspace."""
    parts = path.split("/")
    if not parts[0].startswith("axess") or "src" not in parts:
        return False
    if integration_test(path) or "benches" in parts:
        return False
    name = parts[-1]
    if name == "tests.rs" or name.endswith("_tests.rs") or "tests" in parts[parts.index("src") :]:
        return False
    return not declared_for_tests(path)


def public_headers(numbered):
    """(line number, header text) for each public item of a file: from its
    `pub` to the `{` or `;` that ends its header, and each public field to
    the end of its line. `numbered` is (line number, code) pairs."""
    text = "\n".join(code for _, code in numbered)
    line_of = [no for no, code in numbered for _ in range(len(code) + 1)]
    for m in ITEM.finditer(text):
        ends = [i for i in (text.find("{", m.end()), text.find(";", m.end())) if i != -1]
        end = min(ends) if ends else len(text)
        yield line_of[min(m.start(), len(line_of) - 1)], text[m.start() : end]
    for no, code in numbered:
        if FIELD.match(code):
            yield no, code


def text_findings(paths):
    """What the text rule refuses in the files of `paths`, one line each."""
    findings = set()
    for path in paths:
        if not library(path):
            continue
        with open(path, encoding="utf-8") as f:
            numbered = production_lines(f.read())
        if path in BOUNDARY:
            for no, header in public_headers(numbered):
                if NAME.search(header):
                    findings.add(f"{path}:{no}: a public item names chrono")
        else:
            for no, code in numbered:
                if NAME.search(code):
                    findings.add(f"{path}:{no}: library code names chrono outside the boundary")
    return sorted(findings)


def text_rule(paths):
    findings = text_findings(paths)
    for line in findings:
        print("REFUSED: " + line, file=sys.stderr)
    if findings:
        print(
            "A reading is an axess_clock::Timestamp, a span a SignedDuration or a std Duration, an end an "
            "Until. Convert a chrono value where the upstream crate hands it, in private code.",
            file=sys.stderr,
        )
        return 1
    print("ok: no public item names chrono, and library code names it only at the boundary")
    return 0


def names_chrono(enables):
    """Whether a feature's list enables the chrono dependency itself."""
    return any(e in ("chrono", "dep:chrono") or e.startswith(("chrono/", "chrono?/")) for e in enables)


def manifest_failures(packages, locks):
    """What the manifest rule refuses. `packages` are the packages of `cargo
    metadata --no-deps`, `locks` the texts of the lock files by path."""
    failures = []
    for package in packages:
        name = package["name"]
        for dep in package["dependencies"]:
            if dep["name"] == "chrono-tz":
                failures.append(f"{name} depends on chrono-tz")
        edges = [d for d in package["dependencies"] if d["name"] == "chrono"]
        admitted = ADMITTED.get(name)
        for dep in edges:
            kind = dep["kind"] or "normal"
            if admitted is None:
                failures.append(f"{name} has a {kind} dependency on chrono")
            elif dep["kind"] != admitted["kind"] or dep["optional"] != admitted["optional"] or dep.get("rename"):
                want = ("an optional " if admitted["optional"] else "a ") + (admitted["kind"] or "normal")
                found = kind + (", optional" if dep["optional"] else "") + (", renamed" if dep.get("rename") else "")
                failures.append(
                    f"{name} may depend on chrono only as {want} dependency under its own name; found: {found}"
                )
        if edges and admitted is not None:
            naming = {feature for feature, enables in package["features"].items() if names_chrono(enables)}
            for feature in sorted(naming - admitted["features"]):
                failures.append(
                    f"{name}: the feature `{feature}` names chrono; only {sorted(admitted['features'])} may"
                )
            if admitted["optional"] and not naming:
                failures.append(
                    f"{name}: no feature names its optional chrono dependency, so cargo makes a feature of its name"
                )
    for path, text in locks.items():
        if '\nname = "chrono-tz"\n' in text:
            failures.append(f"{path} holds chrono-tz")
    return failures


def manifest_rule(workspace_json, fuzz_json, lock_paths):
    """The manifest rule on the two `cargo metadata --no-deps` answers. On
    success it prints the published crates of the workspace, one a line."""
    with open(workspace_json, encoding="utf-8") as f:
        workspace = json.load(f)["packages"]
    with open(fuzz_json, encoding="utf-8") as f:
        fuzz = json.load(f)["packages"]
    locks = {}
    for path in lock_paths:
        with open(path, encoding="utf-8") as f:
            locks[path] = f.read()
    failures = manifest_failures(workspace + fuzz, locks)
    for line in failures:
        print("REFUSED: " + line, file=sys.stderr)
    if failures:
        return 1
    # `publish` is null for a crate that may be published anywhere.
    print("\n".join(sorted(p["name"] for p in workspace if p.get("publish") is None)))
    return 0
