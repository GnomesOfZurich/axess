#!/usr/bin/env bash
# axess: what docs.rs builds for each published crate, feature by feature.
#
# docs.rs builds a crate with the features its `[package.metadata.docs.rs]`
# names, on a machine this project does not control. `all-features = true`
# is the short form, and it builds every feature there is, one that needs a
# tool or a system library the docs.rs image may not hold included:
# `sqlite-unbundled` generates its bindings with libclang and links the
# system's SQLite, so with it on, a missing libclang there is a release
# whose documentation does not build. A crate with such a feature names its
# features one by one and leaves that one out.
#
# A list written by hand goes stale without a word: a feature added to
# `[features]` and not to the list builds everywhere but on docs.rs, and its
# items show up there as if they did not exist. So for every published crate
# of the workspace this check holds:
#
#   - `all-features = true` only while the crate has no feature in EXCLUDED;
#   - otherwise a `features` list, with the default features left on, in
#     which every feature of the crate (the named ones, and the one cargo
#     makes of an optional dependency no feature names with `dep:`) is
#     either listed or in EXCLUDED, never both, and nothing else is listed:
#     a name docs.rs is given that the crate does not define fails its build.
#   - every name in EXCLUDED is a feature of its crate.
#
# EXCLUDED is short and each entry says why.
#
# The same list is written by hand in a second place, and goes stale the
# same way: the feature table a reader finds on the crate's front page.
# axess-core's named a `full` feature the crate does not define and spelled
# `accept-client-id` with underscores, and the README and AGENTS.md tables
# named `full`, `admin`, `request_id` and `trace_id`, none of them a feature;
# a reader who copies such a name gets a build error from cargo. So this
# check also holds every feature table to the manifest of the crate it
# documents, in both directions: each row starts with features of that crate
# and nothing else, and every feature of the crate but `default` has a row.
# The tables are those under a "Feature flags" heading in
#
#   - the crate-level documentation of a published crate's `src/lib.rs`,
#     which documents that crate;
#   - `README.md`, which documents the facade, `axess`;
#   - `AGENTS.md`, under each sub-heading that starts with a crate's name.
#
# A first cell holds one feature in backticks, or several separated by `/`.
#
# And a feature is named in running text, where a table check does not look:
# the request-id middleware's documentation wrote `accept_client_id` eleven
# times for `accept-client-id`. So the check also reads
#
#   - every comment line of a member's Rust sources (`//`, `///`, `//!`) and
#     every page of the book under `docs/`, for a backticked name that stands
#     directly beside the word "feature" or "features" (`the `x` feature`,
#     `feature `x``);
#   - every `feature = "x"` in the code of a member's Rust sources, which is
#     how a `cfg`, a `cfg_attr`, a `cfg!` and a `doc(cfg(..))` name one.
#
# A name in a published crate's sources is a feature of that crate, or of a
# workspace crate named on the same line. An unpublished member (an example)
# is a consumer, and a book page belongs to no crate: there the name is a
# feature of some crate of the workspace. NOT_OURS lists, with the reason,
# the few names that are written precisely because they are not features
# here: a dependency's feature, a feature a release removed, a feature the
# text says does not exist.
#
# A run of comment lines and a paragraph of a page are each read as one
# text, so a name at the end of a line with the word on the next is found.
#
# Left out by rule, because they cannot be told from other text: a name that
# is not directly beside the word (`the `x` and `y` features` reads `y`
# only), a name in a comment that trails code on the same line, a name
# inside a fenced block of a book page, and a `feature = \"x\"` written
# inside a string literal.
#
# Usage: ./scripts/check-docsrs-features.sh [--root DIR]
#   --root DIR  read the workspace under DIR (used by the crafted cases).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${1:-}" = "--root" ]; then
  ROOT="${2:?--root needs a directory}"
fi

exec python3 -I -B - "$ROOT" <<'PY'
import glob
import os
import re
import sys

try:
    import tomllib
except ImportError:
    sys.exit("ERROR: check-docsrs-features needs Python 3.11 or later (tomllib).")

# crate -> feature -> why docs.rs does not build it.
EXCLUDED = {
    "axess-core": {
        "sqlite-unbundled": "needs libclang and the system SQLite header at build time; "
                            "`sqlite` documents the same stores",
    },
    "axess": {
        "sqlite-unbundled": "forwards to axess-core's, which needs libclang and the "
                            "system SQLite header at build time",
    },
}

# file or crate -> name -> why the text names something that is no feature
# of the workspace.
NOT_OURS = {
    "axess-core": {
        "bundled": "a feature of libsqlite3-sys, named by the test that pins it",
        "zeroize": "a feature of aes-gcm, sha1 and sha2, named by the tests that pin it",
    },
    "axess-factors": {
        "danger-user-presence-only-security-keys": "a feature of webauthn-rs, named to say it is off",
        "use_pem": "a feature of jsonwebtoken, named by the test that works without it",
    },
    "axess-strings": {
        "sqlx": "named to say the crate deliberately has none",
    },
    "axess-example-workload-identity": {
        "wif-buildkite": "named to say there is no per-issuer feature",
    },
    "docs": {
        "wif-gitlab": "named to say there is no per-issuer feature",
        "mysql-rsa": "a feature of sqlx, named by the backends chapter and a migration page",
        "testing-oauth": "removed in 0.19.0; the migration page names it",
        "moka-cache": "removed in 0.15.0; the migration page names it",
        "trace-id": "renamed `trace-context` in 0.20.0; the migration page names it",
    },
}

root = sys.argv[1]
problems = []


def load(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def features_of(manifest):
    """Every feature cargo sees: the named ones, and one for each optional
    dependency that no feature names with `dep:`."""
    named = manifest.get("features", {})
    taken = {item[4:] for items in named.values() for item in items if item.startswith("dep:")}
    tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables += [target.get("dependencies", {}), target.get("build-dependencies", {})]
    implicit = {
        name
        for table in tables
        for name, spec in table.items()
        if isinstance(spec, dict) and spec.get("optional") and name not in taken
    }
    return set(named) | implicit


def check(crate, manifest):
    excluded = EXCLUDED.get(crate, {})
    features = features_of(manifest)
    for name in sorted(set(excluded) - features):
        problems.append(f"{crate}: EXCLUDED names `{name}`, which is not a feature of the crate")
    docs = manifest.get("package", {}).get("metadata", {}).get("docs", {}).get("rs")
    if docs is None:
        problems.append(f"{crate}: no [package.metadata.docs.rs]")
        return
    if docs.get("all-features"):
        for name in sorted(set(excluded) & features):
            problems.append(
                f"{crate}: `all-features = true` makes docs.rs build `{name}` "
                f"({excluded[name]}); list the features one by one without it"
            )
        return
    if docs.get("no-default-features"):
        problems.append(f"{crate}: docs.rs is told to drop the default features")
    listed = docs.get("features")
    if not isinstance(listed, list):
        problems.append(f"{crate}: [package.metadata.docs.rs] has neither `all-features = true` nor a `features` list")
        return
    listed = set(listed)
    wanted = features - {"default"}
    for name in sorted(wanted - listed - set(excluded)):
        problems.append(
            f"{crate}: the feature `{name}` is in neither the docs.rs `features` list nor EXCLUDED, "
            f"so docs.rs would leave it out without a word"
        )
    for name in sorted(listed & set(excluded)):
        problems.append(f"{crate}: `{name}` is in the docs.rs `features` list and in EXCLUDED ({excluded[name]})")
    for name in sorted(listed - features):
        problems.append(f"{crate}: the docs.rs `features` list names `{name}`, which is not a feature of the crate")


HEADING = re.compile(r"(#{1,6})\s+(.*?)\s*$")
FENCE = re.compile(r"\s*(```|~~~)")
SEPARATOR = re.compile(r"[|:\- ]+")
# What the README's feature tables document.
FACADE = "axess"
tables_checked = 0


def sections(lines, wanted):
    """The lines under each heading `wanted(level, text)` accepts, up to the
    next heading of the same or a higher level, as `(text, lines)`. A `#`
    inside a fenced block is code, not a heading."""
    found, current, level, fenced = [], None, 0, False
    for line in lines:
        if FENCE.match(line):
            fenced = not fenced
        heading = None if fenced else HEADING.match(line)
        if heading and current is not None and len(heading.group(1)) <= level:
            current = None
        if heading and current is None and wanted(len(heading.group(1)), heading.group(2)):
            level = len(heading.group(1))
            current = []
            found.append((heading.group(2), current))
        elif current is not None:
            current.append(line)
    return found


def feature_flags(level, text):
    return text.lower() == "feature flags"


def table_rows(lines):
    """The data rows of the Markdown tables in `lines`: every table row but
    the separator and the header a separator follows."""
    rows = [line.strip() for line in lines]
    data = []
    for index, row in enumerate(rows):
        if not row.startswith("|") or SEPARATOR.fullmatch(row):
            continue
        following = rows[index + 1] if index + 1 < len(rows) else ""
        if following.startswith("|") and SEPARATOR.fullmatch(following):
            continue
        data.append(row)
    return data


def check_table(where, crate, features, lines):
    """Hold the feature tables in `lines` to `features`, the features of
    `crate`, in both directions."""
    global tables_checked
    rows = table_rows(lines)
    if not rows:
        problems.append(f"{where}: a \"Feature flags\" section with no table row for {crate}")
        return
    tables_checked += 1
    named = set()
    for row in rows:
        cell = row.strip("|").split("|")[0].strip()
        names = re.findall(r"`([^`]*)`", cell)
        if not names or re.sub(r"`[^`]*`", "", cell).replace("/", "").strip():
            problems.append(
                f"{where}: a row of the feature table does not start with feature names "
                f"in backticks: {row[:80]}"
            )
            continue
        named |= set(names)
    for name in sorted(named - features):
        problems.append(f"{where}: the feature table names `{name}`, which is not a feature of {crate}")
    for name in sorted(features - named - {"default"}):
        problems.append(f"{where}: the feature `{name}` of {crate} has no row in the feature table")


def crate_root_docs(directory, manifest):
    """The crate-level documentation of the crate's library, as Markdown
    lines; empty when there is no library source to read."""
    path = os.path.join(directory, manifest.get("lib", {}).get("path", "src/lib.rs"))
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as handle:
        inner = [line for line in handle.read().splitlines() if line.startswith("//!")]
    return [line[4:] if line.startswith("//! ") else line[3:] for line in inner]


PROSE_FEATURE = re.compile(
    r"\bfeatures?\s+`([a-z0-9][a-z0-9_-]*)`|`([a-z0-9][a-z0-9_-]*)`\s+features?\b"
)
CODE_FEATURE = re.compile(r"\bfeature\s*=\s*\"([^\"\\]*)\"")
names_checked = 0


def prose_names(run):
    """The feature names a run of prose lines writes beside the word, as
    `(line number, name, line text)`. The lines are read as one text, so a
    name at the end of one line with the word on the next is found."""
    starts, text = [], ""
    for number, line in run:
        starts.append((len(text), number, line))
        text += line + " "
    found = []
    for match in PROSE_FEATURE.finditer(text):
        group = 1 if match.group(1) else 2
        at = match.start(group)
        _, number, line = [start for start in starts if start[0] <= at][-1]
        found.append((number, match.group(group), line))
    return found


def check_sources(crate, directory, own, everyone, is_published):
    """Hold the feature names in the Rust sources under `directory`: the
    ones a comment writes beside the word, and the ones a cfg names."""
    global names_checked
    allowed = NOT_OURS.get(crate, {})
    for base, folders, files in os.walk(directory):
        folders[:] = sorted(f for f in folders if f not in ("target", ".git"))
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(base, name)
            shown = os.path.relpath(path, root)
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines()
            run = []
            # A line past the end closes the last run of comment lines.
            for number, line in enumerate(lines + [""], 1):
                text = line.strip()
                if text.startswith("//"):
                    run.append((number, text.lstrip("/!").strip()))
                    continue
                for at, feature, said in prose_names(run):
                    names_checked += 1
                    named_crates = [f for c, f in everyone.items() if c in said]
                    known = own if is_published else set().union(*everyone.values())
                    if feature in known or feature in allowed:
                        continue
                    if any(feature in features for features in named_crates):
                        continue
                    problems.append(
                        f"{shown}:{at}: the comment names the feature `{feature}`, "
                        f"which is not a feature of {crate}"
                    )
                run = []
                for feature in CODE_FEATURE.findall(line):
                    names_checked += 1
                    if feature not in own:
                        problems.append(
                            f"{shown}:{number}: `feature = \"{feature}\"` names no feature of {crate}"
                        )


def check_book(everyone):
    """Hold the feature names the book's pages write beside the word to the
    features of the workspace. A fenced block is code, not prose."""
    global names_checked
    known = set().union(*everyone.values()) if everyone else set()
    allowed = NOT_OURS.get("docs", {})
    pattern = os.path.join(root, "docs", "**", "*.md")
    for path in sorted(glob.glob(pattern, recursive=True)):
        shown = os.path.relpath(path, root)
        if shown.startswith(os.path.join("docs", "book") + os.sep):
            continue
        fenced = False
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
        run = []
        for number, line in enumerate(lines + [""], 1):
            if FENCE.match(line):
                fenced = not fenced
            if line.strip() and not fenced and not FENCE.match(line):
                run.append((number, line.strip()))
                continue
            # A blank line, a fence or the end closes the paragraph.
            for at, feature, _ in prose_names(run):
                names_checked += 1
                if feature not in known and feature not in allowed:
                    problems.append(
                        f"{shown}:{at}: the page names the feature `{feature}`, "
                        f"which is not a feature of any crate of the workspace"
                    )
            run = []


def read_lines(name):
    path = os.path.join(root, name)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return handle.read().splitlines()


try:
    members = load(os.path.join(root, "Cargo.toml"))["workspace"]["members"]
except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
    sys.exit(f"ERROR: no workspace members read from {root}/Cargo.toml: {error}")

seen = set()
published = {}
everyone = {}
directories = {}
for pattern in members:
    for directory in sorted(glob.glob(os.path.join(root, pattern))):
        path = os.path.join(directory, "Cargo.toml")
        if not os.path.isfile(path):
            continue
        manifest = load(path)
        package = manifest.get("package", {})
        crate = package.get("name", directory)
        everyone[crate] = features_of(manifest)
        directories[crate] = directory
        if package.get("publish") is False:
            continue
        seen.add(crate)
        published[crate] = features_of(manifest)
        check(crate, manifest)
        for _, lines in sections(crate_root_docs(directory, manifest), feature_flags):
            check_table(f"{crate}: src/lib.rs", "the crate", published[crate], lines)

for crate in sorted(set(EXCLUDED) - seen):
    problems.append(f"EXCLUDED names the crate `{crate}`, which is not a published member of the workspace")
if not seen:
    sys.exit(f"ERROR: no published crate found under {root}: the selection is broken, not the tree.")

for crate in sorted(everyone):
    check_sources(crate, directories[crate], everyone[crate], everyone, crate in published)
check_book(everyone)

for _, lines in sections(read_lines("README.md"), feature_flags):
    if FACADE in published:
        check_table("README.md", FACADE, published[FACADE], lines)
    else:
        problems.append(
            f"README.md has a \"Feature flags\" section, which documents `{FACADE}`, "
            f"and `{FACADE}` is not a published member of the workspace"
        )
for _, lines in sections(read_lines("AGENTS.md"), feature_flags):
    # Each sub-heading that starts with a crate's name documents that crate;
    # the others (combinations, advice) are not feature tables.
    for heading, body in sections(lines, lambda level, text: text.split(" ")[0] in published):
        crate = heading.split(" ")[0]
        check_table(f"AGENTS.md: {crate}", crate, published[crate], body)

if problems:
    for line in problems:
        print("ERROR: " + line, file=sys.stderr)
    print(f"{len(problems)} feature list problem(s).", file=sys.stderr)
    sys.exit(1)
explicit = sorted(crate for crate in seen if crate in EXCLUDED)
print(
    f"OK: {len(seen)} published crates; docs.rs builds every feature of each but the "
    f"{sum(len(v) for v in EXCLUDED.values())} named in EXCLUDED ({', '.join(explicit)}); "
    f"{tables_checked} documented feature table(s) name exactly the features of their crates; "
    f"{names_checked} feature name(s) in comments, cfg attributes and book pages are features."
)
PY
