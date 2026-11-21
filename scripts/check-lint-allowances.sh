#!/usr/bin/env bash
# axess: no lint is allowed away.
#
# The repository's rule (AGENTS.md, "No lint suppressions") is that a
# warning is fixed where it fires, never silenced. This refuses, by file
# and line:
#
#   - an `allow` or `expect` attribute in any Rust file, outer or inner, on
#     any lint (rustc, clippy, rustdoc), alone or inside a `cfg_attr`, and
#     the same words with a group after them anywhere inside an attribute,
#     where a procedural macro may turn them into one;
#   - an attribute a macro builds from a metavariable or a `quote!`
#     interpolation, unless it is `#[$name]` in a `macro_rules` arm whose
#     matcher binds `#[$name:meta]` (the caller then writes the whole
#     attribute at the call site, where this reads it);
#   - the same attributes in the Rust code of a doc example, which rustdoc
#     compiles as a test: a Rust code block of a doc comment, of a `doc`
#     attribute or of a file `doc = include_str!(...)` names;
#   - a rustc flag in any cargo configuration git lists, tracked or
#     untracked and not ignored (`.cargo/config.toml`, `.cargo/config`, in
#     any directory), that allows a lint, caps the lint levels or adds a
#     crate attribute;
#   - the same flags set for a build elsewhere: in a variable whose name
#     ends in RUSTFLAGS or RUSTDOCFLAGS, in a workflow's `env:` or an
#     action's input at any level, or in a shell script or a workflow step
#     (an assignment, `export`, `env`, a line `echo` or `printf` writes),
#     and after `--` on a cargo, rustc or rustdoc command line.
#
# Comments, doc comments and string literals are not code: text there that
# only looks like an attribute is not refused (scripts/lib/rust_source.py
# blanks them first), except the code of a doc example, which is. scripts/lib/lint_allowances.py says why each rule
# holds for every input. A lint table set to `allow` or `expect` in a
# manifest is scripts/check-member-lints.sh's to refuse.
#
# scripts/lint-allowance-exemptions.txt may name a file and a lint the
# rule cannot be kept in (generated code, a macro's output this repository
# does not write), each with its reason. An entry exempts that lint in that
# file and nothing else, and an entry that exempts nothing is refused. It
# refuses to report clean when it read no Rust file.
#
# Usage: ./scripts/check-lint-allowances.sh [--root DIR]
#   --root DIR  check the files under DIR, and
#               DIR/scripts/lint-allowance-exemptions.txt, instead of
#               the files git lists in this repository
#               (scripts/check-lint-allowances-tests.sh)

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$AXESS_DIR/scripts/lib"

if [ "${1:-}" = "--root" ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$2"
  files() { find . -type f | sed 's|^\./||' | sort; }
else
  [ $# -eq 0 ] || { echo "usage: $0 [--root DIR]" >&2; exit 2; }
  cd "$AXESS_DIR"
  # Tracked files and untracked ones git does not ignore, so a file not
  # yet added is checked as well.
  files() { git ls-files --cached --others --exclude-standard --deduplicate; }
fi

listed="$(files)"
python3 -I -B -c '
import os, sys

sys.path.insert(0, sys.argv[1])
try:
    import tomllib
except ImportError:
    print("ERROR: python3 has no tomllib (3.11 or newer); the cargo configuration cannot be read.", file=sys.stderr)
    sys.exit(1)
from lint_allowances import (config_findings, doc_findings, findings, read_exemptions,
                             script_flag_findings, workflow_flag_findings)
import shell_scripts
import shell_words
import workflow_yaml as yaml

EXEMPTIONS = "scripts/lint-allowance-exemptions.txt"
exempt, errors = read_exemptions(EXEMPTIONS)
used = set()
refused = []
files = 0
paths = [p for p in sys.stdin.read().split("\n") if p and os.path.isfile(p)]
configs = [p for p in paths if p.endswith((".cargo/config.toml", ".cargo/config"))
           and (p.startswith(".cargo/") or "/.cargo/" in p)]
for path in paths:
    if shell_scripts.is_workflow(path):
        try:
            doc = yaml.read(open(path, encoding="utf-8").read())
        except yaml.Refusal as err:
            errors.append(f"{path}:{err.line}: the YAML cannot be read: {err.message}")
            continue
        for line, flag in workflow_flag_findings(doc, yaml):
            refused.append(f"{path}:{line}: {flag}: a flag that silences lints")
        for run in shell_scripts.run_steps(doc):
            for line, flag in script_flag_findings(run.value, run.line_at, shell_words):
                refused.append(f"{path}:{line}: {flag}: a flag that silences lints")
        continue
    if not path.endswith(".rs"):
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        if shell_scripts.is_script(path, text):
            starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
            line_of = lambda offset, starts=starts: sum(1 for s in starts if s <= offset)
            for line, flag in script_flag_findings(text, line_of, shell_words):
                refused.append(f"{path}:{line}: {flag}: a flag that silences lints")
        continue
    files += 1
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for line, kind, detail in findings(path, text) + doc_findings(path, text):
        if kind == "lint":
            lint = detail[detail.index("(") + 1 : detail.rindex(")")]
            if (path, lint) in exempt:
                used.add((path, lint))
                continue
            refused.append(f"{path}:{line}: {detail}: a lint allowed away; fix what it reports")
        elif kind == "doc":
            refused.append(f"{path}:{line}: {detail}")
        else:
            refused.append(
                f"{path}:{line}: {detail}: an attribute built from a macro argument, which may expand "
                "to an allowance; bind it as #[$name:meta] in the matcher and write #[$name]"
            )
for key, no in sorted(exempt.items(), key=lambda kv: kv[1]):
    if key not in used:
        errors.append(f"{EXEMPTIONS}:{no}: {key[0]} | {key[1]} exempts nothing; remove the entry")
for rel in configs:
    try:
        with open(rel, "rb") as f:
            doc = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as err:
        errors.append(f"{rel}: cannot be read as TOML ({err})")
        continue
    for where, flag in config_findings(rel, doc):
        refused.append(f"{where}: {flag}: a flag that silences lints")
if files == 0:
    print("ERROR: no Rust file read; nothing was checked.", file=sys.stderr)
    sys.exit(1)
for line in errors + refused:
    print(line, file=sys.stderr)
if errors or refused:
    print(
        f"{len(refused)} allowance(s) refused, {len(errors)} error(s) in the exemption file or the "
        "configuration; see the header of scripts/check-lint-allowances.sh.",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"ok: no lint allowance in {files} Rust file(s) and their doc examples, the cargo configuration, the shell scripts or the workflows ({len(used)} exempted)")
' "$LIB" <<<"$listed"
