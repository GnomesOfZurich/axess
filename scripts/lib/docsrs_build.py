"""The docs.rs configuration of each published crate, as cargo arguments.

Used by scripts/check-docsrs-build.sh, which documents every published crate
of the workspace as docs.rs builds it: with the features its
`[package.metadata.docs.rs]` table names, and `--cfg docsrs` handed to
rustdoc, which docs.rs always hands it.

Run as `python3 -I -B docsrs_build.py METADATA`, METADATA being the output of
`cargo metadata --no-deps --format-version 1`. It prints one line per
published crate (a member whose `publish` is not `false`), in name order,
with two fields separated by `|`: the crate and the feature arguments of its
`cargo doc` (`--all-features`, `--no-default-features`, `--features a,b`,
or nothing for the default features).

The table's keys the gate applies are `features`, `all-features` and
`no-default-features`, and `rustdoc-args` when it is `--cfg docsrs`, which
the gate hands rustdoc in any case (the script writes its RUSTDOCFLAGS out,
so the workflow pin check reads what cargo is given). Any other key
(`rustc-args`, `cargo-args`, `targets`, `default-target`, or a misspelt
one), and any other rustdoc argument, is refused by name with exit status
1, so a build here never differs from docs.rs's in silence: the gate is
taught the key before a crate uses it. So is a value of the wrong type, and
a feature with a space, a tab or a `|` in it, which the line could not
carry.
"""

import json
import sys

APPLIED = {"features", "all-features", "no-default-features", "rustdoc-args"}
# The rustdoc arguments the script hands rustdoc itself.
RUSTDOC_ARGS = ["--cfg", "docsrs"]
UNSAFE = set(" \t\n|")


def published(package):
    """A member cargo would publish: `publish` is absent (any registry) or
    names a registry."""
    return package.get("publish") is None or bool(package.get("publish"))


def plan(package):
    """The feature arguments of one crate, or a list of refusals."""
    name = package["name"]
    table = ((package.get("metadata") or {}).get("docs") or {}).get("rs") or {}
    refusals = [
        "%s: [package.metadata.docs.rs] key `%s` is not applied by this gate; "
        "teach scripts/lib/docsrs_build.py what docs.rs does with it" % (name, key)
        for key in sorted(set(table) - APPLIED)
    ]
    features = table.get("features", [])
    rustdoc = table.get("rustdoc-args", [])
    for key, value in (("features", features), ("rustdoc-args", rustdoc)):
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            refusals.append("%s: `%s` is not a list of strings" % (name, key))
    for key in ("all-features", "no-default-features"):
        if not isinstance(table.get(key, False), bool):
            refusals.append("%s: `%s` is not true or false" % (name, key))
    if refusals:
        return refusals
    if rustdoc and rustdoc != RUSTDOC_ARGS:
        refusals.append("%s: `rustdoc-args` is %r; the gate hands rustdoc %r and nothing else"
                        % (name, rustdoc, RUSTDOC_ARGS))
    for item in features:
        if not item or UNSAFE & set(item):
            refusals.append("%s: the feature %r cannot be handed on as it is" % (name, item))
    if refusals:
        return refusals
    args = []
    if table.get("all-features"):
        args.append("--all-features")
    if table.get("no-default-features"):
        args.append("--no-default-features")
    if features:
        args += ["--features", ",".join(features)]
    return " ".join(args)


def main(path):
    with open(path, encoding="utf-8") as handle:
        packages = json.load(handle).get("packages", [])
    lines, refusals = [], []
    for package in sorted(packages, key=lambda p: p["name"]):
        if not published(package):
            continue
        result = plan(package)
        if isinstance(result, list):
            refusals += result
        else:
            lines.append("%s|%s" % (package["name"], result))
    if refusals:
        for refusal in refusals:
            print("REFUSED: " + refusal, file=sys.stderr)
        return 1
    if not lines:
        print("REFUSED: the metadata names no published crate", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: docsrs_build.py METADATA")
    sys.exit(main(sys.argv[1]))
