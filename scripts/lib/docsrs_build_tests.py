"""Crafted cases for scripts/lib/docsrs_build.py, run by
scripts/check-docsrs-build-tests.sh with `python3 -I -B`.

Each case writes cargo's metadata for crafted members, runs the helper over
it and asserts its status and what it printed: one line per published crate
with the feature arguments its docs.rs table asks for,
an unpublished member left out, and a key the gate does not apply, a value
of the wrong type or an argument it cannot hand on refused by name.
"""

import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import docsrs_build

passed = 0
failed = 0


def member(name, table=None, publish=None):
    package = {"name": name, "publish": publish, "metadata": None}
    if table is not None:
        package["metadata"] = {"docs": {"rs": table}}
    return package


def case(name, want, fragments, packages, unwanted=()):
    global passed, failed
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump({"packages": packages}, f)
        path = f.name
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            status = docsrs_build.main(path)
    finally:
        os.unlink(path)
    text = out.getvalue() + err.getvalue()
    missing = [frag for frag in fragments if frag not in text]
    present = [frag for frag in unwanted if frag in text]
    if status == want and not missing and not present:
        passed += 1
        return
    failed += 1
    print("FAIL: %s: wanted exit %d, got %d; missing %r, present %r; printed:\n%s"
          % (name, want, status, missing, present, text), file=sys.stderr)


DOCSRS = ["--cfg", "docsrs"]
case("every feature", 0, ["axess-a|--all-features\n"],
     [member("axess-a", {"all-features": True, "rustdoc-args": DOCSRS})])
case("a list of features", 0, ["axess-a|--features x,y\n"],
     [member("axess-a", {"features": ["x", "y"]})])
case("the default features dropped", 0, ["axess-a|--no-default-features --features x\n"],
     [member("axess-a", {"no-default-features": True, "features": ["x"]})])
case("no table is the default features", 0, ["axess-a|\n"], [member("axess-a")])
case("crates in name order", 0, ["axess-a|\naxess-b|\n"], [member("axess-b"), member("axess-a")])
case("an unpublished member is left out", 0, ["axess-a|\n"],
     [member("axess-a"), member("axess-example", publish=[])], unwanted=["axess-example"])
case("a member published to a named registry is in", 0, ["axess-a|\n"],
     [member("axess-a", publish=["crates-io"])])
case("no published crate", 1, ["names no published crate"], [member("axess-example", publish=[])])
for key in ("rustc-args", "cargo-args", "targets", "default-target", "all_features"):
    case("the key %s is refused" % key, 1, ["axess-a: [package.metadata.docs.rs] key `%s` is not applied" % key],
         [member("axess-a", {key: ["x"]})], unwanted=["axess-a|"])
case("features that are no list", 1, ["axess-a: `features` is not a list of strings"],
     [member("axess-a", {"features": "x"})])
case("all-features that is no boolean", 1, ["axess-a: `all-features` is not true or false"],
     [member("axess-a", {"all-features": "yes"})])
case("another rustdoc argument", 1, ["axess-a: `rustdoc-args` is ['--cfg', 'docsrs', '-Zx']"],
     [member("axess-a", {"rustdoc-args": DOCSRS + ["-Zx"]})], unwanted=["axess-a|"])
case("rustdoc arguments that are no list", 1, ["axess-a: `rustdoc-args` is not a list of strings"],
     [member("axess-a", {"rustdoc-args": "--cfg docsrs"})])
case("a feature with a space", 1, ["axess-a: the feature 'x y' cannot be handed on"],
     [member("axess-a", {"features": ["x y"]})])
case("a feature with the separator", 1, ["cannot be handed on"],
     [member("axess-a", {"features": ["x|y"]})])
case("every crate's refusal is said", 1, ["axess-a: [package.metadata.docs.rs] key `targets`",
                                          "axess-b: `features` is not a list"],
     [member("axess-a", {"targets": []}), member("axess-b", {"features": 3})])

print("docsrs-build crafted cases: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
