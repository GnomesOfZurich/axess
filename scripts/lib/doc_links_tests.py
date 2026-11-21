"""Crafted cases for scripts/lib/doc_links.py, run by
scripts/check-doc-links-tests.sh with `python3 -I -B`.

Each case writes a workspace under a temporary root (its crates' sources,
cargo's metadata, the JSON messages a `cargo doc` run printed and the pages
it rendered), runs the report over them and asserts its status and what it
printed: every diagnostic of every crate is reported with its crate, a
diagnostic with no location names the module docs it can come from, and a
run that documented less than the workspace, or failed with nothing said,
does not pass.
"""

import io
import json
import os
import shutil
import sys
import tempfile

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import doc_links

ROOT = tempfile.mkdtemp(prefix="axess-doc-links.")
passed = 0
failed = 0


def package(name, kind="lib"):
    d = os.path.join(ROOT, name)
    return {"id": "path+file://%s#%s@0.1.0" % (d, name), "name": name,
            "manifest_path": os.path.join(d, "Cargo.toml"),
            "targets": [{"kind": [kind], "name": name.replace("-", "_"), "src_path": os.path.join(d, "src", "lib.rs")}]}


def message(pkg, text, level="error", file=None, code="rustdoc::broken_intra_doc_links"):
    spans = [{"file_name": file, "line_start": 3}] if file else []
    rendered = "%s: %s\n" % (level, text) + (" --> %s:3:5\n" % file if file else "  |\n")
    return json.dumps({"reason": "compiler-message", "package_id": pkg["id"],
                       "message": {"message": text, "level": level, "rendered": rendered,
                                   "code": {"code": code} if code else None, "spans": spans}})


def case(name, want, fragments, crates, messages, status=0, pages=None, files=None, sentinel="", unwanted=()):
    global passed, failed
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(ROOT)
    for path, text in (files or {}).items():
        full = os.path.join(ROOT, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)
    meta = os.path.join(ROOT, "metadata.json")
    with open(meta, "w", encoding="utf-8") as f:
        json.dump({"packages": crates, "workspace_root": ROOT}, f)
    msgs = os.path.join(ROOT, "messages.json")
    with open(msgs, "w", encoding="utf-8") as f:
        f.write("\n".join(['{"reason":"compiler-artifact","package_id":"x"}'] + messages) + "\n")
    doc = os.path.join(ROOT, "doc")
    for crate in (pages if pages is not None else [c["name"] for c in crates]):
        os.makedirs(os.path.join(doc, crate.replace("-", "_")), exist_ok=True)
        open(os.path.join(doc, crate.replace("-", "_"), "index.html"), "w").close()
    out, err = io.StringIO(), io.StringIO()
    got = doc_links.report(msgs, meta, doc, status, sentinel, out, err)
    text = out.getvalue() + err.getvalue()
    missing = [f for f in fragments if f not in text]
    present = [u for u in unwanted if u in text]
    if got == want and not missing and not present:
        passed += 1
    else:
        failed += 1
        print("FAIL: %s: wanted %d with %s%s, got %d:\n    %s" % (
            name, want, missing or fragments, " and without %s" % present if present else "", got,
            text.replace("\n", "\n    ")), file=sys.stderr)


A, B, C = package("axess-a"), package("axess-b"), package("axess-c")

case("a clean run passes", 0, ["OK: 3 workspace members documented, no link warnings."], [A, B, C], [])
case("an error in each of two crates is reported with each crate", 1,
     ["axess-a: error: unresolved link to `X`", "axess-c: error: unresolved link to `Y`",
      "rustdoc reported 2 diagnostic(s), fatal under -D warnings, in 2 crate(s): axess-a, axess-c."],
     [A, B, C], [message(A, "unresolved link to `X`", file="axess-a/src/lib.rs"),
                 message(C, "unresolved link to `Y`", file="axess-c/src/lib.rs")], status=101, pages=["axess-b"])
case("every error of one crate is reported", 1,
     ["axess-a: error: unresolved link to `X`", "axess-a: error: unresolved link to `Z`", "2 diagnostic(s)"],
     [A], [message(A, "unresolved link to `X`", file="axess-a/src/lib.rs"),
           message(A, "unresolved link to `Z`", file="axess-a/src/x.rs")], status=101, pages=[])
case("a warning is reported as one", 1, ["axess-b: warning: unclosed HTML tag", "1 diagnostic(s)"],
     [A, B], [message(B, "unclosed HTML tag", level="warning", file="axess-b/src/lib.rs", code="rustdoc::invalid_html_tags")])
case("the closing summaries are not diagnostics", 0, ["OK: 1 workspace members"],
     [A], [message(A, "aborting due to 2 previous errors", code=None),
           message(A, "3 warnings emitted", level="warning", code=None)])
case("a failed run with nothing said fails", 1, ["cargo doc exited 101 and reported no diagnostic"], [A], [], status=101)
case("a member with no page and no error fails", 1,
     ["no rendered docs for workspace member 'axess-b'", "1 of 2 workspace members have no rendered page"],
     [A, B], [], pages=["axess-a"])
case("a crate whose docs failed is not also missing", 1, ["axess-a: error"], [A],
     [message(A, "unresolved link to `X`", file="axess-a/src/lib.rs")], status=101, pages=[],
     unwanted=["no rendered docs"])
case("a sentinel crate outside the workspace fails", 1, ["no rendered docs for workspace member 'axess-nowhere'"],
     [A], [], sentinel="axess-nowhere")
case("no member is no pass", 1, ["cargo metadata listed no workspace members"], [], [])

TWO_PLACE = {
    "axess-a/src/lib.rs": "//! Crate.\n\npub use otp::TotpConfig;\n\n/// The OTP settings, [`TotpConfig`](otp::TotpConfig).\n#[cfg(feature = \"x\")]\npub mod otp;\n\n/// Once only, [`Other`](other::Other).\npub mod other;\n\n/// Nested.\npub mod nested;\n\n/// From elsewhere, [`Moved`](moved::Moved).\n#[path = \"elsewhere.rs\"]\npub mod moved;\n",
    "axess-a/src/otp.rs": "//! Codes, see [`HotpConfig`](crate::otp::HotpConfig) and [docs](https://example.org/x).\npub struct TotpConfig;\npub struct HotpConfig;\n",
    "axess-a/src/other.rs": "pub struct Other;\n",
    "axess-a/src/nested/mod.rs": "//! Inner, [`Deep`](self::deep::Deep).\npub mod deep;\n",
    "axess-a/src/nested/deep.rs": "pub struct Deep;\n",
    "axess-a/src/elsewhere.rs": "//! Moved here.\npub struct Moved;\n",
}
REDUNDANT = message(A, "redundant explicit link target", code="rustdoc::redundant_explicit_links")
case("an error with no location names the module docs it can come from", 1,
     ["rustdoc gives no file or line for this error.",
      "axess-a/src/lib.rs:5: [`TotpConfig`](otp::TotpConfig) (module otp)",
      "axess-a/src/otp.rs:1: [`HotpConfig`](crate::otp::HotpConfig) (module otp), label not named there",
      "axess-a/src/nested/mod.rs:1: [`Deep`](self::deep::Deep) (module nested)",
      "axess-a/src/lib.rs:15: [`Moved`](moved::Moved) (module moved)"],
     [A], [REDUNDANT], status=101, pages=[], files=TWO_PLACE,
     unwanted=["(other::Other)", "https://example.org"])
case("the links whose label the parent names come first", 1,
     ["(module otp)\n" + " " * 11 + "axess-a/src/lib.rs:15"], [A], [REDUNDANT], status=101, pages=[], files=TWO_PLACE)
case("a module documented in one place only is no candidate", 1,
     ["No module of axess-a is documented both on its mod line and in its own file"],
     [A], [REDUNDANT], status=101, pages=[],
     files={"axess-a/src/lib.rs": "/// Once, [`Other`](other::Other).\npub mod other;\n",
            "axess-a/src/other.rs": "pub struct Other;\n"})
UNRESOLVED = json.dumps({"reason": "compiler-message", "package_id": A["id"], "message": {
    "message": "unresolved link to `crate::otp::HotpConfig`", "level": "error", "code": {"code": "rustdoc::broken_intra_doc_links"},
    "spans": [], "rendered": "error: unresolved link to `crate::otp::HotpConfig`\n  |\n  = note: the link appears in this line:\n\n          Codes, see [`HotpConfig`](crate::otp::HotpConfig) and [docs](https://example.org/x).\n"}})
case("an unresolved link with no location is found by the line rustdoc quotes", 1,
     ["rustdoc gives no file or line for this error.", "The line rustdoc quotes stands at: axess-a/src/otp.rs:1",
      "axess-a/src/lib.rs:5: [`TotpConfig`](otp::TotpConfig) (module otp)"],
     [A], [UNRESOLVED], status=101, pages=[], files=TWO_PLACE)
SPANNED = json.loads(UNRESOLVED)
SPANNED["message"]["spans"] = [{"file_name": "axess-a/src/lib.rs", "line_start": 1}]
case("a span with no file and line shown is no location", 1,
     ["rustdoc gives no file or line for this error.", "The line rustdoc quotes stands at: axess-a/src/otp.rs:1"],
     [A], [json.dumps(SPANNED)], status=101, pages=[], files=TWO_PLACE)
case("an error with no location that is not rustdoc's is reported without candidates", 1,
     ["axess-a: error: something else", "rustdoc gives no file or line for this error."],
     [A], [message(A, "something else", code="E0000")], status=101, pages=[], files=TWO_PLACE,
     unwanted=["(module otp)"])

shutil.rmtree(ROOT, ignore_errors=True)
print("doc-links crafted cases: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
