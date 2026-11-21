"""Crafted cases for scripts/lib/semver_inventory.py, run by
scripts/check-semver-tests.sh.

The report texts follow cargo-semver-checks 0.51.0 as its source writes
them: the block header, `Description:`, the `ref:` and `impl:` lines and
`Failed in:` from print_report and print_triggered_lint in
src/check_release.rs; the status lines (`Checking`, `Checked`, `Summary`,
`Warning`) right-aligned to twelve columns by shell_print in src/config.rs;
each place from the lint's `per_result_error_template` in src/lints/*.ron
(function_missing, inherent_method_missing, enum_variant_missing,
trait_method_added, partial_ord_enum_struct_variant_fields_reordered, and
the template forms of the other lints), all read at the v0.51.0 tag of the
tool's repository. Run with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import semver_inventory as I

# (a place as a lint's template writes it, the item it names)
ITEMS = [
    ("function axess_core::session::rotate_id, previously in file /w/axess-core/src/session.rs:42", "axess_core::session::rotate_id"),
    ("SessionStore::load, previously in file /w/axess-core/src/store.rs:7", "SessionStore::load"),
    ("variant AuthError::Expired, previously in file /w/src/e.rs:3", "AuthError::Expired"),
    ("trait method axess_core::store::SessionRegistry::rotate in file /w/src/r.rs:9", "axess_core::store::SessionRegistry::rotate"),
    ("trait method <axess_core::store::SessionRegistry>::rotate in file src/r.rs:9", "axess_core::store::SessionRegistry::rotate"),
    ("struct Session in /w/src/s.rs:1", "Session"),
    ("struct axess_core::Session became enum in file src/s.rs:1", "axess_core::Session"),
    ("enum Kind in src/k.rs:4", "Kind"),
    ("feature rsa in the package's Cargo.toml", "rsa"),
    ("feature client-assertion-rsa in the package's Cargo.toml", "client-assertion-rsa"),
    ("feature jwt now enables rsa", "jwt"),
    ("macro axess_routes in src/m.rs:2", "axess_routes"),
    ("field Config.max_age in file src/c.rs:5", "Config.max_age"),
    ("field secret of variant Credential::Client in src/c.rs:5", "Credential::Client"),
    ("variant Kind:Old in src/k.rs:4", "Kind:Old"),
    ("Event::Login.at moved from position 1 to 2, in src/e.rs:8", "Event::Login.at"),
    ("axess_core::Layer::new now takes 2 instead of 1 parameters, in file src/l.rs:3", "axess_core::Layer::new"),
    ("SessionKey::LEN, previously at src/k.rs:2", "SessionKey::LEN"),
    ("struct", None),
    ("in file src/x.rs:1", None),
]

# (a backtick span on the page, an item, named)
NAMES = [
    ("axess_core::session::rotate_id", "axess_core::session::rotate_id", True),
    ("session::rotate_id", "axess_core::session::rotate_id", True),
    ("rotate_id", "axess_core::session::rotate_id", False),
    ("axess::session::rotate_id()", "axess_core::session::rotate_id", True),
    ("SessionStore::load(&key)", "SessionStore::load", True),
    ("SessionStore<S>::load", "SessionStore::load", True),
    ("Store::load", "SessionStore::load", False),
    ("axess::Session", "Session", True),
    ("Session", "Session", True),
    ("Sessions", "Session", False),
    ("Config::max_age", "Config.max_age", True),
    ("config.max_age", "Config.max_age", False),
    ("Kind::Old", "Kind:Old", True),
    ("Login::at", "Event::Login.at", True),
    ("client-assertion-rsa", "client-assertion-rsa", True),
]

HEAD = "    Checking axess-core v0.19.0 -> v0.20.0 (minor change)\n     Checked [   0.100s] 200 checks: 199 pass, 1 fail, 0 warn, 54 skip\n"
BLOCK = ("\n--- failure function_missing: pub fn removed or renamed ---\n\nDescription:\nA publicly-visible function cannot be imported by its prior path.\n"
         "        ref: https://doc.rust-lang.org/cargo/reference/semver.html#item-remove\n"
         "       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.51.0/src/lints/function_missing.ron\n\n"
         "Failed in:\n  function axess_core::session::rotate_id, previously in file /w/axess-core/src/session.rs:42\n")
SUMMARY = "\n     Summary semver requires new major version: 1 major and 0 minor checks failed\n"
# (name, report, the breaks' items, or the start of the refusal)
REPORTS = [
    ("one failure", HEAD + BLOCK + SUMMARY, ["axess_core::session::rotate_id"]),
    ("colours", "\x1b[1m\x1b[32m" + HEAD + "\x1b[0m" + BLOCK.replace("Failed in:", "\x1b[1mFailed in:\x1b[0m") + SUMMARY,
     ["axess_core::session::rotate_id"]),
    ("clean", "    Checking axess-core v0.19.0 -> v0.20.0 (minor change)\n     Checked [   0.100s] 200 checks: 200 pass, 54 skip\n     Summary no semver update required\n", []),
    ("two crates", HEAD + BLOCK + SUMMARY + HEAD.replace("axess-core", "axess") + BLOCK.replace("rotate_id", "renew") + SUMMARY,
     ["axess_core::session::rotate_id", "axess_core::session::renew"]),
    ("a block with no place", HEAD + BLOCK.split("Failed in:")[0] + "Failed in:\n" + SUMMARY, "line 4: failure function_missing of axess-core: no place"),
    ("a block with no Failed in", HEAD + BLOCK.replace("Failed in:", "Found in:") + SUMMARY, "line 4: failure function_missing of axess-core: no place"),
    ("a header in another form", HEAD + BLOCK.replace("--- failure function_missing:", "--- failure: function_missing") + SUMMARY,
     "line 4: a block header this does not read"),
    ("fewer blocks than the summary counts", HEAD + BLOCK + SUMMARY.replace("1 major", "2 major"), "axess-core: 1 failure blocks, and its Summary counts 2"),
    ("a block and no summary", HEAD + BLOCK, "axess-core has blocks and no Summary line"),
    ("no checking line", BLOCK + SUMMARY, "line 2: a failure block before any Checking line"),
    ("empty", "", "the report holds no Checking line"),
    ("a place that names no item", HEAD + BLOCK.replace("function axess_core::session::rotate_id, previously in file", "in file") + SUMMARY,
     "line 12: a place of function_missing that names no item"),
]


def main():
    failures = []
    for place, want in ITEMS:
        got = I.item_of(place)
        if got != want:
            failures.append("item of %r: %r, wanted %r" % (place, got, want))
    for span, item, want in NAMES:
        got = I.named(item, I.spans("`%s`" % span))
        if got != want:
            failures.append("span `%s` names %s: %r, wanted %r" % (span, item, got, want))
    fenced = "```rust\n// was `axess_core::session::rotate_id`\nSession::rotate();\n```\n"
    if I.named("axess_core::session::rotate_id", I.spans(fenced)):
        failures.append("a name inside a fenced code block counted")
    for name, report, want in REPORTS:
        try:
            got = [b[4] for b in I.parse(report)]
        except I.Unread as error:
            got = str(error)
        if isinstance(want, str):
            ok = isinstance(got, str) and got.startswith(want)
        else:
            ok = got == want
        if not ok:
            failures.append("report %s: %r, wanted %r" % (name, got, want))
    for failure in failures:
        print("FAIL: semver_inventory: " + failure, file=sys.stderr)
    total = len(ITEMS) + len(NAMES) + 1 + len(REPORTS)
    print("semver_inventory tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
