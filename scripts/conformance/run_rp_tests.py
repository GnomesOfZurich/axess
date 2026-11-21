#!/usr/bin/env python3
"""Cases for the results section run_rp.py writes.

The page's results section is what the runner renders from results.json,
the provenance paragraph included, so a fresh run rewrites the statement of
which run and which tree the verdicts come from. Standard library only:

    python3 -I scripts/conformance/run_rp_tests.py
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True

import run_rp  # noqa: E402

START, END = "<!-- results:start -->", "<!-- results:end -->"


def results():
    with open(os.path.join(HERE, "results.json")) as f:
        return json.load(f)


def section(text):
    return text.split(START, 1)[1].split(END, 1)[0]


class Section(unittest.TestCase):
    def test_the_page_holds_what_the_runner_writes_from_the_results(self):
        with open(os.path.join(ROOT, "docs", "factors", "conformance.md")) as f:
            page = f.read()
        self.assertEqual(section(page), "\n" + run_rp.render_markdown(results()) + "\n")

    def test_the_provenance_opens_the_section(self):
        rendered = run_rp.render_markdown(results())
        first = rendered.split("\n", 1)[0]
        self.assertTrue(first.startswith("**The verdicts below are from a run of 2026-10-30, against "
                                         "the tree that became axess 0.14.0.**"), first)

    def test_a_fresh_run_leaves_no_statement_of_the_earlier_one(self):
        fresh = copy.deepcopy(results())
        for plan in fresh["plans"]:
            plan["date"] = "2027-01-02 03:04"
            plan["against"] = "axess 0.21.0 at commit 0123456789ab"
            if plan.get("signing_key"):
                plan["signing_key"] = "a P-256 key (ES256)"
        rendered = run_rp.render_markdown(fresh)
        self.assertTrue(rendered.startswith("**The verdicts below are from a run of 2027-01-02, against "
                                            "axess 0.21.0 at commit 0123456789ab.**"), rendered[:200])
        for stale in ("2026-10-30", "0.14.0", "RSA"):
            self.assertNotIn(stale, rendered)
        self.assertIn("The client assertions were signed with a P-256 key (ES256).", rendered)

    def test_plans_of_more_than_one_run_say_so_and_name_each(self):
        mixed = copy.deepcopy(results())
        mixed["plans"][0]["date"] = "2027-01-02 03:04"
        mixed["plans"][0]["against"] = "axess 0.21.0 at commit 0123456789ab"
        rendered = run_rp.render_markdown(mixed)
        self.assertTrue(rendered.startswith("**The verdicts below come from more than one run"), rendered[:200])
        self.assertIn("Run 2027-01-02 03:04 (UTC), against axess 0.21.0 at commit 0123456789ab.", rendered)
        self.assertIn("Run 2026-10-30 21:01 (UTC), against the tree that became axess 0.14.0.", rendered)


class Tree(unittest.TestCase):
    def test_the_tree_is_the_manifests_version_and_the_commit(self):
        with tempfile.TemporaryDirectory() as root:
            def git(*args):
                subprocess.run(["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.org"]
                               + list(args), check=True, capture_output=True)
            git("init", "-q")
            with open(os.path.join(root, "Cargo.toml"), "w") as f:
                f.write('[workspace]\nmembers = []\n\n[workspace.package]\nversion = "9.8.7"\n')
            git("add", "Cargo.toml")
            git("commit", "-q", "-m", "one")
            head = subprocess.run(["git", "-C", root, "rev-parse", "--short=12", "HEAD"],
                                  check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(run_rp.tree_of(root), "axess 9.8.7 at commit %s" % head)
            with open(os.path.join(root, "Cargo.toml"), "a") as f:
                f.write("# changed\n")
            self.assertEqual(run_rp.tree_of(root),
                             "axess 9.8.7 at commit %s, with changes not committed" % head)


if __name__ == "__main__":
    unittest.main(verbosity=2)
