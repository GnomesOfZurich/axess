#!/usr/bin/env python3
"""Merge the cargo-mutants shards of one sweep and refuse a blind one.

The weekly sweep runs as N shards (`cargo mutants --shard k/N`), each of
which writes its own `outcomes.json`. This script reads all of them, writes
one per-file kill-rate table, and fails when the sweep did not see what it
was asked to see. A sweep that measured nothing used to pass with a warning
for months; here that is an error, by name:

  * a shard directory or its `outcomes.json` is missing or unreadable;
  * a shard's run did not finish (`end_time` is null, which is what an
    interrupted or cancelled cargo-mutants leaves behind);
  * a shard recorded fewer outcomes than the mutants it was assigned;
  * the shards together tested a different number of mutants than the
    plan listed (`--expected-total`), or none at all on a full sweep.

Exit status: 0 when the sweep is whole; 1 when it is blind in any of the
ways above; 2 when it is whole but `--fail-on-missed` is set and a mutant
survived or timed out (the pull-request gate).

Usage:
  mutants-summary.py --shards N --expected-total T [--fail-on-missed] DIR
  mutants-summary.py --self-test

DIR holds one sub-directory per shard, `mutants-shard-<k>` for k in 0..N-1,
each containing the `outcomes.json` of that shard (directly, or under a
`mutants.out/` directory). The table goes to `$GITHUB_STEP_SUMMARY` when it
is set, and to stdout always. A merged `outcomes-merged.json` is written to
DIR for the uploaded artifact.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile

# Outcome names as cargo-mutants 27.x writes them in `summary`.
CAUGHT = "CaughtMutant"
MISSED = "MissedMutant"
TIMEOUT = "Timeout"
UNVIABLE = "Unviable"
BUCKETS = {CAUGHT: "caught", MISSED: "missed", TIMEOUT: "timeout", UNVIABLE: "unviable"}


class Blind(Exception):
    """The sweep did not measure what it was asked to measure."""


def find_outcomes(shard_dir: pathlib.Path) -> pathlib.Path:
    for candidate in (shard_dir / "outcomes.json", shard_dir / "mutants.out" / "outcomes.json"):
        if candidate.is_file():
            return candidate
    raise Blind(f"{shard_dir.name}: no outcomes.json (the shard did not run, or its artifact was not uploaded)")


def mutant_outcomes(data: dict) -> list[dict]:
    """Every outcome except the baseline, which is a string scenario."""
    return [
        o
        for o in data.get("outcomes", [])
        if isinstance(o.get("scenario"), dict) and "Mutant" in o["scenario"]
    ]


def read_shard(shard_dir: pathlib.Path) -> list[dict]:
    path = find_outcomes(shard_dir)
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as err:
        raise Blind(f"{shard_dir.name}: outcomes.json is unreadable: {err}") from err
    if not isinstance(data, dict):
        raise Blind(f"{shard_dir.name}: outcomes.json is not an object")
    if data.get("end_time") is None:
        raise Blind(f"{shard_dir.name}: the run did not finish (end_time is null): cancelled or timed out")
    outcomes = mutant_outcomes(data)
    assigned = data.get("total_mutants")
    if not isinstance(assigned, int):
        raise Blind(f"{shard_dir.name}: outcomes.json carries no total_mutants")
    if len(outcomes) != assigned:
        raise Blind(f"{shard_dir.name}: {len(outcomes)} outcomes for {assigned} assigned mutants")
    return outcomes


def merge(root: pathlib.Path, shards: int, expected_total: int | None) -> list[dict]:
    if shards < 1:
        raise Blind(f"--shards must be at least 1, got {shards}")
    merged: list[dict] = []
    errors: list[str] = []
    for k in range(shards):
        try:
            merged.extend(read_shard(root / f"mutants-shard-{k}"))
        except Blind as err:
            errors.append(str(err))
    if errors:
        raise Blind("; ".join(errors))
    if expected_total is None and not merged:
        raise Blind("the shards tested no mutants and no plan said that was expected")
    if expected_total is not None and len(merged) != expected_total:
        raise Blind(f"the shards tested {len(merged)} mutants; the plan listed {expected_total}")
    return merged


def per_file(outcomes: list[dict]) -> dict[str, dict[str, int]]:
    table: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: {"total": 0, "caught": 0, "missed": 0, "timeout": 0, "unviable": 0}
    )
    for o in outcomes:
        row = table[o["scenario"]["Mutant"].get("file") or "unknown"]
        row["total"] += 1
        bucket = BUCKETS.get(o.get("summary", ""))
        if bucket:
            row[bucket] += 1
    return table


def kill_rate(row: dict[str, int]) -> float:
    # Unviable mutants do not compile, so they are not a coverage gap and
    # stay out of the denominator. A timeout stays in: it was not caught.
    denom = row["total"] - row["unviable"]
    return (row["caught"] / denom) * 100.0 if denom else 100.0


def render(outcomes: list[dict], shards: int) -> str:
    table = per_file(outcomes)
    totals = collections.Counter()
    for row in table.values():
        totals.update(row)
    lines = [
        "## cargo-mutants kill rate",
        "",
        f"{len(outcomes)} mutants over {shards} shard(s): {totals['caught']} caught, "
        f"{totals['missed']} missed, {totals['timeout']} timeout, {totals['unviable']} unviable.",
        "",
        "| Kill rate | File | caught | missed | timeout | unviable | total |",
        "|----------:|------|-------:|-------:|--------:|---------:|------:|",
    ]
    for src, row in sorted(table.items(), key=lambda item: (kill_rate(item[1]), item[0])):
        lines.append(
            f"| {kill_rate(row):5.1f}% | `{src}` | {row['caught']} | {row['missed']} | "
            f"{row['timeout']} | {row['unviable']} | {row['total']} |"
        )
    survivors = [o for o in outcomes if o.get("summary") in (MISSED, TIMEOUT)]
    if survivors:
        lines += ["", "### Survivors", ""]
        for o in sorted(survivors, key=lambda o: o["scenario"]["Mutant"]["name"]):
            lines.append(f"- {o['summary']}: `{o['scenario']['Mutant']['name']}`")
    return "\n".join(lines) + "\n"


def run(root: pathlib.Path, shards: int, expected_total: int | None, fail_on_missed: bool) -> int:
    try:
        outcomes = merge(root, shards, expected_total)
    except Blind as err:
        print(f"::error::mutation sweep is blind: {err}")
        return 1
    report = render(outcomes, shards)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report)
    (root / "outcomes-merged.json").write_text(json.dumps({"outcomes": outcomes}, indent=1))
    survivors = sum(1 for o in outcomes if o.get("summary") in (MISSED, TIMEOUT))
    if fail_on_missed and survivors:
        print(f"::error::{survivors} mutant(s) survived or timed out; see the Survivors list.")
        return 2
    return 0


def self_test() -> int:
    """Prove each refusal fires, on fixtures shaped like cargo-mutants output."""

    def mutant(summary: str, name: str = "a/src/x.rs:1:1: replace f with ()") -> dict:
        return {"scenario": {"Mutant": {"name": name, "file": "a/src/x.rs"}}, "summary": summary}

    def shard(root: pathlib.Path, k: int, outcomes: list[dict], end_time: str | None = "t", total=None):
        d = root / f"mutants-shard-{k}"
        d.mkdir(parents=True)
        body = {
            "total_mutants": len(outcomes) if total is None else total,
            "end_time": end_time,
            "outcomes": [{"scenario": "Baseline", "summary": "Success"}] + outcomes,
        }
        (d / "outcomes.json").write_text(json.dumps(body))

    cases = []

    def case(name, build, shards, expected, fail_on_missed, want):
        cases.append((name, build, shards, expected, fail_on_missed, want))

    case("whole sweep", lambda r: (shard(r, 0, [mutant(CAUGHT)]), shard(r, 1, [mutant(UNVIABLE)])), 2, 2, False, 0)
    case("missing shard", lambda r: shard(r, 0, [mutant(CAUGHT)]), 2, None, False, 1)
    case("interrupted shard", lambda r: shard(r, 0, [mutant(CAUGHT)], end_time=None), 1, None, False, 1)
    case("short shard", lambda r: shard(r, 0, [mutant(CAUGHT)], total=3), 1, None, False, 1)
    case("total drift", lambda r: shard(r, 0, [mutant(CAUGHT)]), 1, 5, False, 1)
    case("empty full sweep", lambda r: shard(r, 0, []), 1, 1, False, 1)
    case("survivor, report only", lambda r: shard(r, 0, [mutant(MISSED)]), 1, 1, False, 0)
    case("survivor, gated", lambda r: shard(r, 0, [mutant(MISSED)]), 1, 1, True, 2)
    case("timeout, gated", lambda r: shard(r, 0, [mutant(TIMEOUT)]), 1, 1, True, 2)
    case("empty diff", lambda r: shard(r, 0, []), 1, 0, True, 0)

    failed = 0
    saved = os.environ.pop("GITHUB_STEP_SUMMARY", None)
    try:
        for name, build, shards, expected, fail_on_missed, want in cases:
            # The fixture runs print their reports and `::error::` lines to
            # stdout; on GitHub those lines would become annotations on a
            # passing step, so the self-test keeps them to itself.
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                root = pathlib.Path(tmp)
                build(root)
                got = run(root, shards, expected, fail_on_missed)
            verdict = "ok" if got == want else "FAILED"
            failed += got != want
            print(f"self-test {verdict}: {name}: exit {got}, want {want}", file=sys.stderr)
    finally:
        if saved is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = saved
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", type=pathlib.Path)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--expected-total", type=int)
    parser.add_argument("--fail-on-missed", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.root is None or args.shards is None:
        parser.error("DIR and --shards are required")
    return run(args.root, args.shards, args.expected_total, args.fail_on_missed)


if __name__ == "__main__":
    sys.exit(main())
