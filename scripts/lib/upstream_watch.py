"""Has an upstream crate moved to the release that fixes an accepted advisory?

Run by scripts/watch-advisory-fixes.sh, which has the reasons. Each WATCH
names a crate axess depends on (the dependent), a crate it pins below a
fixed release (the dependency) and that release. The question is answered
from crates.io: the newest stable release of the dependent, and its
requirement on the dependency. The watch is a hit when that requirement
admits the fixed release or a later one, or when the dependency is gone;
it is still waiting while everything the requirement admits is older. A
watch may also name features the fixed release no longer has: a
requirement that asks for one cannot be met by that release, whatever its
range admits, so it is still waiting.

A requirement is read as cargo reads it: comparators joined by commas, each
a caret (`^0.9.6`, or bare `0.9.6`), a tilde, an exact `=`, a wildcard or
an inequality, on a release or a pre-release. Each is a half-open range of
releases and the requirement is their intersection; it reaches the fixed
release when the range holds that release or a later one. A form this
does not read is refused by name, never guessed.

Run with `python3 -I`.
"""

import http.client
import json
import os
import re
import sys
import urllib.request

API = "https://crates.io/api/v1"
AGENT = "axess-upstream-watch (https://github.com/GnomesOfZurich/axess)"

# name: (advisory, dependent, dependency, fixed release, features of the
# dependency the fixed release no longer has, what the fix lets axess do)
WATCHES = {
    "jsonwebtoken-rsa": (
        "RUSTSEC-2023-0071", "jsonwebtoken", "rsa", "0.10.0", (),
        "RS256 under `jwt-rust-crypto` signs through the patched rsa",
    ),
    "openidconnect-rsa": (
        "RUSTSEC-2023-0071", "openidconnect", "rsa", "0.10.0", (),
        "an `oauth` build no longer carries rsa 0.9",
    ),
    "crypto-glue-rsa": (
        "RUSTSEC-2023-0071", "crypto-glue", "rsa", "0.10.0", ("sha2",),
        "a `fido2` build moves from the rsa 0.10 pre-release to the release",
    ),
    # jsonwebtoken holds crypto-bigint 0.5 through two curves, so the
    # advisory's ignore goes when both watches are hits, not at the first.
    "jsonwebtoken-p256": (
        "RUSTSEC-2026-0387", "jsonwebtoken", "p256", "0.14.0", (),
        "p256 0.14 is on crypto-bigint 0.7, patched from 0.7.6; crypto-bigint 0.5 leaves the tree "
        "when `jsonwebtoken-p384` is a hit too",
    ),
    "jsonwebtoken-p384": (
        "RUSTSEC-2026-0387", "jsonwebtoken", "p384", "0.14.0", (),
        "p384 0.14 is on crypto-bigint 0.7, patched from 0.7.6; crypto-bigint 0.5 leaves the tree "
        "when `jsonwebtoken-p256` is a hit too",
    ),
    "sqlx-sqlite-libsqlite3-sys": (
        "RUSTSEC-2026-0459", "sqlx-sqlite", "libsqlite3-sys", "0.39.0", (),
        "the `sqlite` feature bundles SQLite 3.54.0 or later",
    ),
}


class Refused(Exception):
    """A broken answer or a requirement that cannot be read: a red run."""


def version(text):
    """`X.Y.Z` as a tuple; a missing part is zero, a pre-release is refused."""
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not m:
        raise Refused(f"cannot read version '{text}'")
    return tuple(int(part or 0) for part in m.groups())


def _bump(parts, index):
    """`parts` with the number at `index` raised by one and the rest zeroed."""
    return tuple(parts[:index]) + (parts[index] + 1,) + (0,) * (2 - index)


def comparator_range(comparator):
    """The releases a comparator admits, as a half-open range `(low, high)`
    of release versions; `high` None is no end, and `low == high` admits no
    release. The second value says whether the comparator names a
    pre-release.

    A watch asks about a fixed release, so only releases are counted. A
    comparator on a pre-release (`0.10.0-rc.18`) is read as cargo reads it
    for releases: the release `0.10.0` comes after all of its pre-releases,
    so `^0.10.0-rc.18`, `>=0.10.0-rc.18` and `>0.10.0-rc.18` admit it,
    while `=0.10.0-rc.18`, `<=0.10.0-rc.18` and `<0.10.0-rc.18` admit no
    release of 0.10.0 at all.
    """
    m = re.fullmatch(
        r"(\^|~|>=|<=|>|<|=)?\s*(\d+|[*xX])(?:\.(\d+|[*xX]))?(?:\.(\d+|[*xX]))?(-[0-9A-Za-z.-]+)?",
        comparator,
    )
    if not m:
        raise Refused(f"cannot read requirement part '{comparator}'")
    op = m.group(1) or "^"
    pre = m.group(5) is not None
    given = [g for g in m.groups()[1:4] if g is not None]
    wild = next((i for i, g in enumerate(given) if g in "*xX"), None)
    if wild is not None:
        if op != "^" or pre or any(g not in "*xX" for g in given[wild:]):
            raise Refused(f"cannot read requirement part '{comparator}'")
        if wild == 0:
            return ((0, 0, 0), None), False
        low = tuple(int(g) for g in given[:wild]) + (0,) * (3 - wild)
        return (low, _bump(low, wild - 1)), False
    if pre and len(given) < 3:
        raise Refused(f"cannot read requirement part '{comparator}'")
    low = tuple(int(g) for g in given) + (0,) * (3 - len(given))
    # The release just after everything the comparator's version names:
    # `0.10` names every 0.10.z, `0.10.3` names itself.
    after = _bump(low, len(given) - 1)
    if op == "^":
        # The first number that is not zero is the one a caret holds still;
        # a requirement of all zeros holds the last one it names.
        hold = next((i for i in range(len(given)) if low[i] != 0), len(given) - 1)
        return (low, _bump(low, hold)), pre
    if op == "~":
        return (low, _bump(low, min(len(given), 2) - 1)), pre
    if op == "=":
        return ((low, low) if pre else (low, after)), pre
    if op == ">=":
        return (low, None), pre
    if op == ">":
        return ((low if pre else after), None), pre
    if op == "<":
        return ((0, 0, 0), low), pre
    return ((0, 0, 0), (low if pre else after)), pre  # <=


def reaches(requirement, fixed):
    """Whether `requirement` admits the release `fixed` or a later release."""
    low, high, names_pre = (0, 0, 0), None, False
    for comparator in requirement.split(","):
        (part_low, part_high), pre = comparator_range(comparator.strip())
        names_pre = names_pre or pre
        low = max(low, part_low)
        if part_high is not None and (high is None or part_high < high):
            high = part_high
    if high is not None and high <= low and not names_pre:
        raise Refused(f"requirement '{requirement}' admits no version")
    return high is None or high > max(low, version(fixed))


def answer(path, answers):
    """The JSON object crates.io gives for `path`, or the one recorded under
    `answers`. A body cut short (an `http.client` error, which is not an
    `OSError`) and a body that is JSON but no object are no answer either."""
    try:
        if answers:
            with open(os.path.join(answers, path + ".json"), encoding="utf-8") as f:
                body = json.load(f)
        else:
            request = urllib.request.Request(f"{API}/{path}", headers={"User-Agent": AGENT})
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.load(response)
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise Refused(f"no answer for {path}: {error}") from error
    if not isinstance(body, dict):
        raise Refused(f"no answer for {path}: the body is not a JSON object")
    return body


def judge(name, answers):
    """(hit, summary) for the watch `name`."""
    advisory, dependent, dependency, fixed, gone, gain = WATCHES[name]
    crate = answer(f"crates/{dependent}", answers).get("crate")
    newest = crate.get("max_stable_version") if isinstance(crate, dict) else None
    if not newest or not isinstance(newest, str):
        raise Refused(f"no stable {dependent} version in the answer")
    dependencies = answer(f"crates/{dependent}/{newest}/dependencies", answers).get("dependencies")
    if not dependencies or not isinstance(dependencies, list):
        # A crate with no dependency at all is a broken answer here, not a
        # dependency dropped: every dependent watched has several.
        raise Refused(f"empty dependency list in the answer for {dependent} {newest}")
    if not all(isinstance(d, dict) for d in dependencies):
        raise Refused(f"a dependency of {dependent} {newest} in the answer is not a JSON object")
    needs = [d for d in dependencies if d.get("crate_id") == dependency and d.get("kind") == "normal"]
    if not all(isinstance(d.get("req"), str) for d in needs):
        raise Refused(f"a {dependency} dependency of {dependent} {newest} in the answer has no requirement")
    if not all(isinstance(d.get("features") or [], list) for d in needs):
        raise Refused(f"a {dependency} dependency of {dependent} {newest} in the answer has features that are no list")
    requirements = sorted({d["req"] for d in needs})
    if not requirements:
        return True, f"{advisory}: {dependent} {newest} no longer depends on {dependency}."
    stuck = [r for r in requirements if not reaches(r, fixed)]
    said = " and ".join(f"`{r}`" for r in requirements)
    summary = f"{advisory}: {dependent} {newest} requires {dependency} {said}"
    if stuck:
        return False, f"{summary}, which stays below {fixed}."
    asked = sorted({f for d in needs for f in d.get("features") or [] if f in gone})
    if asked:
        features = " and ".join(f"`{f}`" for f in asked)
        return False, f"{summary} with the feature {features}, which {dependency} {fixed} does not have."
    return True, f"{summary}, which admits {fixed}: {gain}."


def write(lines, output):
    """`lines` to stdout, and to `output` (a file the caller names, or
    $GITHUB_OUTPUT under GitHub Actions) as step outputs."""
    print("\n".join(lines))
    output = output if output is not None else os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def main(argv):
    output = None
    if len(argv) >= 2 and argv[-2] == "--output":
        output = argv[-1]
        argv = argv[:-2]
    answers = None
    if len(argv) == 3 and argv[1] == "--answers":
        answers = argv[2]
        argv = argv[:1]
    if argv == ["--all"]:
        # Every watch, one after another: a hit is reported whatever another
        # watch answers, and a watch that could not read fails the run after
        # the hits are written. That holds for a failure nothing here
        # foresaw as well: whatever one watch raises is that watch's
        # refusal, named with its kind, and the others are still judged.
        hits, refused = [], 0
        for name in WATCHES:
            try:
                hit, summary = judge(name, answers)
            except Refused as why:
                print(f"watch-advisory-fixes: {name}: {why}", file=sys.stderr)
                refused += 1
                continue
            except Exception as why:
                print(f"watch-advisory-fixes: {name}: could not be judged ({type(why).__name__}: {why})", file=sys.stderr)
                refused += 1
                continue
            print(f"{name}: {'hit' if hit else 'waiting'}: {summary}")
            if hit:
                hits.append({"watch": name, "summary": summary})
        write(["hits=" + json.dumps(hits, separators=(",", ":"))], output)
        return 1 if refused else 0
    if len(argv) != 1 or argv[0] not in WATCHES:
        print(f"usage: watch-advisory-fixes.sh {'|'.join(WATCHES)}|--all [--answers DIR] [--output FILE]", file=sys.stderr)
        return 2
    try:
        hit, summary = judge(argv[0], answers)
    except Refused as refused:
        print(f"watch-advisory-fixes: {refused}", file=sys.stderr)
        return 1
    write([f"hit={'true' if hit else 'false'}", f"summary={summary}"], output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
