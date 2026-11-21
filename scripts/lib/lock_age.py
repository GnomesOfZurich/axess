"""The age of the registry entries a change adds to a lockfile, for
scripts/check-lock-age.sh.

.cargo/config.toml holds the resolver to versions published at least
`registry.global-min-publish-age` ago. The resolver is not the only way a
version enters a lockfile: a locked version is never re-judged, a lockfile can
be written by hand or by a bot, and a cargo older than 1.100 ignores the key.
So this reads the lockfiles themselves. A young version is the one a
compromised publisher account ships before anyone has read it; seven days is
the time the ecosystem's advisories usually take to name one.

What counts as added. Every lockfile git tracks (any path whose last part is
`Cargo.lock`, the fuzz crate's included) is read from the working tree, so
an uncommitted change is judged too. An entry is a [[package]] table whose
`source` is crates.io (`registry+https://github.com/rust-lang/crates.io-index`
or `sparse+https://index.crates.io/`); it is added when its name and version
are in the file and not in the same file at the base (a file new since the
base adds every entry). A path or git entry has no publish time and is not
read. An added entry from any other registry is refused: its publish time is
not on the index this reads.

The publish time. The sparse index of crates.io, the source cargo's own
publish-age rule reads, serves one file per crate at
https://index.crates.io/<prefix>/<name> (prefix `1`, `2`, `3/<first letter>`,
or the first two and the next two letters, lowercased), one JSON object per
line and per version. The field is `pubtime`, a string in RFC 3339 form at
UTC with second precision, as in `"pubtime":"2026-07-18T23:05:13Z"` (read
from https://index.crates.io/se/rd/serde: every one of its 316 lines held
it). An entry is refused, never passed, when the index cannot be reached,
answers with an error, lists no such crate or version, lists the version
twice, holds a line that is not a JSON object, or gives no `pubtime` or one
that is not such a time.

The exception. An added entry younger than the age is admitted only when a
commit between the base and HEAD that adds that very entry (its name and
version are in that commit's lockfile and in none of its parents') ends its
message with the trailer

    Cooldown-Exempt: <advisory id> <crate>

naming that crate, the id a RUSTSEC-YYYY-NNNN, GHSA-xxxx-xxxx-xxxx or
CVE-YYYY-NNNN id. git reads trailers from the last paragraph of a message
only, so an id in the subject or in prose admits nothing, and a trailer
admits the one crate it names, in the one commit that carries it: a later
bump of the same crate to another young version needs a trailer of its own.
A commit the history simplification of `git rev-list --full-history` leaves
out only takes an admission away, never adds one.

The age is the one the repository's .cargo/config.toml sets: `N seconds|minutes|hours|days|
weeks`, singular or plural, N above zero. A missing key, "0" (no cooldown)
or a form cargo takes and this does not (months, whose length cargo fixes and
this would have to guess) is refused: the check holds the age the resolver
holds, and with none written there is nothing to hold.

Run with `python3 -I -B lock_age.py --repo DIR --base REF [--index URL|DIR]`,
or `--repo DIR --print-age` to print the age alone; `--config FILE` reads the
age from FILE instead of DIR/.cargo/config.toml (the crafted cases). The index is https://index.crates.io/ unless
another https URL or a local directory laid out like it is named; the crafted
cases use a directory.
"""

import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request

CRATES_IO = {"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}
DEFAULT_INDEX = "https://index.crates.io/"
ADVISORY = r"(?:RUSTSEC-[0-9]{4}-[0-9]{4}|GHSA(?:-[0-9a-z]{4}){3}|CVE-[0-9]{4}-[0-9]{4,})"
TRAILER = re.compile(r"\s*(" + ADVISORY + r")\s+([A-Za-z0-9_-]+)\s*")
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
VERSION = re.compile(r"[0-9A-Za-z.+-]{1,128}")
PUBTIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})")
AGE = re.compile(r"([1-9][0-9]{0,8}) (second|minute|hour|day|week)s?")
UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800}
TIMEOUT_SECONDS = 30


class Refused(Exception):
    """A fact the check cannot establish, which it reports instead of passing."""


def printable(text):
    """Text from git, a file or a server as one line of plain ASCII, so that
    nothing it holds can start a workflow command or move the terminal."""
    return re.sub(r"[^\x20-\x7e]", "?", str(text))


def git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if check and result.returncode != 0:
        raise Refused("git %s failed: %s" % (" ".join(args), printable(result.stderr.decode("utf-8", "replace").strip())))
    return result


# The age.

def parse_age(text):
    """Seconds of a cargo publish-age setting, or Refused."""
    if not isinstance(text, str):
        raise Refused("registry.global-min-publish-age is not a string")
    m = AGE.fullmatch(text)
    if not m:
        raise Refused("registry.global-min-publish-age is %r, which this check does not read: "
                      "write N seconds, minutes, hours, days or weeks, N above zero" % printable(text))
    return int(m.group(1)) * UNIT_SECONDS[m.group(2)]


def read_age(path):
    """(the setting as written, its seconds) from a cargo configuration file."""
    try:
        with open(path, "rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise Refused("%s cannot be read: %s" % (printable(path), printable(error)))
    text = config.get("registry", {}).get("global-min-publish-age") if isinstance(config.get("registry"), dict) else None
    if text is None:
        raise Refused("%s sets no registry.global-min-publish-age, so there is no cooldown to hold" % printable(path))
    return text, parse_age(text)


# Lockfiles.

def entries(text, where):
    """(crates.io entries as a set of (name, version), entries of any other
    registry as a set of (name, version, source)) of a lockfile's text."""
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise Refused("%s is not a lockfile this check reads: %s" % (where, printable(error)))
    packages = lock.get("package", [])
    if not isinstance(packages, list):
        raise Refused("%s is not a lockfile this check reads: `package` is not a list of tables" % where)
    crates_io, other = set(), set()
    for package in packages:
        if not isinstance(package, dict):
            raise Refused("%s is not a lockfile this check reads: a package that is not a table" % where)
        source = package.get("source")
        if source is None or (isinstance(source, str) and (source.startswith("git+") or source.startswith("path+"))):
            continue
        name, version = package.get("name"), package.get("version")
        if not (isinstance(name, str) and NAME.fullmatch(name) and isinstance(version, str) and VERSION.fullmatch(version)):
            raise Refused("%s holds a registry entry whose name or version this check does not read: %s %s"
                          % (where, printable(name), printable(version)))
        if source in CRATES_IO:
            crates_io.add((name, version))
        else:
            other.add((name, version, printable(source)))
    return crates_io, other


def lock_at(repo, rev, path):
    """The text of PATH at REV, or "" when REV has no such file."""
    if git(repo, "cat-file", "-e", "%s:%s" % (rev, path), check=False).returncode != 0:
        return ""
    return git(repo, "show", "%s:%s" % (rev, path)).stdout.decode("utf-8", "replace")


def tracked_locks(repo):
    """The lockfiles git tracks, and the untracked ones it does not ignore,
    so a lockfile not yet added is judged as well."""
    out = git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "--deduplicate",
              "-z").stdout.decode("utf-8", "replace")
    locks = sorted(p for p in out.split("\0") if p == "Cargo.lock" or p.endswith("/Cargo.lock"))
    if not locks:
        raise Refused("git lists no Cargo.lock under %s, tracked or untracked" % printable(repo))
    return locks


# The exception.

def trailer_crates(repo, commit):
    """(crates named by well-formed Cooldown-Exempt trailers of COMMIT, the
    trailer values that are not well formed)."""
    out = git(repo, "log", "-1", "--format=%(trailers:key=Cooldown-Exempt,valueonly,unfold)", commit).stdout
    crates, malformed = set(), []
    for line in out.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        m = TRAILER.fullmatch(line)
        if m:
            crates.add(m.group(2))
        else:
            malformed.append(printable(line.strip()))
    return crates, malformed


def admissions(repo, base, path, notes):
    """The (name, version) entries of PATH that a commit in BASE..HEAD adds
    and names in a Cooldown-Exempt trailer."""
    admitted = set()
    commits = git(repo, "rev-list", "--full-history", "%s..HEAD" % base, "--", path).stdout.decode().split()
    for commit in commits:
        crates, malformed = trailer_crates(repo, commit)
        for value in malformed:
            notes.append("note: %s carries a Cooldown-Exempt trailer that admits nothing (not `<advisory id> <crate>`): %s"
                         % (commit[:12], value))
        if not crates:
            continue
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).stdout.decode().split()[1:]
        before = set()
        for parent in parents:
            before |= entries(lock_at(repo, parent, path), "%s at %s" % (path, parent[:12]))[0]
        after = entries(lock_at(repo, commit, path), "%s at %s" % (path, commit[:12]))[0]
        admitted |= {(name, version) for name, version in after - before if name in crates}
    return admitted


# The index.

def index_path(name):
    """The path of a crate's file in the sparse index."""
    lower = name.lower()
    if len(lower) <= 2:
        return "%d/%s" % (len(lower), lower)
    if len(lower) == 3:
        return "3/%s/%s" % (lower[0], lower)
    return "%s/%s/%s" % (lower[:2], lower[2:4], lower)


def fetch(index, name):
    """The text of a crate's index file, or Refused."""
    if index.startswith("https://"):
        url = index.rstrip("/") + "/" + index_path(name)
        request = urllib.request.Request(url, headers={"User-Agent": "axess scripts/check-lock-age.sh"})
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise Refused("the index lists no crate %s (%s answered 404)" % (name, url))
            raise Refused("the index cannot be read for %s: %s answered %d" % (name, url, error.code))
        except (urllib.error.URLError, OSError, UnicodeDecodeError, ValueError) as error:
            raise Refused("the index cannot be read for %s: %s: %s" % (name, url, printable(error)))
    path = os.path.join(index, *index_path(name).split("/"))
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        raise Refused("the index lists no crate %s (no file %s)" % (name, printable(path)))
    except (OSError, UnicodeDecodeError) as error:
        raise Refused("the index cannot be read for %s: %s" % (name, printable(error)))


def pubtime(text, name, version):
    """The publish time of NAME VERSION in a crate's index file, or Refused."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            raise Refused("the index file of %s is not read: line %d is not a JSON object" % (name, number))
        if record.get("vers") == version:
            found.append(record)
    if not found:
        raise Refused("the index lists no version %s of %s" % (version, name))
    if len(found) > 1:
        raise Refused("the index lists version %s of %s %d times" % (version, name, len(found)))
    when = found[0].get("pubtime")
    if when is None:
        raise Refused("the index gives no publish time (pubtime) for %s %s" % (name, version))
    if not isinstance(when, str) or not PUBTIME.fullmatch(when):
        raise Refused("the publish time the index gives for %s %s is not a time: %s" % (name, version, printable(when)))
    try:
        return datetime.datetime.fromisoformat(when.replace("Z", "+00:00"))
    except ValueError:
        raise Refused("the publish time the index gives for %s %s is not a time: %s" % (name, version, printable(when)))


def publish_times(index, wanted):
    """{(name, version): datetime or Refused} for every wanted entry, one
    request per crate."""
    names = sorted({name for name, _ in wanted})

    def one(name):
        try:
            return name, fetch(index, name)
        except Refused as refusal:
            return name, refusal

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        files = dict(pool.map(one, names))
    times = {}
    for name, version in wanted:
        text = files[name]
        if isinstance(text, Refused):
            times[(name, version)] = text
            continue
        try:
            times[(name, version)] = pubtime(text, name, version)
        except Refused as refusal:
            times[(name, version)] = refusal
    return times


# The verdict.

def judge(repo, config, base, index, now):
    """(lines to print, refused) for every lockfile git lists (tracked, or
    untracked and not ignored) against BASE."""
    setting, age = read_age(config)
    cutoff = now - datetime.timedelta(seconds=age)
    lines, notes, added, others, admitted = [], [], {}, [], {}
    for path in tracked_locks(repo):
        try:
            with open(os.path.join(repo, path), encoding="utf-8") as handle:
                current = handle.read()
        except (OSError, UnicodeDecodeError) as error:
            raise Refused("%s cannot be read: %s" % (path, printable(error)))
        now_crates, now_other = entries(current, path)
        base_crates, base_other = entries(lock_at(repo, base, path), "%s at %s" % (path, base))
        added[path] = sorted(now_crates - base_crates)
        others += [(path, entry) for entry in sorted(now_other - base_other)]
        admitted[path] = admissions(repo, base, path, notes) if added[path] else set()
    times = publish_times(index, {entry for entries_ in added.values() for entry in entries_})
    refused = False
    for path, entry in others:
        lines.append("REFUSED %s: %s %s comes from %s, not crates.io, whose index is the only one this check reads"
                     % (path, entry[0], entry[1], entry[2]))
        refused = True
    count = 0
    for path in sorted(added):
        for name, version in added[path]:
            count += 1
            when = times[(name, version)]
            if isinstance(when, Refused):
                lines.append("REFUSED %s: %s %s: %s" % (path, name, version, when))
                refused = True
            elif when > cutoff:
                stamp = when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if (name, version) in admitted[path]:
                    lines.append("admitted %s: %s %s, published %s, younger than %s; a Cooldown-Exempt trailer of the commit that adds it names %s"
                                 % (path, name, version, stamp, setting, name))
                else:
                    lines.append("REFUSED %s: %s %s, published %s, is younger than %s, and no commit that adds it ends with a trailer "
                                 "`Cooldown-Exempt: <advisory id> %s`" % (path, name, version, stamp, setting, name))
                    refused = True
            else:
                lines.append("ok %s: %s %s" % (path, name, version))
    lines = notes + lines
    if refused:
        lines.append("ERROR: the lockfiles hold entries the cooldown of %s refuses (base %s). Wait until the version is old "
                     "enough, or take it to fix an advisory: see .cargo/config.toml." % (setting, base))
    elif count == 0:
        lines.append("OK: no lockfile gained a crates.io entry since %s." % base)
    else:
        lines.append("OK: %d crates.io entries added since %s, each published at least %s ago or admitted by a "
                     "Cooldown-Exempt trailer." % (count, base, setting))
    return lines, refused


def main(argv):
    usage = "usage: lock_age.py --repo DIR [--config FILE] (--base REF [--index URL|DIR] | --print-age)"
    args, rest = {}, list(argv)
    while rest:
        flag = rest.pop(0)
        if flag == "--print-age":
            args[flag] = True
        elif flag in ("--repo", "--config", "--base", "--index") and rest:
            args[flag] = rest.pop(0)
        else:
            print(usage, file=sys.stderr)
            return 2
    if "--repo" not in args or ("--base" in args) == ("--print-age" in args):
        print(usage, file=sys.stderr)
        return 2
    repo = args["--repo"]
    config = args.get("--config", os.path.join(repo, ".cargo", "config.toml"))
    try:
        if "--print-age" in args:
            setting, seconds = read_age(config)
            print("%s (%d seconds)" % (setting, seconds))
            return 0
        index = args.get("--index", DEFAULT_INDEX)
        if "://" in index and not index.startswith("https://"):
            raise Refused("the index %s is not read: name an https URL or a directory" % printable(index))
        lines, refused = judge(repo, config, args["--base"], index, datetime.datetime.now(datetime.timezone.utc))
    except Refused as refusal:
        print("ERROR: %s" % refusal, file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
