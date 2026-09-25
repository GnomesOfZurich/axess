#!/usr/bin/env bash
# axess: fail when the book names a Rust type that does not exist.
#
# `check-doc-links.sh` catches a broken *intra-doc link* in a doc comment.
# It cannot see the book: `docs/**.md` is prose plus 112 fenced Rust
# blocks, and 108 of those are ```rust,ignore, which nothing compiles.
# So a chapter can confidently document a struct, an enum variant or an
# error that was renamed years ago, or never existed, and every gate stays
# green. That is not hypothetical. One sweep found 59 such names across 20
# of the 44 chapters, including:
#
#   - a 363-line audit-events catalogue specifying `LoginStarted`,
#     `LoginCompleted`, `LoginFailed` and per-event field lists, against a
#     flat `AuthEvent` whose outcome lives in `event_status`;
#   - a FIPS route through a `crypto-aws-lc` feature that does not exist;
#   - `InMemorySessionStore` in the getting-started tutorial, where the
#     type is `MemorySessionStore`, so the first block an adopter copies
#     did not compile.
#
# The check is deliberately crude and therefore cheap: every CamelCase
# identifier the docs write in backticks must appear somewhere in the
# workspace's Rust. It proves nothing about semantics; it catches the one
# failure that matters most, a name a reader cannot find.
#
# Legitimate exceptions live in ALLOW below, with a reason each. Adding a
# name there is a claim that it is not ours to define, so say why.
#
# Usage: ./scripts/check-doc-identifiers.sh
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$@" <<'PY'
import pathlib, re, sys, collections

ROOT = pathlib.Path(".")

# Not ours to define. Each entry is a claim about provenance, not a mute.
# Names this workspace deliberately removed, which the migration guide must
# still write in order to tell an adopter to delete their call. Distinct from
# ALLOW, which is for names that were never ours.
#
# Keep this list short-lived: an entry belongs here for the release that
# removed the name and the one that documents the migration, then goes when
# that migration section is retired. A permanent entry means the gate has
# stopped checking something it should.
#
# Holds bare type names and `Type::member` alike; both branches below
# consult it. Until 0.7.0 only the `Type::member` branch did, so a removed
# *type* had no way through the gate at all and the only recourse was
# ALLOW, which would have been a false claim about provenance.
REMOVED = {
    # Removed in 0.6.0. `docs/production/migrating.md` names it under
    # "0.5.0 to 0.6.0" to say the call has no replacement.
    "ShortString::prefix",
    # Removed in 0.7.0: the runtime policy that checked whether a route had
    # wired an audit context. `docs/production/migrating.md` names it to say
    # the check is the compiler's now, and `docs/production/audit-events.md`
    # names it to say why the SQL detector outlives it.
    "AuditContextPolicy",
}

ALLOW = {
    # std / core
    "RwLock", "HashMap", "AtomicU64", "DashMap",
    # SQL, Redis and HTTP vocabulary that happens to be CamelCase
    "SELECT", "INSERT", "MERGE", "NULL", "DATETIME", "EXPIRE", "SETNX", "PING",
    "HttpOnly", "README",
    # webauthn-rs ceremony and option types
    "CreationChallengeResponse", "RegisterPublicKeyCredential",
    "RequestChallengeResponse", "PublicKeyCredential",
    "AttestationConveyancePreference", "ResidentKeyRequirement",
    # The `iggy` crate's client, named in the analytics-sink recipe.
    "IggyClient",
    # Not ours: the `getrandom` crate, and `cluster`, which is a feature of
    # a redis client rather than of axess.
    "getrandom", "cluster",
    # Features named precisely because axess does NOT ship them: `spire` is
    # on the ROADMAP, and `wif-gitlab` is the per-issuer adapter the
    # federation chapter explains why there is no point building.
    "spire", "wif-gitlab",
    # cedar-policy
    "EntitySet",
    # AWS STS action name, and the Kubernetes API that mints pod tokens
    "AssumeRoleWithWebIdentity", "TokenRequest",
    # Named precisely to say it does NOT exist; the prose depends on it.
    # A chapter that could not write the name a reader is looking for
    # could not tell them it is not there.
    "JwtSvidLayer", "LoginFailed",
    "AttemptRecord", "LockoutRecord", "NewUser",   # identity/store.md
    "TenantStore",                                  # identity/tenancy.md
    "JwtSvidError", "NoCredential",                 # workload-identity/jwt-svid.md
    # The adopter's own types, standing in for a domain axess does not
    # have: the app data in a session, an error a sink or a middleware
    # returns. Named, not declared, because the chapter is showing the
    # shape of the caller's code rather than ours.
    "DraftForm", "UserPreferences", "MyError", "MySinkError",
    # ROADMAP items, named as not-yet-built.
    "SpireWorkloadApiResolver",
    # Named by the migration guide precisely because they were REMOVED.
    # A migration guide that could not name a deleted symbol would be useless.
    "AxessSession", "SqliteStore",
}

# Only tracked files. Two local-only trees would otherwise be read, and both
# hold stale copies of the source: `.mutants-worktree`, which `mutants.sh`
# leaves behind, and `target/package/`, where `cargo package` unpacks every
# release ever built here. Reading either lets a name deleted from the real
# source keep resolving, which is the one thing this gate exists to notice.
#
# This was not hypothetical. The filter used to be a substring test for
# "/target", which never matched the top-level `target/` because a relative
# path has no leading slash. `ShortString::prefix` was removed in 0.6.0 and
# went on resolving locally against `target/package/axess-strings-0.4.0/`
# for a whole session; CI, which checks out clean, caught it. A filesystem
# walk cannot tell a stale copy from the real thing, so ask git instead.
import subprocess


def tracked(pattern):
    """Paths git knows about, which is what a clean checkout will contain."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", pattern],
            capture_output=True, text=True, check=True, cwd=ROOT,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise SystemExit(
            "ERROR: this gate lists its inputs with `git ls-files`, and that "
            "failed. Run it inside a git checkout of the repository; a "
            "filesystem walk was the previous approach and it read stale "
            f"copies under target/ that a clean checkout does not have. ({exc})"
        )
    return [ROOT / p for p in out.split("\0") if p]


RS = tracked("*.rs")
src = "\n".join(p.read_text(errors="ignore") for p in RS)
defined = set(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", src))

# Lower-case names: functions, struct fields and consts. A chapter writes
# `Type::method()` and `Type::field` in the same shape, so one set answers
# both. Fabricated verbs are the half of this problem the CamelCase scan
# never saw: `mint_token`, `revoke_credential`, `last_attempts`,
# `AuthzSession::decide` and `SessionLayer::with_absolute_ttl` all named
# something that was never in the workspace, and all of them are lower-case.
lower_defined = set(re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", src))
lower_defined |= set(
    re.findall(r"^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:\s*[A-Za-z_&<\[]", src, re.M)
)
lower_defined |= set(re.findall(r"\b(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)", src))

# Every feature declared anywhere in the workspace. A chapter that routes an
# adopter through a feature that does not exist sends them to a build error
# with no obvious cause; `crypto-aws-lc` in the security-posture chapter was
# exactly that.
FEATURES = set()
for manifest in tracked("*Cargo.toml"):
    body = re.search(
        r"^\[features\]$(.*?)(?=^\[|\Z)", manifest.read_text(errors="ignore"), re.M | re.S
    )
    if body:
        FEATURES |= set(re.findall(r"^([A-Za-z0-9_-]+)\s*=", body.group(1), re.M))

# Which type owns which member. `Type::method` resolving *somewhere* in the
# workspace is a weak claim: `DeviceStore::revoke` passed the lower-case scan
# because `revoke` is real, on `DelegatedCredentialStore`. The reader is sent
# to a method the type does not have, which is the same dead end as an
# invented name. So attribute members to the type or trait that declares them,
# and let a trait's members flow to its implementors.
OWNS = collections.defaultdict(set)
IMPLS = collections.defaultdict(set)
HEAD = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?"
    r"(?:trait\s+(?P<tname>[A-Z]\w*)"
    r"|impl(?:<[^>]*>)?\s+(?:(?P<tr>[A-Za-z_][\w:]*(?:<[^>]*>)?)\s+for\s+)?"
    r"(?P<ity>(?:\w+::)*[A-Z]\w*))"
)
TYPE_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+([A-Z]\w*)")
DERIVE = re.compile(r"#\[derive\(([^)]*)\)\]")
MEMBER = re.compile(
    r"^\s+(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?"
    r"(?:const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*fn\s+([a-z_]\w*)"
    r"|^\s+(?:pub(?:\([^)]*\))?\s+)?([a-z_]\w*)\s*:\s*[A-Za-z_&<\[(]"
    r"|^\s+(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z_][A-Z0-9_]*)"
)

for f in RS:
    lines = f.read_text(errors="ignore").splitlines()
    i = 0
    derives = set()
    while i < len(lines):
        line = lines[i]
        d = DERIVE.search(line)
        if d:
            derives |= {t.strip().split("::")[-1] for t in d.group(1).split(",") if t.strip()}
            i += 1
            continue
        head, decl = HEAD.match(line), TYPE_DECL.match(line)
        if not (head or decl):
            if line.strip() and not line.lstrip().startswith(("//", "#[")):
                derives = set()
            i += 1
            continue
        if head:
            owner = (head.group("tname") or head.group("ity")).split("::")[-1]
            impl_of = (head.group("tr") or "").split("::")[-1].split("<")[0]
            if impl_of:
                IMPLS[owner].add(impl_of)
        else:
            owner = decl.group(1)
        IMPLS[owner] |= derives
        derives = set()
        # Walk to the body's opening brace, past a multi-line `where`. A `;`
        # first means the item has no body (a bare `struct Foo;`).
        j = i
        while j < len(lines) and "{" not in lines[j]:
            if lines[j].rstrip().endswith(";"):
                break
            j += 1
        if j >= len(lines) or "{" not in lines[j]:
            i += 1
            continue
        depth = lines[j].count("{") - lines[j].count("}")
        j += 1
        while j < len(lines) and depth > 0:
            member = MEMBER.match(lines[j])
            if member:
                name = member.group(1) or member.group(2) or member.group(3)
                if name:
                    OWNS[owner].add(name)
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        i = j

for ty, traits in list(IMPLS.items()):
    for tr in traits:
        OWNS[ty] |= OWNS.get(tr, set())
ENUMERABLE = {t for t in OWNS if OWNS[t]}

# Members that arrive from a derive or from a trait declared outside this
# workspace. Their definitions are not here to read, so they are not judged.
EXTERNAL_MEMBERS = {
    "clone", "fmt", "default", "deserialize", "serialize", "eq", "ne", "hash",
    "cmp", "partial_cmp", "drop", "from", "into", "try_from", "try_into",
    "next", "poll", "poll_ready", "call", "as_ref", "as_mut", "deref",
    "deref_mut", "borrow", "borrow_mut", "to_string", "from_str", "source",
    "to_owned", "extend", "len", "is_empty", "iter", "into_iter", "add",
    "sub", "mul", "div", "index", "zeroize",
}
owner_pat = re.compile(r"`([A-Z]\w*)::([a-z_]\w*)(?:\(\))?`")

# Declared signatures. Every name in `verify_factor(&session, credential)`
# is real, and the argument order is still wrong; the getting-started
# tutorial shipped exactly that and no name-based check could see it. So
# where a fenced block *declares* a function the workspace also declares,
# compare the parameter-name sequences.
FN_HEAD = re.compile(r"\bfn\s+([a-z_]\w*)\s*(?:<[^>]*>)?\s*\(", re.S)
SELF_ARG = re.compile(r"(?:&\s*(?:'\w+\s+)?)?(?:mut\s+)?self\b")
NAMED_ARG = re.compile(r"(?:mut\s+)?([a-z_]\w*)\s*:")


def param_names(arg_text):
    """Parameter names, splitting only at top-level commas so a generic
    or a tuple argument does not split into pieces."""
    depth, parts, cur = 0, [], ""
    for ch in arg_text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    names = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if SELF_ARG.match(part):
            names.append("self")
            continue
        named = NAMED_ARG.match(part)
        # "?" marks an argument this crude parser cannot name, such as an
        # axum extractor pattern. A signature holding one is not compared.
        names.append(named.group(1) if named else "?")
    return names


def declared_signatures(text):
    found = collections.defaultdict(list)
    for m in FN_HEAD.finditer(text):
        open_paren = m.end() - 1
        depth = 0
        close = None
        for k in range(open_paren, len(text)):
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    close = k
                    break
        if close is None:
            continue
        found[m.group(1)].append(param_names(text[open_paren + 1 : close]))
    return found


REAL_SIGS = collections.defaultdict(list)
for f in RS:
    for fn, seqs in declared_signatures(f.read_text(errors="ignore")).items():
        REAL_SIGS[fn] += seqs

# From git for the same reason as the Rust sources above: `docs/book/` is
# generated output that is present locally and absent in a clean checkout,
# and a gate whose input depends on what happens to be on disk reports
# something different in CI than it does here.
docs = [p for p in tracked("docs/*.md") if "docs/book/" not in str(p)]
# A name inside backticks, allowing a trailing path, call or generic:
# `Foo`, `Foo::bar()`, `Foo<T>`. Without the tail, `TestSuite::default()`
# slips past, which is how a fabricated test harness survived a sweep.
pat = re.compile(r"`([A-Z][A-Za-z0-9]*(?:[A-Z][A-Za-z0-9]*)+)(?:::[a-z_]+\(?\)?|<[^`]*>)?`")

# `use axess...::{A, B}` inside a fenced block. More precise than the
# backtick scan and, unlike it, this reaches into code: 108 of the book's
# 112 Rust blocks are ```rust,ignore, so an import that cannot resolve is
# invisible to every other gate. The getting-started tutorial imported
# `InMemorySessionStore` for exactly that reason.
use_pat = re.compile(r"use\s+axess[A-Za-z_]*(?:::[a-z_]+)*::\{?([^;]*)")

# `Type::Variant` in backticks. The backtick pattern above cannot see the
# variant: its optional tail is `::lower_case()` or `<T>`, so a CamelCase
# tail makes the whole reference fail to match and the mention is skipped
# entirely. That is how `MtlsError::MalformedSpiffeId` and
# `MtlsError::TrustDomainMismatch`, neither of which has ever been a
# variant of that enum, survived a sweep that was looking for exactly
# this. An error a reader is told to match on is worth as much as a type.
variant_pat = re.compile(
    r"`([A-Z][A-Za-z0-9]*)::([A-Z][A-Za-z0-9]*)(?:\([^`]*\)|\s*\{[^`]*\})?`"
)

# CamelCase written as code inside a fenced Rust block, rather than in
# backticks. The `use` scan above reaches into those blocks for imports
# only, which leaves every type named in the body of an example invisible:
# a `let config = OutboundOAuthConfig { .. }` or a
# `client: &CachedOutboundOAuthClient` is as fabricated as a bad import
# and rather more likely to be copied. Two humps are required, as in the
# backtick pattern, so `Ok`, `Some`, `Vec` and friends stay out.
# `Type::method()`, `method()`, `Type::field`. The parens or the `Type::`
# prefix are what make it unambiguously code rather than an English word in
# backticks, which is why a bare `foo` is not checked.
method_pat = re.compile(
    r"`(?:[A-Z][A-Za-z0-9]*(?:::[A-Za-z0-9_]+)*::)?([a-z_][a-z0-9_]*)\(\)`"
    r"|`[A-Z][A-Za-z0-9]*::([a-z_][a-z0-9_]*)`"
)

# A cargo feature, recognised by the word "feature" beside it.
feature_pat = re.compile(
    r"features?\s+`([a-z0-9][a-z0-9-]*)`|`([a-z0-9][a-z0-9-]*)`\s+feature"
)

FENCE = re.compile(r"^\s*```+\s*([A-Za-z0-9_,+-]*)")
code_pat = re.compile(r"\b([A-Z][A-Za-z0-9]*(?:[A-Z][A-Za-z0-9]*)+)\b")
STRING = re.compile(r"\"(?:[^\"\\]|\\.)*\"")
LINE_COMMENT = re.compile(r"//.*$")


def code_names(line):
    """CamelCase in the executable part of a line of an example.

    Strings and trailing comments are prose: `// VPN range` and
    `.expect("cert has a CN")` are English, and scanning them reports
    `VPN` and `CN` as undefined types. Strings go first so a `//` inside
    a URL does not truncate the line.
    """
    return code_pat.findall(LINE_COMMENT.sub("", STRING.sub('""', line)))

checked = 0
missing = collections.defaultdict(list)
# A chapter's examples routinely name the *adopter's* types: the
# `DocumentRow` a Cedar provider loads, the `AppEntityProvider` an adopter
# writes. Those are not ours to define, and listing each one in ALLOW would
# turn a provenance claim into a mute button. Instead, treat a name the
# chapter itself declares as locally defined: if the prose shows
# `struct DocumentRow` or `impl AppEntityProvider`, the reader has the
# definition in front of them and the name is answered.
local_pat = re.compile(
    r"\b(?:struct|enum|trait|type|union)\s+([A-Z][A-Za-z0-9]*)"
    r"|\bimpl(?:<[^>]*>)?\s+(?:[A-Za-z0-9_:<>, ]+?\s+for\s+)?([A-Z][A-Za-z0-9]*)"
)

def check_block(doc, start_line, body):
    """Compare every function the block declares against the workspace."""
    global checked
    for fn, seqs in declared_signatures(body).items():
        if fn not in REAL_SIGS or fn in ALLOW:
            continue
        real = REAL_SIGS[fn]
        # Nothing to compare against if every real variant is unparseable.
        if all("?" in r for r in real):
            continue
        for seq in seqs:
            if "?" in seq:
                continue
            checked += 1
            if not any(seq == r for r in real):
                shown = ", ".join(real[0])
                missing[f"{fn}({', '.join(seq)}), declared as ({shown})"].append(
                    f"{doc}:{start_line}"
                )


for d in docs:
    text = d.read_text(errors="ignore")
    local = {g for match in local_pat.findall(text) for g in match if g}
    in_rust_block = False
    block, block_start = [], 0
    for i, line in enumerate(text.splitlines(), 1):
        fence = FENCE.match(line)
        if fence:
            if in_rust_block:
                check_block(d, block_start, "\n".join(block))
            block, block_start = [], i
            # An opening fence carries a language, a closing one does not,
            # so a bare ``` always leaves the block.
            lang = fence.group(1).split(",")[0]
            in_rust_block = (not in_rust_block) and lang == "rust"
            continue
        if in_rust_block:
            block.append(line)
        names = [m.group(1) for m in pat.finditer(line)]
        for m in variant_pat.finditer(line):
            names += [m.group(1), m.group(2)]
        for m in use_pat.finditer(line):
            names += re.findall(r"\b([A-Z][A-Za-z0-9]*)\b", m.group(1))
        if in_rust_block:
            names += code_names(line)
        for name in names:
            if name in ALLOW or name in local or name in REMOVED:
                continue
            checked += 1
            if name not in defined:
                missing[name].append(f"{d}:{i}")

        for m in method_pat.finditer(line):
            name = m.group(1) or m.group(2)
            if name in ALLOW or name in local:
                continue
            checked += 1
            if name not in lower_defined:
                missing[name].append(f"{d}:{i}")

        for m in owner_pat.finditer(line):
            ty, member = m.group(1), m.group(2)
            if ty not in ENUMERABLE or member in EXTERNAL_MEMBERS or ty in ALLOW:
                continue
            if f"{ty}::{member}" in REMOVED:
                continue
            checked += 1
            if member not in OWNS[ty]:
                missing[f"{ty}::{member}"].append(f"{d}:{i}")

        for m in feature_pat.finditer(line):
            name = m.group(1) or m.group(2)
            if name in ALLOW:
                continue
            checked += 1
            if name not in FEATURES:
                missing[name].append(f"{d}:{i}")

# An empty result over an empty search space proves nothing, so say how
# much was looked at. A scan that stops finding identifiers is a broken
# scan, not a clean book.
if checked < 200:
    print(
        f"check-doc-identifiers: only {checked} identifiers scanned across "
        f"{len(docs)} chapters; the scan is not reaching the docs.",
        file=sys.stderr,
    )
    sys.exit(2)

if missing:
    total = sum(len(v) for v in missing.values())
    print(
        f"ERROR: {len(missing)} identifier(s) named in the book do not exist "
        f"in the workspace ({total} mention(s), {checked} scanned):\n",
        file=sys.stderr,
    )
    for name in sorted(missing):
        print(f"  {name}", file=sys.stderr)
        for site in missing[name][:3]:
            print(f"      {site}", file=sys.stderr)
    print(
        "\nEither the name is wrong (fix the chapter) or it is not ours to "
        "define (add it to ALLOW in this script, with the reason), or it "
        "is ours and deliberately removed and a migration section has to "
        "name it (add it to REMOVED).",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"check-doc-identifiers: {checked} identifiers across {len(docs)} chapters, all resolve.")
PY
