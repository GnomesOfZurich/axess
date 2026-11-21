"""Crafted cases for scripts/lib/cargo_config.py, run by
scripts/check-workflow-pins-tests.sh.

Each case pins the verdict on one `--config` value, one variable of the
environment, or every problem of one configuration file. Run with
`python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cargo_config as C

WHY = " (an alias, a source, a registry or a program cargo runs)"
FILE = "a --config that names a file is not read: %s (name the setting as key=value)"
SETS = "a --config that sets %s is not read: %s" + WHY
SETTING = "a setting that changes what cargo fetches or runs is not read: %s"

SETTINGS = [
  ("net.retry=3", None),
  ("net.retry = 3", None),
  ("'net'.\"retry\"=3", None),
  ("build.jobs=4", None),
  ("build.rustflags=['-D', 'warnings']", None),
  ("build.target=x", None),
  ("build.target-dir=t", None),
  ("build.incremental=false", None),
  ("build.dep-info-basedir=d", None),
  ("build.rustdocflags=[]", None),
  ("profile.release.lto=true", None),
  ("term.color='always'", None),
  ("net.offline=true", None),
  ("http.timeout=30", None),
  ("http.low-speed-limit=5", None),
  ("http.multiplexing=false", None),
  ("http.debug=true", None),
  ("target.x86_64-unknown-linux-gnu.rustflags=[]", None),
  ("target.x.rustdocflags=[]", None),
  ("env.FOO='x'", None),
  ("future-incompat-report.frequency='never'", None),
  ("cargo-new.vcs='none'", None),
  ("resolver.incompatible-rust-versions='fallback'", None),
  ("resolver.incompatible-publish-age='deny'", None),
  ("registry.global-min-publish-age='7 days'", None),
  ("registry.global-min-publish-agex='7 days'", SETS % ("registry.global-min-publish-agex", "registry.global-min-publish-agex='7 days'")),
  ("registry.min-publish-age='7 days'", SETS % ("registry.min-publish-age", "registry.min-publish-age='7 days'")),
  ("registry.global-min-publish-age.x=1", SETS % ("registry.global-min-publish-age.x", "registry.global-min-publish-age.x=1")),
  ("registries.m.min-publish-age='0'", SETS % ("registries.m.min-publish-age", "registries.m.min-publish-age='0'")),
  ("registry.token='t'", SETS % ("registry.token", "registry.token='t'")),
  ("alias.x=install", SETS % ("alias.x", "alias.x=install")),
  ("\"alias\".x='install'", SETS % ("alias.x", "\"alias\".x='install'")),
  ("alias = {x = 'install'}", SETS % ("alias", "alias = {x = 'install'}")),
  ("source.crates-io.replace-with=m", SETS % ("source.crates-io.replace-with", "source.crates-io.replace-with=m")),
  ("registry.default=m", SETS % ("registry.default", "registry.default=m")),
  ("registries.m.index=u", SETS % ("registries.m.index", "registries.m.index=u")),
  ("include='a.toml'", SETS % ("include", "include='a.toml'")),
  ("paths=['.']", SETS % ("paths", "paths=['.']")),
  ("build.rustc=r", SETS % ("build.rustc", "build.rustc=r")),
  ("build.rustc-wrapper=w", SETS % ("build.rustc-wrapper", "build.rustc-wrapper=w")),
  ("build.rustc-workspace-wrapper=w", SETS % ("build.rustc-workspace-wrapper", "build.rustc-workspace-wrapper=w")),
  ("build.jobsx=1", SETS % ("build.jobsx", "build.jobsx=1")),
  ("target.x.runner=r", SETS % ("target.x.runner", "target.x.runner=r")),
  ("target.x.linker=l", SETS % ("target.x.linker", "target.x.linker=l")),
  ("target.x.y.rustflags=[]", SETS % ("target.x.y.rustflags", "target.x.y.rustflags=[]")),
  ("target.'a.b'.rustflags=[]", None),
  ("env.RUSTC_WRAPPER=w", SETS % ("env.RUSTC_WRAPPER", "env.RUSTC_WRAPPER=w")),
  ("env.CARGO_HOME=h", SETS % ("env.CARGO_HOME", "env.CARGO_HOME=h")),
  ("env=1", SETS % ("env", "env=1")),
  ("net.git-fetch-with-cli=true", SETS % ("net.git-fetch-with-cli", "net.git-fetch-with-cli=true")),
  ("unstable.x=true", SETS % ("unstable.x", "unstable.x=true")),
  ("tools.toml", FILE % "tools.toml"),
  ("=1", FILE % "=1"),
  ("a b=1", FILE % "a b=1"),
  ("", FILE % ""),
]

ENV = [
  ("CARGO_ALIAS_X", True), ("CARGO_SOURCE_CRATES_IO_REPLACE_WITH", True), ("CARGO_REGISTRY_DEFAULT", True),
  ("CARGO_REGISTRIES_M_INDEX", True), ("CARGO_HOME", True), ("CARGO_BUILD_RUSTC", True),
  ("CARGO_BUILD_RUSTC_WRAPPER", True), ("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", True),
  ("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", True), ("CARGO_TARGET_X_LINKER", True),
  ("RUSTC", True), ("RUSTC_WRAPPER", True), ("RUSTC_WORKSPACE_WRAPPER", True),
  ("RUSTDOC", True), ("RUSTFMT", True), ("CARGO_BUILD_RUSTDOC", True), ("CARGO_UNSTABLE_BUILD_STD", True),
  ("CARGO_UNSTABLE_", False), ("RUSTDOCFLAGS", False), ("RUSTDOCX", False), ("CARGO_BUILD_RUSTDOCFLAGS", False),
  ("CARGO_REGISTRY_TOKEN", False), ("CARGO_REGISTRIES_M_TOKEN", True), ("CARGO_REGISTRIES_M_CREDENTIAL_PROVIDER", True), ("CARGO_REGISTRY_INDEX", True), ("CARGO_REGISTRY_CREDENTIAL_PROVIDER", True), ("CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS", True), ("CARGO_CREDENTIAL_PROVIDER", True), ("CARGO_HTTP_PROXY", True), ("CARGO_HTTP_CAINFO", True), ("CARGO_HTTP_CHECK_REVOKE", True), ("CARGO_HTTP_SSL_VERSION_MAX", True), ("CARGO_HTTP_TIMEOUT", False), ("CARGO_TARGET_DIR", False),
  ("CARGO_TERM_COLOR", False), ("CARGO_INCREMENTAL", False), ("CARGO_HOMEX", False), ("XRUSTC", False),
  ("RUSTC_BOOTSTRAP", False), ("CARGO_TARGET_X_RUSTFLAGS", False), ("CARGO_ALIAS_", False),
]

FILES = [
  ("empty", "", []),
  ("comments and blanks", "# a\n\n   # b\n", []),
  ("allowed tables", "[build]\njobs = 4\n[profile.release]\nlto = true # fast\n[[profile.x]]\nopt-level = 3\n", []),
  ("alias table", "[alias]\ntools = \"install foo\"\n", [(2, SETTING % "alias.tools")]),
  ("the publish age in the registry table", "[registry]\nglobal-min-publish-age = \"7 days\"\n", []),
  ("a neighbour of the publish age", "[registry]\nglobal-min-publish-age = \"7 days\"\nglobal-credential-providers = [\"x\"]\nmin-publish-age = \"0\"\n",
   [(3, SETTING % "registry.global-credential-providers"), (4, SETTING % "registry.min-publish-age")]),
  ("alias dotted at the top", "alias.tools = \"install foo\"\n", [(1, SETTING % "alias.tools")]),
  ("alias quoted in a header", "[ \"alias\" ]\nt = 1\n", [(2, SETTING % "alias.t")]),
  ("alias as an inline table", "alias = { t = \"install\" }\n", [(1, SETTING % "alias")]),
  ("array of tables", "[[alias]]\nt = 1\n", [(2, SETTING % "alias.t")]),
  ("header with a comment", "[build] # the build\nrustc = \"r\"\n", [(2, SETTING % "build.rustc")]),
  ("a dot inside a quoted part", "[target.'a.b']\nrunner = \"r\"\nrustflags = []\n", [(2, SETTING % "target.a․b.runner")]),
  ("multi-line array", "[build]\nrustflags = [\n  \"x]\",\n  'y'\n]\nrustc = \"r\"\n", [(6, SETTING % "build.rustc")]),
  ("inline table over lines", "[env]\nFOO = { value = \"x\",\n  force = true }\nRUSTC = \"r\"\n", [(4, SETTING % "env.RUSTC")]),
  ("multi-line basic string", "[env]\nA = \"\"\"\nx = 1\nalias.t = 2\n\"\"\"\nB = 1\n", []),
  ("multi-line literal string", "[build]\nrustflags = '''\nalias.t = 2'''\nrustc = 1\n", [(4, SETTING % "build.rustc")]),
  ("escaped quote in a string", "[env]\nA = \"a\\\"[\"\nB = 1\n", []),
  ("hash in a string", "[env]\nA = \"#[\"\nB = 1\n", []),
  ("value that does not close", "[env]\nA = [\n", [(3, "a value that does not close")]),
  ("string that does not close on its line", "[env]\nA = \"x\nB = 1\n", []),
  ("line that is not a key", "[build]\njobs\n", [(2, "a line the check cannot read: jobs")]),
  ("header that does not close", "[build\n", [(1, "a line the check cannot read: [build")]),
  ("mismatched array header", "[[build]\n", [(1, "a line the check cannot read: [[build]")]),
  ("a bracket in a comment", "[build]\njobs = 1 # [\n[alias]\nt = 'install x'\n", [(4, "a setting that changes what cargo fetches or runs is not read: alias.t")]),
  ("an empty multi-line string", "[env]\nA = \'\'\'\'\'\'\n[alias]\nt = 'install x'\n", [(4, "a setting that changes what cargo fetches or runs is not read: alias.t")]),
  ("a multi-line string on one line", "[env]\nA = \'\'\'x\'\'\'\n[alias]\nt = 'install x'\n", [(4, "a setting that changes what cargo fetches or runs is not read: alias.t")]),
  ("an empty string in an array", "[env]\nA = ['', 'b']\n[alias]\nt = 'install x'\n", [(4, "a setting that changes what cargo fetches or runs is not read: alias.t")]),
  ("an escaped quote in an array", "[env]\nA = [\"\\\"\", \"b\"]\n[alias]\nt = 'install x'\n", [(4, "a setting that changes what cargo fetches or runs is not read: alias.t")]),
  ("an array in an array", "[env]\nA = [[1]]\n[alias]\nt = 'install x'\n", [(4, "a setting that changes what cargo fetches or runs is not read: alias.t")]),
]
NAMES = "%s names a program rustc runs or code it loads (%s), which is not read"
UNREAD = "%s from a variable or an expression is not read: write the flags out"
FLAG_FILE = "flags that name a program rustc runs or code it loads are not read: %s"
# (variable, its value or None when an expansion fills it in, the problem)
FLAGS = [
  ("RUSTFLAGS", "-D warnings", None), ("RUSTDOCFLAGS", "-D warnings --cfg docsrs", None),
  ("RUSTFLAGS", "--cfg tokio_unstable -C target-cpu=native -C debuginfo=1 -Cinstrument-coverage", None),
  ("RUSTFLAGS", "-C opt-level=3 -W unused-labels -A dead_code --cap-lints warn", None), ("RUSTFLAGS", "", None),
  ("RUSTFLAGS", "-C linker=tools/ld", NAMES % ("RUSTFLAGS", "linker")), ("RUSTFLAGS", "-Clinker=clang", NAMES % ("RUSTFLAGS", "linker")),
  ("RUSTFLAGS", "-C link-arg=-fuse-ld=lld", NAMES % ("RUSTFLAGS", "link-arg")), ("RUSTFLAGS", "-Clink-args=-x", NAMES % ("RUSTFLAGS", "link-args")),
  ("RUSTFLAGS", "-Zcodegen-backend=b.so", NAMES % ("RUSTFLAGS", "codegen-backend")), ("RUSTFLAGS", "-Z llvm-plugins=p.so", NAMES % ("RUSTFLAGS", "llvm-plugins")),
  ("RUSTFLAGS", "-C llvm-args=-load=p.so", NAMES % ("RUSTFLAGS", "llvm-args")), ("RUSTFLAGS", "--sysroot /tmp/sysroot", NAMES % ("RUSTFLAGS", "sysroot")),
  ("RUSTFLAGS", "--extern a=/tmp/a.rlib", NAMES % ("RUSTFLAGS", "--extern")), ("RUSTFLAGS", "-L /tmp/lib", NAMES % ("RUSTFLAGS", "-L")),
  ("RUSTFLAGS", "-Lnative=/tmp/lib", NAMES % ("RUSTFLAGS", "-L")), ("RUSTFLAGS", None, UNREAD % "RUSTFLAGS"),
  ("RUSTDOCFLAGS", "-C linker=x", NAMES % ("RUSTDOCFLAGS", "linker")), ("CARGO_ENCODED_RUSTFLAGS", "-Clinker=x", NAMES % ("CARGO_ENCODED_RUSTFLAGS", "linker")),
  ("CARGO_BUILD_RUSTFLAGS", "-L x", NAMES % ("CARGO_BUILD_RUSTFLAGS", "-L")), ("CARGO_BUILD_RUSTDOCFLAGS", None, UNREAD % "CARGO_BUILD_RUSTDOCFLAGS"),
  ("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "-Clinker=x", NAMES % ("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "linker")),
  ("MIRIFLAGS", "-Zmiri-disable-isolation -L x", None), ("CFLAGS", "-L/tmp", None), ("MY_RUSTFLAGS", "-Clinker=x", None), ("RUSTFLAGSX", None, None),
]
FLAG_SETTINGS = [
  ("build.rustflags=['-D', 'warnings']", None), ("target.x86_64-unknown-linux-gnu.rustflags=['-Ctarget-cpu=native']", None),
  ("build.rustflags=['-Clinker=x']", "a --config whose build.rustflags names a program rustc runs or code it loads is not read: build.rustflags=['-Clinker=x']"),
  ("build.rustdocflags=['-L', 'x']", "a --config whose build.rustdocflags names a program rustc runs or code it loads is not read: build.rustdocflags=['-L', 'x']"),
  ("target.a.rustflags='-C link-arg=x'", "a --config whose target.a.rustflags names a program rustc runs or code it loads is not read: target.a.rustflags='-C link-arg=x'"),
  ("build.jobs=4", None), ("env.NOTE='-Clinker=x'", None),
]
FLAG_FILES = [
  ("flags that deny warnings", "[build]\nrustflags = [\"-D\", \"warnings\"]\n", []),
  ("a linker in the build's flags", "[build]\nrustflags = [\"-C\", \"linker=x\"]\n", [(2, FLAG_FILE % "build.rustflags")]),
  ("a linker on a later line of the flags", "[build]\nrustflags = [\n  \"-D\", \"warnings\",\n  \"-Clinker=x\",\n]\njobs = 2\n", [(4, FLAG_FILE % "build.rustflags")]),
  ("a library path in a target's flags", "[target.x86_64-unknown-linux-gnu]\nrustdocflags = \"-L x\"\n", [(2, FLAG_FILE % "target.x86_64-unknown-linux-gnu.rustdocflags")]),
  ("a linker in a dotted key", "build.rustflags = ['-Clinker=x']\n", [(1, FLAG_FILE % "build.rustflags")]),
  ("the word in a value that holds no flags", "[env]\nNOTE = \"-Clinker=x\"\n[build]\njobs = 2\n", []),
  ("the word in a later value", "[build]\nrustflags = [\n  \"-D\", \"warnings\",\n]\n[env]\nNOTE = [\n  \"linker\",\n]\n", []),
]


def main():
    failures = []
    for name, value, want in FLAGS:
        got = C.flags_problem(name, value)
        if got != want:
            failures.append("flags %s=%r: %r, wanted %r" % (name, value, got, want))
    for text, want in FLAG_SETTINGS:
        got = C.setting_problem(text)
        if got != want:
            failures.append("--config %r: %r, wanted %r" % (text, got, want))
    for name, text, want in FLAG_FILES:
        got = C.file_problems(text)
        if got != want:
            failures.append("file %s: %r, wanted %r" % (name, got, want))
    for text, want in SETTINGS:
        got = C.setting_problem(text)
        if got != want:
            failures.append("--config %r: %r, wanted %r" % (text, got, want))
    for name, want in ENV:
        got = C.ENV.fullmatch(name) is not None
        if got != want:
            failures.append("variable %s refused: %r, wanted %r" % (name, got, want))
    for name, text, want in FILES:
        got = C.file_problems(text)
        if got != want:
            failures.append("file %s: %r, wanted %r" % (name, got, want))
    for failure in failures:
        print("FAIL: cargo_config: " + failure, file=sys.stderr)
    total = len(SETTINGS) + len(ENV) + len(FILES) + len(FLAGS) + len(FLAG_SETTINGS) + len(FLAG_FILES)
    print("cargo_config tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
