"""Crafted cases for scripts/lib/workflow_jobs.py, run by
scripts/check-workflow-pins-tests.sh.

Each case writes the files it names into a temporary directory, runs the
check over it, and pins its exit status and every refusal it prints, in
order: the rules of a job that names a secret, may ask for an OIDC token
or holds a token that can write. The forms of a `shell:` the check reads
and the `path` of a download are pinned one by one. Run with
`python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workflow_jobs as J
import workflow_yaml as yaml
from workflow_pins_tests import R, SHA, run

SECRET = "jobs:\n  a:\n    env:\n      T: ${{ secrets.T }}\n    steps:\n"
NAMES = "REFUSED: w.yml: a job that names a secret runs what the check does not read: job a, "
UNLISTED = ("REFUSED: w.yml: line %d: an action that is not on the list (%s): what its pinned commit runs is not read, "
            "so scripts/lib/workflow_actions.txt names each action with what it is trusted to do")
PASTED = "REFUSED: w.yml: line %d: an expression the runner pastes into the script before the shell reads it (%s): pass the value in an env: and quote it"
CHANGES = "REFUSED: w.yml: a job that names a secret changes its checkout and runs code from it, which is not the code the check read: job a, "
CHECKOUT = "      - uses: actions/checkout@" + SHA + " # v7\n        with:\n          persist-credentials: false\n"
ACTION = "runs:\n  using: composite\n  steps:\n"
CASES = [
  ("a job that holds nothing runs what it likes", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - run: docker ps; python3 -c 'print(1)'; echo x > out; cargo build\n      - uses: Swatinem/rust-cache@" + SHA + " # v1\n"},
   (0, [])),
  ("every note of a job beside a secret, once, in order", {"w.yml": R + SECRET + "      - run: |\n          docker ps\n          docker ps\n          cp a b\n      - run: docker ps\n"},
   (1, [NAMES + "line 9: a program the check does not name (docker)", NAMES + "line 10: a program the check does not name (docker)",
        NAMES + "line 11: a program the check does not name (cp)", NAMES + "line 12: a program the check does not name (docker)"])),
  ("a program by a path the repository does not hold, in any job", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - run: ./tool\n"},
   (1, ["REFUSED: w.yml: line 6: a program run by a path the repository does not hold is not read: ./tool (a file a step made or downloaded)"])),
  ("an external cargo subcommand two jobs run and one installs", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - run: cargo install --locked cargo-audit@1.0.0\n      - run: scripts/x.sh\n"
                                                                   "  b:\n    steps:\n      - run: scripts/x.sh\n      - run: cargo audit\n", "scripts/x.sh": "cargo audit\ncargo audit\n"},
   (1, ["REFUSED: w.yml: job b, scripts/x.sh line 1: an external cargo subcommand whose program the job does not install (cargo audit): install it in the job with cargo install --locked cargo-audit@X.Y.Z",
        "REFUSED: w.yml: job b, scripts/x.sh line 2: an external cargo subcommand whose program the job does not install (cargo audit): install it in the job with cargo install --locked cargo-audit@X.Y.Z",
        "REFUSED: w.yml: job b, line 11: an external cargo subcommand whose program the job does not install (cargo audit): install it in the job with cargo install --locked cargo-audit@X.Y.Z"])),
  ("an external cargo subcommand a local action installs for the job", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n      - run: cargo audit\n",
                                                                        "act/action.yml": ACTION + "    - run: cargo install --locked cargo-audit@1.0.0\n      shell: bash\n"},
   (0, [])),
  ("an install and a note beside a secret", {"w.yml": R + SECRET + "      - run: cargo install --locked a@1.0.0 && docker ps\n"},
   (1, ["REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 8", NAMES + "line 8: a program the check does not name (docker)"])),
  ("the notes of one job are not another's", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - run: docker ps\n  b:\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: echo\n"},
   (0, [])),
  ("a note in a repository script two jobs run", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - run: scripts/x.sh\n  b:\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: scripts/x.sh\n",
                                                 "scripts/x.sh": "docker ps\n"},
   (1, ["REFUSED: w.yml: a job that names a secret runs what the check does not read: job b, scripts/x.sh line 1: a program the check does not name (docker)"])),
  ("an expression pasted into a script on two lines", {"w.yml": R + SECRET + "      - run: |\n          echo ${{ github.sha }}\n          echo ok ${{ toJSON(matrix) }} ${{ 'a' }}\n"},
   (1, [PASTED % (9, "${{ github.sha }}"), PASTED % (10, "${{ toJSON(matrix) }}"), PASTED % (10, "${{ 'a' }}")])),
  ("an expression pasted into a script of a job that holds nothing", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - run: echo ${{ matrix.x }}\n"},
   (1, [PASTED % (6, "${{ matrix.x }}")])),
  ("an expression pasted into a script of a local action", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n      - uses: ./act\n",
                                                           "act/action.yml": ACTION + "    - run: echo ${{ inputs.x }}\n      shell: bash\n"},
   (1, ["REFUSED: act/action.yml: line 4: an expression the runner pastes into the script before the shell reads it (${{ inputs.x }}): pass the value in an env: and quote it"])),
  ("an expression in an env and an if is not pasted", {"w.yml": R + SECRET + "      - if: ${{ github.ref == 'x' }}\n        env:\n          V: ${{ github.sha }}\n        run: echo \"$V\"\n"},
   (0, [])),
  ("an action the check does not name, by owner and repository", {"w.yml": R + SECRET + "      - uses: Actions/Checkout@" + SHA + " # v7\n        with:\n          persist-credentials: false\n      - uses: actions/cache/restore@" + SHA + " # v4\n"},
   (1, [UNLISTED % (11, "actions/cache/restore")])),
  ("a checkout in capitals keeps no credential", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - uses: Actions/Checkout@" + SHA + " # v7\n"},
   (1, ["REFUSED: w.yml: checkout at line 6 does not set persist-credentials: false"])),
  ("a toolchain action in capitals names its toolchain", {"w.yml": R + SECRET + "      - uses: DTolnay/Rust-Toolchain@" + SHA + " # master\n      - run: echo\n"},
   (1, ["REFUSED: w.yml: line 8: a toolchain that is not an exact version (none named) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z"])),
  ("a checkout of another ref with no code", {"w.yml": R + SECRET + CHECKOUT + "          ref: main\n      - run: git log -1\n"},
   (0, [])),
  ("a checkout of another ref and a build", {"w.yml": R + SECRET + CHECKOUT + "          ref: main\n      - run: cargo build --locked\n"},
   (1, [CHANGES + "line 8: a checkout of another repository or ref, and line 12: cargo build"])),
  ("a checkout of another repository and a script of a script", {"w.yml": R + SECRET + CHECKOUT + "          repository: o/r\n      - run: bash scripts/x.sh\n", "scripts/x.sh": "scripts/y.sh\n", "scripts/y.sh": "echo\n"},
   (1, [CHANGES + "line 8: a checkout of another repository or ref, and line 12: scripts/x.sh"])),
  ("a change by git in a repository script and a build in the workflow", {"w.yml": R + SECRET + "      - run: scripts/x.sh\n      - run: cargo test --locked\n", "scripts/x.sh": "git reset --hard origin/main\n"},
   (1, [CHANGES + "scripts/x.sh line 1: git reset, and line 8: scripts/x.sh"])),
  ("an artifact over the checkout and a local action", {"w.yml": R + SECRET + "      - uses: actions/download-artifact@" + SHA + " # v8\n      - uses: ./act\n", "act/action.yml": ACTION + "    - run: echo\n      shell: bash\n"},
   (1, [CHANGES + "line 8: an artifact unpacked over the checkout, and line 9: ./act"])),
  ("a local action beside a secret, used twice", {"w.yml": R + SECRET + "      - uses: ./act\n      - uses: ./act\n", "act/action.yml": ACTION + "    - run: docker ps\n      shell: bash\n"},
   (1, ["REFUSED: w.yml: a job that names a secret runs what the check does not read: job a, act/action.yml line 4: a program the check does not name (docker)"])),
  ("a local action that names a secret holds the job that uses it", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n      - run: docker ps\n",
                                                                  "act/action.yml": ACTION + "    - env:\n        T: ${{ github.token }}\n      run: echo\n      shell: bash\n"},
   (1, [NAMES + "line 7: a program the check does not name (docker)"])),
  ("a local action used by a local action that names a secret", {"w.yml": R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n      - run: docker ps\n",
                                                               "act/action.yml": ACTION + "    - uses: ./inner\n", "inner/action.yml": ACTION + "    - env:\n        T: ${{ github.token }}\n      run: echo\n      shell: bash\n"},
   (1, [NAMES + "line 7: a program the check does not name (docker)"])),
  ("a job handed the caller's secrets names one", {"w.yml": R + "jobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@" + SHA + " # v1\n    secrets: inherit\n"},
   (1, [UNLISTED % (5, "o/r/.github/workflows/w.yml")])),
  ("an action for jobs that hold no secret, beside one", {"w.yml": R + SECRET + "      - uses: Swatinem/rust-cache@" + SHA + " # v2\n"},
   (1, [NAMES + "line 8: an action that may run in no job beside a secret (Swatinem/rust-cache)"])),
  ("an image run as a step beside a secret", {"w.yml": R + SECRET + "      - uses: docker://example.invalid/tools@sha256:" + "0" * 64 + "\n"},
   (1, [NAMES + "line 8: an image run as a step (docker://example.invalid/tools)"])),
  ("a token that can write and the advice", {"w.yml": "jobs:\n  a:\n    permissions:\n      contents: write\n    steps:\n      - run: docker ps\n"},
   (1, ["REFUSED: w.yml: a job whose token can write runs what the check does not read: job a, line 6: a program the check does not name (docker) (give the job read permissions)"])),
  ("the path in an env of a job and of a step", {"w.yml": R + "env:\n  PATH: /a\njobs:\n  a:\n    steps:\n      - env:\n          PATH: /b\n        run: echo\n"},
   (1, ["REFUSED: w.yml: line 4: PATH in an env: names the directories every program of the job is run from, which is not read: a step that needs a directory on the path writes it to $GITHUB_PATH",
        "REFUSED: w.yml: line 9: PATH in an env: names the directories every program of the job is run from, which is not read: a step that needs a directory on the path writes it to $GITHUB_PATH"])),
]
SHELLS = [
  ("bash", True), ("sh", True), ("bash {0}", True), ("bash -e {0}", True), ("bash -euo pipefail {0}", True), ("bash -eo pipefail {0}", True),
  ("bash --noprofile --norc -eo pipefail {0}", True), ("sh -e {0}", True), ("bash -x -e -u {0}", True), ("bash -o errexit -o nounset {0}", True),
  ("  bash  ", True), ("", False), ("zsh", False), ("pwsh", False), ("python", False), ("bash -c x {0}", False), ("bash -c 'cargo install a' {0}", False),
  ("bash --rcfile f {0}", False), ("bash --init-file f {0}", False), ("bash -i {0}", False), ("bash -l {0}", False), ("bash --login {0}", False),
  ("bash -s {0}", False), ("bash - {0}", False), ("env bash {0}", False), ("bash {0} ; id", False), ("/bin/bash", False), ("bash -O extglob {0}", False),
  ("sh -c id", False), ("bash -euo pipefail {0} extra", False),
]
# (the `path` of a download, whether it keeps the files off the checkout);
# the repository holds `scripts` and `Cargo.toml`.
PATHS = [
  ("attested", True), ("attested/files", True), ("./attested", True), ("out/a/b", True), ("${{ runner.temp }}/attested", True),
  ("${{runner.temp}}/a/b", True), (None, False), ("", False), (".", False), ("./", False), ("scripts", False), ("scripts/generated", False),
  ("./scripts/x", False), ("Cargo.toml", False), ("attested/../scripts", False), ("../outside", False), ("/tmp/x", False), ("~/x", False),
  ("${{ inputs.where }}", False), ("${{ runner.temp }}", False), ("${{ runner.temp }}/../x", False), ("${{ runner.temp }}/${{ inputs.x }}", False),
  ("attested/${{ matrix.x }}", False), ("${{ github.workspace }}/attested", False),
]


TRUST = "Fetch the repository into the workspace and nothing else."
# (the text of a list, (the actions it names with where each may run, its problems))
LISTS = [
  ("a/b | any job | " + TRUST + "\nC/D | no secret | " + TRUST + "\n", ({"a/b": ("a/b", True), "c/d": ("C/D", False)}, [])),
  ("# NAME | WHERE | TRUSTED TO\n\n  # more\na/b | any job | " + TRUST, ({"a/b": ("a/b", True)}, [])),
  ("a/b|any job|" + TRUST + " It names a pipe | in its text.", ({"a/b": ("a/b", True)}, [])),
  ("a/b | any job", ({}, [(1, "a line that is not NAME | WHERE | TRUSTED TO, with NAME an owner and a repository")])),
  ("a | any job | " + TRUST, ({}, [(1, "a line that is not NAME | WHERE | TRUSTED TO, with NAME an owner and a repository")])),
  ("a/b/c | any job | " + TRUST, ({}, [(1, "a line that is not NAME | WHERE | TRUSTED TO, with NAME an owner and a repository")])),
  ("a/b | every job | " + TRUST, ({}, [(1, "a/b may run in 'every job', which is neither \"any job\" nor \"no secret\"")])),
  ("a/b | any job | trusted", ({}, [(1, "a/b is listed without what it is trusted to do")])),
  ("a/b | any job |", ({}, [(1, "a/b is listed without what it is trusted to do")])),
  ("a/b | any job | " + TRUST + "\nA/B | no secret | " + TRUST, ({"a/b": ("a/b", True)}, [(2, "A/B is listed twice")])),
]


class Root(J.Jobs):
    def __init__(self, root):
        self.root = root


def main():
    failures = []
    for name, files, want in CASES:
        got = run(files)
        if got != want:
            failures.append("%s: %r, wanted %r" % (name, got, want))
    for value, want in SHELLS:
        if J.shell_read(value) is not want:
            failures.append("shell %r read: %r, wanted %r" % (value, J.shell_read(value), want))
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for value, want in PATHS:
        got = Root(here).beside_checkout(None if value is None else yaml.Scalar(value, 1, "plain"))
        if got is not want:
            failures.append("download path %r beside the checkout: %r, wanted %r" % (value, got, want))
    for text, want in LISTS:
        actions, problems = J.read_actions(text)
        got = ({key: (name, held) for key, (name, held, _, _) in actions.items()}, problems)
        if got != want:
            failures.append("list %r: %r, wanted %r" % (text, got, want))
    listed, _ = J.read_actions("a/b | any job | " + TRUST + "\n\nc/d | no secret | " + TRUST + "\ne/f | any job | " + TRUST)
    for used, want in (({"a/b", "c/d", "e/f"}, []), ({"a/b", "e/f", "x/y"}, [(3, "c/d is listed and no workflow uses it: remove the line")]),
                       (set(), [(1, "a/b is listed and no workflow uses it: remove the line"), (3, "c/d is listed and no workflow uses it: remove the line"),
                                (4, "e/f is listed and no workflow uses it: remove the line")])):
        if J.unused_actions(listed, used) != want:
            failures.append("unused actions with %r used: %r, wanted %r" % (sorted(used), J.unused_actions(listed, used), want))
    if J.load_actions(os.path.join(here, "no-such-list"))[0] != {} or "cannot be read" not in J.load_actions(os.path.join(here, "no-such-list"))[1][0][1]:
        failures.append("a list that is not there names actions or has no problem")
    own, problems = J.load_actions()
    if problems or len(own) < 5 or any(len(trust) < 40 for _, _, trust, _ in own.values()):
        failures.append("the repository's own list: %r %r" % (problems, sorted(own)))
    for failure in failures:
        print("FAIL: workflow_jobs: " + failure, file=sys.stderr)
    total = len(CASES) + len(SHELLS) + len(PATHS) + len(LISTS) + 5
    print("workflow_jobs tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
