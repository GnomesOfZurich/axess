"""Crafted cases for scripts/lib/workflow_pins.py, run by
scripts/check-workflow-pins-tests.sh.

Each case writes the files it names into a temporary directory, runs the
check over it, and pins its exit status and every refusal it prints, in
order. Run with `python3 -I -B`.
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workflow_pins as P


def run(files):
    root = tempfile.mkdtemp()
    try:
        for name, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, name)) or root, exist_ok=True)
            with open(os.path.join(root, name), "wb") as f:
                f.write(text if isinstance(text, bytes) else text.encode())
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = P.main(["workflow_pins.py", root])
        lines = [line.replace(root + "/", "").replace(root, "<dir>") for line in out.getvalue().splitlines()]
        return status, [line for line in lines if line.startswith("REFUSED")]
    finally:
        shutil.rmtree(root)


SHA = "0123456789abcdef0123456789abcdef01234567"
D = "sha256:" + "0" * 64
R = "permissions:\n  contents: read\n"
I = "cargo install --locked a@1.0.0"
CALLED = ("jobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      TOK: ${{ inputs.tok }}\n"
          "    steps:\n      - run: " + I + "\n" + R)
TC = "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@" + SHA + " # master\n        with:\n          toolchain: %s\n"
PIN = '[toolchain]\nchannel = "1.2.4"\n'
NF = "nightly-toolchain.toml"
NP = '[toolchain]\nchannel = "nightly-2026-02-02"\n'
CASES = [
  ('inputs of a workflow another calls, on a mapping', {'w.yml': "on:\n  workflow_call:\n" + CALLED},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job build, cargo install at line 9'])),
  ('inputs of a workflow another calls, on a list', {'w.yml': "on: [push, workflow_call]\n" + CALLED},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job build, cargo install at line 8'])),
  ('inputs of a workflow another calls, on a word', {'w.yml': "on: workflow_call\n" + CALLED},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job build, cargo install at line 8'])),
  ('inputs of a workflow a person starts', {'w.yml': "on:\n  workflow_dispatch:\n" + CALLED},
   (0, [])),
  ('inputs of a workflow with no trigger', {'w.yml': CALLED},
   (0, [])),
  ('inputs of a workflow on a list without a call', {'w.yml': "on: [push, workflow_dispatch]\n" + CALLED},
   (0, [])),
  ('inputs of a workflow on a list of other events', {'w.yml': "on: [push, pull_request]\n" + CALLED},
   (0, [])),
  ('a token that reads everything may install', {'w.yml': "permissions: read-all\njobs:\n  a:\n    steps:\n      - run: " + I + "\n"},
   (0, [])),
  ('a cargo configuration that is not text', {'w.yml': R + "jobs:\n  a:\n    steps:\n      - run: cargo build\n", '.cargo/config.toml': b'\xff'},
   (1, ["REFUSED: .cargo/config.toml: the cargo configuration cannot be read: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"])),
  ('a cargo configuration under target', {'w.yml': R + "jobs: {}\n", 'target/.cargo/config.toml': "[alias]\nt = 'install x'\n"},
   (0, [])),
  ('a cargo configuration under .git', {'w.yml': R + "jobs: {}\n", '.git/.cargo/config.toml': "[alias]\nt = 'install x'\n"},
   (0, [])),
  ('a cargo configuration under node_modules', {'w.yml': R + "jobs: {}\n", 'node_modules/.cargo/config.toml': "[alias]\nt = 'install x'\n"},
   (0, [])),
  ('a toolchain a script selects, run twice beside a secret', {'w.yml': R + "jobs:\n  a:\n    steps:\n      - run: scripts/tc.sh\n      - run: scripts/tc.sh\n      - env:\n          T: ${{ secrets.T }}\n        run: cargo publish --locked\n",
   'scripts/tc.sh': "rustup default stable\n"},
   (1, ['REFUSED: w.yml: a job that names a secret runs what the check does not read: job a, scripts/tc.sh line 1: a program the check does not name (rustup)',
        'REFUSED: w.yml: scripts/tc.sh, line 1: a toolchain that is not an exact version (stable) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('a local action that is not YAML beside a secret', {'w.yml': R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n      - env:\n          T: ${{ secrets.T }}\n        run: cargo publish --locked\n",
   'act/action.yml': "runs: [\n"},
   (1, ['REFUSED: act/action.yml: line 2: not read as YAML: a value in brackets that does not close',
        'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, a local action it cannot read at line 6 (act/action.yml, line 1)'])),
  ('a local action used twice beside a secret', {'w.yml': R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n      - uses: ./act\n      - env:\n          T: ${{ secrets.T }}\n        run: cargo publish --locked\n",
   'act/action.yml': "runs:\n  using: composite\n  steps:\n    - uses: dtolnay/rust-toolchain@" + SHA + " # v1\n      with:\n        toolchain: stable\n"},
   (1, ['REFUSED: w.yml: act/action.yml, line 6: a toolchain that is not an exact version (stable) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('a legacy toolchain file over two lines beside a secret', {'w.yml': R + "jobs:\n  a:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: cargo publish --locked\n",
   'rust-toolchain': "stable\nbeta\n"},
   (1, ['REFUSED: w.yml: rust-toolchain names a toolchain that is not an exact version (none named), in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('inputs of a local action in a called workflow', {'w.yml': "on: workflow_call\n" + R + "jobs:\n  a:\n    steps:\n      - uses: ./act\n",
   'act/action.yml': "runs:\n  using: composite\n  steps:\n    - env:\n        X: ${{ inputs.x }}\n      run: echo\n      shell: bash\n    - run: " + I + "\n      shell: bash\n"},
   (0, [])),
  ('no files', {},
   (1, ['REFUSED: <dir>: no workflow file (*.yml, *.yaml): a checkout without its workflows has nothing to pass'])),
  ('not yaml extension only', {'notes.txt': 'x'},
   (1, ['REFUSED: <dir>: no workflow file (*.yml, *.yaml): a checkout without its workflows has nothing to pass'])),
  ('unreadable bytes', {'w.yml': b'jobs: \xff\n'},
   (1, ["REFUSED: w.yml: the workflow cannot be read: 'utf-8' codec can't decode byte 0xff in position 6: invalid start byte"])),
  ('not yaml', {'w.yml': 'a: b: c\n'},
   (1, ['REFUSED: w.yml: line 1: not read as YAML: a colon and a space inside a plain value: quote the value'])),
  ('not a mapping', {'w.yml': '- a\n'},
   (1, ['REFUSED: w.yml: the workflow is not a mapping'])),
  ('no jobs', {'w.yml': 'permissions:\n  contents: read\n'},
   (0, [])),
  ('jobs not a mapping', {'w.yml': 'permissions:\n  contents: read\njobs: [a]\n'},
   (1, ['REFUSED: w.yml: line 3: jobs that is not a mapping'])),
  ('job not a mapping', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a: x\n'},
   (1, ['REFUSED: w.yml: line 4: the job a is not a mapping'])),
  ('step not a mapping', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - x\n'},
   (1, ['REFUSED: w.yml: line 6: a step that is not a mapping'])),
  ('steps not a sequence', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps: x\n'},
   (1, ['REFUSED: w.yml: line 5: steps that is not a sequence'])),
  ('uses not a scalar', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: [x]\n'},
   (1, ['REFUSED: w.yml: uses that is not a single value: 6:      - uses: [x]'])),
  ('uses pinned', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # v1\n'},
   (0, [])),
  ('uses pinned to main', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # main\n'},
   (0, [])),
  ('uses comment main then text', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # main branch\n'},
   (1, ['REFUSED: w.yml: action not pinned to a full commit SHA with a version comment: 6:      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # main branch'])),
  ('uses no comment', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n'},
   (1, ['REFUSED: w.yml: action not pinned to a full commit SHA with a version comment: 6:      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567'])),
  ('uses sha with suffix', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567x # v1\n'},
   (1, ['REFUSED: w.yml: action not pinned to a full commit SHA with a version comment: 6:      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567x # v1'])),
  ('uses local', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./x\n'},
   (1, ['REFUSED: w.yml: line 6: a local action or workflow the repository does not hold: ./x (job a)'])),
  ('uses docker digest', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: docker://a@sha256:0000000000000000000000000000000000000000000000000000000000000000\n'},
   (0, [])),
  ('uses docker tag', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: docker://a:1\n'},
   (1, ['REFUSED: w.yml: image not pinned by an @sha256 digest: 6:      - uses: docker://a:1'])),
  ('image digest', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    container:\n      image: a@sha256:0000000000000000000000000000000000000000000000000000000000000000\n'},
   (0, [])),
  ('image tag', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    container:\n      image: a:1\n'},
   (1, ['REFUSED: w.yml: image not pinned by an @sha256 digest: 6:      image: a:1'])),
  ('image not scalar', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    container:\n      image: [a]\n'},
   (1, ['REFUSED: w.yml: image that is not a single value: 6:      image: [a]'])),
  ('container short', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    container: a:1\n'},
   (1, ['REFUSED: w.yml: image not pinned by an @sha256 digest: 5:    container: a:1'])),
  ('container mapping without image', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    container:\n      options: x\n'},
   (0, [])),
  ('flow uses', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - {uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567}\n'},
   (1, ['REFUSED: w.yml: flow-style mapping on uses: or image: (write it in block style): 6:      - {uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567}'])),
  ('flow image', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    services: {db: {image: a@sha256:0000000000000000000000000000000000000000000000000000000000000000}}\n'},
   (1, ['REFUSED: w.yml: flow-style mapping on uses: or image: (write it in block style): 5:    services: {db: {image: a@sha256:0000000000000000000000000000000000000000000000000000000000000000}}'])),
  ('checkout ok', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v1\n        with:\n          persist-credentials: FALSE\n'},
   (0, [])),
  ('checkout with not a mapping', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v1\n        with: x\n'},
   (1, ['REFUSED: w.yml: checkout at line 6 does not set persist-credentials: false'])),
  ('checkout flag not scalar', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v1\n        with:\n          persist-credentials: [false]\n'},
   (1, ['REFUSED: w.yml: checkout at line 6 does not set persist-credentials: false'])),
  ('checkout uses not scalar elsewhere', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: [actions/checkout@v4]\n'},
   (1, ['REFUSED: w.yml: uses that is not a single value: 6:      - uses: [actions/checkout@v4]'])),
  ('secret job install', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 8'])),
  ('secret job no install', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: echo\n'},
   (0, [])),
  ('secret key expression', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    env:\n      ${{ secrets.T }}: x\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 8'])),
  ('shared secret top key', {'w.yml': 'permissions:\n  contents: read\n${{ secrets.T }}: x\njobs:\n  a:\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 7'])),
  ('shared secret in on', {'w.yml': "permissions:\n  contents: read\non:\n  push:\n    branches: ['${{ secrets.B }}']\njobs:\n  a:\n    steps:\n      - run: cargo install --locked a@1.0.0\n"},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 9'])),
  ('unread expression and install', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    env:\n      T: ${{ $x }}\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ["REFUSED: w.yml: line 6: an expression the check cannot read: a character an expression cannot hold: '$'", 'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 8'])),
  ('if whole expression', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    if: secrets.T\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 7'])),
  ('if with braces', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    if: ${{ github.token }}\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 7'])),
  ('if not a scalar', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    if: [secrets]\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 5: an if that is not a single value', 'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 7'])),
  ('if empty', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    if:\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (0, [])),
  ('text like secrets outside expression', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    name: secrets.T\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (0, [])),
  ('oidc install', {'w.yml': 'jobs:\n  a:\n    permissions:\n      id-token: write\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 6'])),
  ('oidc upper', {'w.yml': 'jobs:\n  a:\n    permissions:\n      id-token: WRITE\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 6'])),
  ('write-all install', {'w.yml': 'jobs:\n  a:\n    permissions: write-all\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 5'])),
  ('read-all install', {'w.yml': 'jobs:\n  a:\n    permissions: read-all\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (0, [])),
  ('empty permissions install', {'w.yml': 'jobs:\n  a:\n    permissions: {}\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (0, [])),
  ('null permissions', {'w.yml': 'jobs:\n  a:\n    permissions:\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 3: a permissions value the check does not read: ', 'REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 5'])),
  ('permissions bad scalar', {'w.yml': 'jobs:\n  a:\n    permissions: read\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 3: a permissions value the check does not read: read', 'REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 5'])),
  ('permissions list', {'w.yml': 'jobs:\n  a:\n    permissions: [read]\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 3: a permissions value the check does not read', 'REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 5'])),
  ('permission bad level', {'w.yml': 'jobs:\n  a:\n    permissions:\n      contents: maybe\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 4: a permission the check does not read: contents', 'REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 6'])),
  ('permission level not scalar', {'w.yml': 'jobs:\n  a:\n    permissions:\n      contents: [read]\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 4: a permission the check does not read: contents', 'REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 6'])),
  ('permission none', {'w.yml': 'jobs:\n  a:\n    permissions:\n      contents: none\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (0, [])),
  ('write then oidc', {'w.yml': 'jobs:\n  a:\n    permissions:\n      contents: write\n      id-token: write\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: a job that may ask for an OIDC token installs a tool on the same runner: job a, cargo install at line 7'])),
  ('undeclared install', {'w.yml': 'jobs:\n  a:\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ["REFUSED: w.yml: a job whose token has the repository's default permissions installs a tool on the same runner: job a, cargo install at line 4 (declare permissions: contents: read)"])),
  ('undeclared no install', {'w.yml': 'jobs:\n  a:\n    steps:\n      - run: echo\n'},
   (0, [])),
  ('workflow write job read', {'w.yml': 'permissions:\n  contents: write\njobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - run: cargo install --locked a@1.0.0\n'},
   (0, [])),
  ('workflow oidc', {'w.yml': 'permissions:\n  id-token: write\njobs:\n  a:\n    permissions: {}\n    steps:\n      - run: echo\n'},
   (1, ['REFUSED: w.yml: line 2: the OIDC permission stands on the whole workflow, so every job may ask for a token: give it to the job that needs it'])),
  ('workflow oidc read', {'w.yml': 'permissions:\n  id-token: read\njobs: {}\n'},
   (0, [])),
  ('workflow write-all', {'w.yml': 'permissions: write-all\njobs: {}\n'},
   (1, ['REFUSED: w.yml: line 1: every permission, the OIDC one included, stands on the whole workflow: give each job the permissions it needs'])),
  ('workflow read-all', {'w.yml': 'permissions: read-all\njobs: {}\n'},
   (0, [])),
  ('workflow permissions list', {'w.yml': 'permissions: [x]\njobs: {}\n'},
   (0, [])),
  ('cargo env in env', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    env:\n      CARGO_ALIAS_X: install\n      OK: 1\n    steps:\n      - run: echo\n'},
   (1, ['REFUSED: w.yml: line 6: CARGO_ALIAS_X changes what cargo installs or runs (an alias, a source, its configuration or a program in place of rustc), which is not read'])),
  ('env not mapping', {'w.yml': 'permissions:\n  contents: read\nenv: x\njobs: {}\n'},
   (0, [])),
  ('step shell python', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: x\n        shell: python\n'},
   (1, ['REFUSED: w.yml: line 6: a run step in a shell the check does not read: python (use bash or sh)'])),
  ('step shell python over an install', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: cargo install a\n        shell: python\n'},
   (1, ['REFUSED: w.yml: line 6: a run step in a shell the check does not read: python (use bash or sh)'])),
  ('windows runner over an install', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n      - run: cargo install a\n'},
   (1, ['REFUSED: w.yml: line 7: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('step shell expression', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: x\n        shell: ${{ inputs.s }}\n'},
   (1, ['REFUSED: w.yml: line 6: a run step in a shell the check does not read: ${{ inputs.s }} (use bash or sh)'])),
  ('step shell bash over job pwsh', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    defaults:\n      run:\n        shell: pwsh\n    steps:\n      - run: cargo install a\n        shell: bash\n'},
   (1, ['REFUSED: w.yml: line 9: cargo install without --locked', 'REFUSED: w.yml: line 9: no exact version for a (crate@X.Y.Z or --version X.Y.Z)'])),
  ('step shell python over job bash', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    defaults:\n      run:\n        shell: bash\n    steps:\n      - run: x\n        shell: python\n'},
   (1, ['REFUSED: w.yml: line 9: a run step in a shell the check does not read: python (use bash or sh)'])),
  ('job default shell pwsh', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    defaults:\n      run:\n        shell: pwsh\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 9: a run step in a shell the check does not read: pwsh (use bash or sh)'])),
  ('workflow default shell pwsh', {'w.yml': 'permissions:\n  contents: read\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  a:\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 9: a run step in a shell the check does not read: pwsh (use bash or sh)'])),
  ('job default bash over workflow pwsh', {'w.yml': 'permissions:\n  contents: read\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  a:\n    defaults:\n      run:\n        shell: sh -e {0}\n    steps:\n      - run: cargo install a\n'},
   (1, ['REFUSED: w.yml: line 12: cargo install without --locked', 'REFUSED: w.yml: line 12: no exact version for a (crate@X.Y.Z or --version X.Y.Z)'])),
  ('defaults not mapping', {'w.yml': 'permissions:\n  contents: read\ndefaults: x\njobs:\n  a:\n    defaults:\n      run: x\n    steps:\n      - run: cargo install a\n'},
   (1, ['REFUSED: w.yml: line 9: cargo install without --locked', 'REFUSED: w.yml: line 9: no exact version for a (crate@X.Y.Z or --version X.Y.Z)'])),
  ('windows runner', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    runs-on: windows-2022\n    steps:\n      - run: cargo install a\n'},
   (1, ['REFUSED: w.yml: line 7: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('windows runner bash', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    runs-on: windows-2022\n    defaults:\n      run:\n        shell: bash\n    steps:\n      - run: cargo install a\n'},
   (1, ['REFUSED: w.yml: line 10: cargo install without --locked', 'REFUSED: w.yml: line 10: no exact version for a (crate@X.Y.Z or --version X.Y.Z)'])),
  ('runs-on labels', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    runs-on: [self-hosted, Windows]\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 7: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('runs-on linux labels', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: x\n'},
   (0, [])),
  ('runs-on expression', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    runs-on: ${{ inputs.os }}\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 7: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('runs-on matrix with include', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include:\n          - os: windows-latest\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 12: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('runs-on matrix not list', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    strategy:\n      matrix:\n        os: ${{ fromJSON(inputs.o) }}\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 10: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('runs-on matrix nested', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [[ubuntu-latest]]\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 10: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('runs-on matrix other key', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n    runs-on: ${{ matrix.other }}\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 10: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('runs-on matrix linux', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-14]\n    runs-on: ${{matrix.os}}\n    steps:\n      - run: x\n'},
   (0, [])),
  ('strategy not mapping', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    strategy: x\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: x\n'},
   (1, ['REFUSED: w.yml: line 8: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash'])),
  ('run not scalar', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: [x]\n'},
   (1, ['REFUSED: w.yml: line 6: run that is not a single value'])),
  ('composite', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': 'runs:\n  using: composite\n  steps:\n    - run: cargo install a\n      shell: bash\n    - uses: actions/upload-artifact@v1\n    - x\n'},
   (1, ['REFUSED: act/action.yml: action not pinned to a full commit SHA with a version comment: 6:    - uses: actions/upload-artifact@v1', 'REFUSED: act/action.yml: line 4: cargo install without --locked', 'REFUSED: act/action.yml: line 4: no exact version for a (crate@X.Y.Z or --version X.Y.Z)', 'REFUSED: act/action.yml: line 7: a step that is not a mapping'])),
  ('composite yaml', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n      - uses: ./act\n', 'act/action.yaml': 'runs:\n  using: composite\n  steps:\n    - run: cargo install a\n      shell: bash\n'},
   (1, ['REFUSED: act/action.yaml: line 4: cargo install without --locked', 'REFUSED: act/action.yaml: line 4: no exact version for a (crate@X.Y.Z or --version X.Y.Z)'])),
  ('composite unreadable yaml', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': 'a: b: c\n'},
   (1, ['REFUSED: act/action.yml: line 1: not read as YAML: a colon and a space inside a plain value: quote the value', 'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, a local action it cannot read at line 6 (act/action.yml, line 1)'])),
  ('composite unreadable bytes', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': b'\xff\n'},
   (1, ["REFUSED: act/action.yml: the local action cannot be read: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte", 'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, a local action it cannot read at line 6 (act/action.yml, line 1)'])),
  ('composite not mapping', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': '- x\n'},
   (1, ['REFUSED: act/action.yml: the local action is not a mapping', 'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, a local action it cannot read at line 6 (act/action.yml, line 1)'])),
  ('a local action with no runs', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': 'name: x\n'},
   (1, ['REFUSED: act/action.yml: a local action that is not composite is not read: it runs nothing the check reads',
        'REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, a local action it cannot read at line 6 (act/action.yml, line 1)'])),
  ('composite secret', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n      - run: cargo install --locked a@1.0.0\n', 'act/action.yml': 'runs:\n  using: composite\n  steps:\n    - env:\n        T: ${{ github.token }}\n      run: echo\n      shell: bash\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 7'])),
  ('composite secret used by two jobs', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n      - run: cargo install --locked a@1.0.0\n  b:\n    steps:\n      - uses: ./act\n', 'act/action.yml': 'runs:\n  using: composite\n  steps:\n    - env:\n        T: ${{ github.token }}\n      run: echo\n      shell: bash\n'},
   (1, ['REFUSED: w.yml: a job that names a secret installs a tool on the same runner: job a, cargo install at line 7'])),
  ('missing local action', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./none\n      - run: cargo install --locked a@1.0.0\n'},
   (1, ['REFUSED: w.yml: line 6: a local action or workflow the repository does not hold: ./none (job a)'])),
  ('local reusable workflow', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    uses: ./.github/workflows/x.yml\n'},
   (1, ['REFUSED: w.yml: line 5: a local action or workflow the repository does not hold: ./.github/workflows/x.yml (job a)'])),
  ('local reusable workflow held', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    uses: ./w.yml\n'},
   (0, [])),
  ('local action held as yaml', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yaml': 'runs:\n  using: composite\n  steps: []\n'},
   (0, [])),
  ('toolchain exact', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567 # master\n        with:\n          toolchain: 1.2.3\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (0, [])),
  ('toolchain floating', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567 # master\n        with:\n          toolchain: stable\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (1, ['REFUSED: w.yml: line 8: a toolchain that is not an exact version (stable) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('toolchain not scalar', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # v1\n        with:\n          toolchain: [stable]\n  b:\n    permissions:\n      id-token: write\n    steps:\n      - run: echo\n'},
   (1, ['REFUSED: w.yml: line 6: a toolchain that is not an exact version (none named) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('toolchain input on another action', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # v1\n        with:\n          toolchain: stable\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (1, ['REFUSED: w.yml: line 8: a toolchain that is not an exact version (stable) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('toolchain action without input', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@1.2.3\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (1, ['REFUSED: w.yml: action not pinned to a full commit SHA with a version comment: 6:      - uses: dtolnay/rust-toolchain@1.2.3', 'REFUSED: w.yml: line 6: a toolchain that is not an exact version (none named) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('toolchain with not mapping', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567 # master\n        with: x\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (1, ['REFUSED: w.yml: line 6: a toolchain that is not an exact version (none named) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  ('toolchain floating no secret', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567 # master\n        with:\n          toolchain: stable\n'},
   (0, [])),
  ('toolchain selector in another file', {'w.yml': 'permissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n', 'x.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: cargo +stable build\n'},
   (0, [])),
  ('toolchain dated', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: cargo +nightly-2026-01-01 build; cargo +beta-2026-01-01 build; cargo +stable-2026-01-01 build\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (0, [])),
  ('toolchain with suffix', {'w.yml': 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: cargo +1.2.3x build\n  b:\n    steps:\n      - env:\n          T: ${{ secrets.T }}\n        run: echo\n'},
   (1, ['REFUSED: w.yml: line 6: a toolchain that is not an exact version (1.2.3x) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z'])),
  # The pinned toolchain, in every workflow: a release written out is the
  # one the toolchain file pins, and a workflow that runs on a change names
  # no floating channel.
  ('pinned release lags the file', {'w.yml': R + TC % "1.2.3", 'rust-toolchain.toml': PIN},
   (1, ['REFUSED: w.yml: line 8: the toolchain 1.2.3 is not the release rust-toolchain.toml pins (1.2.4): read the channel from that file, or write the same release'])),
  ('pinned release lags the legacy file', {'w.yml': R + TC % "1.2.3", 'rust-toolchain': '1.2.4\n'},
   (1, ['REFUSED: w.yml: line 8: the toolchain 1.2.3 is not the release rust-toolchain pins (1.2.4): read the channel from that file, or write the same release'])),
  ('pinned release is the file', {'w.yml': R + TC % "1.2.4", 'rust-toolchain.toml': PIN},
   (0, [])),
  ('pinned release with no toolchain file', {'w.yml': R + TC % "1.2.3"},
   (0, [])),
  ('pinned release beside a floating file', {'w.yml': R + TC % "1.2.3", 'rust-toolchain.toml': '[toolchain]\nchannel = "stable"\n'},
   (0, [])),
  ('pinned release in an env lags the file', {'w.yml': R + 'jobs:\n  a:\n    env:\n      RUSTUP_TOOLCHAIN: 1.2.3\n    steps:\n      - run: echo\n', 'rust-toolchain.toml': PIN},
   (1, ['REFUSED: w.yml: line 6: the toolchain 1.2.3 is not the release rust-toolchain.toml pins (1.2.4): read the channel from that file, or write the same release'])),
  ('pinned release in a local action lags the file', {'w.yml': R + 'jobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': "runs:\n  using: composite\n  steps:\n    - uses: dtolnay/rust-toolchain@" + SHA + " # v1\n      with:\n        toolchain: 1.2.3\n", 'rust-toolchain.toml': PIN},
   (1, ['REFUSED: w.yml: act/action.yml, line 6: the toolchain 1.2.3 is not the release rust-toolchain.toml pins (1.2.4): read the channel from that file, or write the same release'])),
  ('pinned release from an expression', {'w.yml': R + TC % "${{ steps.pin.outputs.channel }}", 'rust-toolchain.toml': PIN},
   (0, [])),
  ('pinned dated channel is not compared', {'w.yml': R + TC % "nightly-2026-01-01", 'rust-toolchain.toml': PIN},
   (0, [])),
  ('floating on a push', {'w.yml': "on: push\n" + R + TC % "stable"},
   (1, ['REFUSED: w.yml: line 9: a floating toolchain (stable) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins'])),
  ('floating on a pull request, as a list', {'w.yml': "on: [pull_request]\n" + R + TC % "beta"},
   (1, ['REFUSED: w.yml: line 9: a floating toolchain (beta) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins'])),
  ('floating on a release, as a mapping', {'w.yml': "on:\n  release:\n    types: [published]\n" + R + TC % "1.2"},
   (1, ['REFUSED: w.yml: line 11: a floating toolchain (1.2) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins'])),
  ('floating with a host on a call', {'w.yml': "on:\n  workflow_call:\n" + R + TC % "stable-x86_64-unknown-linux-gnu"},
   (1, ['REFUSED: w.yml: line 10: a floating toolchain (stable-x86_64-unknown-linux-gnu) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins'])),
  ('floating in an env on a merge queue', {'w.yml': "on: merge_group\n" + R + 'jobs:\n  a:\n    env:\n      RUSTUP_TOOLCHAIN: stable\n    steps:\n      - run: echo\n'},
   (1, ['REFUSED: w.yml: line 7: a floating toolchain (stable) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins'])),
  ('floating in a local action on a push', {'w.yml': "on: push\n" + R + 'jobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': "runs:\n  using: composite\n  steps:\n    - uses: dtolnay/rust-toolchain@" + SHA + " # v1\n      with:\n        toolchain: stable\n"},
   (1, ['REFUSED: w.yml: act/action.yml, line 6: a floating toolchain (stable) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins'])),
  ('floating on a schedule alone, a canary', {'w.yml': "on:\n  schedule:\n    - cron: '0 3 * * 0'\n  workflow_dispatch:\n" + R + TC % "stable"},
   (0, [])),
  # Nightly: undated in no workflow that runs on a change, and every dated
  # one is the one the nightly file pins.
  ('nightly on a push', {'w.yml': "on: push\n" + R + TC % "nightly"},
   (1, ['REFUSED: w.yml: line 9: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly with a host on a pull request', {'w.yml': "on: [pull_request]\n" + R + TC % "nightly-x86_64-unknown-linux-gnu"},
   (1, ['REFUSED: w.yml: line 9: a floating nightly (nightly-x86_64-unknown-linux-gnu) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly a script selects on a push', {'w.yml': "on: push\n" + R + "jobs:\n  a:\n    steps:\n      - run: cargo +nightly build\n"},
   (1, ['REFUSED: w.yml: line 7: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly in an env on a release', {'w.yml': "on:\n  release:\n" + R + 'jobs:\n  a:\n    env:\n      RUSTUP_TOOLCHAIN: nightly\n    steps:\n      - run: echo\n'},
   (1, ['REFUSED: w.yml: line 8: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly written for the later steps on a call', {'w.yml': "on: workflow_call\n" + R + 'jobs:\n  a:\n    steps:\n      - run: echo "RUSTUP_TOOLCHAIN=nightly" >> "$GITHUB_ENV"\n'},
   (1, ['REFUSED: w.yml: line 7: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly rustup installs on a push', {'w.yml': "on: push\n" + R + "jobs:\n  a:\n    steps:\n      - run: rustup toolchain install nightly\n"},
   (1, ['REFUSED: w.yml: line 7: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly in a local action on a push', {'w.yml': "on: push\n" + R + 'jobs:\n  a:\n    steps:\n      - uses: ./act\n', 'act/action.yml': "runs:\n  using: composite\n  steps:\n    - uses: dtolnay/rust-toolchain@" + SHA + " # v1\n      with:\n        toolchain: nightly\n"},
   (1, ['REFUSED: w.yml: act/action.yml, line 6: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly in a script the workflow runs, on a push', {'w.yml': "on: push\n" + R + "jobs:\n  a:\n    steps:\n      - run: scripts/f.sh\n", 'scripts/f.sh': "cargo +nightly build\n"},
   (1, ['REFUSED: w.yml: scripts/f.sh, line 1: a floating nightly (nightly) in a workflow that runs on a push, a pull request or a release: install the dated nightly nightly-toolchain.toml pins (.github/actions/pinned-nightly)'])),
  ('nightly on a schedule alone, a canary', {'w.yml': "on:\n  schedule:\n    - cron: '0 3 * * 0'\n" + R + TC % "nightly"},
   (0, [])),
  ('a dated nightly that is not the pinned one', {'w.yml': "on: push\n" + R + TC % "nightly-2026-01-01", NF: NP},
   (1, ['REFUSED: w.yml: line 9: the nightly nightly-2026-01-01 is not the one nightly-toolchain.toml pins (nightly-2026-02-02): read it from that file (.github/actions/pinned-nightly), or write the same date'])),
  ('a dated nightly a script selects that is not the pinned one, on a schedule', {'w.yml': "on:\n  schedule:\n    - cron: '0 3 * * 0'\n" + R + "jobs:\n  a:\n    steps:\n      - run: cargo +nightly-2026-01-01 miri test\n", NF: NP},
   (1, ['REFUSED: w.yml: line 9: the nightly nightly-2026-01-01 is not the one nightly-toolchain.toml pins (nightly-2026-02-02): read it from that file (.github/actions/pinned-nightly), or write the same date'])),
  ('a dated nightly with a host that is not the pinned one', {'w.yml': R + 'jobs:\n  a:\n    env:\n      RUSTUP_TOOLCHAIN: nightly-2026-01-01-x86_64-unknown-linux-gnu\n    steps:\n      - run: echo\n', NF: NP},
   (1, ['REFUSED: w.yml: line 6: the nightly nightly-2026-01-01-x86_64-unknown-linux-gnu is not the one nightly-toolchain.toml pins (nightly-2026-02-02): read it from that file (.github/actions/pinned-nightly), or write the same date'])),
  ('the pinned nightly passes, with and without a host', {'w.yml': "on: push\n" + R + TC % "nightly-2026-02-02" + "      - run: cargo +nightly-2026-02-02-x86_64-unknown-linux-gnu build\n", NF: NP},
   (0, [])),
  ('a nightly from an expression is read where it is written', {'w.yml': "on: push\n" + R + TC % "${{ steps.pin.outputs.channel }}", NF: NP},
   (0, [])),
  ('a nightly file that names no dated nightly is refused', {'w.yml': R + "jobs: {}\n", NF: '[toolchain]\nchannel = "nightly"\n'},
   (1, ['REFUSED: nightly-toolchain.toml: names no dated nightly (nightly): write channel = "nightly-YYYY-MM-DD"'])),
  ('a nightly file with a host is refused', {'w.yml': R + "jobs: {}\n", NF: '[toolchain]\nchannel = "nightly-2026-02-02-x86_64-unknown-linux-gnu"\n'},
   (1, ['REFUSED: nightly-toolchain.toml: names no dated nightly (nightly-2026-02-02-x86_64-unknown-linux-gnu): write channel = "nightly-YYYY-MM-DD"'])),
  ('a nightly file with no channel is refused', {'w.yml': R + "jobs: {}\n", NF: '[toolchain]\n'},
   (1, ['REFUSED: nightly-toolchain.toml: names no dated nightly (none named): write channel = "nightly-YYYY-MM-DD"'])),
  ('dated stable on a push', {'w.yml': "on: push\n" + R + TC % "stable-2026-01-01"},
   (0, [])),
  ('release and expression on a push', {'w.yml': "on: push\n" + R + TC % "1.2.4" + '  b:\n    steps:\n      - uses: dtolnay/rust-toolchain@' + SHA + ' # master\n        with:\n          toolchain: ${{ steps.pin.outputs.channel }}\n', 'rust-toolchain.toml': PIN},
   (0, [])),
]


def main():
    failures = []
    for name, files, want in CASES:
        got = run(files)
        if got != want:
            failures.append("%s: %r, wanted %r" % (name, got, want))
    root = tempfile.mkdtemp()
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = P.main(["workflow_pins.py", os.path.join(root, "none")])
        if status != 1 or "no workflow directory" not in out.getvalue():
            failures.append("a missing directory: %r %r" % (status, out.getvalue()))
        os.makedirs(os.path.join(root, ".github", "workflows"))
        os.makedirs(os.path.join(root, "scripts"))
        with open(os.path.join(root, ".github", "workflows", "w.yml"), "w") as f:
            f.write("permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: scripts/x.sh\n")
        with open(os.path.join(root, "scripts", "x.sh"), "w") as f:
            f.write("cargo install a\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = P.main(["workflow_pins.py", os.path.join(root, ".github", "workflows")])
        if status != 1 or "REFUSED: scripts/x.sh: line 1: cargo install without --locked" not in out.getvalue():
            failures.append("scripts resolve from above .github/workflows: %r %r" % (status, out.getvalue()))
        if "2 workflow pin problem(s)." not in out.getvalue():
            failures.append("the count of problems: %r" % out.getvalue())
        clean = io.StringIO()
        with open(os.path.join(root, "scripts", "x.sh"), "w") as f:
            f.write("cargo install --locked a@1.0.0\n")
        with contextlib.redirect_stdout(clean), contextlib.redirect_stderr(clean):
            status = P.main(["workflow_pins.py", os.path.join(root, ".github", "workflows")])
        if status != 0 or clean.getvalue() != P.OK + "\n":
            failures.append("a clean tree prints the OK line alone: %r %r" % (status, clean.getvalue()))
    finally:
        shutil.rmtree(root)
    for failure in failures:
        print("FAIL: workflow_pins: " + failure, file=sys.stderr)
    total = len(CASES) + 4
    print("workflow_pins tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
