# shellcheck shell=bash disable=SC2016,SC2154
# Cases for scripts/check-workflow-pins.sh: forms the readers take wherever
# they stand, in every job. Sourced by scripts/check-workflow-pins-tests.sh.

# A substitution is a command of the script wherever it stands: in the
# value a parameter expansion falls back to, and in an array.
UNLOCKED="line 5: cargo install without --locked"
block_case "an install in backticks inside a quoted parameter expansion is read" 1 "$UNLOCKED" 'echo "${TOOLS:-`cargo install cargo-audit`}"'
block_case "an install in backticks inside a bare parameter expansion is read" 1 "$UNLOCKED" 'echo ${TOOLS:-`cargo install cargo-audit`}'
block_case "an install in backticks inside a nested parameter expansion is read" 1 "$UNLOCKED" 'echo "${A:-${B:-`cargo install cargo-audit`}}"'
block_case "an install in backticks inside an array is read" 1 "$UNLOCKED" 'tools=(`cargo install cargo-audit`)'
block_case "an install in a process substitution inside an array is read" 1 "$UNLOCKED" 'tools=(<(cargo install cargo-audit))'
block_case "a pinned install in backticks inside a parameter expansion passes" 0 "OK: every action" 'echo "${TOOLS:-`cargo install --locked cargo-audit@0.22.2`}"'
block_case "backticks in single quotes inside a parameter expansion are text" 0 "OK: every action" "echo \"\${TOOLS:-'\`cargo install cargo-audit\`'}\""

# A long option is the one any prefix of it names, as getopt_long takes
# it, and a cluster of short options is read letter by letter.
block_case "the string flock runs through a shortened --command is read" 1 "$UNLOCKED" "flock lock --comm 'cargo install cargo-audit'"
block_case "the string su runs through a shortened --command is read" 1 "$UNLOCKED" "su --comm 'cargo install cargo-audit' builder"
block_case "the string env splits through a shortened --split-string is read" 1 "$UNLOCKED" "env --split 'cargo install cargo-audit'"
block_case "the string env splits through -S in a cluster is read" 1 "$UNLOCKED" "env -iS 'cargo install cargo-audit'"
block_case "a sed program given through a shortened --expression is read" 1 "a sed program that runs a command (the e command or flag) is not read" "sed --expr='1e cargo install cargo-audit' -e p Cargo.toml"
block_case "a sed program from a file named in a cluster is refused" 1 "a sed program from a file is not read: -Ef" "sed -Ef tools.sed Cargo.toml"
block_case "a sed program from a file named by a shortened --file is refused" 1 "a sed program from a file is not read: --fil=tools.sed" "sed --fil=tools.sed Cargo.toml"
block_case "a sed program after options in a cluster passes" 0 "OK: every action" "sed -nE 's/^version = \"(.*)\"/\\1/p' Cargo.toml"

# awk takes a program, a file of one or a library through an option too.
AWK_OPTION="an awk program, a file of one or a library given by an option is not read"
block_case "an awk program given by --source is refused" 1 "$AWK_OPTION: --source" "awk --source='BEGIN { system(\"cargo install cargo-audit\") }' Cargo.toml"
block_case "an awk program given by -e is refused" 1 "$AWK_OPTION: -e" "awk -e 'BEGIN { print 1 }' Cargo.toml"
block_case "an awk library loaded by -l is refused" 1 "$AWK_OPTION: -l" "awk -l tools '{ print }' Cargo.toml"
block_case "an awk file included by a shortened --include is refused" 1 "$AWK_OPTION: --incl" "awk --incl=tools '{ print }' Cargo.toml"
block_case "an awk program with a separator and a variable passes" 0 "OK: every action" "awk -F: -v n=1 '{ print \$n }' Cargo.toml"

# git runs a program it is given, or one in place of the program the other
# end of a transfer runs, with no setting made.
GIT_RUNS="a git command that runs a program it is given is not read"
GIT_OPTION="a git option that runs a program is not read"
block_case "git bisect run is refused" 1 "line 5: $GIT_RUNS: git bisect run" "git bisect run ./tools/check"
block_case "git submodule foreach is refused" 1 "$GIT_RUNS: git submodule foreach" "git submodule foreach 'cargo install cargo-audit'"
block_case "git filter-branch is refused" 1 "$GIT_RUNS: git filter-branch" "git filter-branch --tree-filter 'cargo install cargo-audit' HEAD"
block_case "git difftool is refused" 1 "$GIT_RUNS: git difftool" "git difftool -y HEAD~1"
block_case "git rebase -x is refused" 1 "$GIT_OPTION: git rebase -x" "git rebase -x 'cargo install cargo-audit' main"
block_case "git rebase with a shortened --exec is refused" 1 "$GIT_OPTION: git rebase --exec" "git rebase --ex='cargo install cargo-audit' main"
block_case "git fetch with another upload-pack is refused" 1 "$GIT_OPTION: git fetch --upload-pack" "git fetch --upload-pack=./tools/pack origin"
block_case "git push with another receive-pack is refused" 1 "$GIT_OPTION: git push --receive-pack" "git push --receive-pack ./tools/pack origin main"
block_case "git clone with another upload-pack is refused" 1 "$GIT_OPTION: git clone -u" "git clone -u ./tools/pack https://example.invalid/r"
block_case "git grep with a pager is refused" 1 "$GIT_OPTION: git grep -Oless" "git grep -Oless needle"
block_case "a setting that runs a program on a clone is refused" 1 "a git setting that can run a program is not read: core.fsmonitor" "git clone -c core.fsmonitor=./tools/watch https://example.invalid/r"
block_case "a setting that runs a program on a clone, joined, is refused" 1 "a git setting that can run a program is not read: core.pager" "git clone --config=core.pager=./tools/page https://example.invalid/r"
block_case "a setting that runs nothing on a clone passes" 0 "OK: every action" "git clone -c user.name=bot https://example.invalid/r"
block_case "git push with an upstream passes" 0 "OK: every action" "git push -u origin main"
block_case "git submodule update passes" 0 "OK: every action" "git submodule update --init"
block_case "an option after the end of options is a path" 0 "OK: every action" "git log --oneline -- --exec"

# A gh extension is a program installed from a repository with no pin, and
# an alias is a command the check does not see where it runs.
block_case "gh extension install is refused" 1 "line 5: an install route the check does not read: gh extension" "gh extension install owner/gh-tool"
block_case "gh ext exec is refused" 1 "an install route the check does not read: gh extension" "gh ext exec tool"
block_case "gh alias set is refused" 1 "a gh alias is not read: write the command out" "gh alias set co 'pr checkout'"
block_case "gh alias list passes" 0 "OK: every action" "gh alias list"
block_case "gh api passes" 0 "OK: every action" "gh api repos/owner/repo"

# A builtin that runs a command through an option, a name reference, and a
# coprocess, which runs the command after it.
block_case "a callback of mapfile is refused" 1 "a command mapfile runs through an option is not read" "mapfile -C 'cargo install cargo-audit' -c 1 lines < list"
block_case "a command compgen runs is refused" 1 "a command compgen runs through an option is not read" "compgen -C 'cargo install cargo-audit'"
block_case "a key bound to a command is refused" 1 "a command bind runs through an option is not read" "bind -x '\"\\C-t\": cargo install cargo-audit'"
block_case "a name reference is refused" 1 "a name reference is not read (declare -n)" "declare -n ref=PATH"
block_case "a local name reference is refused" 1 "a name reference is not read (local -n)" "f() { local -n ref=\$1; }"
block_case "mapfile with no callback passes" 0 "OK: every action" "mapfile -t lines < list"
block_case "compgen over file names passes" 0 "OK: every action" "compgen -G 'target/*.crate' >/dev/null"
for coprocess in 'coproc ./scripts/tools.sh' 'coproc tools { ./scripts/tools.sh; }'; do
  case_ "the repository script of $coprocess is read" 1 "scripts/tools.sh: line 1: cargo install without --locked" c.yml "jobs:
  a:
    steps:
      - run: $coprocess" scripts/tools.sh "cargo install cargo-audit"
done

# A variable is assigned by more than NAME=value: the variable of a for,
# the operands of read, mapfile, getopts and printf -v, and an expansion
# that assigns as it expands. One through which a program runs another is
# refused by name wherever it is assigned, and so is an assignment to a
# variable that a variable names.
RUNS_ANOTHER="makes a program run another one or load code before the command it is given"
block_case "a for that assigns BASH_ENV is refused" 1 "line 5: BASH_ENV $RUNS_ANOTHER" "for BASH_ENV in tools/env.sh; do bash -c true; done"
block_case "a read that assigns PS4 is refused" 1 "PS4 $RUNS_ANOTHER" "read -r PS4 < prompt"
block_case "a read into an array named GIT_SSH is refused" 1 "GIT_SSH $RUNS_ANOTHER" "read -ra GIT_SSH < ssh"
block_case "a printf that assigns PROMPT_COMMAND is refused" 1 "PROMPT_COMMAND $RUNS_ANOTHER" "printf -v PROMPT_COMMAND %s 'cargo install cargo-audit'"
block_case "a mapfile that assigns BASH_ENV is refused" 1 "BASH_ENV $RUNS_ANOTHER" "mapfile -t BASH_ENV < list"
block_case "a getopts that assigns ENV is refused" 1 "ENV $RUNS_ANOTHER" "getopts ab ENV"
block_case "an expansion that assigns BASH_ENV is refused" 1 "BASH_ENV $RUNS_ANOTHER" ': "${BASH_ENV:=tools/env.sh}"'
block_case "an expansion that assigns RUSTC_WRAPPER is refused" 1 "RUSTC_WRAPPER changes what cargo installs or runs" 'echo "${RUSTC_WRAPPER=tools/wrap.sh}"'
NAMED_BY_VARIABLE="a variable whose name comes from a variable is not read"
block_case "an export of a variable a variable names is refused" 1 "line 5: $NAMED_BY_VARIABLE: \"\$PAIR\"" 'export "$PAIR"'
block_case "a declare of a variable a variable names is refused" 1 "$NAMED_BY_VARIABLE: \"\$name=\$value\"" 'declare "$name=$value"'
block_case "a read into a variable a variable names is refused" 1 "$NAMED_BY_VARIABLE: \"\$name\"" 'read -r "$name" < list'
block_case "a printf into a variable a variable names is refused" 1 "$NAMED_BY_VARIABLE: \"\$name\"" 'printf -v "$name" %s value'
block_case "an expansion that runs the commands in a value is refused" 1 "an expansion that runs the commands in the value of a variable is not read: \${prompt@P}" 'echo "${prompt@P}"'
block_case "a for over plain names passes" 0 "OK: every action" "for crate in axess axess-core; do echo \"\$crate\"; done"
block_case "a read into plain names passes" 0 "OK: every action" "while IFS= read -r line; do echo \"\$line\"; done < list"
block_case "a read with a prompt from a variable passes" 0 "OK: every action" 'read -r -p "$prompt" answer'
block_case "a printf into a plain name passes" 0 "OK: every action" 'printf -v out "%s" "$value"'
block_case "an expansion that assigns a plain name passes" 0 "OK: every action" ': "${TMPDIR:=/tmp}"'
block_case "an export with a value from a variable passes" 0 "OK: every action" 'export RELEASE="$tag"'

# A variable that says where a program finds its settings, or the job its
# files, is the runner's to set; one that makes a program load code is
# refused in a script and in an env.
for variable in HOME XDG_CONFIG_HOME GITHUB_WORKSPACE RUNNER_TEMP GITHUB_ENV GITHUB_PATH; do
  block_case "the variable $variable in a script is refused" 1 "line 5: $variable says where a program finds its settings or the job its files" "$variable=/tmp/elsewhere git status"
  case_ "the variable $variable in an env is refused" 1 "line 4: $variable says where a program finds its settings or the job its files" v.yml "jobs:
  a:
    env:
      $variable: /tmp/elsewhere
    steps:
      - run: cargo test --locked"
done
for variable in GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE PYTHONPATH PYTHONSTARTUP PERL5LIB RUBYOPT NODE_OPTIONS AWKPATH CURL_HOME LESSOPEN TAR_OPTIONS SHELL CDPATH GH_CONFIG_DIR RUSTUP_HOME RUSTUP_DIST_SERVER; do
  block_case "the variable $variable in a script is refused" 1 "line 5: $variable $RUNS_ANOTHER" "export $variable=x"
done
case_ "the path in an env is refused" 1 "line 4: PATH in an env: names the directories every program of the job is run from" v.yml "jobs:
  a:
    env:
      PATH: /tmp/tools:/usr/bin
    steps:
      - run: cargo test --locked"

# The flags cargo hands to rustc run a program in place of the linker, or
# load code, when they name one.
FLAGS="names a program rustc runs or code it loads"
block_case "flags that name a linker are refused" 1 "line 5: RUSTFLAGS $FLAGS (linker)" 'RUSTFLAGS="-C linker=tools/ld" cargo build --locked'
block_case "exported flags that name a codegen backend are refused" 1 "RUSTFLAGS $FLAGS (codegen-backend)" 'export RUSTFLAGS="-Zcodegen-backend=tools/backend.so"'
block_case "flags for one target that add a library path are refused" 1 "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS $FLAGS (-L)" 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-L tools/lib" cargo build --locked'
block_case "flags from a variable are refused" 1 "RUSTFLAGS from a variable or an expression is not read" 'RUSTFLAGS="$EXTRA_FLAGS" cargo build --locked'
block_case "flags written for the later steps that name a linker are refused" 1 "RUSTFLAGS $FLAGS (linker)" 'echo "RUSTFLAGS=-Clinker=tools/ld" >> "$GITHUB_ENV"'
block_case "flags that deny warnings pass" 0 "OK: every action" 'RUSTFLAGS="-D warnings" cargo build --locked'
block_case "rustdoc flags that deny warnings pass" 0 "OK: every action" 'RUSTDOCFLAGS="-D warnings" cargo doc --locked'
case_ "flags in an env that name a linker are refused" 1 "line 4: RUSTFLAGS $FLAGS (link-arg)" v.yml "jobs:
  a:
    env:
      RUSTFLAGS: -C link-arg=-fuse-ld=tools/ld
    steps:
      - run: cargo build --locked"
case_ "flags in an env from an expression are refused" 1 "line 4: RUSTFLAGS from a variable or an expression is not read" v.yml "jobs:
  a:
    env:
      RUSTFLAGS: \${{ matrix.flags }}
    steps:
      - run: cargo build --locked"
case_ "flags in an env that deny warnings pass" 0 "OK: every action" v.yml "jobs:
  a:
    env:
      RUSTFLAGS: -D warnings
    steps:
      - run: cargo build --locked"
case_ "flags in a cargo configuration that name a linker are refused" 1 ".cargo/config.toml: line 3: flags that name a program rustc runs or code it loads are not read: build.rustflags" v.yml "jobs:
  a:
    steps:
      - run: cargo build --locked" .cargo/config.toml '[build]
rustflags = [
  "-C", "linker=tools/ld",
]'
block_case "flags in a --config that name a linker are refused" 1 "a --config whose build.rustflags names a program rustc runs or code it loads is not read" "cargo --config \"build.rustflags=['-Clinker=tools/ld']\" build --locked"
case_ "flags in a cargo configuration that deny warnings pass" 0 "OK: every action" v.yml "jobs:
  a:
    steps:
      - run: cargo build --locked" .cargo/config.toml '[build]
rustflags = ["-D", "warnings"]'

# A Python program is read as Python reads it: a name written with other
# code points for the same letters is the name it normalises to, and a
# lookup by name runs what a string names.
block_case "a Python program that names system in full-width letters is read" 1 "the program python3 -c runs is not read: it runs cargo install" "python3 -c 'import os; os.ｓystem(\"cargo install cargo-audit\")'"
block_case "a Python program that looks a function up by name is read" 1 "the program python3 -c runs is not read: it runs cargo install" "python3 -c 'import os; getattr(os, \"sys\" + \"tem\")(\"cargo install cargo-audit\")'"

# A shell is bash or sh with the options that set how a script fails: any
# other word of a `shell:` runs or loads what the check does not read.
shell_case() { # shell_case NAME EXPECTED_EXIT FRAGMENT SHELL
  case_ "$1" "$2" "$3" h.yml "jobs:
  a:
    steps:
      - shell: $4
        run: cargo test --locked"
}
NOT_READ="line 4: a run step in a shell the check does not read"
shell_case "a shell that runs a string before the script is refused" 1 "$NOT_READ: bash -c \"cargo install cargo-audit\" {0}" 'bash -c "cargo install cargo-audit" {0}'
shell_case "a shell that reads a start-up file is refused" 1 "$NOT_READ: bash --init-file tools/env.sh {0}" 'bash --init-file tools/env.sh {0}'
shell_case "a shell given another rc file is refused" 1 "$NOT_READ: bash --rcfile tools/env.sh -i {0}" 'bash --rcfile tools/env.sh -i {0}'
shell_case "a login shell is refused" 1 "$NOT_READ: bash -l {0}" 'bash -l {0}'
shell_case "a shell under another program is refused" 1 "$NOT_READ: env bash {0}" 'env bash {0}'
shell_case "bash with the options that set how a script fails passes" 0 "OK: every action" 'bash -euo pipefail {0}'
shell_case "bash with no profile and no rc file passes" 0 "OK: every action" 'bash --noprofile --norc -eo pipefail {0}'
shell_case "sh that stops on an error passes" 0 "OK: every action" 'sh -e {0}'
shell_case "bash by its name passes" 0 "OK: every action" bash

# A local action is read when it is composite, each of its scripts in bash
# or sh, with the local actions it uses in turn and its env.
action_case() { # action_case NAME EXPECTED_EXIT FRAGMENT ACTION [FILE CONTENT...]
  local name="$1" want="$2" fragment="$3" action="$4"
  shift 4
  case_ "$name" "$want" "$fragment" l.yml "jobs:
  a:
    steps:
      - uses: ./.github/actions/tools" .github/actions/tools/action.yml "$action" "$@"
}
action_case "a local action that runs node is refused" 1 ".github/actions/tools/action.yml: a local action that is not composite is not read: it runs node20" "name: tools
runs:
  using: node20
  main: index.js"
action_case "a local action that builds an image is refused" 1 "a local action that is not composite is not read: it runs docker" "name: tools
runs:
  using: docker
  image: docker://example.invalid/tools@$DIGEST"
action_case "a local action that says nothing of how it runs is refused" 1 "a local action that is not composite is not read: it runs nothing the check reads" "name: tools"
action_case "a script of a local action in Python is refused" 1 ".github/actions/tools/action.yml: line 5: a run step in a shell the check does not read: python" 'name: tools
runs:
  using: composite
  steps:
    - shell: python
      run: |
        import os
        os.system("cargo install cargo-audit")'
action_case "a script of a local action with no shell is refused" 1 "line 5: a run step in a shell the check does not read: none set" "name: tools
runs:
  using: composite
  steps:
    - run: cargo test --locked"
action_case "a script of a local action in a shell that runs a string is refused" 1 "line 5: a run step in a shell the check does not read: bash -c id {0}" "name: tools
runs:
  using: composite
  steps:
    - shell: bash -c id {0}
      run: cargo test --locked"
INNER="name: inner
runs:
  using: composite
  steps:
    - shell: bash
      run: cargo install cargo-audit"
action_case "an install in a local action another one uses is read" 1 ".github/actions/inner/action.yml: line 6: cargo install without --locked" "name: tools
runs:
  using: composite
  steps:
    - uses: ./.github/actions/inner" .github/actions/inner/action.yml "$INNER"
action_case "a local action another one uses and the repository does not hold is refused" 1 ".github/actions/tools/action.yml: line 5: a local action the repository does not hold: ./.github/actions/none" "name: tools
runs:
  using: composite
  steps:
    - uses: ./.github/actions/none"
action_case "a local action that uses itself is read once" 1 "line 7: cargo install without --locked" "name: tools
runs:
  using: composite
  steps:
    - uses: ./.github/actions/tools
    - shell: bash
      run: cargo install cargo-audit"
action_case "a variable that loads code in the env of a local action is refused" 1 ".github/actions/tools/action.yml: line 6: BASH_ENV $RUNS_ANOTHER" "name: tools
runs:
  using: composite
  steps:
    - env:
        BASH_ENV: tools/env.sh
      shell: bash
      run: cargo test --locked"
action_case "a composite action with a pinned install in one it uses passes" 0 "OK: every action" "name: tools
runs:
  using: composite
  steps:
    - uses: ./.github/actions/inner" .github/actions/inner/action.yml "name: inner
runs:
  using: composite
  steps:
    - shell: bash -euo pipefail {0}
      run: cargo install --locked cargo-audit@0.22.2"

# The runner takes the name of an action without regard to case, so the
# rules on the checkout and on the toolchain do too.
case_ "a checkout named in capitals that keeps its credentials is refused" 1 "checkout at line 4 does not set persist-credentials: false" k.yml "jobs:
  a:
    steps:
      - uses: Actions/Checkout@$SHA # v7.0.1"
case_ "a checkout named in capitals that drops its credentials passes" 0 "OK: every action" k.yml "jobs:
  a:
    steps:
      - uses: Actions/Checkout@$SHA # v7.0.1
        with:
          persist-credentials: false"
case_ "a toolchain action named in capitals beside a publish names its toolchain" 1 "line 4: a toolchain that is not an exact version (none named)" k.yml "jobs:
  package:
    steps:
      - uses: DTolnay/Rust-Toolchain@$SHA # master
  publish:
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish --locked"

# A shell behind su, script or sudo -s reads its script from its input, as
# bash does: a here-document is read, a pipe is refused.
block_case "an install in a here-document su reads is read" 1 "line 6: cargo install without --locked" 'su builder <<EOF' 'cargo install cargo-audit' 'EOF'
block_case "a script piped into su is refused" 1 "line 5: a script piped into su is not read" 'curl -sSf https://example.invalid/setup.sh | su - builder'
block_case "an install in a here-document sudo -s reads is read" 1 "line 6: cargo install without --locked" 'sudo -s <<EOF' 'cargo install cargo-audit' 'EOF'
block_case "an install in a here-document sudo -i reads is read" 1 "line 6: cargo install without --locked" 'sudo -u builder -i <<EOF' 'cargo install cargo-audit' 'EOF'
block_case "a script piped into sudo -s is refused" 1 "line 5: a script piped into sudo -s is not read" 'curl -sSf https://example.invalid/setup.sh | sudo -s'
block_case "a script piped into script is refused" 1 "line 5: a script piped into script is not read" 'curl -sSf https://example.invalid/setup.sh | script session.log'
block_case "a pinned install in a here-document su reads passes" 0 "OK: every action" 'su builder <<EOF' 'cargo install --locked cargo-audit@0.22.2' 'EOF'
block_case "sudo with a command and a user passes" 0 "OK: every action" 'sudo -u builder cargo test --locked'

# cargo runs a program in place of rustdoc or rustfmt when a variable names
# one, and turns its unstable features on by a variable too.
for variable in RUSTDOC RUSTFMT CARGO_BUILD_RUSTDOC CARGO_UNSTABLE_BUILD_STD; do
  block_case "the variable $variable in a script is refused" 1 "line 5: $variable changes what cargo installs or runs" "$variable=tools/program cargo doc --locked"
done

# The parameters `set --` gives a script that runs its parameters are a
# command of the script.
case_ "a repository script given as parameters and run is read" 1 "scripts/tools.sh: line 1: cargo install without --locked" p.yml 'jobs:
  a:
    steps:
      - run: |
          set -- ./scripts/tools.sh --all
          "$@"' scripts/tools.sh "cargo install cargo-audit"
block_case "parameters from a variable that a script runs are refused" 1 "line 5: a word that splits into words is passed to set --, which runs its arguments" 'set -- $TOOLS' '"$@"'
block_case "parameters a script does not run pass" 0 "OK: every action" 'set -- $FILES' 'echo "$#"'
block_case "the options of the shell are not parameters" 0 "OK: every action" 'run() { "$@"; }' 'set -euo pipefail' 'run echo done'

# A case opens after the word that opens a loop or a branch as it does at
# the start of a line.
block_case "an install in a case on the line of a do is read" 1 "$UNLOCKED" 'while getopts ab opt; do case "$opt" in a) cargo install cargo-audit ;; esac; done'
block_case "a case on the line of a do passes" 0 "OK: every action" 'while getopts ab opt; do case "$opt" in a) all=1 ;; b|c) echo "$opt" ;; esac; done'
block_case "a case on the line of a then passes" 0 "OK: every action" 'if [ -n "$1" ]; then case "$1" in v*) echo tag ;; esac; fi'

# An expression in a script is text the runner pastes in before the shell
# reads it: a title or a branch name becomes commands. It is refused in
# every job, since a job that holds nothing still makes what later jobs
# take from it. The value goes through an env.
PASTED="an expression the runner pastes into the script before the shell reads it"
block_case "an expression in a script is refused" 1 "line 5: $PASTED (\${{ github.event.issue.title }}): pass the value in an env: and quote it" 'echo "${{ github.event.issue.title }}"'
block_case "the name of a branch pasted into a script is refused" 1 "line 6: $PASTED (\${{ github.base_ref }})" 'set -eu' 'git diff "origin/${{ github.base_ref }}"...HEAD'
block_case "a value of the matrix pasted into a script is refused" 1 "line 5: $PASTED (\${{ matrix.flags }})" 'cargo check --locked ${{ matrix.flags }}'
block_case "two expressions on a line are each refused" 1 "line 5: $PASTED (\${{ needs.plan.outputs.shards }})" 'echo "${{ matrix.shard }}" "${{ needs.plan.outputs.shards }}"'
action_case "an expression pasted into the script of a local action is refused" 1 ".github/actions/tools/action.yml: line 6: $PASTED (\${{ inputs.name }})" "name: tools
runs:
  using: composite
  steps:
    - shell: bash
      run: echo \"\${{ inputs.name }}\""
case_ "an expression handed to a script in an env passes" 0 "OK: every action" x.yml 'jobs:
  a:
    strategy:
      matrix:
        flags: [--all-features]
    steps:
      - if: ${{ github.event_name == '"'pull_request'"' }}
        env:
          BASE_REF: ${{ github.base_ref }}
          FLAGS: ${{ matrix.flags }}
        run: |
          git diff "origin/$BASE_REF"...HEAD
          cargo check --locked $FLAGS'

# A program named by a path is a file the repository holds, a program of
# the runner's image, or a file a step made or downloaded, which no job
# runs: nobody read it and nothing pins it.
BY_PATH="a program run by a path the repository does not hold is not read"
block_case "a downloaded program run by its path is refused" 1 "line 7: $BY_PATH: ./tool (a file a step made or downloaded)" 'curl -sSfL -o tool https://example.invalid/tool' 'chmod +x tool' './tool --version'
block_case "a program in the runner's temporary directory is refused" 1 "line 5: $BY_PATH: \"\$RUNNER_TEMP/tool\"" '"$RUNNER_TEMP/tool" --version'
# The tilde is the text of the script the case writes.
# shellcheck disable=SC2088
block_case "a program in the home directory is refused" 1 "line 5: $BY_PATH: ~/.cargo/bin/cargo-audit" '~/.cargo/bin/cargo-audit audit'
block_case "a program by an absolute path outside the image's directories is refused" 1 "line 5: $BY_PATH: /tmp/tool" '/tmp/tool'
block_case "a built program run by its path is refused" 1 "line 5: $BY_PATH: target/release/tool" 'target/release/tool'
block_case "a program by a path that xargs runs is refused" 1 "line 5: $BY_PATH: ./tool" 'echo a | xargs ./tool'
block_case "a program by a path that find runs is refused" 1 "line 5: $BY_PATH: ./tool" 'find . -name x -exec ./tool {} \;'
block_case "a program by a path in a substitution is refused" 1 "line 5: $BY_PATH: ./tool" 'echo "${VALUE:-`./tool`}"'
block_case "a program by a path in the text of sh -c is refused" 1 "line 5: $BY_PATH: ./tool" 'sh -c "./tool --version"'
block_case "a program by a path after timeout is refused" 1 "line 5: $BY_PATH: ./tool" 'timeout 5 ./tool'
block_case "a program by a path a coprocess runs is refused" 1 "line 5: $BY_PATH: ./tool" 'coproc ./tool'
block_case "a program by a path a function runs for its caller is refused" 1 "line 6: $BY_PATH: ./tool" 'step() { local name="$1"; shift; "$@"; }' 'step "the tool" ./tool --version'
block_case "a program by a path given as parameters and run is refused" 1 "line 5: $BY_PATH: ./tool" 'set -- ./tool --flag' '"$@"'
block_case "a program by a path given as the first parameter and run is refused" 1 "line 5: $BY_PATH: ./tool" 'set -- ./tool' '"$1" --flag'
block_case "a program by a path into the image's directories passes" 0 "OK: every action" '/usr/bin/git status' '/bin/echo done'
block_case "a label that reads as a path before the command a function runs passes" 0 "OK: every action" 'step() { local name="$1"; shift; "$@"; }' 'step "lists agree (deny.toml vs .cargo/audit.toml)" echo ok'

# An external cargo subcommand (`cargo audit`) is the program `cargo-audit`
# on the runner's path. A job installs the ones it runs, locked at an exact
# version: a program the image holds, a cache restored or another job
# handed over is one nobody pinned.
EXTERNAL="an external cargo subcommand whose program the job does not install"
block_case "an external cargo subcommand the job does not install is refused" 1 "job a, line 5: $EXTERNAL (cargo xtask): install it in the job with cargo install --locked cargo-xtask@X.Y.Z" 'cargo xtask publish'
block_case "an external cargo subcommand the image holds is refused" 1 "job a, line 5: $EXTERNAL (cargo audit)" 'cargo audit --deny warnings'
block_case "a single-file package is refused" 1 "job a, line 5: $EXTERNAL (cargo tools/build.rs)" 'cargo tools/build.rs'
block_case "a subcommand installed under another name is refused" 1 "job a, line 6: $EXTERNAL (cargo upgrade)" 'cargo install --locked cargo-edit@0.13.0' 'cargo upgrade'
case_ "a subcommand another job installs is refused" 1 "job shard, line 9: $EXTERNAL (cargo mutants)" m.yml "jobs:
  plan:
    steps:
      - run: cargo install --locked cargo-mutants@27.0.0
      - run: cargo mutants --list
  shard:
    steps:
      - run: install -m 0755 plan/cargo-mutants \"\$HOME/.cargo/bin/cargo-mutants\"
      - run: cargo mutants --shard 0/4"
case_ "a subcommand a repository script runs and the job does not install is refused" 1 "job a, scripts/sweep.sh line 1: $EXTERNAL (cargo mutants)" m.yml "jobs:
  a:
    steps:
      - run: scripts/sweep.sh" scripts/sweep.sh 'cargo mutants --shard "$1"'
block_case "an external cargo subcommand the job installs passes" 0 "OK: every action" 'cargo install --locked cargo-audit@0.22.2 cargo-deny@0.20.2' 'cargo audit --deny warnings' 'cargo deny check'
block_case "an external cargo subcommand installed after it is tried passes" 0 "OK: every action" 'cargo semver-checks --version || cargo install cargo-semver-checks@0.51.0 --locked' 'cargo semver-checks check-release'
case_ "a subcommand a repository script runs and a step of the job installs passes" 0 "OK: every action" m.yml "jobs:
  a:
    steps:
      - run: cargo install cargo-mutants --version 27.0.0 --locked
      - run: scripts/sweep.sh" scripts/sweep.sh 'cargo mutants --shard "$1"'
block_case "the toolchain's own subcommands need no install" 0 "OK: every action" 'cargo fmt --all -- --check' 'cargo clippy --workspace' 'cargo +nightly miri setup'

# A --config after the subcommand sets what cargo runs as one before it
# does, and what xargs fills into the script of a shell is not read.
block_case "a program in place of rustc set after the subcommand is refused" 1 "line 5: a --config that sets build.rustc-wrapper is not read" "cargo build --locked --config 'build.rustc-wrapper=\"tools/wrap\"'"
block_case "an alias set after the subcommand is refused" 1 "line 5: a --config that sets alias.t is not read" 'cargo test --config=alias.t=install'
block_case "a configuration file named after the subcommand is refused" 1 "line 5: a --config that names a file is not read: tools/config.toml" 'cargo publish --locked --config tools/config.toml'
block_case "a setting from a variable after the subcommand is refused" 1 "line 5: a --config from a variable is not read: \"\$SETTING\"" 'cargo check --config "$SETTING"'
block_case "the options of an external subcommand are its own" 0 "OK: every action" 'cargo install --locked cargo-deny@0.20.2' 'cargo deny --config deny-production.toml check bans'
block_case "a setting that changes nothing cargo runs passes after the subcommand" 0 "OK: every action" 'cargo build --locked --config net.retry=5' 'cargo run --locked -- --config tools/config.toml'
block_case "a script xargs fills in for a shell is refused" 1 "line 5: the script sh -c runs comes from a variable or a substitution" 'cat list | xargs -I{} sh -c "{}"'
block_case "a script xargs fills in for a shell after its options is refused" 1 "line 5: the script bash -c runs comes from a variable or a substitution" 'xargs -a list -I@ bash -c @'
