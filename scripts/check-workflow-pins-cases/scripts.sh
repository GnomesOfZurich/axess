# shellcheck shell=bash disable=SC2016,SC2088,SC2154
# Cases for scripts/check-workflow-pins.sh: the scripts a job runs, read as
# the shell reads them. Sourced by scripts/check-workflow-pins-tests.sh.

block_case "an install by a quoted cargo is refused" 1 "line 5: cargo install without --locked" '"cargo" install cargo-audit'
block_case "an install by a single-quoted cargo is refused" 1 "line 5: cargo install without --locked" "'cargo' install cargo-audit"
block_case "a command word quoted in part is read" 1 "line 5: cargo install without --locked" 'car"go" install cargo-audit'
block_case "a quoted install is refused" 1 "line 5: cargo install without --locked" 'cargo "install" cargo-audit'
block_case "an install under a quoted toolchain selector is read" 1 "cargo install without --locked" 'cargo "+nightly" install cargo-audit'
block_case "an install after a quoted flag of cargo's own is read" 1 "cargo install without --locked" 'cargo "-q" install cargo-audit'
block_case "an install by cargo named by its path is read" 1 "cargo install without --locked" '~/.cargo/bin/cargo install cargo-audit'
block_case "an install by a quoted variable with cargo as its default is refused" 1 "line 5: cargo install without --locked" '"${CARGO:-cargo}" install cargo-audit'
block_case "an install by the quoted CARGO variable is refused" 1 "line 5: no exact version for cargo-audit" '"${CARGO}" install --locked cargo-audit'
block_case "an install by a quoted variable of another name is read" 1 "cargo install without --locked" '"$TOOL" install cargo-audit'
block_case "an install by a quoted substitution is read" 1 "cargo install without --locked" '"$(which cargo)" install cargo-audit'
block_case "a cargo subcommand from a variable is refused by name" 1 'a cargo subcommand from a variable is not read: "$SUB"' 'cargo "$SUB" cargo-audit'
block_case "a pinned install with both words quoted passes" 0 "OK: every action" '"cargo" "install" --locked cargo-audit@0.22.2'
block_case "a pinned install by the quoted CARGO variable passes" 0 "OK: every action" '"$CARGO" install --locked cargo-audit@0.22.2'
# A command word whose value splits is any command and its arguments, so it
# is refused by name, whatever its name; quoted, it is one program.
block_case "an unquoted variable with cargo as its default is refused by name" 1 'line 5: a command from an expansion that splits into words is not read: ${CARGO:-cargo}' '${CARGO:-cargo} install --locked cargo-audit@0.22.2'
block_case "an unquoted CARGO variable is refused by name" 1 'line 5: a command from an expansion that splits into words is not read: $CARGO' '$CARGO install --locked cargo-audit@0.22.2'
block_case "an unquoted variable holding a whole install is refused by name" 1 'line 6: a command from an expansion that splits into words is not read: $c' 'c="cargo install cargo-audit"' '$c'
block_case "an unquoted substitution as the command is refused by name" 1 'line 5: a command from an expansion that splits into words is not read: $(which cargo)' '$(which cargo) install --locked cargo-audit@0.22.2'
block_case "an array as the command is refused by name" 1 'line 6: a command from an expansion that splits into words is not read: "${tools[@]}"' 'tools=(cargo install cargo-audit)' '"${tools[@]}"'
block_case "a variable split on another separator is refused by name" 1 'line 7: a command from an expansion that splits into words is not read: $c' 'IFS=x' 'c=cargoxinstallxcargo-audit' '$c'
block_case "a variable command and a variable subcommand are refused by name" 1 'line 5: a command from an expansion that splits into words is not read: $CARGO' '$CARGO $SUB cargo-audit'
block_case "a quoted variable command and a quoted variable subcommand are refused by name" 1 'line 5: a cargo subcommand from a variable is not read: "$SUB"' '"$CARGO" "$SUB" cargo-audit'
# What xargs and find -exec fill in from their input is a word the check
# cannot read, so it may not be the subcommand of cargo.
block_case "xargs filling in the subcommand of cargo is refused" 1 "line 5: a cargo subcommand from a variable is not read: the input of xargs" 'printf "install\ncargo-audit\n" | xargs cargo'
block_case "xargs replacing the subcommand of cargo is refused" 1 "line 5: a cargo subcommand from a variable is not read: {}" 'echo install | xargs -I {} cargo {} cargo-audit'
block_case "find -exec filling in the subcommand of cargo is refused" 1 "line 5: a cargo subcommand from a variable is not read: {}" 'find install -maxdepth 0 -exec cargo {} cargo-audit \;'
block_case "find -exec running an install is read" 1 "line 5: cargo install without --locked" 'find . -maxdepth 0 -execdir cargo install cargo-audit \;'
# A brace expansion or a pathname pattern makes words the script does not
# hold as written, so it reads as an expansion that splits; inside `[[ ]]`
# nothing is expanded, and its parentheses and bars end no command.
block_case "a brace expansion as the command is refused by name" 1 "line 5: a command from an expansion that splits into words is not read: {cargo,install,cargo-audit}" '{cargo,install,cargo-audit}'
block_case "a brace expansion holding a shell is refused by name" 1 'line 5: a command from an expansion that splits into words is not read: {bash,-c,"cargo install cargo-audit"}' '{bash,-c,"cargo install cargo-audit"}'
block_case "a brace expansion in the command word is refused by name" 1 "line 5: a command from an expansion that splits into words is not read: c{a,}rgo" 'c{a,}rgo install cargo-audit'
block_case "a brace expansion as the subcommand is refused by name" 1 "line 5: a cargo subcommand from a variable is not read: {install,cargo-audit}" 'cargo {install,cargo-audit}'
block_case "a sequence expansion as the subcommand is refused by name" 1 "line 5: a cargo subcommand from a variable is not read: {1..2}" 'cargo {1..2}'
block_case "a pattern in the command word is refused by name" 1 "line 5: a command from an expansion that splits into words is not read: ~/.cargo/bin/car?o" '~/.cargo/bin/car?o install cargo-audit'
block_case "a pattern as the subcommand is refused by name" 1 "line 5: a cargo subcommand from a variable is not read: ins*ll" 'cargo ins*ll cargo-audit'
block_case "quoted braces and patterns are text" 1 "line 5: cargo install without --locked" "cargo install '{a,b}' \"*\" cargo-audit"
block_case "a conditional with a regex ends where it closes" 1 "line 5: cargo install without --locked" '[[ $v =~ ^[0-9]+(\.[0-9]+)?$ ]] && cargo install cargo-audit'
block_case "a conditional after if and ! reads as one" 0 "OK: every action" 'if ! [[ "$r" =~ ^release/(next|[0-9]+\.x)$ ]]; then exit 1; fi'
block_case "a conditional that does not close is refused" 1 "line 5: a script the check cannot read: a conditional expression that does not close" '[[ -f x ; cargo build'
block_case "xargs and find -exec running other programs pass" 0 "OK: every action" 'git ls-files | xargs grep -n x' 'find . -name "*.json" -exec mv {} out/ \;'
block_case "a function that runs its arguments is refused a word that splits" 1 'line 6: a word that splits into words is passed to run, which runs its arguments, and is not read: $c' 'run() { "$@"; }' 'run $c'
block_case "a function that runs its arguments takes quoted words" 0 "OK: every action" 'run() { "$@"; }' 'run "$c" --version'
# The words a function or a script that runs its arguments is called with
# are a command, read as one; and a shell given -c, eval, or an interpreter
# given -c or -e, among the arguments of another program is read from there.
block_case "a function that runs its arguments called with bash -c is read" 1 "line 6: cargo install without --locked" 'run() { "$@"; }' 'run bash -c "cargo install cargo-audit"'
block_case "a function that runs its arguments called with eval is read" 1 "line 6: cargo install without --locked" 'run() { "$@"; }' 'run eval "cargo install cargo-audit"'
block_case "a function that runs its arguments called with python -c is read" 1 "line 6: the program python3 -c runs is not read: it runs cargo install" 'run() { "$@"; }' "run python3 -c 'import os; os.system(\"cargo install x\")'"
block_case "a function that runs its later arguments called with a shell is read" 1 "line 6: cargo install without --locked" 'step() { echo "$1"; "${@:2}"; }' 'step label sh -c "cargo install cargo-audit"'
block_case "a shell given -c after another program's arguments is read" 1 "line 5: cargo install without --locked" 'flock /tmp/lock bash -ec "cargo install cargo-audit"'
block_case "eval after another program's arguments is read" 1 "line 5: cargo install without --locked" 'docker run image eval "cargo install cargo-audit"'
block_case "an interpreter given -c after another program's arguments is read" 1 "line 5: the program python -c runs is not read: it runs cargo install" "nice -n 5 time python -c 'import os; os.system(\"cargo install x\")'"
block_case "a shell named among the words of a search runs nothing" 0 "OK: every action" 'grep -rn bash .' 'run() { "$@"; }' 'run cargo build --locked'
block_case "a quoted program name and a variable argument pass" 0 "OK: every action" 'check-tool "$arg" "$file"'
block_case "an install after a prefix command is read" 1 "cargo install without --locked" 'env RUSTFLAGS=-Dwarnings timeout 600 cargo install cargo-audit'
block_case "the two words on continued lines are one install" 1 "line 5: cargo install without --locked" 'cargo \' '  install cargo-audit'
block_case "a flag and the subcommand on continued lines are one install" 1 "line 5: no exact version for cargo-audit" 'cargo \' '  --locked \' '  install cargo-audit'
block_case "an unversioned crate on a continued line is refused" 1 "line 5: no exact version for cargo-deny" 'cargo install --locked cargo-audit@0.22.2 \' '  cargo-deny'
block_case "a pinned install continued over two lines passes" 0 "OK: every action" 'cargo install --locked \' '  cargo-audit@0.22.2'
block_case "a pinned install continued over three lines passes" 0 "OK: every action" 'cargo install \' '  --locked \' '  cargo-mutants --version 26.1.0'
block_case "a continued line keeps the number of the lines after it" 1 "line 7: cargo install without --locked" 'echo one \' '  two' 'cargo install cargo-audit@0.22.2'
block_case "a comment does not continue onto the next line" 1 "line 5: cargo install without --locked" 'cargo install cargo-audit # \' '  --locked --version 0.22.2'
block_case "a comment line after a continued line ends the arguments" 1 "line 5: cargo install names no crate" 'cargo install --locked \' '# the audit tool' '  cargo-audit@0.22.2'
block_case "the two words on a comment line install nothing" 0 "OK: every action" '# cargo install cargo-audit'
block_case "the two words in a sentence install nothing" 0 "OK: every action" 'echo "run cargo install to get the tool"'
block_case "a here-document holds text, not commands" 0 "OK: every action" 'cat <<EOF' 'cargo install cargo-audit' 'EOF'
block_case "a here-document after a pinned install passes" 0 "OK: every action" 'cargo install --locked cargo-audit@0.22.2 <<EOF' 'yes' 'EOF'
block_case "a here-document with tabs stripped ends at its delimiter" 1 "line 8: cargo install without --locked" 'cat <<-EOF' 'text' 'EOF' 'cargo install cargo-audit'
block_case "a substitution in a here-document runs" 1 "cargo install without --locked" 'cat <<EOF' '$(cargo install cargo-audit)' 'EOF'
block_case "a substitution in a quoted here-document is text" 0 "OK: every action" "cat <<'EOF'" '$(cargo install cargo-audit)' 'EOF'
block_case "a here-document handed to a shell runs" 1 "cargo install without --locked" 'bash <<EOF' 'cargo install cargo-audit' 'EOF'
block_case "a here-document that does not close is refused" 1 "a script the check cannot read: a here-document with no closing EOF" 'cat <<EOF' 'text'
block_case "a quote that does not close is refused" 1 "a script the check cannot read: a quote that does not close" 'echo "text'
block_case "a case statement is read" 1 "cargo install without --locked" 'case "$x" in' '  a|b) cargo install cargo-audit ;;' 'esac'
block_case "a case statement in a substitution is read" 0 "OK: every action" 'y=$(case "$x" in a) echo one ;; esac)' 'cargo install --locked cargo-audit@0.22.2'
# Each part of a case pattern is skipped as the shell skips it, and no
# further: the pattern after `|`, after a leading `(` and after `;;` or `;&`,
# a parenthesis in a quoted pattern, and the arms of a nested case.
block_case "an install after a quoted pattern that follows a bar is read" 1 "line 5: cargo install without --locked" 'case "$x" in a|"b) c") cargo install cargo-audit ;; esac'
block_case "an install after a quoted pattern that follows a leading parenthesis is read" 1 "line 5: cargo install without --locked" 'case "$x" in ("b) c") cargo install cargo-audit ;; esac'
block_case "an install in the arm after a fall-through is read" 1 "line 6: cargo install without --locked" 'case "$x" in a) true ;&' '  b) cargo install cargo-audit ;; esac'
block_case "an install in the arm after a double semicolon is read" 1 "line 6: cargo install without --locked" 'case "$x" in a) true ;;' '  (b) cargo install cargo-audit ;; esac'
block_case "a piped install after a nested case is read" 1 "line 6: cargo install without --locked" 'case "$x" in a) case "$y" in b) true ;; esac' '  cargo install cargo-audit | cat ;; esac'
# The lines of a backtick substitution are the script's lines: a command on
# the line after the opening backtick, and a problem at the end of a line.
block_case "an install on the line after a backtick is on that line" 1 "line 6: cargo install without --locked" 'x=`' 'cargo install cargo-audit`'
block_case "an install on the line after a quoted backtick is on that line" 1 "line 6: cargo install without --locked" 'x="`' 'cargo install cargo-audit`"'
block_case "an install on the line after a backtick in a here-document is on that line" 1 "line 7: cargo install without --locked" 'cat <<EOF' '`' 'cargo install cargo-audit`' 'EOF'
block_case "a problem at the end of a line in backticks is on that line" 1 "line 5: a script the check cannot read: a redirection with no target" 'x=`echo >' '`'
block_case "a problem at the end of a line in quoted backticks is on that line" 1 "line 5: a script the check cannot read: a redirection with no target" 'x="`echo >' '`"'
block_case "a problem at the end of a line in backticks in a here-document is on that line" 1 "line 6: a script the check cannot read: a redirection with no target" 'cat <<EOF' '`echo >' '`' 'EOF'
block_case "a substitution that does not close is refused on its last line" 1 "line 6: a script the check cannot read: a substitution that does not close" 'echo $(' 'x'
block_case "a piped install after a case is read" 1 "line 6: cargo install without --locked" 'case "$x" in a) true ;; esac' 'cargo install cargo-audit | cat'
block_case "a subshell install after a case is read" 1 "line 6: cargo install without --locked" 'case "$x" in a) true ;; esac' '( cargo install cargo-audit )'
block_case "an array is one word" 0 "OK: every action" 'tools=(cargo install x)' 'cargo install --locked cargo-audit@0.22.2'
# A reserved word is reserved only as written bare: a quoted or escaped
# `case` is a command of that name, so what follows it is not a pattern.
for spelling in '"case"' "'case'" '\case' 'ca"se"'; do
  block_case "a subshell after $spelling in is read" 1 "line 6: cargo install without --locked" "$spelling in || true" '( cargo install cargo-audit )'
  block_case "a pipeline after $spelling in is read" 1 "line 6: cargo install without --locked" "$spelling in || true" 'cargo install cargo-audit | cat'
done
block_case "an install after a quoted esac in a case arm is read" 1 "line 6: cargo install without --locked" 'case x in a)' '  "esac" | cargo install cargo-audit ;;' 'esac'
block_case "a quoted in does not open the patterns of a case" 1 "a closing parenthesis that closes nothing" 'case x "in" a) b ;; esac'
for spelling in '"if"' '\then' "'!'"; do
  block_case "an install after a quoted reserved word $spelling is still read" 1 "line 5: cargo install without --locked" "$spelling cargo install cargo-audit"
done

# A folded scalar, a plain scalar over two lines and a double-quoted scalar
# are read as the runner reads them: folded into one line, escapes decoded.
case_ "the two words on two lines of a folded scalar are one install" 1 "line 5: cargo install without --locked" folded.yml "jobs:
  a:
    steps:
      - run: >
          cargo
          install cargo-audit"
case_ "the arguments of an install on a later line of a folded scalar are read" 0 "OK: every action" folded.yml "jobs:
  a:
    steps:
      - run: >
          cargo install --locked
          cargo-audit@0.22.2"
case_ "a plain scalar over two lines is one install" 1 "cargo install without --locked" plain.yml "jobs:
  a:
    steps:
      - run: cargo
          install cargo-audit"
case_ "a command word behind a YAML escape is read" 1 "cargo install without --locked" esc.yml "jobs:
  a:
    steps:
      - run: \"c\\x61rgo install cargo-audit\""
case_ "a quoted run value with an unversioned install is refused" 1 "no exact version for cargo-audit" q.yml "jobs:
  a:
    steps:
      - \"run\": \"cargo install cargo-audit --locked\""
case_ "a quoted run value with a pinned install passes" 0 "OK: every action" q.yml "jobs:
  a:
    steps:
      - \"run\": \"cargo install cargo-audit@0.22.2 --locked\""
crlf() { printf '%s\n' "$1" | awk '{ printf "%s\r\n", $0 }'; }
case_ "a pinned install continued over two CRLF lines passes" 0 "OK: every action" crlf.yml "$(crlf "jobs:
  a:
    steps:
      - run: |
          cargo install --locked \\
            cargo-audit@0.22.2")"
case_ "an unversioned crate on a continued CRLF line is refused" 1 "line 5: no exact version for cargo-deny" crlf.yml "$(crlf "jobs:
  a:
    steps:
      - run: |
          cargo install --locked cargo-audit@0.22.2 \\
            cargo-deny")"

# Every other route that installs or runs a tool is refused by name.
for route in 'cargo binstall cargo-audit' 'cargo quickinstall cargo-audit' 'cargo-binstall cargo-audit' 'pip install ruff' 'python3 -m pip install ruff' 'npm install -g x' 'npx x' 'go install example.invalid/x@latest' 'sudo apt-get install -y jq' 'brew install jq' 'gem install x' 'uvx ruff'; do
  block_case "the install route $route is refused" 1 "an install route the check does not read" "$route"
done
for route in 'npm run tools' 'yarn tools' 'pnpm run tools' 'bun x tools'; do
  block_case "the package scripts of $route are refused" 1 "an install route the check does not read" "$route"
done
# A task runner runs the recipes of a file the check does not read, so it is
# refused by name wherever the shell runs it.
for runner in make gmake just task rake ninja; do
  case_ "the task runner $runner is refused beside a secret" 1 "line 4: the recipes $runner runs are not read: $runner" s.yml "jobs:
  publish:
    steps:
      - run: $runner tools
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: cargo publish" Makefile "tools:
	cargo install cargo-audit"
done
block_case "a task runner after sudo is refused" 1 "line 5: the recipes make runs are not read" 'sudo -E make tools'
block_case "the name of a task runner as an argument runs nothing" 0 "OK: every action" 'echo make' 'ls justfile'

# A script a command runs is read as part of the job.
case_ "a repository script the workflow runs is read" 1 "scripts/tools.sh: line 2: cargo install without --locked" w.yml "jobs:
  a:
    steps:
      - run: ./scripts/tools.sh" scripts/tools.sh "#!/usr/bin/env bash
cargo install cargo-audit"
case_ "a repository script named after an expansion is read" 1 "scripts/tools.sh: line 2: cargo install without --locked" w.yml "jobs:
  a:
    steps:
      - run: '\"\$GITHUB_WORKSPACE/scripts/tools.sh\"'" scripts/tools.sh "#!/usr/bin/env bash
cargo install cargo-audit"
case_ "a script a repository script runs is read" 1 "scripts/inner.sh: line 1: cargo install without --locked" w.yml "jobs:
  a:
    steps:
      - run: bash scripts/outer.sh" scripts/outer.sh 'source "$(dirname "$0")/inner.sh"' scripts/inner.sh "cargo install cargo-audit"
case_ "a pinned repository script passes" 0 "OK: every action" w.yml "jobs:
  a:
    steps:
      - run: sh scripts/tools.sh" scripts/tools.sh "cargo install --locked cargo-audit@0.22.2"
case_ "a shell script the repository does not hold is refused" 1 "a script the repository does not hold is not read: ./tools.sh" w.yml "jobs:
  a:
    steps:
      - run: ./tools.sh"
case_ "a script run by a shell from a variable is refused" 1 'a script the check cannot read is run by bash: "$SCRIPT"' w.yml "jobs:
  a:
    steps:
      - run: bash \"\$SCRIPT\""
case_ "a Python script that runs cargo install is refused" 1 "a Python script that runs cargo install is not read" w.yml "jobs:
  a:
    steps:
      - run: python3 scripts/tools.py" scripts/tools.py "import subprocess
subprocess.run(['cargo', 'install', 'cargo-audit'], check=True)"
case_ "a Python script that runs no install passes" 0 "OK: every action" w.yml "jobs:
  a:
    steps:
      - run: python3 scripts/tools.py" scripts/tools.py "print('the tools are installed by the workflow')"
case_ "a Python script whose command string runs cargo install is refused" 1 "a Python script that runs cargo install is not read" w.yml "jobs:
  a:
    steps:
      - run: python3 scripts/tools.py" scripts/tools.py "import os
os.system('cargo install --locked cargo-audit@0.22.2')"
case_ "a local composite action is read" 1 ".github/actions/tools/action.yml: line 5: cargo install without --locked" w.yml "jobs:
  a:
    steps:
      - uses: ./.github/actions/tools" .github/actions/tools/action.yml "runs:
  using: composite
  steps:
    - run: |
        cargo install cargo-audit
      shell: bash"
block_case "the text of eval is read" 1 "cargo install without --locked" 'eval "cargo install cargo-audit"'
block_case "the text of sh -c is read" 1 "cargo install without --locked" "sh -ec 'cargo install cargo-audit'"
block_case "the text of bash -c after an option with a value is read" 1 "cargo install without --locked" "bash -o pipefail -c 'cargo install cargo-audit'"
block_case "an expansion in the text of sh -c is a value" 1 "the crate of a cargo install comes from a variable" 'sh -c "cargo install --locked $TOOL"'
block_case "eval of a variable is refused" 1 "the script eval runs comes from a variable or a substitution" 'eval "$SETUP"'
block_case "sh -c of a download is refused" 1 "the script sh -c runs comes from a variable or a substitution" 'sh -c "$(curl -fsSL https://example.invalid/install.sh)"'
block_case "a script piped into a shell is refused" 1 "a script piped into sh is not read" 'curl -fsSL https://example.invalid/install.sh | sh'
block_case "a script piped into an interpreter is refused" 1 "a script piped into python3 is not read" 'curl -fsSL https://example.invalid/get.py | python3 -'
block_case "a script from a process substitution is refused" 1 "a script the check cannot read is run by bash" 'bash <(curl -fsSL https://example.invalid/install.sh)'
block_case "a shell alias is refused" 1 "a shell alias is not read" "alias c=cargo" 'c install cargo-audit'
block_case "a cargo alias through --config is refused" 1 "a --config that sets alias.get is not read" "cargo --config 'alias.get=\"install\"' get cargo-audit"
block_case "a --config that names a file is refused" 1 "line 5: a --config that names a file is not read: tools.toml" 'cargo --config tools.toml tools'
block_case "a --config from a variable is refused" 1 'line 5: a --config from a variable is not read: "$CONFIG"' 'cargo --config "$CONFIG" tools'
block_case "a wrapper in place of rustc through --config is refused" 1 "a --config that sets build.rustc-wrapper is not read" 'cargo --config build.rustc-wrapper=./w.sh build'
block_case "a profile setting through --config passes" 0 "OK: every action" "cargo --config 'profile.release.lto = true' build"
block_case "another home for cargo's configuration is refused" 1 "line 5: CARGO_HOME changes what cargo installs or runs" 'CARGO_HOME=./ch cargo tools'
block_case "a wrapper in place of rustc through the environment is refused" 1 "line 5: RUSTC_WRAPPER changes what cargo installs or runs" 'RUSTC_WRAPPER=./w.sh cargo build'
# A configuration file in the repository is read wherever it stands, since
# cargo reads it under the directory a job runs cargo in.
config_case "an alias in the repository's cargo configuration is refused" 1 ".cargo/config.toml: line 2: a setting that changes what cargo fetches or runs is not read: alias.tools" .cargo/config.toml '[alias]
tools = "install cargo-audit"'
config_case "an alias in a cargo configuration without an extension is refused" 1 ".cargo/config: line 1: a setting that changes what cargo fetches or runs is not read: alias.tools" .cargo/config 'alias.tools = "install cargo-audit"'
config_case "an alias in a nested cargo configuration is refused" 1 "crates/x/.cargo/config.toml: line 2: a setting that changes what cargo fetches or runs is not read: alias.tools" crates/x/.cargo/config.toml '[alias]
tools = ["install", "cargo-audit"]'
config_case "a source replacement in the repository's cargo configuration is refused" 1 "line 2: a setting that changes what cargo fetches or runs is not read: source.crates-io.replace-with" .cargo/config.toml '[source.crates-io]
replace-with = "mirror"'
config_case "a default registry in the repository's cargo configuration is refused" 1 "line 1: a setting that changes what cargo fetches or runs is not read: registry.default" .cargo/config.toml 'registry.default = "mirror"'
config_case "a registry index in the repository's cargo configuration is refused" 1 "line 2: a setting that changes what cargo fetches or runs is not read: registries.mirror.index" .cargo/config.toml '[registries.mirror]
index = "sparse+https://example.invalid/"'
config_case "an include in the repository's cargo configuration is refused" 1 "line 1: a setting that changes what cargo fetches or runs is not read: include" .cargo/config.toml 'include = "more.toml"'
config_case "a rustc wrapper in the repository's cargo configuration is refused" 1 "line 2: a setting that changes what cargo fetches or runs is not read: build.rustc-wrapper" .cargo/config.toml '[build]
rustc-wrapper = "./w.sh"'
config_case "an alias as an inline table key is refused" 1 "line 1: a setting that changes what cargo fetches or runs is not read: alias" .cargo/config.toml 'alias = { tools = "install cargo-audit" }'
config_case "a line the reader does not take is refused" 1 "line 1: a line the check cannot read: alias tools" .cargo/config.toml 'alias tools'
config_case "build, profile, term and target flags pass" 0 "OK: every action" .cargo/config.toml '# The flags of the build.
[build]
jobs = 4
rustflags = [
  "-D", "warnings",
]
[profile.release]
lto = true
[term]
color = "always"
[target.'"'"'cfg(unix)'"'"']
rustflags = ["-C", "force-frame-pointers=yes"]
[env]
FOO = { value = "x", force = true }'
config_case "another file in the cargo directory is not cargo's configuration" 0 "OK: every action" .cargo/audit.toml '[advisories]
ignore = []'
config_case "a cargo configuration outside a cargo directory is not read" 0 "OK: every action" tools/config.toml '[alias]
tools = "install cargo-audit"'

block_case "a cargo alias through the environment is refused" 1 "CARGO_ALIAS_GET changes what cargo installs" 'CARGO_ALIAS_GET=install cargo get cargo-audit'
block_case "an exported source replacement is refused" 1 "CARGO_SOURCE_CRATES_IO_REPLACE_WITH changes what cargo installs" 'export CARGO_SOURCE_CRATES_IO_REPLACE_WITH=mirror'
block_case "a script that writes cargo's config is refused" 1 "a script that writes cargo's config is not read" 'printf "[alias]\nget = \"install\"\n" >> ~/.cargo/config.toml'
case_ "a cargo alias in the workflow's environment is refused" 1 "CARGO_ALIAS_GET changes what cargo installs" e.yml "env:
  CARGO_ALIAS_GET: install
jobs:
  a:
    steps:
      - run: cargo get cargo-audit"
case_ "a run step in another shell is refused by name" 1 "a run step in a shell the check does not read: python" s.yml "jobs:
  a:
    steps:
      - run: print('hello')
        shell: python"
case_ "a run step in bash with options is read" 1 "cargo install without --locked" s.yml "jobs:
  a:
    defaults:
      run:
        shell: bash --noprofile --norc -eo pipefail {0}
    steps:
      - run: cargo install cargo-audit"
case_ "a run step on a Windows runner with no shell set is refused" 1 "a run step on a runner that may be Windows runs in PowerShell" s.yml "jobs:
  a:
    runs-on: windows-latest
    steps:
      - run: cargo install cargo-audit"
case_ "a run step on a matrix with a Windows runner is refused" 1 "a run step on a runner that may be Windows" s.yml "jobs:
  a:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: \${{ matrix.os }}
    steps:
      - run: cargo build"
case_ "a run step on a matrix of Linux and macOS runners is read" 0 "OK: every action" s.yml "jobs:
  a:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: \${{ matrix.os }}
    steps:
      - run: cargo build"
