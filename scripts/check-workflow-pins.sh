#!/usr/bin/env bash
# axess: the pins of the workflows. Every action is pinned to a full commit
# SHA, with the release it was read from in a trailing comment, every image
# to a digest, every checkout drops the job token from .git/config, every
# tool install is locked to an exact version, and no job that names a
# secret, may ask for an OIDC token or holds a token that can write installs
# a tool, or runs anything else the check does not read.
#
# How the workflows are read. Each `.yml` and `.yaml` file is read as YAML
# (scripts/lib/workflow_yaml.py): block and flow style, keys bare or quoted
# with or without white space before the colon, plain, quoted and block
# scalars folded the way YAML folds them, double-quoted escapes decoded,
# anchors and aliases followed. So a rule judges the value the runner reads:
# `"c\x61rgo install"` is `cargo install`, a folded scalar over two lines is
# one line, and a job that takes a secret through an alias takes it here
# too. A form the reader does not take is refused by name with its line: a
# tag, an explicit key (`? uses`), a merge key, a duplicate key, a second
# document, a tab in the indentation, and anything that is not YAML. A
# directory with no workflow file is refused: a checkout that lost its
# workflows has nothing to pass.
#
# Actions and images. A tag or a branch moves, so an action pinned to one
# runs whatever its owner points it at on the day, with the job's token and
# secrets. A commit does not move; the comment keeps the pin readable and
# lets a bump tool tell which release a SHA is. Local actions and reusable
# workflows (`uses: ./...`) are in this repository and need no pin. A
# service or container image (`image:`, `container: name:tag`, `uses:
# docker://...`) carries an @sha256 digest. A `uses:` or `image:` in a
# flow-style mapping is refused by name: the version comment is the line's,
# and a flow mapping can hold two of them. The name of an action is taken
# as the runner takes it, without regard to case (`Actions/Checkout` is the
# checkout). A local action is read when it is composite: one that runs
# node or builds an image is refused by name, each of its scripts names
# bash or sh, the local actions it uses are read in turn, and its `env:` is
# held as a workflow's.
#
# Scripts. Each `run:` script is read as the shell reads it
# (scripts/lib/shell_words.py): quotes, escapes, continued lines, comments,
# operators, every redirection with its target, here-documents and their
# bodies, the conditional `[[ ]]`, and the substitutions inside a word,
# whose commands are commands of the script wherever they stand: in a
# word, in the value a `${...}` falls back to, in an array. A brace
# expansion (`{a,b}`) or a pathname pattern (`*`, `?`, `[...]`) makes words
# the script does not hold as written, so it is read as an expansion that
# splits. A `shell:` is bash or sh with the options that set how a script
# fails (`bash -euo pipefail {0}`): any other word of it (`-c`, `--rcfile`,
# `--init-file`, a second program) runs or loads what the check does not
# read, and is refused by name, as is another shell, set on the step or in
# `defaults`, and a script on a runner that may be Windows with no shell
# set (PowerShell). An expression in a script (`${{ github.base_ref }}`) is
# text the runner pastes in before the shell reads it, so the name of a
# branch or the title of an issue becomes commands: it is refused by name
# in every job, in a workflow and in a local action, and the value goes
# through an `env:`. The command a line runs is the word after its
# assignments, the words that open a compound command (`if`, `then`, `do`,
# `!`, ...) and the commands that run another (`sudo`, `env`, `timeout`,
# `xargs`, `coproc`, ...) with their options. A reserved word (`case`,
# `in`, `esac`, `if`, ...) is one only when written bare: a quoted or
# escaped one is a command of that name, as the shell runs it. The scripts
# a command runs are read the same way, recursively: a repository script
# named by its path, with or without an expansion before it
# (`./scripts/x.sh`, `"$DIR/scripts/x.sh"`, every file the path after the
# expansion names), run by `bash`, `sh` or `source`, or handed to a shell
# as a here-document, a here-string or a redirection of input; the text of
# `eval` and `sh -c`, where an expansion stands as a value; and the steps
# of a local composite action. A Python program (a file, `python -c`, a
# here-document) that can run another program (it names `subprocess`,
# `os.system`, an `exec` or `spawn` function, `eval`, `exec`, `getattr` or
# `__import__`, each as Python normalises the name) is refused when a
# statement of it passes `cargo` and then `install`. What a command runs
# that cannot be read is refused by name: a script or a program that is all
# variable or substitution (`eval "$X"`, `sh -c "$(curl ...)"`), a script
# piped into a shell or an interpreter, a script the repository does not
# hold, a node, perl or ruby program, and a shell alias. The string a
# program hands to a shell is read as `sh -c` text: `env -S`, `flock -c`,
# `su -c`, `runuser -c`, `script -c`, `watch`, `trap` and the command `ssh`
# runs (scripts/lib/workflow_runners.py); `su`, `script` and `sudo -s` with
# no command read their script from their input, as a shell does: a
# here-document is read and a pipe is refused. A long option is the one any
# prefix of it names, as getopt_long takes it (`flock --comm` is
# `--command`), and a cluster of short options is read letter by letter
# (`sed -Ef` names a file). What runs a program the check does not see is
# refused by name: a git setting other than a short list that runs none (an
# alias, `core.hooksPath`, a pager, an included file), in `git -c`, `git
# config` or `git clone -c`; a git command that runs a program it is given
# (`bisect run`, `submodule foreach`, `filter-branch`, `rebase --exec`, a
# diff or merge tool, `--upload-pack`, `--receive-pack`, `grep -O`); a gh
# extension, which is a program installed with no pin, and a gh alias; an
# awk program that calls `system` or a pipe, holds an expansion (pass a
# value with `-v`) or comes through an option (`-f`, `-e`, `--source`,
# `-i`, `-l`); a sed program with the `e` command or flag or one it cannot
# follow; `parallel`; a command a builtin runs through an option (`mapfile
# -C`, `compgen -C`, `complete -C`, `bind -x`); an expansion that runs the
# commands in a variable's value (`${x@P}`); and a variable through which
# the shell, the loader, git or an interpreter runs code first or finds
# its files elsewhere (`BASH_ENV`, `ENV`, `PS4`, `PROMPT_COMMAND`,
# `LD_PRELOAD`, `GIT_SSH_COMMAND`, `PAGER`, `GIT_CONFIG_*`, `GIT_DIR`,
# `PYTHONPATH`, `NODE_OPTIONS`, `HOME`, `XDG_CONFIG_HOME`,
# `GITHUB_WORKSPACE`, `RUNNER_TEMP`, ...), in a script, as an argument of
# `env` or `sudo`, or in an `env:`. A variable is assigned by more than
# `NAME=value`, and each form is held the same: the variable of a `for`,
# the operands of `read`, `mapfile`, `getopts`, `printf -v`, and
# `${NAME:=value}`. An assignment to a variable that a variable names
# (`export "$X"`, `read "$X"`), a name reference (`declare -n`) and a bash
# builtin loaded from a file (`enable -f`) are refused by name. What a
# step writes to `$GITHUB_ENV` with echo, printf or a here-document is held
# to the same rules as an `env:` for the steps after it, and any other
# write to it is refused by name. A directory a step puts on the path
# (`PATH=`, `for PATH in`, `$GITHUB_PATH`, `hash -p`) makes the programs it
# names ones the job wrote, so it counts as an install, and a `PATH` in an
# `env:` is refused by name. A local action or reusable workflow the
# repository does not hold is refused, and so is a job, a step, `steps`,
# `run` or `if` that is not the kind of value the runner takes.
#
# Cargo's configuration (scripts/lib/cargo_config.py). A cargo setting can
# change what cargo builds or runs with no word of it in the command: an
# alias (`cargo tools` as `cargo install foo`), a source or a registry, an
# `include` of another file, a program in place of rustc or a runner. So
# every cargo configuration file in the repository (`.cargo/config.toml` or
# `.cargo/config`, in any directory, since cargo reads the one above the
# directory a job runs it in) and every `--config KEY=VALUE` holds only
# settings from a list that changes none of it: how cargo builds
# (`build.jobs`, `build.rustflags`, `build.target`, ...), the profiles, the
# terminal, the network's retries, the flags of a target and the environment
# of the programs cargo runs. Any other setting, a `--config` that names a
# file or comes from a variable, and a line the reader does not take are
# refused by name, and so is a variable that sets an alias, a source, a
# registry, cargo's home (`CARGO_HOME`), a program in place of rustc,
# rustdoc or rustfmt (`RUSTC_WRAPPER`, `RUSTDOC`, `CARGO_TARGET_*_RUNNER`)
# or an unstable feature (`CARGO_UNSTABLE_*`), in a script or in an
# `env:`, and a script that writes `.cargo/config.toml`. The flags cargo
# hands to rustc are read wherever they are set (`RUSTFLAGS`,
# `RUSTDOCFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_TARGET_*_RUSTFLAGS`,
# `build.rustflags`, `target.*.rustflags`): flags that name a program rustc
# runs in place of the linker or code it loads (`linker`, `link-arg`,
# `codegen-backend`, `llvm-plugins`, `--sysroot`, `--extern`, `-L`), and
# flags a variable or an expression fills in, are refused by name.
#
# Installs. `cargo install` builds whatever version the registry serves that
# day, from whatever lockfile it resolves, so every install carries
# `--locked` and names each crate at an exact version (`crate@X.Y.Z` or
# `--version X.Y.Z`, digits and dots with an optional pre-release suffix).
# An install is the word `cargo` (or a path that ends in it, or a quoted
# word an expansion fills in, `"$CARGO"`) wherever it stands in a command,
# an optional toolchain, cargo's own flags, and the subcommand `install`,
# every part read with its quotes removed. A command word whose value splits
# into words (`$c`, `$(which cargo)`, `"${a[@]}"`, a `${{ }}`) is a program
# and arguments the check cannot see, whatever IFS holds, so it is refused
# by name, and so is such a word passed to a function or a repository script
# that runs its arguments (`"$@"`), whose callers' words are read as the
# command they are; the words `set --` gives a script that runs its own
# parameters are read the same way. A quoted program whose name an
# expansion fills in (`"$c"`, `"${CARGO:-cargo}"`) may be a shell, `eval`
# or a task runner whose script is not read, so it counts as an install in
# a job held to the rules on secrets below, and elsewhere is read as a
# cargo it may be; one named by a path after an expansion (`"$DIR/bash"`)
# is the program it names. The commands `find -exec` runs are read as
# commands, and what `xargs` and `find -exec` fill in from their input
# stands as such a word. A version, a crate or a subcommand from a
# variable or an expression resolves on the runner, where this check does
# not run, so it is refused by name,
# after `cargo` and after a quoted program from a variable alike (`"$CARGO"
# "$SUB" crate`); a program whose path names another one (`"$DIR/tool"`), or
# one followed by a flag cargo does not have, is not cargo. An install from
# `--git` or `--path`, from another registry or index (`--registry` other
# than crates-io, `--index`), and a flag of `cargo install` the check does
# not know are refused by name too. Every other route that installs or runs
# a tool from a registry has no pin this check can read and is refused by
# name: `cargo binstall`, `cargo quickinstall`, `pip install`, `npm`, `npx`,
# `yarn`, `go install`, `apt-get install` and the like. A task runner
# (`make`, `just`, `task`, `rake`, `ninja`, ...) runs the recipes of a file
# this check does not read, so it is refused by name wherever the shell runs
# it.
#
# Jobs. A job that names a secret installs no tool: `cargo install` runs the
# build scripts and procedural macros of whatever the registry serves on the
# runner the secret reaches. A secret is named in an expression, read with
# the runner's grammar (scripts/lib/workflow_expressions.py): the `secrets`
# context in any use, and the job's token under its other names,
# `github.token`, `github.*`, any index into `github` and the whole `github`
# context (`toJSON(github)`, `format('{0}', 1, github)`); a property of
# `github` other than `token` names nothing, and neither does a name that is
# a property of another object (`matrix.github`) or text outside `${{ }}` (a
# step name, a script, a comment). In a workflow another one calls (`on:
# workflow_call`), the `inputs` context counts as a secret in any use, since
# the caller may hand one in, and a job that hands its secrets to the
# workflow it calls (`secrets:`) names one. An `if:` is an expression whole.
# An expression outside `jobs:` reaches every job. A job that may ask for an
# OIDC token (`id-token: write`, `permissions: write-all`) installs no tool
# either, and nor does a job whose token can write or whose permissions are
# not declared: every step that uses an action can reach the job's token
# without naming it, so a job that installs a tool holds a token that can
# only read. A job's permissions are its own, or the workflow's when it
# declares none. The OIDC permission is refused on the workflow as a whole,
# where it reaches every job. In a workflow with a job that names a secret
# or may ask for an OIDC token, every toolchain is an exact release: the
# `toolchain` of a rust-toolchain step, `cargo +X.Y.Z`, the toolchain
# `rustup` installs or selects and a `RUSTUP_TOOLCHAIN` in an `env:` or a
# script, in the workflow, the repository scripts it runs and the local
# actions it uses, and the channel of the repository's
# `rust-toolchain.toml`. rustup takes that file over its default toolchain
# and takes RUSTUP_TOOLCHAIN or a `+toolchain` over the file, so all of them
# are held. What that workflow builds is what it signs or publishes. A
# workflow it calls is held as its own.
#
# The pinned toolchain, in every workflow. A release written out as a
# toolchain (the `toolchain` of a rust-toolchain step, a RUSTUP_TOOLCHAIN in
# an `env:`, in the workflow or a local action it uses) is the release the
# repository's toolchain file pins, when that file pins one: a literal that
# lags the file builds with another compiler than a checkout does, and the
# move of the pin fails here until every literal moves with it. In a
# workflow that runs on a push, a pull request, a release or a call from
# another workflow, no toolchain is `stable`, `beta` or a two-part version:
# such a job would meet a new stable release, and the lints it adds, the
# day it ships, with no commit responsible. A job there reads the release
# from the file (`.github/actions/pinned-toolchain` does) or names it.
# A workflow that runs only on a schedule or on demand may run `stable` as
# a canary. A script's own selector (`cargo +X.Y.Z`) is not compared with
# the file: beside a secret it is held to an exact release above.
#
# The pinned nightly, in every workflow. The jobs that need what only a
# nightly has (cargo-fuzz, Miri) install the dated nightly
# `nightly-toolchain.toml` names, through .github/actions/pinned-nightly. A
# dated nightly a workflow names (a rust-toolchain step's `toolchain`, a
# RUSTUP_TOOLCHAIN in an `env:` or written to $GITHUB_ENV, a script's
# `+toolchain`, what `rustup` installs or selects, in the workflow, the
# repository scripts it runs and the local actions it uses) is that one,
# and in a workflow that runs on a push, a pull request, a release or a
# call, no nightly is undated: `nightly` is whatever the runner installs
# that day. The file itself names a dated nightly with no host.
#
# In every job. A program run by a path the repository does not hold
# (`./tool`, `"$RUNNER_TEMP/tool"`, `~/.cargo/bin/x`, `target/release/x`)
# is a file a step downloaded or built, or one another job handed over,
# and nobody read or pinned it: it is refused by name in every job, unless
# it is a download the job checked against a digest, or lies in the
# directory a checked archive was unpacked into (Downloads, below). A path
# into `/bin`, `/usr/bin`, `/usr/local/bin`, `/sbin` or `/usr/sbin` is the
# program of that name. An external cargo subcommand (`cargo audit`) is the
# program `cargo-audit` on the runner's path, so a job runs one only after
# a `cargo install` of that crate in the same job, in a step, a repository
# script or a local action, held to `--locked` and an exact version; a
# program the image holds, a cache restored or an artifact copied in is
# refused by name. A `--config` after one of cargo's own subcommands is
# held as one before it. Every action a workflow uses, in any job, stands
# in scripts/lib/workflow_actions.txt with where it may run and what it is
# trusted to do; an action that is not listed is refused, and so is a line
# no workflow uses. A function that runs its arguments is read from the
# first argument its body runs, by the `shift`s before it (`step "label"
# cargo ...` runs `cargo`), so a label is not read as a program. A
# variable that sends a program to another host or changes which hosts it
# trusts is refused by name wherever it is set: gh's host and repository
# (`GH_HOST`, `GH_REPO`), the URLs of the runner's services
# (`GITHUB_API_URL`, `ACTIONS_RUNTIME_URL`, ...), `GITHUB_REPOSITORY`, a
# proxy (`HTTPS_PROXY`), a certificate store
# (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`) and the switches
# that turn a check off (`GIT_SSL_NO_VERIFY`,
# `NODE_TLS_REJECT_UNAUTHORIZED`); and so are the variables that name a
# registry, a credential provider, a proxy or the certificates of cargo
# (`CARGO_REGISTRIES_*`, `CARGO_REGISTRY_DEFAULT`, `CARGO_REGISTRY_INDEX`,
# `CARGO_*CREDENTIAL_PROVIDER*`, `CARGO_HTTP_PROXY`, `CARGO_HTTP_CAINFO`),
# beside the `[registries]` and `[registry]` tables the list of cargo's
# settings above leaves out. The stand-ins a test sets for the runner, the
# OIDC token service (`ACTIONS_ID_TOKEN_REQUEST_URL`,
# `ACTIONS_ID_TOKEN_REQUEST_TOKEN`) and the files of a step's outputs,
# state and summary (`GITHUB_OUTPUT`, `GITHUB_STATE`,
# `GITHUB_STEP_SUMMARY`), are allowed in a job that holds none of the four
# below and refused in one that does: where nothing is held they redirect
# nothing of value, since there is no token to request and nothing such a
# job makes is run, sourced or built by a job beside a secret.
#
# Downloads (scripts/lib/workflow_downloads.py). A file a step downloads
# is whatever the server sends that day, so in every job a download is
# held to a SHA-256 written out in the repository before it is run or
# unpacked: `curl`, `wget` and `gh release download` are read for the file
# they write (`-o`, `-O`, `--output-dir`, a redirection, a `tee` after
# them), and the check is `sha256sum --check` or `shasum -a 256 --check`
# reading `<sha256>  <file>` from what `echo` or `printf` print into it, a
# here-string or a here-document. The digest is 64 hex digits written out,
# a variable the same script sets to such a literal and nothing else, or a
# variable an `env:` of the workflow, the job, a step or a local action
# sets to one, which no script of the job sets otherwise and no step
# writes to `$GITHUB_ENV`: a digest fetched from the network, read from a
# file or filled in by a substitution covers nothing. The check counts only
# where its failure stops the script: at the top level of a script that
# set `-e` before it, outside a function, a subshell, a substitution and a
# condition, and joined to the command after it by none of `&&`, `||`,
# `|` and `&`. A file is read by the name the script writes, a variable
# with one value standing as that value. Refused by name, each with its
# line: a downloaded file named by any program but one that only names it
# (`ls`, `test`, `rm`, the checksum programs) or reads it as data (`jq`,
# `grep`, `diff`, ...) before its check, or after a write over it that
# follows the check; a download no check covers whose name or URL says it
# is an archive or a program (`.tar.gz`, `.zip`, `.deb`, `.sh`, ...) and
# every `gh release download` with none; a stream unpacked as it arrives
# (`curl ... | tar -x`, `tar -xf <(curl ...)`); a download whose file the
# check cannot name (`curl -J`, `--remote-name-all`, `-K`, `wget` without
# `-O` or with `-i`, `-e`, `-r`, `gh release download` without
# `--output`, a file named through a variable with more than one value);
# and an action handed a URL as an input, which fetches it where no step
# can check it first. A program run by a path the repository does not hold
# is then the checked download itself, or lies under the directory of
# `$RUNNER_TEMP` (not `$RUNNER_TEMP` itself, where other steps put their
# files) into which a checked archive was unpacked (`tar -C`, `unzip -d`),
# after the unpacking; a repository script may run it through a variable
# whose one value, set outside its functions, is a positional parameter,
# which is read as the word the job passed it.
#
# Beside a secret. A job that names a secret, may ask for an OIDC token,
# holds a token that can write or declares no permissions runs only what
# the check reads (scripts/lib/workflow_held.py, workflow_programs.py,
# workflow_jobs.py). Each of the following is refused by name there, with
# its file and line, and passes in a job that holds none of the four:
#   - a program the check does not name. The named ones are the shell's own
#     words and builtins, the functions of the script and of a repository
#     script it sources, a repository script, and a list of programs of the
#     runner's image: those that run no program and write nothing into a
#     file (`grep`, `cut`, `jq`, `sha256sum`, ...), those that do so only
#     through options the list names and refuses (`sort -o`, `sort
#     --compress-program`, `base64 --output`), and `git`, `gh`, `cargo`,
#     `curl`, `sed`, `awk` and `find`, each read by a reader of its own.
#     So `docker run`, `chroot`, `setsid`, `vim -c`, `cp`, `chmod`, `tar`,
#     `tee`, `wget`, `rustup` and the like do not run beside a secret. A
#     function is the function only where the shell runs the word itself:
#     after `command`, `env` or `sudo` the word is a program, and so it is
#     once `unset -f` removed the function;
#   - a repository file that may not be the file the check read: one named
#     through a variable (`"$DIR/scripts/x.sh"`; `$GITHUB_WORKSPACE/...` is
#     the repository's root), one named by a relative path after a `cd`, a
#     `pushd` or under a `working-directory` (a `cd` in a subshell or a
#     substitution moves that alone, and `cd "$GITHUB_WORKSPACE"`, or a
#     repository script's `cd "$(dirname "$0")/.."` that lands on the root,
#     moves back), and a repository program that is neither a shell nor a
#     Python script;
#   - cargo other than its own subcommands that build, package, publish or
#     read the workspace, each with `--locked` or `--frozen`, and the
#     external subcommands it installs: a subcommand that rewrites the
#     sources or the lockfile (`update`, `add`, `fix`, `fmt`, ...) or acts
#     on a crate's owners or releases (`owner`, `yank`, `login`), a build
#     without `--locked`, a `--manifest-path` the repository does not hold,
#     `-Z`, `-C`, an argument a variable fills in before `--`, a build after
#     a change of directory, and a registry named by `--registry` or
#     `--index`, `crates-io` included: a job beside a secret publishes to
#     crates.io, cargo's default, with no registry named anywhere;
#   - git other than a list of subcommands, git in another directory or
#     repository (`-C`, `--git-dir`, `--work-tree`, after a `cd`), an
#     option that writes a file (`--output`, `--template`), and, for a
#     subcommand with an option that runs a program or writes a file, an
#     argument that begins with an expansion and does not stand after
#     `--`: `git fetch "$X"` runs a program when X is `--upload-pack=...`;
#     and a remote other than `origin` (a URL, another name, `--repo`), a
#     clone and a change to the remotes, since git sends the job's
#     credentials to the remote it talks to;
#   - gh other than the commands that call the API (`api`, `issue`, `pr`,
#     `release`, `workflow`, `run`, ...): no download, clone or checkout;
#     and gh pointed at another host: `--hostname`, a repository named
#     `HOST/OWNER/REPO` or by a variable other than `$GITHUB_REPOSITORY`,
#     and a `gh api` endpoint that is a URL;
#   - a curl option other than a list that writes no file and reads no
#     options from one, an output (`--output`) outside the runner's
#     temporary directory, an output format that writes a file
#     (`%output{}`), and an address of a host other than crates.io,
#     GitHub and the runner's own services: written out to its host, or
#     named by a variable every value of which the script wrote out, or by
#     a URL the runner sets
#     (`$ACTIONS_ID_TOKEN_REQUEST_URL`). With `-L` no header or credential
#     a variable fills in goes along, since curl sends it to the next host
#     too;
#   - a sed that edits a file in place or whose program writes one (`w`),
#     an awk program that redirects its output, a find action that writes
#     a file, and an operand of sed, sort, uniq, base64 or find that begins
#     with an expansion and does not stand after `--`;
#   - a redirection that writes anywhere but `/dev/null`, the standard
#     streams, `$GITHUB_OUTPUT`, `$GITHUB_STEP_SUMMARY`, `$GITHUB_STATE` and
#     a file written out under `$RUNNER_TEMP`: a file in the checkout is one
#     a later command runs or cargo builds;
#   - an arithmetic operand that is not a number
#     (scripts/lib/workflow_arithmetic.py). bash evaluates the value of
#     every name in `$((...))`, `((...))`, `let`, a comparison inside
#     `[[ ]]`, an array subscript (in an expansion, an assignment, `unset`,
#     `read`, `printf -v` or a test with `-v`) and a substring offset as
#     arithmetic in turn, and a subscript in a value runs the command it
#     holds. So each operand is a number written out, one the shell sets
#     (`$#`, `$?`, `$RANDOM`), or a name every value of which the script
#     made a number (written out, the result of arithmetic, a substitution
#     that prints a number by its form: `date +%s`, `wc -l`, `grep -c`,
#     `expr`) and which an assignment sets on every way to the read: before
#     it, outside a pipeline and the right of `||` or `&&`, in a block and a
#     subshell that hold it (scripts/lib/workflow_values.py). An integer
#     variable (`declare -i`) and the legacy `$[...]` are refused by name.
#     `[ ]` and `test` compare without evaluating, and are not judged;
#   - a copy of the path of `$GITHUB_ENV` or `$GITHUB_PATH` in a variable,
#     and an indirect expansion (`${!name}`), through which a script writes
#     the runner's files by another name;
#   - a Python program, which is read for `cargo install` alone;
#   - a script one shell fills in for another, which is a paste like an
#     expression in a script: a variable in the text of `sh -c`, `eval`,
#     `trap` or the string of a program that hands one to a shell, written
#     in double quotes, and in a here-document a shell reads whose
#     delimiter is not quoted;
#   - a value a variable fills in, written to `$GITHUB_ENV`: a line break
#     in it sets another variable for the steps after;
#   - a stand-in for the runner (`ACTIONS_ID_TOKEN_REQUEST_URL`,
#     `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `GITHUB_OUTPUT`, `GITHUB_STATE`,
#     `GITHUB_STEP_SUMMARY`), in a script, an `env:` or a `$GITHUB_ENV`
#     line, and so when a job beside a secret takes its value from a job
#     that holds nothing;
#   - a variable by which the build script of a dependency finds a program
#     to run or a library to load (`CC`, `CXX`, `AR`, `CC_<target>`,
#     `CMAKE`, `PKG_CONFIG`, `PROTOC`, `LIBCLANG_PATH`), in a script or in
#     an `env:` of the workflow, the job or a step;
#   - an action the list lets run only in a job that holds no secret (the
#     cache of `Swatinem/rust-cache`, whose files an earlier run made), in
#     the job or in a local action it uses, and an image run as a step
#     (`uses: docker://...`).
# Such a job does not both change its checkout and run code from it. A
# checkout of another repository or ref, an artifact unpacked with no
# `path`, into a directory the repository holds or into one an expression
# other than `${{ runner.temp }}` names, and a git subcommand that
# rewrites the working tree (`checkout`, `merge`, `pull`, `apply`,
# `clone`, ...), each beside a repository script, a local action or a
# cargo build in the same job, is refused: what runs would not be what the
# check read.
#
# What the check does not judge, why, and what covers it.
#   - A job that holds none of the four. The rules of the list above are
#     relaxed there, and only those: a program the check does not name
#     (`docker run`, `chroot`, `cp`, `tar`, read only for a literal `cargo`,
#     a shell given `-c`, `eval` or an interpreter given `-c` or `-e` among
#     its words), an option of a named program that writes a file, git, gh
#     and curl beyond their lists, a Python program beyond `cargo install`,
#     a redirection into the checkout, a variable pasted into the text of
#     an inner shell, a value from a variable written to `$GITHUB_ENV`, a
#     variable a build script reads, a stand-in for the runner, the cache
#     action, an image run as a step, and a changed checkout beside a
#     build all pass. Such a job builds and tests the repository's own
#     code, and the programs of a build, a test run, a fuzz run or a book
#     are an open set the check cannot name. Every other rule holds there
#     as everywhere: the pins, the installs, the expressions, the paths,
#     the subcommands, the list of actions, the variables that run code
#     and the settings of cargo.
#     What covers the boundary: such a job holds no secret, no OIDC
#     permission and a token that can only read, and nothing it makes is
#     run by a job beside a secret. A file of its artifact is run by no
#     path, sourced by no shell, handed to no `eval`, `sh -c`, interpreter,
#     sed or awk program, built by no `--manifest-path` or `cd`, made no
#     cargo configuration, no `$GITHUB_ENV` or `$GITHUB_PATH` line and no
#     repository file, and an artifact unpacked over the checkout stands
#     beside no code run from it; its cache is restored into no job beside
#     a secret; and its outputs reach a script as an `env:` value only,
#     which is no command, no script of another shell, no shell of a step,
#     no working directory and no ref of a checkout code runs from
#     (scripts/check-workflow-pins-cases/boundary.sh holds each).
#   - What the pinned commit of an action runs, on the list or off it, and
#     what a listed action does with its inputs. The action's source is in
#     another repository, and most are JavaScript, which this check does
#     not read, and the list (scripts/lib/workflow_actions.txt) says it
#     was not read to write it either. What covers it: the pin to a
#     commit, which does not move, with its release in a comment, and the
#     maintainer's review of a pull request that moves one
#     (docs/project/publishing.md), which changes the action's line when
#     what it does changed. No listed action installs a tool named in its
#     inputs but rust-toolchain, whose toolchain the rule above holds to an
#     exact release.
#   - The programs of the runner's image, or of the container a job names
#     by digest. `git`, `gh`, `cargo` and the filters are whatever the image
#     holds: it is not in the repository. What covers it: the image is
#     GitHub's, or pinned by digest, and a job beside a secret puts no
#     directory on the path, sets none of the variables that move a
#     program's files, and redirects no output into a file outside the
#     runner's temporary directory.
#   - The repository's own Rust code (a build script, a procedural macro, a
#     test, an `xtask` crate) and the build scripts and macros of its
#     locked dependencies, which cargo builds and runs, with the variables
#     a build script reads beyond the ones named above. Rust is not a
#     language this check reads. What covers it: beside a secret every
#     build is `--locked`, so the dependencies are those of the committed
#     lockfile with its checksums; scripts/supply-chain.sh holds their
#     sources, advisories and licences; and the code is the repository's,
#     reviewed like the workflows.
#   - An option of a named program that writes a file or runs a program
#     and that the lists do not know. The lists are what the check knows of
#     each program, not the program. What covers it: a program is named
#     only with its options read, the lists stand in
#     scripts/lib/workflow_programs.py with a case for each entry, and an
#     argument a variable fills in is refused wherever a listed option
#     could hide in it.
#   - A value a script takes on the runner, read by a named program: the
#     answer of a server handed to `jq` or `grep`, a file compared by
#     `diff`. It is data to this check, which does not know it. What covers
#     it: beside a secret no value is pasted into a script (`eval`, `sh -c`,
#     a command word, a here-document a shell reads, `$GITHUB_ENV` and
#     arithmetic take none), the named programs are those that run nothing
#     they read, and an operand from a variable stands where no option of
#     the program can hide in it.
#   - What a credential may do on a host the check lets a job reach. A
#     job's token sent to api.github.com may act on any repository the
#     token's scope admits, and a crates.io token on any crate its scope
#     admits; the check judges the host, not the request. What covers it:
#     the job's token is scoped to the repository and to the permissions
#     the job declares, a trusted-publishing token to the crates whose
#     settings name this workflow and environment, and each lasts as long
#     as the job.
#   - A downloaded file a script names by another path than the one it
#     downloaded it to (a relative name after a `cd`, a copy, a link),
#     what else a step writes into the directory a checked archive was
#     unpacked into, and what an action fetches from an input an
#     expression fills in. The file is followed by the name the script
#     writes, and an input by its written value. What covers it: a program
#     run by a path the repository does not hold is still refused unless
#     it lies in a checked download, and a download no check covers is
#     refused whenever its name or its URL says it is an archive or a
#     program.
#   - Names a function declares `local`. The values of a name are read
#     over the whole script, so a local and a global of the same name are
#     one: a reading that is stricter than the shell's, never looser.
#     What covers it: nothing needs to; a script that reuses a name gives
#     the local another one (scripts/check-release-version.sh does).
#
# Usage: ./scripts/check-workflow-pins.sh [WORKFLOW_DIR]   (default: .github/workflows)
#   Scripts are resolved from the directory above `.github/workflows`, or
#   from WORKFLOW_DIR itself when it is not one.

set -euo pipefail

AXESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -I -B "$AXESS_DIR/scripts/lib/workflow_pins.py" "${1:-$AXESS_DIR/.github/workflows}"
