"""The shell scripts of the repository and the scripts of its workflows.

Used by scripts/check-pipe-readers.sh and scripts/check-lint-allowances.sh.
A shell script is a file whose name ends in `.sh`, whose first line is a
`#!` naming a shell, or whose first line is a `# shellcheck shell=`
directive (a file only ever sourced), as scripts/check-shellcheck.sh
selects them. A workflow script is the `run:` of any mapping in a YAML file
under .github/ (a workflow's step, a local action's step), unless that
mapping names a `shell:` other than bash or sh.
"""

import re

import workflow_yaml as yaml

SHEBANG = re.compile(r"#!.*[/\s](sh|bash|dash|ksh|mksh)(\s|$)")
DIRECTIVE = re.compile(r"#\s*shellcheck\s.*shell=")
SHELL_STEP = re.compile(r"(bash|sh)(\s|$)")


def is_workflow(path):
    return path.startswith(".github/") and path.endswith((".yml", ".yaml"))


def is_script(path, text):
    first = text.split("\n", 1)[0].rstrip("\r")
    return path.endswith(".sh") or bool(SHEBANG.match(first)) or bool(DIRECTIVE.match(first))


def run_steps(doc):
    """The `run:` scalars of a workflow or action document read in a shell."""
    for node in yaml.walk(doc):
        if not isinstance(node, yaml.Mapping):
            continue
        run = node.get("run")
        shell = node.get("shell")
        if not isinstance(run, yaml.Scalar):
            continue
        if isinstance(shell, yaml.Scalar) and not SHELL_STEP.match(shell.value):
            continue
        yield run
