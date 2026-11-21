"""The jobs that hold a secret, an OIDC permission or a token that can
write, for scripts/check-workflow-pins.sh.

Such a job runs only what the check reads. The reader of scripts notes
what a script runs that it does not (scripts/lib/workflow_held.py); this
part notes the same for the steps of a job and of the local actions it
uses: an action that is not on the list below, an image run as a step, an
expression the runner pastes into a script before the shell reads it, a
checkout of another repository or ref, and an artifact unpacked over the
checkout. `Jobs.held` then refuses each note of a job that holds one of
the three, and the job that changes its checkout and runs code from it.

The actions a workflow may use stand in scripts/lib/workflow_actions.txt,
one line each: where the action may run and what it is trusted to do. An
action that is not listed is refused in every job, one listed for jobs
that hold no secret is refused beside one, and a line no workflow of the
repository uses is refused as a trust nobody needs. What the pinned commit
of a listed action runs is not read: the file says so, and the pin with
its release comment makes a bump the place where the commit is reviewed.
"""

import os
import re

import workflow_expressions as expressions
import workflow_runners
import workflow_yaml as yaml

# The list of actions, and where a line of it lets an action run.
ACTIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "workflow_actions.txt")
WHERE = {"any job": True, "no secret": False}
# The words of a `shell:` the check reads: bash or sh, the options that set
# how a script fails, and the placeholder for the script.
SHELL_WORD = re.compile(r"--noprofile|--norc|-[euxv]+o?|-o|pipefail|errexit|nounset|xtrace|\{0\}")
RUNNER_TEMP = re.compile(r"\$\{\{\s*runner\.temp\s*\}\}/[^$]+")
HOLDS = {
    "oidc": ("a job that may ask for an OIDC token", ""),
    "write": ("a job whose token can write", " (give the job read permissions)"),
    "undeclared": ("a job whose token has the repository's default permissions", " (declare permissions: contents: read)"),
}


def read_actions(text):
    """(the actions a list names, the problems of its lines). An action is
    kept by its owner and repository in lower case, as (name, whether it
    may run beside a secret, what it is trusted to do, line); a problem is
    (line, message)."""
    actions, problems = {}, []
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = [field.strip() for field in line.split("|", 2)]
        if len(fields) != 3 or not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", fields[0]):
            problems.append((number, "a line that is not NAME | WHERE | TRUSTED TO, with NAME an owner and a repository"))
        elif fields[1] not in WHERE:
            problems.append((number, "%s may run in %r, which is neither \"any job\" nor \"no secret\"" % (fields[0], fields[1])))
        elif len(fields[2]) < 20:
            problems.append((number, "%s is listed without what it is trusted to do" % fields[0]))
        elif fields[0].lower() in actions:
            problems.append((number, "%s is listed twice" % fields[0]))
        else:
            actions[fields[0].lower()] = (fields[0], WHERE[fields[1]], fields[2], number)
    return actions, problems


def load_actions(path=ACTIONS_FILE):
    """The list of actions as `read_actions` returns it; a list that cannot
    be read names no action and has that as its one problem."""
    try:
        with open(path, encoding="utf-8") as f:
            return read_actions(f.read())
    except (OSError, UnicodeDecodeError) as e:
        return {}, [(1, "the list of actions cannot be read: %s" % e)]


def unused_actions(actions, used):
    """(line, message) for each listed action no workflow uses: a trust
    nobody needs any more."""
    return [(line, "%s is listed and no workflow uses it: remove the line" % name)
            for key, (name, _, _, line) in sorted(actions.items(), key=lambda item: item[1][3]) if key not in used]


def shell_read(value):
    """Whether a `shell:` is bash or sh with nothing but the options the
    check knows: any other word (`-c`, `--rcfile`, `--init-file`, a second
    program) runs or loads what the check does not read."""
    words = value.split()
    return bool(words) and words[0] in ("bash", "sh") and all(SHELL_WORD.fullmatch(w) for w in words[1:])


class Jobs:
    """The rules of a job beside a secret; mixed into the check, which
    holds `root`, `installs`, `refuse` and `display`."""

    @staticmethod
    def holding(secret, state):
        """(how the job holds what makes the rules apply, the advice that
        ends a refusal), or None for a job that holds none of the three."""
        return ("a job that names a secret", "") if secret else HOLDS.get(state)

    def step_notes(self, path, step):
        """Note what a step of a job or of a local action runs that the
        check does not read: an expression pasted into its script, an action
        the check does not name, an image, and a step that changes the
        checkout."""
        note = self.installs.note
        self.env_notes(path, step)
        run = step.get("run")
        if isinstance(run, yaml.Scalar):
            try:
                spans = expressions.spans(run.value)
            except expressions.Unreadable:
                spans = []
            for start, inner in spans:
                self.refuse(path, "line %d: an expression the runner pastes into the script before the shell reads it (${{%s}}): pass the value in an env: and quote it" % (run.line_at(start), inner))
        uses = step.get("uses")
        if not isinstance(uses, yaml.Scalar):
            return
        name = uses.value.split("@")[0]
        if uses.value.startswith("./"):
            note("code", path, uses.line, uses.value)
        elif uses.value.startswith("docker://"):
            note("unheld", path, uses.line, "an image run as a step (%s)" % name)
        else:
            self.action_notes(path, uses, name, step.get("with"))

    def listed(self, path, uses, name):
        """Whether the action or workflow a `uses:` names is on the list:
        one that is not is refused by name in every job, and one listed for
        jobs that hold no secret is noted for a job that holds one."""
        action = "/".join(name.split("/")[:2]).lower()
        self.used.add(action)
        entry = self.actions_list.get(action)
        if entry is None:
            self.refuse(path, "line %d: an action that is not on the list (%s): what its pinned commit runs is not read, so scripts/lib/workflow_actions.txt names each action with what it is trusted to do" % (uses.line, name))
        elif not entry[1]:
            self.installs.note("unheld", path, uses.line, "an action that may run in no job beside a secret (%s)" % name)
        return action if entry is not None else None

    def action_notes(self, path, uses, name, given):
        note = self.installs.note
        action = self.listed(path, uses, name)
        given = given if isinstance(given, yaml.Mapping) else None
        if action is None:
            return
        if action == "actions/checkout" and given is not None and (given.key("repository") is not None or given.key("ref") is not None):
            note("tree", path, uses.line, "a checkout of another repository or ref")
        elif action == "actions/download-artifact" and not self.beside_checkout(given.get("path") if given is not None else None):
            note("tree", path, uses.line, "an artifact unpacked over the checkout")

    def beside_checkout(self, value):
        """Whether a download's `path` keeps its files off the checkout: a
        directory under the runner's temporary one, or one written out whose
        first part the repository does not hold."""
        if not isinstance(value, yaml.Scalar):
            return False
        text = value.value.strip()
        if RUNNER_TEMP.fullmatch(text):
            return ".." not in text.split("/")
        parts = [p for p in text.split("/") if p not in ("", ".")]
        if "$" in text or text.startswith(("/", "~")) or not parts or ".." in parts:
            return False
        return not os.path.lexists(os.path.join(self.root, parts[0]))

    def workflow_notes(self, path, doc, job):
        """Note a workflow of another repository a job calls, which is
        pinned to a commit and not read, and a variable of the `env:` of
        the workflow or the job by which a build script finds a program."""
        uses = job.get("uses")
        if isinstance(uses, yaml.Scalar) and not uses.value.startswith("./"):
            self.listed(path, uses, uses.value.split("@")[0])
        for owner in (doc, job):
            self.env_notes(path, owner)

    def env_notes(self, path, owner):
        env = owner.get("env")
        for key, _ in env.pairs if isinstance(env, yaml.Mapping) else []:
            if workflow_runners.BUILD_ENV.fullmatch(key.value):
                self.installs.note("unheld", path, key.line, "a variable by which a build script finds a program to run (%s)" % key.value)
            if workflow_runners.stand_in(key.value):
                self.installs.note("unheld", path, key.line, workflow_runners.stand_in(key.value))

    def moved(self, doc, job, step):
        """Whether a step's script starts in a directory other than the
        repository's root: a `working-directory` on the step, or in the
        `defaults` of its job or its workflow."""
        if step.key("working-directory") is not None:
            return True
        for owner in (job, doc):
            defaults = owner.get("defaults") if owner is not None else None
            run = defaults.get("run") if isinstance(defaults, yaml.Mapping) else None
            if isinstance(run, yaml.Mapping) and run.key("working-directory") is not None:
                return True
        return False

    def subcommands(self, path, key, found, notes):
        """An external cargo subcommand (`cargo audit`) is the program
        `cargo-audit` on the runner's path: every job installs the ones it
        runs, by a `cargo install` the check holds to `--locked` and an
        exact version, so that the program is not one the runner's image, a
        cache or another job's artifact put there."""
        installed = {crate for install in found for crate in install.crates}
        seen = set()
        for kind, where, line, what in notes:
            if kind == "subcommand" and "cargo-" + what not in installed and (where, line, what) not in seen:
                seen.add((where, line, what))
                self.refuse(path, "job %s, %s: an external cargo subcommand whose program the job does not install (cargo %s): install it in the job with cargo install --locked cargo-%s@X.Y.Z" % (
                    key.value, self.at(path, where, line), what, what))

    def held(self, path, key, holding, notes):
        """Refuse what a job beside a secret runs that the check does not
        read, and the job that changes its checkout and runs code from it."""
        how, advice = holding
        seen = set()
        for kind, where, line, what in notes:
            if kind == "unheld" and (where, line, what) not in seen:
                seen.add((where, line, what))
                self.refuse(path, "%s runs what the check does not read: job %s, %s: %s%s" % (how, key.value, self.at(path, where, line), what, advice))
        trees = [n for n in notes if n[0] == "tree"]
        codes = [n for n in notes if n[0] == "code"]
        if trees and codes:
            tree, code = trees[0], codes[0]
            self.refuse(path, "%s changes its checkout and runs code from it, which is not the code the check read: job %s, %s: %s, and %s: %s%s" % (
                how, key.value, self.at(path, tree[1], tree[2]), tree[3], self.at(path, code[1], code[2]), code[3], advice))

    def at(self, path, where, line):
        return "line %d" % line if where == path else "%s line %d" % (self.display(where), line)
