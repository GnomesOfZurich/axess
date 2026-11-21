"""The pins of the workflows: the rules scripts/check-workflow-pins.sh holds.

Usage: python3 -I -B scripts/lib/workflow_pins.py WORKFLOW_DIR

The header of scripts/check-workflow-pins.sh says what each rule holds and
why. This reads each workflow with scripts/lib/workflow_yaml.py, each `${{ }}`
expression with scripts/lib/workflow_expressions.py and each script a job
runs with scripts/lib/workflow_installs.py, holds the jobs beside a secret
to scripts/lib/workflow_jobs.py, and prints one `REFUSED:` line per
problem.
"""

import os
import re
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cargo_config
import workflow_downloads as downloads
import workflow_expressions as expressions
import workflow_installs as installs
import workflow_jobs
import workflow_yaml as yaml

SHA_PIN = re.compile(r"[A-Za-z0-9._/-]+@[0-9a-f]{40}")
VERSION_COMMENT = re.compile(r"(v?[0-9]|(master|main)\s*$)")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")
EXACT_TOOLCHAIN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+|(stable|beta|nightly)-[0-9]{4}-[0-9]{2}-[0-9]{2}")
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
# A channel that moves under a workflow that did not change: `stable`, `beta`
# and a two-part version, with or without a host. A dated channel does not
# move; nightly is left to the jobs that need it.
FLOATING = re.compile(r"(stable|beta|[0-9]+\.[0-9]+)(-[A-Za-z0-9_]+(-[A-Za-z0-9_]+)*)?")
# The dated nightly of the jobs that need what only a nightly has, written
# in one place; a nightly that is not dated moves under a workflow that did
# not change, as `stable` does.
NIGHTLY_FILE = "nightly-toolchain.toml"
DATED_NIGHTLY = re.compile(r"nightly-([0-9]{4}-[0-9]{2}-[0-9]{2})(-[A-Za-z0-9_]+)*")
FLOATING_NIGHTLY = re.compile(r"nightly(-(?![0-9]{4}-)[A-Za-z0-9_]+)*")
CHANGE_EVENTS = ("push", "pull_request", "pull_request_target", "merge_group", "release", "workflow_call")
OK = ("OK: every action is pinned to a commit SHA, every image to a digest, every checkout drops its "
      "credentials, every tool install is locked to an exact version, and no job that names a secret, "
      "may ask for an OIDC token or holds a token that can write installs a tool.")


class Check(workflow_jobs.Jobs):
    def __init__(self, root):
        self.root = root
        self.errors = 0
        self.installs = installs.Installs(root, self.refuse, self.display)
        self.actions = {}
        self.used = set()
        self.actions_list, self.list_problems = workflow_jobs.load_actions()
        self.called = False

    def display(self, path):
        """A file under the root by its path from the root; anything else as given."""
        rel = os.path.relpath(os.path.abspath(path), self.root)
        return path if rel == "." or rel.startswith("..") else rel

    def refuse(self, path, message):
        print("REFUSED: %s: %s" % (self.display(path), message), file=sys.stderr)
        self.errors += 1

    # One workflow.

    def file(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            self.refuse(path, "the workflow cannot be read: %s" % e)
            return
        try:
            doc = yaml.read(text)
        except yaml.Refusal as e:
            self.refuse(path, "line %d: not read as YAML: %s" % (e.line, e.message))
            return
        if not isinstance(doc, yaml.Mapping):
            self.refuse(path, "the workflow is not a mapping")
            return
        lines = text.split("\n")
        self.pins(path, doc, lines)
        self.envs(path, doc)
        jobs = doc.get("jobs")
        self.called = self.is_called(doc)
        shared = self.names_secret(path, [v for k, v in doc.pairs if k.value != "jobs"] + [k for k, _ in doc.pairs])
        workflow_permissions = doc.get("permissions")
        self.workflow_oidc(path, workflow_permissions)
        if not isinstance(jobs, yaml.Mapping):
            if jobs is not None:
                self.refuse(path, "line %d: jobs that is not a mapping" % doc.key("jobs").line)
            return
        self.installs.toolchains = []
        holds = False
        for key, job in jobs.pairs:
            if not isinstance(job, yaml.Mapping):
                self.refuse(path, "line %d: the job %s is not a mapping" % (key.line, key.value))
                continue
            self.local_files(path, key, job)
            mark = self.installs.mark()
            found = self.job_installs(path, doc, job)
            self.workflow_notes(path, doc, job)
            notes = self.installs.notes[mark[1]:]
            del self.installs.notes[mark[1]:]
            self.download_rules(path, doc, job, notes)
            secret = shared or self.names_secret(path, [job]) or self.composite_secret(path, job) or job.key("secrets") is not None
            permissions = job.get("permissions") if job.key("permissions") is not None else workflow_permissions
            state = self.permission_state(path, permissions)
            holds = holds or secret or state == "oidc"
            self.subcommands(path, key, found, notes)
            holding = self.holding(secret, state)
            if holding is None:
                continue
            if found:
                self.refuse(path, "%s installs a tool on the same runner: job %s, %s%s" % (holding[0], key.value, found[0].describe(), holding[1]))
            self.held(path, key, holding, notes)
        if holds:
            self.toolchains(path, doc, jobs)
        self.pinned_toolchains(path, doc, jobs)

    def download_rules(self, path, doc, job, notes):
        """What the job downloads is checked against a SHA-256 the repository
        writes before it is run or unpacked, and no action of the job is
        handed a URL (scripts/lib/workflow_downloads.py)."""
        documents = [job]
        for node in yaml.walk(job):
            uses = node.get("uses") if isinstance(node, yaml.Mapping) else None
            action = self.local_action(uses) if isinstance(uses, yaml.Scalar) and uses.value.startswith("./") else None
            if action is not None and action[2] is not None:
                documents.append(action[2])
        nodes = [doc] + [n for d in documents for n in yaml.walk(d) if isinstance(n, yaml.Mapping)]
        downloads.judge(notes, downloads.env_digests(nodes), self.refuse, lambda where, line: self.at(path, where, line))
        for line, name, url in downloads.action_urls(nodes):
            self.refuse(path, "line %d: an action is handed a URL as its input %s (%s): what it fetches is checked against no SHA-256 the repository writes (download it in a run step and check it with sha256sum --check)" % (line, name, url))

    def envs(self, path, doc):
        """Every variable of an `env:` in a workflow or a local action is
        held to the rules on variables: one that changes what cargo, a shell
        or git runs is refused, and so are the directories programs are run
        from and flags for rustc that name a program or come from an
        expression."""
        for node in yaml.walk(doc):
            env = node.get("env") if isinstance(node, yaml.Mapping) else None
            for key, value in env.pairs if isinstance(env, yaml.Mapping) else []:
                self.installs.cargo_env(key.value, path, key.line)
                if key.value == "PATH":
                    self.refuse(path, "line %d: PATH in an env: names the directories every program of the job is run from, which is not read: a step that needs a directory on the path writes it to $GITHUB_PATH" % key.line)
                text = value.value if isinstance(value, yaml.Scalar) else None
                self.installs.flags_env(key.value, None if text is None or "${{" in text else text, path, key.line)

    def pins(self, path, doc, lines):
        """Every action pinned to a commit, every image to a digest, every checkout without credentials."""
        for node in yaml.walk(doc):
            if not isinstance(node, yaml.Mapping):
                continue
            for key, value in node.pairs:
                if key.value not in ("uses", "image") and not (key.value == "container" and isinstance(value, yaml.Scalar)):
                    continue
                shown = "%d:%s" % (key.line, lines[key.line - 1])
                if node.flow:
                    self.refuse(path, "flow-style mapping on uses: or image: (write it in block style): %s" % shown)
                    continue
                if not isinstance(value, yaml.Scalar):
                    self.refuse(path, "%s that is not a single value: %s" % (key.value, shown))
                    continue
                text = value.value
                if key.value != "uses" or text.startswith("docker://"):
                    if not DIGEST.search(text):
                        self.refuse(path, "image not pinned by an @sha256 digest: %s" % shown)
                elif not text.startswith("./") and not (
                        SHA_PIN.fullmatch(text) and value.comment is not None and VERSION_COMMENT.match(value.comment)):
                    self.refuse(path, "action not pinned to a full commit SHA with a version comment: %s" % shown)
            uses = node.get("uses")
            if isinstance(uses, yaml.Scalar) and uses.value.lower().startswith("actions/checkout@"):
                given = node.get("with")
                flag = given.get("persist-credentials") if isinstance(given, yaml.Mapping) else None
                if not (isinstance(flag, yaml.Scalar) and flag.value.lower() == "false"):
                    self.refuse(path, "checkout at line %d does not set persist-credentials: false" % node.key("uses").line)

    # Secrets and permissions.

    @staticmethod
    def is_called(doc):
        """Whether another workflow may call this one (`on: workflow_call`):
        its caller may hand it a secret as an input."""
        on = doc.get("on")
        if isinstance(on, yaml.Scalar):
            return on.value == "workflow_call"
        if isinstance(on, yaml.Sequence):
            return any(isinstance(i, yaml.Scalar) and i.value == "workflow_call" for i in on.items)
        return isinstance(on, yaml.Mapping) and on.key("workflow_call") is not None

    def names_secret(self, path, nodes, called=None):
        """Whether an expression in `nodes` names a secret or hands on the job's
        token; in a called workflow, `inputs` counts as one. A local action's
        inputs come from the step that uses it, which the job's own reading holds."""
        called = self.called if called is None else called
        named = False
        for top in nodes:
            ifs = set()
            for node in yaml.walk(top):
                if isinstance(node, yaml.Mapping):
                    for key, value in node.pairs:
                        if key.value == "if":
                            ifs.add(id(value))
                if id(node) in ifs and not isinstance(node, yaml.Scalar):
                    self.refuse(path, "line %d: an if that is not a single value" % node.line)
                    named = True
                if not isinstance(node, yaml.Scalar) or not node.value:
                    continue
                try:
                    found = expressions.spans(node.value)
                    texts = [inner for _, inner in found]
                    if not found and id(node) in ifs:
                        texts = [node.value]
                    if any(expressions.names_secret(t, called) for t in texts):
                        named = True
                except expressions.Unreadable as e:
                    self.refuse(path, "line %d: an expression the check cannot read: %s" % (node.line, e))
                    named = True
        return named

    def permission_state(self, path, permissions):
        """undeclared, read, write or oidc, for a permissions value."""
        if permissions is None:
            return "undeclared"
        if isinstance(permissions, yaml.Scalar):
            value = permissions.value.lower()
            if value == "read-all":
                return "read"
            if value == "write-all":
                return "oidc"
            self.refuse(path, "line %d: a permissions value the check does not read: %s" % (permissions.line, permissions.value))
            return "oidc"
        if not isinstance(permissions, yaml.Mapping):
            self.refuse(path, "line %d: a permissions value the check does not read" % permissions.line)
            return "oidc"
        state = "read"
        for key, value in permissions.pairs:
            level = value.value.lower() if isinstance(value, yaml.Scalar) else None
            if level not in ("read", "write", "none"):
                self.refuse(path, "line %d: a permission the check does not read: %s" % (key.line, key.value))
                return "oidc"
            if level == "write" and key.value == "id-token":
                return "oidc"
            if level == "write":
                state = "write"
        return state

    def workflow_oidc(self, path, permissions):
        """The OIDC permission stands on the job that asks for the token, never on the workflow."""
        if permissions is None:
            return
        if isinstance(permissions, yaml.Scalar) and permissions.value.lower() == "write-all":
            self.refuse(path, "line %d: every permission, the OIDC one included, stands on the whole workflow: give each job the permissions it needs" % permissions.line)
        elif isinstance(permissions, yaml.Mapping):
            value = permissions.get("id-token")
            if isinstance(value, yaml.Scalar) and value.value.lower() == "write":
                self.refuse(path, "line %d: the OIDC permission stands on the whole workflow, so every job may ask for a token: give it to the job that needs it" % permissions.key("id-token").line)

    # Installs.

    def job_installs(self, path, doc, job):
        """The installs of every run step of a job, and of the local actions it uses."""
        found = []
        steps = job.get("steps")
        if steps is not None and not isinstance(steps, yaml.Sequence):
            self.refuse(path, "line %d: steps that is not a sequence" % job.key("steps").line)
        for step in steps.items if isinstance(steps, yaml.Sequence) else []:
            if not isinstance(step, yaml.Mapping):
                self.refuse(path, "line %d: a step that is not a mapping" % step.line)
                continue
            run = step.get("run")
            if run is not None and not isinstance(run, yaml.Scalar):
                self.refuse(path, "line %d: run that is not a single value" % step.key("run").line)
            if isinstance(run, yaml.Scalar):
                if self.shell_of(path, doc, job, step):
                    found.extend(self.installs.script(run.value, run.line_at, path, self.moved(doc, job, step)))
            self.step_notes(path, step)
            uses = step.get("uses")
            if isinstance(uses, yaml.Scalar) and uses.value.startswith("./"):
                found.extend(self.composite(path, uses))
        return found

    def shell_of(self, path, doc, job, step):
        """Whether the step's script runs in bash or sh, which the check reads."""
        shell = step.get("shell")
        for owner in (job, doc):
            defaults = owner.get("defaults")
            run = defaults.get("run") if isinstance(defaults, yaml.Mapping) else None
            if shell is None and isinstance(run, yaml.Mapping):
                shell = run.get("shell")
        if shell is None:
            if self.may_run_on_windows(job):
                self.refuse(path, "line %d: a run step on a runner that may be Windows runs in PowerShell, which is not read: set shell: bash" % step.line)
                return False
            return True
        if isinstance(shell, yaml.Scalar) and workflow_jobs.shell_read(shell.value):
            return True
        self.refuse(path, "line %d: a run step in a shell the check does not read: %s (use bash or sh)" % (step.line, shell.value if isinstance(shell, yaml.Scalar) else ""))
        return False

    @staticmethod
    def may_run_on_windows(job):
        runs_on = job.get("runs-on")
        values = []
        for node in yaml.walk(runs_on) if runs_on is not None else []:
            if isinstance(node, yaml.Scalar):
                values.append(node.value)
        resolved = []
        strategy = job.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, yaml.Mapping) else None
        for value in values:
            m = re.fullmatch(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}", value.strip())
            if m and isinstance(matrix, yaml.Mapping) and isinstance(matrix.get(m.group(1)), yaml.Sequence):
                items = matrix.get(m.group(1)).items
                if all(isinstance(i, yaml.Scalar) for i in items) and matrix.get("include") is None:
                    resolved.extend(i.value for i in items)
                    continue
            if "${{" in value:
                return True
            resolved.append(value)
        return any("windows" in v.lower() for v in resolved)

    def local_files(self, path, key, job):
        """A local action or reusable workflow a job names is one the repository holds."""
        steps = job.get("steps")
        named = [job.get("uses")] + [s.get("uses") for s in (steps.items if isinstance(steps, yaml.Sequence) else []) if isinstance(s, yaml.Mapping)]
        for uses in named:
            if isinstance(uses, yaml.Scalar) and uses.value.startswith("./"):
                target = os.path.normpath(os.path.join(self.root, uses.value))
                if not (os.path.isfile(target) or os.path.isfile(os.path.join(target, "action.yml")) or os.path.isfile(os.path.join(target, "action.yaml"))):
                    self.refuse(path, "line %d: a local action or workflow the repository does not hold: %s (job %s)" % (uses.line, uses.value, key.value))

    def local_action(self, uses):
        """(path, (installs, names a secret), document, the toolchains its
        scripts select and the notes of what they run) of the local action a
        step uses, read and held to its pins once: None when the step names
        no action file, a None document when the file cannot be read, which
        is refused by name."""
        base = os.path.normpath(os.path.join(self.root, uses.value))
        names = [os.path.join(base, n) for n in ("action.yml", "action.yaml")]
        path = next((n for n in names if os.path.isfile(n)), None)
        if path is None:
            return None
        if path not in self.actions:
            self.actions[path] = (path, ([], False), None, ([], []))
            try:
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                doc = yaml.read(text)
            except (OSError, UnicodeDecodeError) as e:
                self.refuse(path, "the local action cannot be read: %s" % e)
                doc = None
            except yaml.Refusal as e:
                self.refuse(path, "line %d: not read as YAML: %s" % (e.line, e.message))
                doc = None
            if doc is not None:
                self.pins(path, doc, text.split("\n"))
                self.envs(path, doc)
            mark = self.installs.mark()
            reading = self.action_reading(path, doc)
            saved = self.installs.since(mark)
            self.installs.drop(mark)
            self.actions[path] = (path, reading, doc, saved)
        return self.actions[path]

    def action_reading(self, path, doc):
        """(installs, names a secret) of a local action's document."""
        if not isinstance(doc, yaml.Mapping):
            if doc is not None:
                self.refuse(path, "the local action is not a mapping")
            return [installs.Install(1, "a local action it cannot read")], True
        runs = doc.get("runs")
        using = runs.get("using") if isinstance(runs, yaml.Mapping) else None
        if not (isinstance(using, yaml.Scalar) and using.value == "composite"):
            self.refuse(path, "a local action that is not composite is not read: it runs %s" % (
                using.value if isinstance(using, yaml.Scalar) and using.value else "nothing the check reads"))
            return [installs.Install(1, "a local action it cannot read")], True
        steps = runs.get("steps")
        found = []
        secret = self.names_secret(path, [doc], called=False)
        for step in steps.items if isinstance(steps, yaml.Sequence) else []:
            if not isinstance(step, yaml.Mapping):
                self.refuse(path, "line %d: a step that is not a mapping" % step.line)
                continue
            run = step.get("run")
            shell = step.get("shell")
            if isinstance(run, yaml.Scalar) and not (isinstance(shell, yaml.Scalar) and workflow_jobs.shell_read(shell.value)):
                self.refuse(path, "line %d: a run step in a shell the check does not read: %s (use bash or sh)" % (step.line, shell.value if isinstance(shell, yaml.Scalar) else "none set"))
            elif isinstance(run, yaml.Scalar):
                found.extend(self.installs.script(run.value, run.line_at, path, step.key("working-directory") is not None))
            self.step_notes(path, step)
            uses = step.get("uses")
            if isinstance(uses, yaml.Scalar) and uses.value.startswith("./"):
                inner = self.local_action(uses)
                if inner is None:
                    self.refuse(path, "line %d: a local action the repository does not hold: %s" % (uses.line, uses.value))
                    continue
                found.extend(self.composite(path, uses))
                secret = secret or inner[1][1]
        return found, secret

    def composite(self, path, uses):
        """The installs of a local composite action a step uses."""
        action = self.local_action(uses)
        if action is None:
            return []
        action_path, (found, _), _, saved = action
        self.installs.replay(saved)
        return [installs.Install(uses.line, f.what, f.where or "%s, line %d" % (self.display(action_path), f.line), f.crates) for f in found]

    def composite_secret(self, path, job):
        """Whether a local action the job uses names a secret."""
        steps = job.get("steps")
        for step in steps.items if isinstance(steps, yaml.Sequence) else []:
            uses = step.get("uses") if isinstance(step, yaml.Mapping) else None
            action = self.local_action(uses) if isinstance(uses, yaml.Scalar) and uses.value.startswith("./") else None
            if action is not None and action[1][1]:
                return True
        return False

    # Cargo's configuration.

    def cargo_configs(self):
        """Every cargo configuration file in the repository holds only the
        settings cargo_config allows: cargo reads each one under the
        directory a job runs it in."""
        for base, dirs, names in os.walk(self.root):
            dirs[:] = sorted(d for d in dirs if d not in (".git", "target", "node_modules"))
            if os.path.basename(base) != ".cargo":
                continue
            for name in sorted(n for n in names if n in ("config", "config.toml")):
                path = os.path.join(base, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                except (OSError, UnicodeDecodeError) as e:
                    self.refuse(path, "the cargo configuration cannot be read: %s" % e)
                    continue
                for line, message in cargo_config.file_problems(text):
                    self.refuse(path, "line %d: %s" % (line, message))

    # Toolchains.

    def documents(self, path, doc, jobs):
        """The workflow and the local actions its steps use, each once."""
        documents = [(path, doc)]
        for node in yaml.walk(jobs):
            uses = node.get("uses") if isinstance(node, yaml.Mapping) else None
            action = self.local_action(uses) if isinstance(uses, yaml.Scalar) and uses.value.startswith("./") else None
            if action is not None and action[2] is not None and all(action[0] != p for p, _ in documents):
                documents.append((action[0], action[2]))
        return documents

    def pinned_toolchains(self, path, doc, jobs):
        """In every workflow, a release written out as a toolchain is the one
        the repository's toolchain file pins, and in a workflow that runs on
        a push, a pull request or a release, no toolchain is `stable` or
        `beta`: what CI builds with is what a checkout builds with, and the
        next move of the pin is the file's one line, which this holds every
        literal to. Nightly stays open, for the jobs that need what only a
        nightly has (cargo-fuzz, Miri), and those hold to the one nightly
        the repository's nightly file names: a dated nightly anywhere, in a
        step, an env, a script's `+toolchain` or what it writes to
        $GITHUB_ENV, is that one, and in a workflow that runs on a change
        no nightly is undated."""
        pinned = self.pinned_channel()
        nightly = self.pinned_nightly()
        changes = self.runs_on_change(doc)
        for where, document in self.documents(path, doc, jobs):
            at = "" if where == path else "%s, " % self.display(where)
            for line, value in self.named_toolchains(document):
                if pinned is not None and RELEASE.fullmatch(value) and value != pinned[1]:
                    self.refuse(path, "%sline %d: the toolchain %s is not the release %s pins (%s): read the channel from that file, or write the same release" % (at, line, value, pinned[0], pinned[1]))
                if changes and FLOATING.fullmatch(value) and not EXACT_TOOLCHAIN.fullmatch(value):
                    self.refuse(path, "%sline %d: a floating toolchain (%s) in a workflow that runs on a push, a pull request or a release: install the release rust-toolchain.toml pins" % (at, line, value))
                self.held_nightly(path, at, line, value, nightly, changes)
        seen = set()
        for where, line, value in self.installs.toolchains:
            if (where, line, value) in seen:
                continue
            seen.add((where, line, value))
            at = "" if where == path else "%s, " % self.display(where)
            self.held_nightly(path, at, line, value, nightly, changes)

    def held_nightly(self, path, at, line, value, nightly, changes):
        """A nightly named in a workflow is the dated one the nightly file
        pins, and is not undated in a workflow that runs on a change."""
        dated = DATED_NIGHTLY.fullmatch(value)
        if dated and nightly is not None and "nightly-" + dated.group(1) != nightly:
            self.refuse(path, "%sline %d: the nightly %s is not the one %s pins (%s): read it from that file (.github/actions/pinned-nightly), or write the same date" % (at, line, value, NIGHTLY_FILE, nightly))
        if changes and FLOATING_NIGHTLY.fullmatch(value):
            self.refuse(path, "%sline %d: a floating nightly (%s) in a workflow that runs on a push, a pull request or a release: install the dated nightly %s pins (.github/actions/pinned-nightly)" % (at, line, value, NIGHTLY_FILE))

    def pinned_nightly(self):
        """The dated nightly the repository's nightly file pins, or None
        when there is no such file or it names none (nightly_file refuses
        that)."""
        found = self.nightly_channel()
        return found if found is not None and re.fullmatch(r"nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}", found) else None

    def nightly_channel(self):
        file = os.path.join(self.root, NIGHTLY_FILE)
        if not os.path.isfile(file):
            return None
        with open(file, encoding="utf-8", errors="replace") as f:
            m = re.search(r"""^\s*channel\s*=\s*["']([^"']*)["']""", f.read(), re.M)
        return m.group(1) if m else ""

    def nightly_file(self):
        """The nightly file, where there is one, names a dated nightly with
        no host: the one place the jobs' nightly is read from."""
        found = self.nightly_channel()
        if found is not None and self.pinned_nightly() is None:
            self.refuse(NIGHTLY_FILE, "names no dated nightly (%s): write channel = \"nightly-YYYY-MM-DD\"" % (found or "none named"))

    def pinned_channel(self):
        """(file name, release) of the exact release X.Y.Z the repository's
        toolchain file pins, or None when it names none."""
        found = self.toolchain_channel()
        return found if found is not None and RELEASE.fullmatch(found[1]) else None

    def toolchain_channel(self):
        """(file name, channel) of the repository's rust-toolchain.toml, or of
        the legacy rust-toolchain, whichever comes first; None without one."""
        for name in ("rust-toolchain.toml", "rust-toolchain"):
            file = os.path.join(self.root, name)
            if not os.path.isfile(file):
                continue
            with open(file, encoding="utf-8", errors="replace") as f:
                text = f.read()
            m = re.search(r"""^\s*channel\s*=\s*["']([^"']*)["']""", text, re.M)
            return name, m.group(1) if m else (text.strip() if "\n" not in text.strip() and "=" not in text else "")
        return None

    @staticmethod
    def runs_on_change(doc):
        """Whether the workflow runs on a push, a pull request, a release or
        a call from another workflow (which may be any of those)."""
        on = doc.get("on")
        if isinstance(on, yaml.Scalar):
            events = [on.value]
        elif isinstance(on, yaml.Sequence):
            events = [i.value for i in on.items if isinstance(i, yaml.Scalar)]
        elif isinstance(on, yaml.Mapping):
            events = [k.value for k, _ in on.pairs]
        else:
            events = []
        return any(e in CHANGE_EVENTS for e in events)

    @staticmethod
    def named_toolchains(document):
        """(line, text) of each toolchain a rust-toolchain step names and each
        RUSTUP_TOOLCHAIN an env sets, as written; an expression is not read."""
        for node in yaml.walk(document):
            if not isinstance(node, yaml.Mapping):
                continue
            env = node.get("env")
            value = env.get("RUSTUP_TOOLCHAIN") if isinstance(env, yaml.Mapping) else None
            if isinstance(value, yaml.Scalar):
                yield value.line, value.value
            given = node.get("with")
            uses = node.get("uses")
            if isinstance(uses, yaml.Scalar) and "rust-toolchain" in uses.value.split("@")[0].lower():
                toolchain = given.get("toolchain") if isinstance(given, yaml.Mapping) else None
                if isinstance(toolchain, yaml.Scalar):
                    yield toolchain.line, toolchain.value

    def toolchains(self, path, doc, jobs):
        """In a workflow with a job that holds a secret or an OIDC permission,
        every toolchain is exact: those of its steps and of the local actions
        they use, a RUSTUP_TOOLCHAIN in an env, the toolchains its scripts
        select, and the repository's toolchain file."""
        for where, document in self.documents(path, doc, jobs):
            self.document_toolchains(path, where, document)
        seen = set()
        for where, line, name in self.installs.toolchains:
            if not EXACT_TOOLCHAIN.fullmatch(name) and (where, line, name) not in seen:
                seen.add((where, line, name))
                at = "line %d" % line if where == path else "%s, line %d" % (self.display(where), line)
                self.refuse(path, "%s: a toolchain that is not an exact version (%s) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z" % (at, name))
        self.toolchain_file(path)

    def toolchain_file(self, path):
        """The repository's rust-toolchain.toml (or rust-toolchain) names an
        exact channel: rustup takes the file over its default toolchain, so
        the file decides wherever no RUSTUP_TOOLCHAIN or `+toolchain` does,
        and those are held to an exact release here as well."""
        found = self.toolchain_channel()
        if found is not None and not EXACT_TOOLCHAIN.fullmatch(found[1]):
            self.refuse(path, "%s names a toolchain that is not an exact version (%s), in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z" % (found[0], found[1] or "none named"))

    def document_toolchains(self, path, where, document):
        """The rust-toolchain steps and RUSTUP_TOOLCHAIN values of a workflow or a local action."""
        at = "" if where == path else "%s, " % self.display(where)
        for node in yaml.walk(document):
            if not isinstance(node, yaml.Mapping):
                continue
            env = node.get("env")
            value = env.get("RUSTUP_TOOLCHAIN") if isinstance(env, yaml.Mapping) else None
            if value is not None:
                text = value.value if isinstance(value, yaml.Scalar) else ""
                if not EXACT_TOOLCHAIN.fullmatch(text):
                    self.refuse(path, "%sline %d: a toolchain that is not an exact version (%s) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z" % (at, env.key("RUSTUP_TOOLCHAIN").line, text or "none named"))
            given = node.get("with")
            uses = node.get("uses")
            names_toolchain = isinstance(uses, yaml.Scalar) and "rust-toolchain" in uses.value.split("@")[0].lower()
            toolchain = given.get("toolchain") if isinstance(given, yaml.Mapping) else None
            if toolchain is None and not names_toolchain:
                continue
            value = toolchain.value if isinstance(toolchain, yaml.Scalar) else ""
            if not EXACT_TOOLCHAIN.fullmatch(value):
                line = toolchain.line if isinstance(toolchain, yaml.Scalar) else node.line
                self.refuse(path, "%sline %d: a toolchain that is not an exact version (%s) in a workflow with a job that holds a secret or an OIDC permission: name the release, X.Y.Z" % (at, line, value or "none named"))


def main(argv):
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    directory = argv[1] if len(argv) > 1 else os.path.join(root_dir, ".github", "workflows")
    absolute = os.path.abspath(directory)
    if absolute.endswith(os.path.join(".github", "workflows")):
        root = os.path.dirname(os.path.dirname(absolute))
    else:
        root = absolute
    check = Check(root)
    for line, message in check.list_problems:
        check.refuse(workflow_jobs.ACTIONS_FILE, "line %d: %s" % (line, message))
    names = sorted(n for n in os.listdir(directory) if n.endswith((".yml", ".yaml"))) if os.path.isdir(directory) else []
    if not os.path.isdir(directory):
        check.refuse(directory, "no workflow directory: a checkout without its workflows has nothing to pass")
    elif not names:
        check.refuse(directory, "no workflow file (*.yml, *.yaml): a checkout without its workflows has nothing to pass")
    for name in names:
        check.file(os.path.join(directory, name))
    check.cargo_configs()
    check.nightly_file()
    if names and os.path.realpath(root) == os.path.realpath(root_dir):
        # The list is the repository's own: a line none of its workflows uses is a trust nobody needs.
        for line, message in workflow_jobs.unused_actions(check.actions_list, check.used):
            check.refuse(workflow_jobs.ACTIONS_FILE, "line %d: %s" % (line, message))
    if check.errors:
        print("%d workflow pin problem(s)." % check.errors, file=sys.stderr)
        return 1
    print(OK)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
