"""The Python programs of a script, for scripts/check-workflow-pins.sh.

A Python program is read for one thing: whether it can run another program
and passes `cargo` and then `install` in one statement. Names are compared
as Python compares them, after NFKC normalisation, so a name written with
other code points for the same letters is the name it normalises to.
"""

import io
import re
import tokenize
import unicodedata

# Names through which Python runs another program.
RUNNERS = {"subprocess", "system", "popen", "spawnl", "spawnlp", "spawnv", "spawnvp", "execl",
           "execlp", "execv", "execve", "execvp", "execvpe", "posix_spawn", "posix_spawnp",
           "create_subprocess_exec", "create_subprocess_shell", "getoutput", "getstatusoutput",
           "importlib", "__import__", "exec", "eval", "pty", "getattr", "__dict__", "vars",
           "globals", "locals", "builtins", "__builtins__", "ctypes", "runpy",
           "multiprocessing", "pickle"}


def python_runs_install(text):
    """Whether Python source can run a program (it names one of RUNNERS) and
    passes `cargo` and then `install` in one statement, as an argv list or a
    command string. Source that does not tokenize counts as one that does."""
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return True
    if not any(tok.type == tokenize.NAME and unicodedata.normalize("NFKC", tok.string) in RUNNERS for tok in toks):
        return False
    statement = []
    for tok in toks + [None]:
        if tok is None or tok.type == tokenize.NEWLINE:
            words = [w for text in statement for w in text.split()]
            for k, word in enumerate(words):
                if word == "cargo" or word.endswith("/cargo"):
                    if any(w in ("install", "binstall", "quickinstall") for w in words[k + 1:]):
                        return True
            statement = []
        elif tok.type == tokenize.STRING:
            statement.append(re.sub(r"^[A-Za-z]*", "", tok.string).strip("'\""))
    return False
