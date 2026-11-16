"""Run git against an untrusted repository without letting it execute code.

A repository is data, but git honours executable configuration inside it:

* ``diff.<driver>.textconv`` (declared through ``.gitattributes`` + ``.git/config``) is run by
  ``git log -p`` — arbitrary command execution while scanning history;
* ``core.fsmonitor`` is run by ``git ls-files`` — arbitrary command execution on *every* scan,
  even with ``--no-history``.

Every git invocation therefore disables both, ignores the user's and the system's config, and can
never prompt. See docs/self-audit/FINDINGS-DETAIL.md (TW-A1, TW-A2).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

#: Config forced on the command line (highest precedence, overrides the repo's own .git/config).
SAFE_CONFIG = (
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "diff.external=",
)


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",     # ignore /etc/gitconfig
        "GIT_CONFIG_GLOBAL": os.devnull,  # ignore ~/.gitconfig
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env


def run_git(root: Path, args: list[str], timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run `git -C root <safe config> <args>` and return the completed process."""
    return subprocess.run(
        ["git", "-C", str(root), *SAFE_CONFIG, *args],
        capture_output=True, text=True, errors="replace", timeout=timeout, env=_env(),
    )
