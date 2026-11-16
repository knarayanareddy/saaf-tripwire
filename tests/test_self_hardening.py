"""Regressions for the self-audit findings (docs/self-audit/): running git on an untrusted repo must
not execute its config, a failed history scan must fail closed, and untrusted text must not forge a
CI workflow command."""
import os
import subprocess

from tripwire import cli, report
from tripwire.model import Finding

GIT = ["git", "-c", "user.email=a@b", "-c", "user.name=t", "-c", "init.defaultBranch=main"]
REAL_GIT = subprocess.run(["sh", "-c", "command -v git"], capture_output=True, text=True).stdout.strip() or "git"
KEY = "sk-ant-" + "Z9x8C7v6B5n4M3l2K1j0QwErTyUiOpAsDf"   # 40 chars after the prefix


def _git(repo, *args):
    return subprocess.run(GIT + ["-C", str(repo), *args], capture_output=True, text=True, check=True)


def _repo(path, files=None):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    for name, content in (files or {"app.py": "x = 1\n"}).items():
        (path / name).write_text(content)
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "one")
    return path


def test_textconv_is_not_executed(tmp_path):
    repo = _repo(tmp_path / "repo", {"app.py": "x = 1\n"})
    (repo / ".gitattributes").write_text("* diff=evil\n")
    marker = tmp_path / "pwned.txt"
    _git(repo, "config", "diff.evil.textconv", f"sh -c 'echo PWNED > {marker}' #")
    (repo / "app.py").write_text("x = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "two")

    findings, meta, _ = cli.scan(repo, history=True)
    assert not marker.exists(), "a scanned repo must never execute diff.<driver>.textconv"
    assert meta["errors"] == []


def test_fsmonitor_is_not_executed(tmp_path):
    repo = _repo(tmp_path / "repo")
    marker = tmp_path / "fsmon.txt"
    _git(repo, "config", "core.fsmonitor", f"sh -c 'echo FS > {marker}' #")

    findings, meta, _ = cli.scan(repo, history=False)
    assert not marker.exists(), "git ls-files must not run core.fsmonitor from the scanned repo"


def test_failed_history_scan_fails_closed(tmp_path, monkeypatch):
    repo = _repo(tmp_path / "repo", {"k.py": f'K = "{KEY}"\n'})
    bindir = tmp_path / "bin"
    bindir.mkdir()
    wrapper = bindir / "git"
    wrapper.write_text(f"""#!/bin/sh
for a in "$@"; do
  if [ "$a" = "log" ]; then echo "fatal: repository is unavailable" >&2; exit 128; fi
done
exec {REAL_GIT} "$@"
""")
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")

    findings, meta, _ = cli.scan(repo, history=True)
    assert any(e["rule"] == "TW-SEC1" for e in meta["errors"]), "a broken history scan must not look clean"
    assert cli.main(["scan", str(repo), "--only", "TW-SEC1"]) == 2


def test_shallow_clone_fails_closed(tmp_path):
    src = _repo(tmp_path / "src", {"k.py": f'K = "{KEY}"\n'})
    (src / "k.py").unlink()
    (src / "README.md").write_text("cleaned\n")
    _git(src, "add", "-A")
    _git(src, "commit", "-qm", "remove")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{src}", str(clone)], check=True)
    assert _git(clone, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"

    findings, meta, _ = cli.scan(clone, history=True)
    assert findings == []
    assert any(e["rule"] == "TW-SEC1" and "shallow" in e["error"] for e in meta["errors"])


def test_newline_in_path_cannot_forge_a_workflow_command():
    f = Finding(rule="TW-NET1", severity="medium", file="evil\n::error::forged.py", line=3,
                message="binds\nall", fix="fix", evidence="line\n::stop-commands::x")
    meta = {"rules_run": 1, "files": 1, "seconds": 0, "errors": [], "history": False,
            "ignored": 0, "baselined": 0}
    out = report.to_text([f], meta)
    assert "\n::" not in out

    sarif = report.to_sarif([f], [], meta, None)
    result = sarif["runs"][0]["results"][0]
    assert "\n" not in result["message"]["text"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\n" not in uri
