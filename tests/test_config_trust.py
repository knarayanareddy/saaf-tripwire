"""R-01/R-02: a change must not be able to silence its own findings via .tripwireignore or a baseline.

The scanned repo is untrusted input. `--config-from` points the engine at a trusted copy (the CI action
uses the base commit); the default stays the scanned root so local runs behave as before.
"""
import json

import pytest

from tripwire import cli, report

APP = 'from flask import Flask\napp = Flask(__name__)\napp.run(host="0.0.0.0")\n'


def _repo(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    return tmp_path


def _net1(findings):
    return [f for f in findings if f.rule == "TW-NET1"]


def test_repo_ignore_is_honoured_for_local_runs(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".tripwireignore").write_text("app.py\n")
    findings, meta, _ = cli.scan(repo, history=False)
    assert not _net1(findings)
    assert meta["ignored"] >= 1 and meta["trusted_config"] is False
    assert any(s["reason"] == "ignore" for s in meta["suppressed"])


def test_trusted_config_ignores_a_pr_supplied_ignore(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".tripwireignore").write_text("app.py\n")
    base = tmp_path / "base"
    base.mkdir()
    findings, meta, _ = cli.scan(repo, history=False, config_from=str(base))
    assert _net1(findings), "a PR-supplied .tripwireignore must not suppress findings in trusted mode"
    assert meta["ignored"] == 0 and meta["trusted_config"] is True


def test_trusted_config_does_not_inherit_a_pr_supplied_baseline(tmp_path):
    repo = _repo(tmp_path)
    findings, _, _ = cli.scan(repo, history=False)
    fingerprint = report.fingerprint(_net1(findings)[0])
    (repo / "accepted.json").write_text(json.dumps({"accepted": [{"fingerprint": fingerprint}]}))
    base = tmp_path / "base"
    base.mkdir()

    with pytest.raises(ValueError):
        # A baseline that exists only in the change is a control-plane change: refuse, do not ignore.
        cli.scan(repo, history=False, baseline="accepted.json", config_from=str(base))

    local, meta_l, _ = cli.scan(repo, history=False, baseline="accepted.json")
    assert not _net1(local)
    assert meta_l["baselined"] == 1


def test_a_baseline_committed_at_the_trusted_base_still_suppresses(tmp_path):
    repo = _repo(tmp_path)
    findings, _, _ = cli.scan(repo, history=False)
    fingerprint = report.fingerprint(_net1(findings)[0])
    base = tmp_path / "base"
    base.mkdir()
    (base / "accepted.json").write_text(json.dumps({"accepted": [{"fingerprint": fingerprint}]}))
    findings, meta, _ = cli.scan(repo, history=False, baseline="accepted.json", config_from=str(base))
    assert not _net1(findings)
    assert meta["baselined"] == 1


# --- the CI trust boundary itself (scripts/ci-config.sh): config comes from the base commit ---

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci-config.sh"
GIT = ["git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", "-c", "init.defaultBranch=main"]


def _git(repo, *args):
    return subprocess.run(GIT + ["-C", str(repo), *args], capture_output=True, text=True, check=True)


def _repo_with_pr(tmp_path):
    """A repo whose base commit is clean and whose head adds a secret plus a suppressing config."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text(APP)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "keys.py").write_text('ANTHROPIC_API_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n')
    (repo / ".tripwireignore").write_text("app.py\nkeys.py\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pr")
    return repo, base


def _ci_config(repo, base, baseline="", dest=None):
    dest = dest or (repo.parent / "trusted")
    r = subprocess.run(["bash", str(SCRIPT), str(repo), base, baseline, str(dest)],
                       capture_output=True, text=True)
    return r, dest


def test_ci_config_excludes_an_ignore_added_by_the_pull_request(tmp_path):
    repo, base = _repo_with_pr(tmp_path)
    r, dest = _ci_config(repo, base)
    assert r.returncode == 0, r.stderr
    assert not (dest / ".tripwireignore").exists(), "the PR's own ignore file must not be trusted"
    findings, meta, _ = cli.scan(repo, history=False, config_from=str(dest))
    assert [f for f in findings if f.rule == "TW-NET1"], "the finding must survive the PR's .tripwireignore"
    assert meta["ignored"] == 0


def test_ci_config_uses_the_checkout_when_there_is_no_base(tmp_path):
    repo, _ = _repo_with_pr(tmp_path)
    r, dest = _ci_config(repo, "")
    assert r.returncode == 0, r.stderr
    assert (dest / ".tripwireignore").read_text().startswith("app.py")


def test_ci_config_refuses_a_baseline_that_the_change_introduces(tmp_path):
    repo, base = _repo_with_pr(tmp_path)
    (repo / "accepted.json").write_text('{"accepted": []}')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add baseline")
    r, _ = _ci_config(repo, base, "accepted.json", dest=tmp_path / "trusted2")
    assert r.returncode == 3
    assert "may not introduce its own baseline" in r.stderr


def test_ci_config_copies_a_baseline_that_exists_at_the_base(tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text(APP)
    (repo / "accepted.json").write_text('{"accepted": []}')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    r, dest = _ci_config(repo, base, "accepted.json", dest=tmp_path / "trusted3")
    assert r.returncode == 0, r.stderr
    assert (dest / "baseline.json").read_text() == '{"accepted": []}'
