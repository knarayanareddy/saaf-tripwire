"""Structural checks for the CI wrappers (stands in for actionlint, which is not installed here)."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "action.yml", ROOT / ".github/workflows/tripwire.yml",
         ROOT / ".github/workflows/self-scan.yml", ROOT / "examples/caller.yml"]
SHA_REF = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _load(p):
    d = yaml.safe_load(p.read_text())
    # PyYAML reads the key `on` as boolean True.
    if True in d:
        d["on"] = d.pop(True)
    return d


def _steps(d):
    if "runs" in d:
        yield from d["runs"]["steps"]
    for job in d.get("jobs", {}).values():
        yield from job.get("steps", [])


def _uses(d):
    for s in _steps(d):
        if "uses" in s:
            yield s["uses"]
    for job in d.get("jobs", {}).values():
        if "uses" in job:
            yield job["uses"]


def test_all_parse():
    for p in FILES:
        assert isinstance(_load(p), dict), p


def test_every_action_is_sha_pinned():
    for p in FILES:
        for u in _uses(_load(p)):
            assert u.startswith("./") or SHA_REF.match(u), f"{p.name}: unpinned {u}"


def test_no_expressions_in_run_steps():
    # Untrusted event data reaches shells only through env vars, never ${{ }} inside run:.
    for p in FILES:
        for s in _steps(_load(p)):
            assert "${{" not in s.get("run", ""), f"{p.name}: expression in run step {s.get('name')}"
        assert "github.event." not in p.read_text().replace("# ", ""), p.name


def test_no_pull_request_target():
    for p in FILES:
        assert "pull_request_target" not in p.read_text()


def test_reusable_workflow_contract():
    d = _load(ROOT / ".github/workflows/tripwire.yml")
    assert "workflow_call" in d["on"]
    assert d["permissions"] == {}
    job = d["jobs"]["tripwire"]
    assert job["permissions"] == {"contents": "read", "security-events": "write"}
    checkouts = [s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    target = [s for s in checkouts if s["with"].get("path") == "target"][0]
    assert target["with"]["fetch-depth"] == 0
    assert all(s["with"].get("persist-credentials") is False for s in checkouts)


def test_action_runs_guard_with_isolated_python():
    d = _load(ROOT / "action.yml")
    scan = [s for s in d["runs"]["steps"] if s.get("id") == "scan"][0]
    assert "-P -m tripwire" in scan["run"]
    assert any("upload-sarif@" in s.get("uses", "") for s in d["runs"]["steps"])


def test_caller_is_short_and_pinned():
    d = _load(ROOT / "examples/caller.yml")
    job = d["jobs"]["tripwire"]
    ref = job["with"]["tripwire-ref"]
    assert isinstance(ref, str) and job["uses"].endswith("@" + ref)   # same SHA, and quoted so YAML keeps a string
    assert set(d["on"]) >= {"push", "pull_request"}
