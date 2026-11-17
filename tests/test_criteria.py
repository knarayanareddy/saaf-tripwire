"""Criteria runner: per-agent pass/fail, safe by default."""
import json
import sys
from pathlib import Path

import pytest
import yaml

from tripwire import cli, criteria, report

VULN = '''from flask import Flask
app = Flask(__name__)
@app.route("/")
def index():
    return "x"
app.run(host="0.0.0.0", port=5000)
'''


def _manifest(root: Path, items, **top):
    (root / ".tripwire").mkdir(parents=True, exist_ok=True)
    data = {"version": 1, **top,
            "criteria": [{"id": i["id"], "check": {i["kind"]: i["value"]}} for i in items]}
    (root / ".tripwire/criteria.yml").write_text(yaml.safe_dump(data, sort_keys=False))


def _repo(tmp_path: Path, code: str = "print(1)\n") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app.py").write_text(code)
    return tmp_path


def test_rule_check_passes_then_fails(tmp_path):
    safe = _repo(tmp_path / "safe")
    _manifest(safe, [{"id": "net", "kind": "rule", "value": "TW-NET1"}])
    v, code = criteria.run(safe, history=False)
    assert code == 0 and v["verdict"] == "pass"

    bad = _repo(tmp_path / "bad", VULN)
    _manifest(bad, [{"id": "net", "kind": "rule", "value": "TW-NET1"}])
    v, code = criteria.run(bad, history=False)
    assert code == 1 and v["verdict"] == "fail"
    assert v["criteria"][0]["status"] == "fail" and "finding" in v["criteria"][0]["detail"]


def test_rule_check_honours_the_baseline(tmp_path):
    root = _repo(tmp_path, VULN)
    _manifest(root, [{"id": "net", "kind": "rule", "value": "TW-NET1"}])
    found, meta, _ = cli.scan(root, history=False, only={"TW-NET1"})
    assert found and not meta["errors"]
    (root / "baseline.json").write_text(json.dumps(
        {"accepted": [{"fingerprint": report.fingerprint(found[0])}]}))
    v, code = criteria.run(root, history=False, baseline="baseline.json")
    assert code == 0 and v["verdict"] == "pass"


def test_exec_checks_are_refused_without_opt_in(tmp_path):
    root = _repo(tmp_path)
    _manifest(root, [{"id": "cmd", "kind": "command", "value": f'"{sys.executable}" -c "print(1)"'}])
    v, code = criteria.run(root, history=False)
    assert code == 2 and v["verdict"] == "error"
    assert "execution disabled" in v["criteria"][0]["detail"]

    v, code = criteria.run(root, history=False, allow_exec=True)
    assert code == 0 and v["verdict"] == "pass"


def test_command_failure_and_test_check(tmp_path):
    root = _repo(tmp_path)
    _manifest(root, [{"id": "cmd", "kind": "command", "value": f'"{sys.executable}" -c "raise SystemExit(3)"'}])
    v, code = criteria.run(root, history=False, allow_exec=True)
    assert code == 1 and v["criteria"][0]["status"] == "fail"

    (root / "tests").mkdir()
    (root / "tests/test_ok.py").write_text("def test_ok():\n    assert True\n")
    _manifest(root, [{"id": "unit", "kind": "test", "value": "tests/test_ok.py"}])
    v, code = criteria.run(root, history=False, allow_exec=True)
    assert code == 0 and v["criteria"][0]["status"] == "pass"


@pytest.mark.parametrize("payload", [
    "criteria: []\n",
    "version: 9\ncriteria:\n  - {id: a, check: {rule: TW-NET1}}\n",
    "criteria:\n  - {id: a, check: {rule: TW-NET1}}\n  - {id: a, check: {rule: TW-NET1}}\n",
    "criteria:\n  - {id: a, check: {nope: x}}\n",
    "criteria:\n  - {id: 'bad id', check: {rule: TW-NET1}}\n",
])
def test_invalid_manifests_fail_closed(tmp_path, payload):
    root = _repo(tmp_path)
    (root / ".tripwire").mkdir()
    (root / ".tripwire/criteria.yml").write_text(payload)
    with pytest.raises(criteria.CriteriaError):
        criteria.run(root, history=False)


def test_manifest_cannot_escape_the_root(tmp_path):
    root = _repo(tmp_path / "repo")
    (tmp_path / "outside.yml").write_text("criteria:\n  - {id: a, check: {rule: TW-NET1}}\n")
    with pytest.raises(criteria.CriteriaError):
        criteria.run(root, file="../outside.yml", history=False)


def test_cli_json_verdict_and_exit_codes(tmp_path, capsys):
    root = _repo(tmp_path, VULN)
    _manifest(root, [{"id": "net", "kind": "rule", "value": "TW-NET1"}], agent="demo")
    out = tmp_path / "verdict.json"
    code = cli.main(["criteria", str(root), "--file", ".tripwire/criteria.yml",
                     "--format", "json", "--output", str(out), "--no-history"])
    assert code == 1
    v = json.loads(out.read_text())
    assert v["agent"] == "demo" and v["verdict"] == "fail"
    assert v["summary"] == {"total": 1, "pass": 0, "fail": 1, "error": 0}
    assert set(v["criteria"][0]) >= {"id", "check", "status", "detail"}

    code = cli.main(["criteria", str(root), "--file", "missing.yml", "--no-history"])
    assert code == 2
    assert "criteria file not found" in capsys.readouterr().err
