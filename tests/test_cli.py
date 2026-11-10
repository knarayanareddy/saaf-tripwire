"""CLI + output-format tests. Uses fake rule modules so they run before/independently of the real rules."""
import json
import types

import pytest

from tripwire import cli, engine, report
from tripwire.model import Finding


def _mod(rid, sev, findings=None, boom=False):
    def check(ctx):
        if boom:
            raise RuntimeError("crafted file")
        return [Finding(rule=rid, severity=sev, **f) for f in (findings or [])]
    return types.SimpleNamespace(
        RULE={"id": rid, "title": f"Title {rid}", "severity": sev, "class": "web-protocol-and-auth",
              "why": f"stops {rid}", "seen_in": ["SAAF-Project (SA-11)"]},
        check=check)


@pytest.fixture
def fake_rules(monkeypatch):
    mods = [
        _mod("TW-T1", "high", [dict(file="app.py", line=3, message="Binds 0.0.0.0 without auth.",
                                    fix="Bind 127.0.0.1.", evidence="key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX")]),
        _mod("TW-T2", "low", [dict(file="tests/fixtures/x/vuln.py", line=1, message="m2", fix="f2"),
                              dict(file="", line=0, message="repo-level", fix="f3")]),
    ]
    monkeypatch.setattr(engine, "load_rules", lambda: mods)
    return mods


def test_text_and_exit_codes(tmp_path, fake_rules, capsys):
    (tmp_path / "app.py").write_text("x")
    assert cli.main(["scan", str(tmp_path), "--no-history"]) == 1          # high >= high
    out = capsys.readouterr().out
    assert "TW-T1" in out and "app.py:3" in out
    assert "ABCDEFGHIJKLMNOP" not in out                                   # secret masked
    assert cli.main(["scan", str(tmp_path), "--only", "TW-T2"]) == 0        # low < high
    assert cli.main(["scan", str(tmp_path), "--only", "TW-T2", "--fail-on", "low"]) == 1
    assert cli.main(["scan", str(tmp_path), "--only", "TW-NOPE"]) == 2
    assert cli.main(["scan", str(tmp_path / "missing")]) == 2


def test_json_format(tmp_path, fake_rules, capsys):
    cli.main(["scan", str(tmp_path), "--format", "json"])
    d = json.loads(capsys.readouterr().out)
    assert d["summary"]["high"] == 1 and len(d["findings"]) == 3
    assert all(f["fingerprint"] for f in d["findings"])
    assert d["findings"][0]["rule"] == "TW-T1"                              # sorted by severity


def test_ignore_file_and_broad_patterns(tmp_path, fake_rules, capsys):
    (tmp_path / ".tripwireignore").write_text("tests/fixtures/\n*\n**\n")
    cli.main(["scan", str(tmp_path), "--format", "json"])
    d = json.loads(capsys.readouterr().out)
    files = [f["file"] for f in d["findings"]]
    assert "tests/fixtures/x/vuln.py" not in files
    assert "app.py" in files and "" in files                                # repo-level never path-ignored
    assert d["meta"]["refused_patterns"] == ["*", "**"]


def test_baseline_roundtrip(tmp_path, fake_rules, capsys):
    base = tmp_path / "baseline.json"
    assert cli.main(["scan", str(tmp_path), "--write-baseline", str(base)]) == 1
    capsys.readouterr()
    assert cli.main(["scan", str(tmp_path), "--baseline", str(base), "--fail-on", "low"]) == 0
    assert "Suppressed by baseline: 3" in capsys.readouterr().out


def test_rule_crash_fails_closed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(engine, "load_rules", lambda: [_mod("TW-B1", "high", boom=True),
                                                       _mod("TW-T2", "low", [dict(file="a", line=1, message="m", fix="f")])])
    assert cli.main(["scan", str(tmp_path), "--fail-on", "critical"]) == 2
    out = capsys.readouterr().out
    assert "RULE ERROR TW-B1" in out and "TW-T2" in out                     # other rules still reported


def test_rules_command(fake_rules, capsys):
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "TW-T1" in out and "why: stops TW-T1" in out and "SA-11" in out
    cli.main(["rules", "--format", "json"])
    assert {r["id"] for r in json.loads(capsys.readouterr().out)} == {"TW-T1", "TW-T2"}


def test_sarif_shape(tmp_path, fake_rules, capsys):
    (tmp_path / "README.md").write_text("x")
    out_file = tmp_path / "out.sarif"
    cli.main(["scan", str(tmp_path), "--format", "sarif", "--sarif-out", str(out_file)])
    s = json.loads(capsys.readouterr().out)
    assert s == json.loads(out_file.read_text())
    assert s["version"] == "2.1.0" and "sarif-2.1.0" in s["$schema"]
    run = s["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert run["tool"]["driver"]["name"]
    for r in rules:
        assert r["shortDescription"]["text"] and r["fullDescription"]["text"] and r["help"]["text"]
        assert r["defaultConfiguration"]["level"] in ("error", "warning", "note")
        float(r["properties"]["security-severity"])
    assert len(run["results"]) == 3
    for res in run["results"]:
        assert ids[res["ruleIndex"]] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note") and res["message"]["text"]
        pl = res["locations"][0]["physicalLocation"]
        assert pl["artifactLocation"]["uri"] and not pl["artifactLocation"]["uri"].startswith("/")
        assert pl["region"]["startLine"] >= 1
        assert res["partialFingerprints"]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["TW-T1"] == "error" and levels["TW-T2"] == "note"
    assert "ABCDEFGHIJKLMNOP" not in json.dumps(s)
    assert run["invocations"][0]["executionSuccessful"] is True


def test_mask():
    assert report.mask("ghp_abcdefghijklmnopqrstuvwxyz0123") == "ghp_********"
    assert report.mask("plain words") == "plain words"


def test_module_entrypoint_runs():
    import subprocess, sys
    r = subprocess.run([sys.executable, "-P", "-m", "tripwire", "--version"], capture_output=True, text=True,
                       cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    assert r.returncode == 0 and "tripwire" in r.stdout
