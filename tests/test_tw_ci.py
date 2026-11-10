import pytest
from sc_fixture_util import materialize, run_rule, cases
from tripwire.rules import ci_pinned_actions, ci_workflow_injection, ci_module_shadowing

RULES = {"TW-CI1": ci_pinned_actions, "TW-CI2": ci_workflow_injection, "TW-CI3": ci_module_shadowing}
VULN = [(r, c) for r in RULES for c in cases(r, "vulnerable_")]
SAFE = [(r, c) for r in RULES for c in cases(r, "safe_")]


@pytest.mark.parametrize("rid,case", VULN)
def test_vulnerable_fires(rid, case, tmp_path):
    fs = [f for f in run_rule(RULES[rid], materialize(rid, case, tmp_path)) if f.severity != "info"]
    assert fs, f"{rid}/{case}"
    assert all(f.rule == rid and f.line > 0 for f in fs)


@pytest.mark.parametrize("rid,case", SAFE)
def test_safe_silent(rid, case, tmp_path):
    fs = [f for f in run_rule(RULES[rid], materialize(rid, case, tmp_path)) if f.severity != "info"]
    assert fs == [], [(f.file, f.line, f.message) for f in fs]


def test_ci1_first_party_is_info(tmp_path):
    fs = run_rule(ci_pinned_actions, materialize("TW-CI1", "safe_first_party_only", tmp_path))
    assert fs and {f.severity for f in fs} == {"info"}


def test_ci1_lines(tmp_path):
    fs = run_rule(ci_pinned_actions, materialize("TW-CI1", "vulnerable_tag_pinned", tmp_path))
    assert sorted((f.line, f.severity) for f in fs) == [(9, "info"), (11, "low"), (12, "low")]


def test_ci2_kinds(tmp_path):
    fs = run_rule(ci_workflow_injection, materialize("TW-CI2", "vulnerable_title_in_run", tmp_path))
    assert sorted(f.line for f in fs) == [14, 15] and {f.severity for f in fs} == {"high"}
    fs = run_rule(ci_workflow_injection, materialize("TW-CI2", "vulnerable_pwn_request", tmp_path / "b"))
    sev = sorted(f.severity for f in fs)
    assert "critical" in sev and "medium" in sev  # pwn request + reusable workflow @main
    fs = run_rule(ci_workflow_injection, materialize("TW-CI2", "vulnerable_github_script_issue", tmp_path / "c"))
    assert any(f.line == 9 for f in fs) and any("permissions" in f.message for f in fs)


def test_ci3_points_at_python_line(tmp_path):
    fs = run_rule(ci_module_shadowing, materialize("TW-CI3", "vulnerable_pythonpath_guard", tmp_path))
    assert len(fs) == 1 and fs[0].line == 15 and "saaf_guard" in fs[0].message
