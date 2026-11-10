import pytest
from sc_fixture_util import materialize, run_rule, cases
from tripwire.rules import dep_hygiene as rule

R = "TW-DEP1"


@pytest.mark.parametrize("case", cases(R, "vulnerable_"))
def test_vulnerable_fires(case, tmp_path):
    assert run_rule(rule, materialize(R, case, tmp_path))


@pytest.mark.parametrize("case", cases(R, "safe_"))
def test_safe_silent(case, tmp_path):
    fs = run_rule(rule, materialize(R, case, tmp_path))
    assert fs == [], [(f.file, f.line, f.message) for f in fs]


def test_severity_capped_at_medium(tmp_path):
    for case in cases(R, "vulnerable_"):
        for f in run_rule(rule, materialize(R, case, tmp_path / case)):
            assert f.severity in ("low", "medium")


def test_ci_install_lists_only_unpinned(tmp_path):
    fs = run_rule(rule, materialize(R, "vulnerable_flask_and_ci", tmp_path))
    ci = [f for f in fs if f.file.endswith("ci.yml")]
    assert len(ci) == 1 and "pyyaml" in ci[0].message and "requests>=2" in ci[0].message
    req = [f for f in fs if f.file == "requirements.txt"]
    assert req and req[0].line == 3
