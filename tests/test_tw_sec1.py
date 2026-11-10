import pytest
from sc_fixture_util import materialize, run_rule, cases, TOKENS
from tripwire.rules import sec_secrets as rule

R = "TW-SEC1"


@pytest.mark.parametrize("case", cases(R, "vulnerable_"))
def test_vulnerable_fires(case, tmp_path):
    fs = [f for f in run_rule(rule, materialize(R, case, tmp_path)) if f.severity in ("high", "critical")]
    assert fs, case


@pytest.mark.parametrize("case", cases(R, "safe_"))
def test_safe_silent(case, tmp_path):
    assert run_rule(rule, materialize(R, case, tmp_path)) == []


def test_never_prints_value(tmp_path):
    for case in cases(R, "vulnerable_") + cases(R, "info_"):
        for f in run_rule(rule, materialize(R, case, tmp_path / case)):
            blob = f.message + f.evidence + f.fix
            for v in TOKENS.values():
                assert v not in blob and v[4:20] not in blob


def test_history_is_high_and_names_commit(tmp_path):
    fs = run_rule(rule, materialize(R, "vulnerable_history_env", tmp_path))
    assert {f.severity for f in fs} == {"high"}
    assert all(f.file == "backend/.env" and "commit " in f.message for f in fs)
    assert len(fs) == 2  # anthropic + high-entropy TEAMMATE key; DEBUG=true ignored


def test_head_provider_is_critical(tmp_path):
    fs = run_rule(rule, materialize(R, "vulnerable_head_provider", tmp_path))
    assert {f.severity for f in fs} == {"critical"} and {f.line for f in fs} == {2, 3}


def test_history_disabled(tmp_path):
    assert run_rule(rule, materialize(R, "vulnerable_history_env", tmp_path), history=False) == []


def test_marked_fixture_is_info(tmp_path):
    fs = run_rule(rule, materialize(R, "info_marked_fixture", tmp_path))
    assert fs and {f.severity for f in fs} == {"info"}


def test_real_shaped_key_in_marked_fixture_still_critical(tmp_path):
    # red-team evades_fixture_dir_mark: an attacker-written "not a real key" comment must not demote a real-shaped key
    fs = run_rule(rule, materialize(R, "vulnerable_rt_fixture_dir_mark", tmp_path))
    assert any(f.severity == "critical" for f in fs)


def test_utf16_and_long_line_fire(tmp_path):
    for case in ("vulnerable_rt_utf16_env", "vulnerable_rt_long_minified_line"):
        assert any(f.severity == "critical" for f in run_rule(rule, materialize(R, case, tmp_path / case)))
