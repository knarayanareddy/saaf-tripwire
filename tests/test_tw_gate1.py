from pathlib import Path
import pytest
from tripwire.model import Context
from tripwire.rules import gate_fail_open as rule

FIX = Path(__file__).parent / "fixtures" / "TW-GATE1"


def run(case):
    root = FIX / case
    return rule.check(Context(root=root, files=sorted(p for p in root.rglob("*") if p.is_file())))


@pytest.mark.parametrize("case", sorted(p.name for p in FIX.iterdir() if p.name.startswith("vulnerable_")))
def test_vulnerable_fires(case):
    assert run(case), case


@pytest.mark.parametrize("case", sorted(p.name for p in FIX.iterdir() if p.name.startswith("safe_")))
def test_safe_is_silent(case):
    assert run(case) == []



def test_rule_shape():
    assert rule.RULE["id"] == "TW-GATE1" and rule.RULE["class"] == "resource-exhaustion" and rule.RULE["seen_in"]

def test_specific_lines():
    l = {f.line for f in run("vulnerable_else_approve")}
    assert {9, 19, 23} <= l
    l = {f.line for f in run("vulnerable_log_only")}
    assert {9, 16, 20} <= l
    l = {f.line for f in run("vulnerable_nan_substring")}
    assert {7, 15} <= l
