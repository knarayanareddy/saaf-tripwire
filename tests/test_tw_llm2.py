from pathlib import Path
import pytest
from tripwire.model import Context
from tripwire.rules import llm_unvalidated_verdict as rule

FIX = Path(__file__).parent / "fixtures" / "TW-LLM2"


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
    assert rule.RULE["id"] == "TW-LLM2" and rule.RULE["class"] == "ai-and-llm" and rule.RULE["seen_in"]

def test_specific_lines():
    assert 13 in {f.line for f in run("vulnerable_found_yes")}
    assert {9, 15} <= {f.line for f in run("vulnerable_splat_profile")}
