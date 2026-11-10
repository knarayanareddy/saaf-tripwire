from pathlib import Path
import pytest
from tripwire.model import Context
from tripwire.rules import llm_unfenced_prompt as rule

FIX = Path(__file__).parent / "fixtures" / "TW-LLM1"


def run(case):
    root = FIX / case
    return rule.check(Context(root=root, files=sorted(p for p in root.rglob("*") if p.is_file())))


@pytest.mark.parametrize("case", sorted(p.name for p in FIX.iterdir() if p.name.startswith("vulnerable_")))
def test_vulnerable_fires(case):
    assert run(case), case


@pytest.mark.parametrize("case", sorted(p.name for p in FIX.iterdir() if p.name.startswith("safe_")))
def test_safe_is_silent(case):
    assert run(case) == []


def test_specific_lines():
    lines = {(f.file, f.line) for f in run("vulnerable_fstring_fence")}
    assert ("audit.py", 8) in lines and ("audit.py", 15) in lines
    lines = {(f.file, f.line) for f in run("vulnerable_openai_concat")}
    assert ("qa.py", 5) in lines and ("qa.py", 11) in lines
    lines = {(f.file, f.line) for f in run("vulnerable_weak_neutraliser")}
    assert ("sanitise.py", 4) in lines and ("sanitise.py", 10) in lines
    assert any(f.line == 7 for f in run("vulnerable_prompt_builder"))


def test_rule_shape():
    assert rule.RULE["id"] == "TW-LLM1" and rule.RULE["class"] == "ai-and-llm" and rule.RULE["seen_in"]
