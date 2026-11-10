from pathlib import Path
import pytest
from tripwire.model import Context
from tripwire.rules import key_secret_to_client as rule

FIX = Path(__file__).parent / "fixtures" / "TW-KEY1"


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
    assert rule.RULE["id"] == "TW-KEY1" and rule.RULE["class"] == "client-side" and rule.RULE["seen_in"]

def test_specific_lines():
    assert {f.line for f in run("vulnerable_flask_form")} == {9, 16}
    assert {f.line for f in run("vulnerable_fastapi_json")} == {11, 17}
