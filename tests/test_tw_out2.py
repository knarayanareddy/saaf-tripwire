import pytest
from tripwire.rules import out_csv_formula as mod
from net_fixture_util import cases, assert_case

CASES = cases("TW-OUT2")


def test_fixture_counts():
    assert sum(c.name.startswith("vulnerable_") for c in CASES) >= 2
    assert sum(c.name.startswith("safe_") for c in CASES) >= 2


def test_rule_metadata():
    assert mod.RULE["id"] == "TW-OUT2" and mod.RULE["seen_in"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_case(case):
    assert_case(mod, case)
