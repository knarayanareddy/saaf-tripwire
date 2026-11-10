"""Shared fixture runner for the TW-NET / TW-OUT / TW-FS rule tests."""
from pathlib import Path
from tripwire.model import Context

FIX = Path(__file__).parent / "fixtures"


def cases(rule_id):
    d = FIX / rule_id
    return sorted(p for p in d.iterdir() if p.is_dir())


def run_case(mod, case: Path):
    ctx = Context(root=case.resolve(), history=False)
    ctx.files = [p for p in ctx.root.rglob("*") if p.is_file()]
    return mod.check(ctx)


def assert_case(mod, case: Path):
    found = run_case(mod, case)
    if case.name.startswith("vulnerable_"):
        assert found, f"{mod.RULE['id']} should fire on {case.name}"
        assert all(f.rule == mod.RULE["id"] and f.line > 0 for f in found)
    else:
        assert not found, f"{mod.RULE['id']} false positive on {case.name}: {[(f.file, f.line, f.evidence) for f in found]}"
