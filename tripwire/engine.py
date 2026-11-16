"""Loads every rule in tripwire/rules/, runs it, returns findings. Rules must be deterministic and offline."""
from __future__ import annotations
import importlib, pkgutil
from pathlib import Path
from .model import Context, Finding
from . import rules as rules_pkg
from .util.gitcmd import run_git
from .util.safeio import is_safe_file

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "__pycache__"}

def tracked_files(root: Path) -> list[Path]:
    """Files the rules may read: tracked (or walked), regular, not symlinks, inside ``root``, bounded size."""
    try:
        r = run_git(root, ["ls-files", "-z"], timeout=60)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip()[:200] or "git ls-files failed")
        candidates = [root / p for p in r.stdout.split("\0") if p]
    except Exception:
        candidates = [p for p in root.rglob("*") if not (set(p.relative_to(root).parts) & SKIP_DIRS)]
    return [p for p in candidates if is_safe_file(p, root)]

def load_rules():
    mods = []
    for m in pkgutil.iter_modules(rules_pkg.__path__):
        mod = importlib.import_module(f"{rules_pkg.__name__}.{m.name}")
        if hasattr(mod, "RULE") and hasattr(mod, "check"): mods.append(mod)
    return sorted(mods, key=lambda m: m.RULE["id"])

def run(root: Path, history: bool = True, only: set[str] | None = None,
        files: list[Path] | None = None) -> list[Finding]:
    """Run rules over `root`. `files` overrides the walk (callers that generated the tree themselves)."""
    ctx = Context(root=root.resolve(), history=history)
    ctx.files = files if files is not None else tracked_files(ctx.root)
    found: list[Finding] = []
    for mod in load_rules():
        if only and mod.RULE["id"] not in only: continue
        found.extend(mod.check(ctx))
    return found
