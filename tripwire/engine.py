"""Loads every rule in tripwire/rules/, runs it, returns findings. Rules must be deterministic and offline."""
from __future__ import annotations
import importlib, pkgutil, subprocess
from pathlib import Path
from .model import Context, Finding
from . import rules as rules_pkg

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "__pycache__"}

def tracked_files(root: Path) -> list[Path]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, text=True, check=True).stdout
        return [root / p for p in out.split("\0") if p]
    except Exception:
        return [p for p in root.rglob("*") if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS)]

def load_rules():
    mods = []
    for m in pkgutil.iter_modules(rules_pkg.__path__):
        mod = importlib.import_module(f"{rules_pkg.__name__}.{m.name}")
        if hasattr(mod, "RULE") and hasattr(mod, "check"): mods.append(mod)
    return sorted(mods, key=lambda m: m.RULE["id"])

def run(root: Path, history: bool = True, only: set[str] | None = None) -> list[Finding]:
    ctx = Context(root=root.resolve(), history=history)
    ctx.files = tracked_files(ctx.root)
    found: list[Finding] = []
    for mod in load_rules():
        if only and mod.RULE["id"] not in only: continue
        found.extend(mod.check(ctx))
    return found
