"""SAAF Tripwire command line: `tripwire scan <path>` and `tripwire rules`.

Exit codes: 0 = clean at the chosen threshold, 1 = findings at or above --fail-on, 2 = usage error or a rule
crashed (the guard fails closed: a file crafted to crash a rule must not silence the other rules).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import time
from pathlib import Path

from . import __version__, engine, report
from .model import Context, SEVERITIES

FAIL_LEVELS = ("critical", "high", "medium", "low")
BROAD_PATTERNS = {"", "*", "**", "**/*", "/", ".", "./", "*/**", "/*", "/**"}


def _rule_meta(mods) -> list[dict]:
    return [dict(m.RULE) for m in mods]


def _load_ignore(root: Path, name: str) -> tuple[list[str], list[str]]:
    p = root / name
    if not name or not p.is_file():
        return [], []
    keep, refused = [], []
    for raw in p.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        (refused if line in BROAD_PATTERNS else keep).append(line)
    return keep, refused


def _ignored(file: str, patterns: list[str]) -> bool:
    if not file:                      # repo-level findings (history secrets etc.) cannot be path-ignored
        return False
    for pat in patterns:
        pat = pat.lstrip("/")
        if fnmatch.fnmatch(file, pat) or fnmatch.fnmatch(file, pat.rstrip("/") + "/*") or file.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def _load_baseline(path: str | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text())
    items = data.get("accepted", data) if isinstance(data, dict) else data
    return {i["fingerprint"] if isinstance(i, dict) else str(i) for i in items}


def scan(root: Path, history: bool = True, only: set[str] | None = None,
         ignore_file: str = ".tripwireignore", baseline: str | None = None):
    """Run every rule in isolation. Returns (findings, meta)."""
    t0 = time.time()
    mods = engine.load_rules()
    ctx = Context(root=root.resolve(), history=history)
    ctx.files = engine.tracked_files(ctx.root)
    found, errors, ran = [], [], 0
    for mod in mods:
        if only and mod.RULE["id"] not in only:
            continue
        ran += 1
        try:
            found.extend(mod.check(ctx) or [])
        except Exception as exc:  # fail closed, but keep the other rules' findings
            errors.append({"rule": mod.RULE["id"], "error": f"{type(exc).__name__}: {exc}"[:300]})
    patterns, refused = _load_ignore(ctx.root, ignore_file)
    accepted = _load_baseline(baseline)
    kept, n_ign, n_base = [], 0, 0
    for f in found:
        if _ignored(f.file, patterns):
            n_ign += 1
        elif report.fingerprint(f) in accepted:
            n_base += 1
        else:
            kept.append(f)
    meta = {"root": str(ctx.root), "history": history, "rules_run": ran, "files": len(ctx.files),
            "seconds": round(time.time() - t0, 2), "ignored": n_ign, "ignore_patterns": patterns,
            "refused_patterns": refused, "baselined": n_base, "errors": errors}
    return kept, meta, _rule_meta(mods)


def _write(text: str, out: str | None):
    if out:
        Path(out).write_text(text)
    else:
        sys.stdout.write(text + ("" if text.endswith("\n") else "\n"))


def cmd_scan(a) -> int:
    root = Path(a.path)
    if not root.is_dir():
        print(f"tripwire: not a directory: {root}", file=sys.stderr)
        return 2
    known = {m.RULE["id"] for m in engine.load_rules()}
    only = {x.strip() for x in a.only.split(",") if x.strip()} if a.only else None
    if only and (only - known):
        print(f"tripwire: unknown rule id(s): {', '.join(sorted(only - known))}. Known: {', '.join(sorted(known))}",
              file=sys.stderr)
        return 2
    try:
        findings, meta, rules = scan(root, history=not a.no_history, only=only,
                                     ignore_file=a.ignore_file, baseline=a.baseline)
    except (OSError, ValueError, KeyError) as exc:
        print(f"tripwire: {exc}", file=sys.stderr)
        return 2
    if a.write_baseline:
        Path(a.write_baseline).write_text(json.dumps({"version": 1, "accepted": [
            {"fingerprint": report.fingerprint(f), "rule": f.rule, "file": f.file, "message": f.message}
            for f in report.sort_findings(findings)]}, indent=2))
    sarif = report.to_sarif(findings, rules, meta, root)
    if a.sarif_out:
        Path(a.sarif_out).write_text(json.dumps(sarif, indent=2))
    if a.format == "sarif":
        _write(json.dumps(sarif, indent=2), a.output)
    elif a.format == "json":
        _write(report.to_json(findings, meta), a.output)
    else:
        _write(report.to_text(findings, meta), a.output)
    if meta["errors"]:
        return 2
    limit = report.SEV_RANK[a.fail_on]
    return 1 if any(report.SEV_RANK.get(f.severity, 9) <= limit for f in findings) else 0


def cmd_rules(a) -> int:
    rules = _rule_meta(engine.load_rules())
    if a.format == "json":
        print(json.dumps(rules, indent=2))
        return 0
    if not rules:
        print("No rules installed.")
    for r in rules:
        print(f"{r['id']:10} {r.get('severity', ''):8} {r.get('class', '')}")
        print(f"           {r.get('title', '')}")
        print(f"           why: {r.get('why', '')}")
        print(f"           seen in: {', '.join(r.get('seen_in', [])) or '-'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tripwire", description="SAAF Tripwire: one guard built from a real audit of 50 SAAF repos.")
    p.add_argument("--version", action="version", version=f"tripwire {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path")
    s.add_argument("--no-history", action="store_true", help="skip git-history checks (faster)")
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("--fail-on", choices=FAIL_LEVELS, default="high", help="exit 1 if any finding is at or above this")
    s.add_argument("--only", help="comma-separated rule ids, e.g. TW-NET1,TW-SEC1")
    s.add_argument("--baseline", help="JSON of accepted findings to suppress (gradual adoption)")
    s.add_argument("--write-baseline", metavar="FILE", help="write current findings as a baseline file")
    s.add_argument("--ignore-file", default=".tripwireignore", help="path globs to skip, relative to the scanned root")
    s.add_argument("--output", "-o", help="write the report to FILE instead of stdout")
    s.add_argument("--sarif-out", metavar="FILE", help="also write SARIF to FILE (for CI upload)")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("rules", help="list rules, the attack each stops, and where the audit saw it")
    r.add_argument("--format", choices=("text", "json"), default="text")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
