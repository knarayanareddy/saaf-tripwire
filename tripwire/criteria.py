"""Per-agent criteria verdicts: the pass/fail layer the scan alone does not provide.

A manifest maps each audit criterion to one check:

    version: 1
    agent: my-agent
    criteria:
      - {id: SA-39, check: {rule: TW-LLM1}}
      - {id: authz,  check: {test: "tests/test_authz.py::test_every_route"}}
      - {id: audit-log, check: {command: "python scripts/check_audit_log.py"}}

`rule` checks are read-only and always allowed. `test`/`command` checks execute code
from the scanned tree, so they are refused unless the caller passes --allow-exec
(the action exposes this as `criteria-exec`, default false).
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from . import __version__, engine, report
from .util.gitcmd import run_git

CHECK_KINDS = ("rule", "test", "command")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class CriteriaError(Exception):
    """The manifest or invocation is invalid; maps to exit 2 (fail closed)."""


def _safe(text: Any) -> str:
    return report._safe(str(text))[:300]


def load_manifest(root: Path, name: str) -> tuple[dict, list[dict]]:
    root = root.resolve()
    p = (root / name).resolve()
    if p != root and root not in p.parents:
        raise CriteriaError(f"criteria file must be inside {root}: {name}")
    if not p.is_file():
        raise CriteriaError(f"criteria file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text())
    except OSError as exc:
        raise CriteriaError(f"cannot read {p}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CriteriaError(f"{p} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CriteriaError("criteria file must be a mapping with a `criteria:` list")
    if data.get("version", 1) != 1:
        raise CriteriaError(f"unsupported criteria version: {data.get('version')!r}")
    criteria = data.get("criteria")
    if not isinstance(criteria, list) or not criteria:
        raise CriteriaError("`criteria:` must be a non-empty list")
    seen: set[str] = set()
    for i, c in enumerate(criteria):
        where = f"criteria[{i}]"
        if not isinstance(c, dict):
            raise CriteriaError(f"{where} must be a mapping")
        cid = c.get("id")
        if not isinstance(cid, str) or not ID_RE.match(cid):
            raise CriteriaError(f"{where}.id must match {ID_RE.pattern}")
        if cid in seen:
            raise CriteriaError(f"duplicate criterion id: {cid}")
        seen.add(cid)
        check = c.get("check")
        if not isinstance(check, dict) or len(check) != 1:
            raise CriteriaError(f"{where}.check must have exactly one of {', '.join(CHECK_KINDS)}")
        kind, value = next(iter(check.items()))
        if kind not in CHECK_KINDS:
            raise CriteriaError(f"{where}.check has unknown kind {kind!r}")
        if not isinstance(value, str) or not value.strip():
            raise CriteriaError(f"{where}.check.{kind} must be a non-empty string")
    return data, criteria


def _run_rule(root: Path, rule_id: str, *, history: bool, baseline: str | None,
              config_from: str | None) -> tuple[str, str]:
    if rule_id not in {m.RULE["id"] for m in engine.load_rules()}:
        return "error", f"unknown rule {rule_id}"
    from .cli import scan as scan_repo  # local: cli imports this module for the subcommand
    try:
        findings, meta, _ = scan_repo(root, history=history, only={rule_id},
                                      baseline=baseline, config_from=config_from)
    except Exception as exc:                       # missing baseline, bad config, ...
        return "error", _safe(f"{type(exc).__name__}: {exc}")
    if meta.get("errors"):
        return "error", _safe(meta["errors"][0].get("error", "rule failed"))
    if findings:
        first = report.sort_findings(findings)[0]
        return "fail", f"{len(findings)} finding(s); first at {_safe(first.file)}:{first.line}"
    return "pass", "0 findings"


def _run_process(argv: list[str], root: Path, timeout: int = 900):
    try:
        return subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=timeout), None
    except FileNotFoundError:
        return None, f"{argv[0]}: not found"
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"


def _last_line(proc: subprocess.CompletedProcess) -> str:
    lines = [ln.strip() for ln in ((proc.stdout or "") + (proc.stderr or "")).splitlines() if ln.strip()]
    return _safe(lines[-1] if lines else f"exit {proc.returncode}")


def _exec_check(root: Path, check: dict, allow_exec: bool) -> tuple[str, str]:
    kind, value = next(iter(check.items()))
    if not allow_exec:
        return "error", ("execution disabled: pass --allow-exec (action: criteria-exec: true) "
                         "to run test/command checks")
    argv = [sys.executable, "-m", "pytest", "-q", value] if kind == "test" else shlex.split(value)
    if not argv:
        return "error", "empty command"
    proc, err = _run_process(argv, root)
    if proc is None:
        return "error", err
    if proc.returncode == 0:
        return "pass", _last_line(proc)
    if kind == "test" and "No module named pytest" in ((proc.stdout or "") + (proc.stderr or "")):
        return "error", "pytest is not installed in this interpreter"
    return "fail", _last_line(proc)


def run(root: Path, *, file: str = ".tripwire/criteria.yml", history: bool = True,
        baseline: str | None = None, config_from: str | None = None,
        allow_exec: bool = False) -> tuple[dict, int]:
    root = Path(root).resolve()
    data, criteria = load_manifest(root, file)
    try:
        commit = run_git(root, ["rev-parse", "HEAD"]).stdout.strip() or None
    except Exception:
        commit = None
    results = []
    for c in criteria:
        check = c["check"]
        kind = next(iter(check))
        if kind == "rule":
            status, detail = _run_rule(root, check["rule"], history=history,
                                       baseline=baseline, config_from=config_from)
        else:
            status, detail = _exec_check(root, check, allow_exec)
        results.append({"id": c["id"], "title": c.get("title", ""), "check": check,
                        "status": status, "detail": detail})
    summary = {"total": len(results),
               "pass": sum(r["status"] == "pass" for r in results),
               "fail": sum(r["status"] == "fail" for r in results),
               "error": sum(r["status"] == "error" for r in results)}
    overall = "error" if summary["error"] else "fail" if summary["fail"] else "pass"
    verdict = {"tool": "saaf-tripwire", "version": __version__,
               "agent": data.get("agent") or root.name, "commit": commit,
               "criteria": results, "summary": summary, "verdict": overall}
    return verdict, {"pass": 0, "fail": 1, "error": 2}[overall]


def to_text(v: dict) -> str:
    lines = []
    for r in v["criteria"]:
        kind, value = next(iter(r["check"].items()))
        lines.append(f"{r['status'].upper():5}  {_safe(r['id']):<28} {_safe(kind)} {_safe(value)}: {r['detail']}")
    s = v["summary"]
    lines += ["", f"VERDICT: {v['verdict'].upper()}  ({s['pass']} passed, {s['fail']} failed, "
                  f"{s['error']} error)  agent={_safe(v['agent'])}"]
    return "\n".join(lines)


def write_json(v: dict) -> str:
    return json.dumps(v, indent=2)
