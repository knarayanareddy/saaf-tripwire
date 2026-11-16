#!/usr/bin/env python3
"""Validate the self-audit's structured output (phase 4) without third-party packages.

The cloudflare skill ships JSON-Schema validators; this audit has the schema
(report-schema.json) but no network-installed `jsonschema`, so the same constraints
are enforced here explicitly. Exit 1 on any violation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CLASSES = {"ai-and-llm", "web-protocol-and-auth", "client-side", "data-isolation",
           "resource-exhaustion", "supply-chain-and-release", "business-logic", "quality"}
STATUSES = {"fixed", "mitigated", "open"}
ID_RE = re.compile(r"^TW-[ARN]\d+$")


def _err(errors: list[str], where: str, msg: str) -> None:
    errors.append(f"{where}: {msg}")


def validate_findings(data: dict) -> list[str]:
    errors: list[str] = []
    audit = data.get("audit")
    if not isinstance(audit, dict):
        _err(errors, "audit", "missing object")
        audit = {}
    for k in ("target", "commit", "method", "reproduce"):
        if not isinstance(audit.get(k), str) or not audit.get(k):
            _err(errors, f"audit.{k}", "required non-empty string")
    records = data.get("records")
    if not isinstance(records, list) or not records:
        _err(errors, "records", "must be a non-empty array")
        return errors
    seen: set[str] = set()
    for i, r in enumerate(records):
        w = f"records[{i}]"
        if not isinstance(r, dict):
            _err(errors, w, "not an object")
            continue
        rid = r.get("id", "")
        if not isinstance(rid, str) or not ID_RE.match(rid):
            _err(errors, f"{w}.id", f"bad id {rid!r}")
        elif rid in seen:
            _err(errors, f"{w}.id", f"duplicate {rid}")
        seen.add(rid)
        verdict = r.get("verdict")
        if verdict not in ("confirmed", "rejected", "needs_validation"):
            _err(errors, f"{w}.verdict", f"bad verdict {verdict!r}")
        if r.get("class") not in CLASSES:
            _err(errors, f"{w}.class", f"bad class {r.get('class')!r}")
        for k in ("component", "summary"):
            if not isinstance(r.get(k), str) or not r.get(k):
                _err(errors, f"{w}.{k}", "required non-empty string")
        if verdict == "confirmed":
            if r.get("severity") not in SEVERITIES:
                _err(errors, f"{w}.severity", f"bad severity {r.get('severity')!r}")
            trace = r.get("trace")
            if not isinstance(trace, list) or not trace:
                _err(errors, f"{w}.trace", "confirmed record needs at least one trace entry")
            else:
                for j, t in enumerate(trace):
                    if not isinstance(t, dict) or not all(k in t for k in ("file", "line", "note")):
                        _err(errors, f"{w}.trace[{j}]", "needs file, line, note")
                    elif not isinstance(t["line"], int) or t["line"] < 1:
                        _err(errors, f"{w}.trace[{j}].line", "must be a positive integer")
            probe = r.get("probe")
            if not isinstance(probe, dict) or not probe.get("command") or not probe.get("expectation"):
                _err(errors, f"{w}.probe", "needs command and expectation")
            for k in ("observedBefore", "observedAfter", "fix"):
                if not isinstance(r.get(k), str) or not r.get(k):
                    _err(errors, f"{w}.{k}", "confirmed record needs this string")
            if r.get("status") not in STATUSES:
                _err(errors, f"{w}.status", f"bad status {r.get('status')!r}")
        elif verdict == "rejected":
            if not isinstance(r.get("refutation"), str) or not r.get("refutation"):
                _err(errors, f"{w}.refutation", "rejected record needs the observation that killed it")
        elif verdict == "needs_validation":
            if "severity" in r:
                _err(errors, f"{w}.severity", "needs_validation records must not carry a severity")
            if not isinstance(r.get("unresolved"), str) or not r.get("unresolved"):
                _err(errors, f"{w}.unresolved", "needs_validation record needs the exact unresolved fact")
    return errors


def validate_ledger(data: dict) -> list[str]:
    errors: list[str] = []
    units = data.get("units")
    if not isinstance(units, list) or not units:
        return ["coverage-ledger.units: must be a non-empty array"]
    seen: set[str] = set()
    for i, u in enumerate(units):
        w = f"units[{i}]"
        if not isinstance(u, dict):
            _err(errors, w, "not an object")
            continue
        uid = u.get("id")
        if not isinstance(uid, str) or not uid:
            _err(errors, f"{w}.id", "required")
        elif uid in seen:
            _err(errors, f"{w}.id", f"duplicate {uid}")
        seen.add(uid)
        status = u.get("status")
        if status not in ("covered", "out_of_scope"):
            _err(errors, f"{w}.status", f"{status!r} is not a terminal ledger status (cloudflare: needs_validation is not one)")
        if status == "covered":
            for k in ("check", "result"):
                if not isinstance(u.get(k), str) or not u.get(k):
                    _err(errors, f"{w}.{k}", "covered unit needs check and result")
        elif status == "out_of_scope":
            if not isinstance(u.get("reason"), str) or not u.get("reason"):
                _err(errors, f"{w}.reason", "out_of_scope unit needs a named reason")
        if u.get("class") not in CLASSES:
            _err(errors, f"{w}.class", f"bad class {u.get('class')!r}")
    return errors


def main() -> int:
    schema = json.loads((HERE / "report-schema.json").read_text())
    if schema.get("$schema") is None:
        print("report-schema.json: not a JSON Schema document", file=sys.stderr)
        return 1
    findings = json.loads((HERE / "findings.json").read_text())
    ledger = json.loads((HERE / "coverage-ledger.json").read_text())
    errors = validate_findings(findings) + validate_ledger(ledger)
    if errors:
        print(f"INVALID — {len(errors)} problem(s)", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    recs = findings["records"]
    counts = {v: sum(1 for r in recs if r["verdict"] == v) for v in ("confirmed", "rejected", "needs_validation")}
    units = ledger["units"]
    print(f"VALID — {counts['confirmed']} confirmed, {counts['rejected']} rejected, "
          f"{counts['needs_validation']} needs_validation; ledger {len(units)} units "
          f"({sum(1 for u in units if u['status'] == 'covered')} covered, "
          f"{sum(1 for u in units if u['status'] == 'out_of_scope')} out_of_scope)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
