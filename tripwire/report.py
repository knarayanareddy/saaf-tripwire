"""Output formats for SAAF Tripwire: text, json and SARIF 2.1.0 (GitHub code scanning).

Pure functions over engine Findings; no I/O except what the caller does with the returned string.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import __version__
from .model import SEVERITIES, Finding

INFO_URI = "https://github.com/SAAF-Project/saaf-tripwire"

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}          # critical=0 ... info=4
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub code scanning reads properties.security-severity (0-10) to bucket alerts.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}

# Defence in depth: rules must mask secrets themselves, but the shell masks anything key-shaped
# that slips through, so a buggy rule can never print a credential into CI logs or SARIF.
_SECRET_RE = re.compile(
    r"(sk-ant-[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{16}|xox[abpr]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{30,}|[A-Za-z0-9_\-+/=]{40,})"
)


def mask(text: str) -> str:
    """Keep the first 4 characters of anything key-shaped, star the rest."""
    def _m(m: re.Match) -> str:
        s = m.group(0)
        if "*" in s:                     # already masked by the rule
            return s
        return s[:4] + "*" * 8
    return _SECRET_RE.sub(_m, text or "")


def fingerprint(f: Finding) -> str:
    """Stable id for baselines: rule + file + normalised message (line numbers excluded so edits above don't churn)."""
    msg = re.sub(r"\d+", "#", f.message.strip().lower())
    raw = f"{f.rule}|{f.file}|{msg}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEV_RANK.get(f.severity, 9), f.rule, f.file, f.line))


def _counts(findings: list[Finding]) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


# ---------------------------------------------------------------- text
def to_text(findings: list[Finding], meta: dict) -> str:
    out = []
    for f in sort_findings(findings):
        loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "(repository)")
        out.append(f"{f.severity.upper():8} {f.rule:10} {loc}")
        out.append(f"         {f.message}")
        if f.evidence:
            out.append(f"         evidence: {mask(f.evidence)}")
        out.append(f"         fix: {f.fix}")
    c = _counts(findings)
    summary = ", ".join(f"{c[s]} {s}" for s in SEVERITIES if c[s])
    out.append("")
    out.append(f"SAAF Tripwire {__version__}: {len(findings)} finding(s)" + (f" ({summary})" if summary else "")
               + f" from {meta.get('rules_run', 0)} rule(s) over {meta.get('files', 0)} file(s)"
               + f" in {meta.get('seconds', 0):.1f}s.")
    if meta.get("baselined"):
        out.append(f"Suppressed by baseline: {meta['baselined']}.")
    if meta.get("ignored"):
        out.append(f"Suppressed by .tripwireignore: {meta['ignored']} (patterns: {', '.join(meta.get('ignore_patterns', []))}).")
    for p in meta.get("refused_patterns", []):
        out.append(f"Refused ignore pattern {p!r}: it would hide every finding.")
    for e in meta.get("errors", []):
        out.append(f"RULE ERROR {e['rule']}: {e['error']}  (scan fails closed)")
    if not meta.get("history", True):
        out.append("Git history was not scanned (--no-history).")
    return "\n".join(out)


# ---------------------------------------------------------------- json
def to_json(findings: list[Finding], meta: dict) -> str:
    items = []
    for f in sort_findings(findings):
        d = f.to_dict()
        d["evidence"] = mask(d.get("evidence", ""))
        d["fingerprint"] = fingerprint(f)
        items.append(d)
    return json.dumps({"tool": "saaf-tripwire", "version": __version__, "summary": _counts(findings),
                       "meta": meta, "findings": items}, indent=2)


# ---------------------------------------------------------------- sarif
def _rule_descriptor(rule: dict) -> dict:
    sev = rule.get("severity", "medium")
    seen = ", ".join(rule.get("seen_in", [])) or "n/a"
    help_md = (f"**{rule.get('title', rule['id'])}**\n\n"
               f"Attack it stops: {rule.get('why', '')}\n\n"
               f"Attack class: `{rule.get('class', '')}`. Seen in the SAAF audit: {seen}.")
    return {
        "id": rule["id"],
        "name": re.sub(r"[^A-Za-z0-9]", "", rule.get("title", rule["id"]).title()) or rule["id"],
        "shortDescription": {"text": rule.get("title", rule["id"])},
        "fullDescription": {"text": rule.get("why", rule.get("title", rule["id"]))},
        "help": {"text": f"{rule.get('why', '')} Seen in: {seen}.", "markdown": help_md},
        "helpUri": f"{INFO_URI}#rules",
        "defaultConfiguration": {"level": SARIF_LEVEL.get(sev, "warning")},
        "properties": {"tags": ["security", rule.get("class", "")], "precision": "high",
                       "security-severity": SECURITY_SEVERITY.get(sev, "5.5"),
                       "problem.severity": "error" if SARIF_LEVEL.get(sev) == "error" else SARIF_LEVEL.get(sev, "warning")},
    }


def _location(f: Finding, root: Path | None) -> dict:
    uri = f.file.replace("\\", "/").lstrip("/") if f.file else ""
    if not uri:
        # Repo-level finding: GitHub needs a file to hang the alert on. Use the README (or the root marker).
        uri = "README.md" if root is not None and (root / "README.md").exists() else ".github"
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": max(int(f.line or 1), 1)}}}
    return loc


def to_sarif(findings: list[Finding], rules: list[dict], meta: dict, root: Path | None = None) -> dict:
    known = {r["id"]: r for r in rules}
    for f in findings:                     # a finding from an unlisted rule still needs a descriptor
        known.setdefault(f.rule, {"id": f.rule, "title": f.rule, "severity": f.severity, "why": "", "class": ""})
    ids = sorted(known)
    index = {rid: i for i, rid in enumerate(ids)}
    results = []
    for f in sort_findings(findings):
        text = f.message.rstrip(".") + ". Fix: " + f.fix
        if f.evidence:
            text += f" Evidence: {mask(f.evidence)}"
        results.append({
            "ruleId": f.rule, "ruleIndex": index[f.rule], "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": text},
            "locations": [_location(f, root)],
            "partialFingerprints": {"tripwireFingerprint/v1": fingerprint(f)},
            "properties": {"severity": f.severity},
        })
    notes = [{"level": "error", "message": {"text": f"Rule {e['rule']} crashed: {e['error']}"},
              "descriptor": {"id": e["rule"]}} for e in meta.get("errors", [])]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SAAF Tripwire", "semanticVersion": __version__, "version": __version__,
                                "informationUri": INFO_URI, "rules": [_rule_descriptor(known[r]) for r in ids]}},
            "automationDetails": {"id": "saaf-tripwire/"},
            "invocations": [{"executionSuccessful": not meta.get("errors"),
                             "toolExecutionNotifications": notes}],
            "results": results,
        }],
    }
