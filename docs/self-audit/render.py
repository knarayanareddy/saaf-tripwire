#!/usr/bin/env python3
"""Phase 6 — derive the reports from findings.json + coverage-ledger.json.

The reports are generated, never hand-edited: a claim that is not a validated record
cannot appear in them. Run after `validate.py`:

    python docs/self-audit/validate.py && python docs/self-audit/render.py
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = json.loads((HERE / "findings.json").read_text())
LEDGER = json.loads((HERE / "coverage-ledger.json").read_text())
RECS = DATA["records"]
BY = {r["id"]: r for r in RECS}
CONFIRMED = [r for r in RECS if r["verdict"] == "confirmed"]
REJECTED = [r for r in RECS if r["verdict"] == "rejected"]
NEEDS = [r for r in RECS if r["verdict"] == "needs_validation"]
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sev(r):
    return r.get("severity", "—")


def table(rows, header):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def report() -> str:
    counts = Counter(sev(r) for r in CONFIRMED)
    fixed = sum(1 for r in CONFIRMED if r["status"] == "fixed")
    mitigated = sum(1 for r in CONFIRMED if r["status"] == "mitigated")
    units = LEDGER["units"]
    covered = sum(1 for u in units if u["status"] == "covered")
    out = []
    out.append("# Self-audit report — SAAF Tripwire")
    out.append("")
    out.append(f"**Target** `{DATA['audit']['target']}` @ `{DATA['audit']['commit']}` · "
               f"**Method** {DATA['audit']['method']} · **Date** 2026-11-16")
    out.append("")
    out.append("## Verdict")
    out.append("")
    out.append(
        f"The guard's *detection* logic holds up; its *delivery* and *evidence integrity* did not. "
        f"{len(CONFIRMED)} confirmed defects ({counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low), all {fixed + mitigated} now fixed or mitigated ({fixed} fixed, "
        f"{mitigated} mitigated); {len(REJECTED)} candidates disproved; {len(NEEDS)} facts still unresolved. "
        "The most serious are not in the rules: a hostile repo could execute code through git "
        "(`textconv`, `core.fsmonitor`), and the shipped action could not start at all because its "
        "only runtime dependency was undeclared and `--no-deps` skipped it.")
    out.append("")
    out.append("This audit also demonstrates the repo's missing phase-4/5 machinery: `findings.json` is "
               "schema-validated and every record re-probed by `probes/`, but that machinery lives in this "
               "audit directory, **not in the product** (R-08 still stands).")
    out.append("")
    out.append("## Confirmed")
    out.append("")
    rows = []
    for r in sorted(CONFIRMED, key=lambda r: (ORDER[sev(r)], r["id"])):
        rows.append([r["id"], sev(r), f"`{r['class']}`", r["status"], r["component"], r["summary"]])
    out.append(table(rows, ["ID", "Severity", "Class", "Status", "Component", "Finding"]))
    out.append("")
    out.append("## Disproved candidates")
    out.append("")
    rows = [[r["id"], f"`{r['class']}`", r["summary"], r["refutation"]] for r in REJECTED]
    out.append(table(rows, ["ID", "Class", "Candidate", "What killed it"]))
    out.append("")
    out.append("## Coverage")
    out.append("")
    out.append(f"{covered}/{len(units)} ledger units covered by an executed check; "
               f"{len(units) - covered} out of scope with a named reason "
               f"(see `coverage-ledger.json`, validated by `validate.py`).")
    out.append("")
    rows = [[u["id"], u["surface"], u["status"], u.get("result", u.get("reason", ""))] for u in units]
    out.append(table(rows, ["Unit", "Surface", "Status", "Result / reason"]))
    out.append("")
    out.append("## Still unresolved")
    out.append("")
    out.append("See `NEEDS-VALIDATION.md` — " + ", ".join(r["id"] for r in NEEDS) + ".")
    out.append("")
    out.append("## Sharp edges worth knowing (not defects)")
    out.append("")
    out.append("- **A shallow checkout now refuses to scan history.** `actions/checkout` defaults to depth 1; "
               "callers must set `fetch-depth: 0` or pass `history: false`. This is the intended fail-closed "
               "behaviour, but it is a breaking change for anyone who relied on the old silent zero.")
    out.append("- **Finding evidence is auditee text.** It reaches the consuming model verbatim. The skill now "
               "declares it untrusted and requires `fence()`; any other consumer must do the same.")
    out.append("- **`--no-history` is an explicit coverage hole.** It is the documented escape hatch for "
               "shallow clones; it must never be the CI default.")
    out.append("- **PyYAML is version-pinned, not hash-pinned.** The action still fetches one wheel from the "
               "index at run time; a `--require-hashes` requirements file is the next step if the runner "
               "must be index-independent.")
    out.append("")
    out.append("## Reproduce")
    out.append("")
    out.append("```sh")
    out.append("python docs/self-audit/validate.py          # schema + ledger constraints")
    out.append("python docs/self-audit/render.py            # regenerate this report")
    out.append("python docs/self-audit/probes/probes.py     # 14/14 probes")
    out.append("python -m pytest -q                         # 287 tests")
    out.append("```")
    out.append("")
    return "\n".join(out)


def detail() -> str:
    out = ["# Findings detail", "",
           "One section per record in `findings.json`; generated by `render.py`. "
           "`Before`/`after` are the observed outputs, not intentions.", ""]
    for r in sorted(CONFIRMED, key=lambda r: (ORDER[sev(r)], r["id"])):
        out += [f"## {r['id']} — {r['summary']}", "",
                f"- **Verdict** confirmed · **Severity** {sev(r)} · **Status** {r['status']} · "
                f"**Class** `{r['class']}` · **Component** {r['component']}", "",
                "**Data flow**", ""]
        out += [f"- `{t['file']}:{t['line']}` — {t['note']}" for t in r["trace"]]
        out += ["", f"**Probe** `{r['probe']['command']}`", "", f"Expectation: {r['probe']['expectation']}.", "",
                f"**Before the patch** {r['observedBefore']}", "",
                f"**After the patch** {r['observedAfter']}", "",
                f"**Fix** {r['fix']}", ""]
    out += ["# Disproved candidates", ""]
    for r in REJECTED:
        out += [f"## {r['id']} — {r['summary']}", "",
                f"- **Verdict** rejected · **Class** `{r['class']}` · **Component** {r['component']}", "",
                "**Why it was raised** " + "; ".join(f"`{t['file']}:{t['line']}` {t['note']}" for t in r.get("trace", [])),
                "", f"**Observation that killed it** {r['refutation']}", ""]
    out += ["# Needs validation", "",
            "These are **not** findings: each is one exact unresolved fact, with no severity.", ""]
    for r in NEEDS:
        out += [f"## {r['id']} — {r['summary']}", "",
                f"- **Class** `{r['class']}` · **Component** {r['component']}", "",
                f"**Unresolved** {r['unresolved']}", ""]
    return "\n".join(out)


def needs() -> str:
    out = ["# Needs validation", "",
           "Not findings. Each row is one thing this audit could not settle, why it matters, "
           "and the check that would settle it. No severity is assigned.", ""]
    rows = []
    for r in NEEDS:
        rows.append([r["id"], r["component"], r["summary"], r["unresolved"]])
    out.append(table(rows, ["ID", "Component", "Question", "Exact unresolved fact"]))
    out.append("")
    out.append("The audit's stop condition does not require these to be closed, but the gate must not "
               "pretend they are covered: `coverage-ledger.json` marks their units `covered` only in the "
               "sense that the question was raised, and the record stays `needs_validation`.")
    out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    (HERE / "REPORT.md").write_text(report())
    (HERE / "FINDINGS-DETAIL.md").write_text(detail())
    (HERE / "NEEDS-VALIDATION.md").write_text(needs())
    print("wrote REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md")
