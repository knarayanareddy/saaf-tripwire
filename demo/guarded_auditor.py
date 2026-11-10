"""llm_owasp's run_audit() with SAAF Tripwire added: the whole fix is the lines marked # TRIPWIRE.

Unchanged from the original: tree builder, file finder, control docs, prompt text, report.
Changed: (1) each auditee file goes in a tripwire.fence() data tag instead of a ``` fence it
can close, (2) SYSTEM_RULE tells the model the tagged text is data, (3) every quote the model
cites is checked with check_quotes() against the real files; an ungrounded verdict fails closed.
"""
from __future__ import annotations

import json
from pathlib import Path

import anthropic
from owasp_llm_audit import collector as C
from owasp_llm_audit.auditor import AUDIT_SYSTEM_PROMPT
from owasp_llm_audit.controls import load_controls
from owasp_llm_audit.report import format_report

from tripwire.fence import SYSTEM_RULE, check_quotes, fence  # TRIPWIRE

EVIDENCE_RULE = ('For each control also return "evidence": a list of quotes copied verbatim from '
                 'the material that support the status.')


def collect_fenced(directory: Path, nonce: str | None = None) -> tuple[str, str]:
    """Same walk as collector._collect_directory, but every file is fenced as untrusted data."""
    sections = ["## Directory Structure\n\n" + fence(C._build_tree(directory), "tree", nonce)]  # TRIPWIRE
    raw = []
    for fp in sorted(C._find_relevant_files(directory)):
        content = fp.read_text(errors="replace")[: C.MAX_FILE_SIZE]
        rel = fp.relative_to(directory)
        sections.append(f"## File: {rel}\n\n" + fence(content, str(rel), nonce))  # TRIPWIRE
        raw.append(content)
    return "\n".join(sections), "\n".join(raw)


def run_audit_guarded(target: str, nonce: str | None = None, model: str = "claude-sonnet-4-20250514"):
    material, raw_source = collect_fenced(Path(target), nonce)
    user_prompt = (f"## OWASP LLM Top 10 Controls\n\n{load_controls(None)}\n\n---\n\n"
                   f"## Agent Material to Audit\n\n{material}\n\n---\n\n"
                   "Assess this agent against all 10 OWASP LLM controls. Return your assessment as JSON.\n")
    system = AUDIT_SYSTEM_PROMPT + "\n" + EVIDENCE_RULE + "\n\n" + SYSTEM_RULE  # TRIPWIRE
    resp = anthropic.Anthropic().messages.create(
        model=model, max_tokens=8192, system=system,
        messages=[{"role": "user", "content": user_prompt}])
    text = resp.content[0].text
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    result = json.loads(text.strip())

    rejected = {}
    for c in result.get("controls", []):                        # TRIPWIRE: fail closed
        evidence = c.get("evidence") or []
        bad = check_quotes(evidence, raw_source) if evidence else ["<no evidence quoted>"]
        if bad and c.get("status") == "PASS":
            rejected[c["id"]] = bad
            c["status"] = "WARN"
            c["findings"] = [f"TRIPWIRE: verdict rejected, quote not found in source: {bad}"] + c.get("findings", [])
    return format_report(result, target), result, rejected, user_prompt, system
