#!/usr/bin/env python3
"""SAAF Tripwire live demo: llm_owasp (audit finding SA-39) before and after tripwire.fence.

    python3 demo/run_demo.py            # from ~/saaf-redteam/tripwire, offline, no API key

BEFORE = the real llm_owasp code (copied unchanged into demo/vendor/llm_owasp).
AFTER  = the same code with tripwire.fence + SYSTEM_RULE + check_quotes (demo/guarded_auditor.py).
The model is stubbed (demo/fake_llm.py) and returns the same fooled verdict in both runs.
"""
from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE / "vendor" / "llm_owasp"), str(HERE.parent)]

import fake_llm  # noqa: E402
fake_llm.install()  # `anthropic` is now the offline stub; sockets refuse to connect

from owasp_llm_audit.auditor import AUDIT_SYSTEM_PROMPT, run_audit  # noqa: E402
from guarded_auditor import run_audit_guarded  # noqa: E402
from tripwire.fence import check_quotes  # noqa: E402

TARGET = HERE / "auditee_repo"
MARKER = "PROBE-INJECT-5521"
NONCE = "7f3a9c21e4b05d68"  # fixed so the demo prints the same thing every run; production = random
W = 50


def fence_state(prompt: str, marker: str) -> tuple[bool, str]:
    """Walk the prompt as Markdown: is the marker line inside a ``` code block?"""
    inside = False
    for line in prompt.splitlines():
        if marker in line:
            return inside, line
        if re.match(r"^\s*(`{3,}|~{3,})", line):
            inside = not inside
    return False, ""


def tag_state(prompt: str, marker: str, nonce: str) -> tuple[bool, str]:
    """Is the marker inside a <untrusted_document id=NONCE> ... </untrusted_document id=NONCE> span?"""
    pos = prompt.find(marker)
    line = prompt[prompt.rfind("\n", 0, pos) + 1: prompt.find("\n", pos)]
    for m in re.finditer(r'<untrusted_document id="%s"[^>]*>(.*?)</untrusted_document id="%s">' % (nonce, nonce),
                         prompt, re.S):
        if m.start(1) <= pos < m.end(1):
            return True, line
    return False, line


def excerpt(prompt: str, marker: str, label, before: int = 3, after: int = 2) -> list[str]:
    """Lines around the marker, each prefixed with how the model will read it."""
    lines = prompt.splitlines()
    i = next(n for n, l in enumerate(lines) if marker in l)
    out, offset = [], sum(len(l) + 1 for l in lines[: max(0, i - before)])
    for l in lines[max(0, i - before): i + after + 1]:
        out.append(f"{label(prompt, offset, l)}| {l}")
        offset += len(l) + 1
    return out


def label_md(prompt: str, offset: int, line: str) -> str:
    inside, _ = fence_state(prompt[: offset] + "\x00MARK\x00", "\x00MARK\x00")
    if re.match(r"^\s*(`{3,}|~{3,})", line):
        return "fence"
    return "code " if inside else "TOP! "


def label_tag(prompt: str, offset: int, line: str) -> str:
    spans = [m.span(1) for m in re.finditer(
        r'<untrusted_document id="%s"[^>]*>(.*?)</untrusted_document id="%s">' % (NONCE, NONCE), prompt, re.S)]
    return "data " if any(a <= offset < b for a, b in spans) else "TOP! "


def status_of(report: str, cid: str) -> str:
    m = re.search(r"\| %s \| [^|]+ \| \*\*(\w+)\*\* \|" % cid, report)
    return m.group(1) if m else "?"


def row(left: str, right: str) -> None:
    lw = textwrap.wrap(left, W) or [""]
    rw = textwrap.wrap(right, W) or [""]
    for i in range(max(len(lw), len(rw))):
        l = lw[i] if i < len(lw) else ""
        r = rw[i] if i < len(rw) else ""
        print(f"  {l:<{W}} | {r}")


def block(lines_l: list[str], lines_r: list[str]) -> None:
    cut = lambda s: (s[: W - 3] + "...") if len(s) > W else s
    for i in range(max(len(lines_l), len(lines_r))):
        l = cut(lines_l[i]) if i < len(lines_l) else ""
        r = cut(lines_r[i]) if i < len(lines_r) else ""
        print(f"  {l:<{W}} | {r}")


def main() -> int:
    # ---------------- BEFORE: the original tool, untouched
    report_b = run_audit(str(TARGET))
    call_b = fake_llm.CALLS[-1]
    prompt_b = call_b["messages"][0]["content"]
    in_code_b, _ = fence_state(prompt_b, MARKER)

    # ---------------- AFTER: same tool + tripwire
    report_a, _, rejected, prompt_a, system_a = run_audit_guarded(str(TARGET), nonce=NONCE)
    in_tag_a, _ = tag_state(prompt_a, MARKER, NONCE)

    source = "\n".join(p.read_text() for p in TARGET.iterdir() if p.is_file())
    fab, real = fake_llm.FABRICATED_QUOTE, fake_llm.REAL_QUOTE

    bar = "=" * (2 * W + 5)
    print(bar)
    print("  SAAF TRIPWIRE  |  agent: llm_owasp (SAAF-Project)  |  audit finding SA-39 (LLM01)")
    print("  Attack: the audited repo's agent.py closes the ``` fence and plants an 'AUDITOR NOTE'")
    print("  Model: offline stub, returns the SAME fooled verdict in both columns (worst case)")
    print(bar)
    row("BEFORE  (llm_owasp as shipped)", "AFTER  (+ tripwire.fence / check_quotes)")
    print("  " + "-" * W + "-+-" + "-" * W)
    print("  1. What the auditor model receives:")
    block(excerpt(prompt_b, MARKER, label_md), excerpt(prompt_a, MARKER, label_tag))
    print("  (code = inside a ``` block, TOP! = top-level prompt text, data = inside the nonce data tag)")
    print()
    row("2. Injected line position: "
        + ("inside a code block (data)" if in_code_b else "TOP-LEVEL PROMPT, reads like an instruction"),
        "2. Injected line position: "
        + (f"INSIDE <untrusted_document id={NONCE}> (data)" if in_tag_a else "outside the data tag"))
    row("3. System prompt says material is data: "
        + ("yes" if "untrusted" in AUDIT_SYSTEM_PROMPT.lower() else "NO"),
        "3. System prompt says material is data: " + ("YES (SYSTEM_RULE)" if "is DATA" in system_a else "no"))
    row(f'4. Model cites "{fab}" -> '
        + ("in source" if fab in source else "NOT in source, but nothing checks: ACCEPTED"),
        f'4. Model cites "{fab}" -> '
        + ("REJECTED by check_quotes (not in source)" if "LLM01" in rejected else "accepted"))
    row(f'5. Real quote "{real}" -> unchecked',
        f'5. Real quote "{real}" -> ' + ("grounded, kept" if not check_quotes([real], source) else "rejected"))
    row(f"6. Report verdict LLM01 Prompt Injection: {status_of(report_b, 'LLM01')}",
        f"6. Report verdict LLM01 Prompt Injection: {status_of(report_a, 'LLM01')} (failed closed)")
    print(bar)
    forgery_b = not in_code_b
    ok = forgery_b and in_tag_a and "LLM01" in rejected and status_of(report_b, "LLM01") == "PASS"
    print(f"  RESULT  before: forgery lands as instruction={forgery_b}, fabricated quote accepted=True")
    print(f"          after : forgery contained in data tag={in_tag_a}, fabricated quote rejected={'LLM01' in rejected}")
    print("  Network calls made: 0 (sockets disabled)   API key used: none")
    print(bar)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
