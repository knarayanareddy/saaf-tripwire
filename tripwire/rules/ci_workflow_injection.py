"""TW-CI2: GitHub workflow script injection and token-scope mistakes."""
from __future__ import annotations
import re
from ..model import Context, Finding
from ..util.gha import load_workflows, uses_lines

RULE = {
    "id": "TW-CI2",
    "title": "Workflow injection or over-broad token scope",
    "severity": "high",
    "class": "supply-chain-and-release",
    "why": "A PR title, issue body or branch name expanded into run: becomes shell code running with the repo token.",
    "seen_in": ["Compliance-Report-Generator", "demo-repository", "judging-found-controls"],  # NEEDS-VALIDATION / SA-R36 (safe case)
}

# Attacker-controlled contexts (GitHub Security Lab list).
TAINT = re.compile(
    r"\$\{\{[^}]*?\b(github\.head_ref|github\.event\.[A-Za-z0-9_.*\[\]'\"-]*?"
    r"\.(?:title|body|message|name|email|head_ref|head_branch|label|default_branch|page_name)"
    r"|github\.event\.pull_request\.head\.ref)(?![A-Za-z0-9_])[^}]*\}\}")
# full_name / repository names cannot carry shell metacharacters
SAFE_NAME = re.compile(r"\.(full_name|repo\.name|repository\.name)\b")
UNTRUSTED_TRIGGERS = {"pull_request_target", "issues", "issue_comment", "discussion", "discussion_comment",
                      "workflow_run", "pull_request_review", "pull_request_review_comment"}
HEAD_CHECKOUT = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|"
                           r"github\.event\.workflow_run\.head_(sha|branch)")


def check(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for wf in load_workflows(ctx):
        trig = wf.triggers
        untrusted = bool(trig & UNTRUSTED_TRIGGERS)
        for st in wf.steps():
            for ln, text in st.run_lines():
                m = TAINT.search(text)
                if m and not SAFE_NAME.search(m.group(1)):
                    out.append(Finding(
                        RULE["id"], "high" if untrusted else "medium", wf.rel, ln,
                        f"Attacker-controlled {m.group(1)} is expanded directly into a script (job '{st.job}').",
                        "Pass it through env: (e.g. env: TITLE: ${{ github.event.pull_request.title }}) and use \"$TITLE\" in the script.",
                        text.strip()[:120]))
            uses = str(st.data.get("uses", ""))
            w = st.data.get("with") if isinstance(st.data.get("with"), dict) else {}
            if ("pull_request_target" in trig or "workflow_run" in trig) and uses.startswith("actions/checkout") \
                    and HEAD_CHECKOUT.search(str(w.get("ref", "")) + str(w.get("repository", ""))):
                out.append(Finding(
                    RULE["id"], "critical" if "pull_request_target" in trig else "high", wf.rel, st.line,
                    "Privileged trigger checks out and runs the untrusted PR head (pwn request).",
                    "Use pull_request instead, or never execute the checked-out PR code in a pull_request_target job.",
                    f"ref: {w.get('ref')}"))
        if wf.kind == "workflow" and wf.doc is not None and "permissions" not in wf.doc:
            jobs = wf.jobs()
            if not jobs or any(isinstance(j, dict) and "permissions" not in j and "uses" not in j for j in jobs.values()):
                out.append(Finding(
                    RULE["id"], "medium" if untrusted else "low", wf.rel, 1,
                    "No top-level permissions: block, so jobs get the repository's default GITHUB_TOKEN scope (often write).",
                    "Add 'permissions: contents: read' at the top and grant extra scopes per job.", "permissions: (missing)"))
        for ln, ref, job_level in uses_lines(wf):
            if job_level and not ref.startswith("./") and "@" in ref and not re.fullmatch(r"[0-9a-f]{40}", ref.rsplit("@", 1)[1]):
                out.append(Finding(
                    RULE["id"], "medium", wf.rel, ln,
                    f"Reusable workflow {ref.rsplit('@', 1)[0]} is called at mutable ref '@{ref.rsplit('@', 1)[1]}'.",
                    "Call the reusable workflow at a full commit SHA (or a protected release tag you control).", f"uses: {ref}"))
    return out
