"""TW-CI1: third-party GitHub Actions (and fetched tools) not pinned to an immutable commit SHA."""
from __future__ import annotations
import re
from ..model import Context, Finding
from ..util.gha import load_workflows, uses_lines, references_secrets

RULE = {
    "id": "TW-CI1",
    "title": "Third-party GitHub Action not pinned to a full commit SHA",
    "severity": "low",
    "class": "supply-chain-and-release",
    "why": "A mutable tag (@v2, @main) lets whoever controls the upstream repo swap the code that runs with your token (tj-actions, 2025).",
    "seen_in": ["Compliance-Report-Generator", "agent-rogue-risk-assessor", "demo-repository", "saaf-guard"],  # SA-24, SA-41 context
}

SHA = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY = {"actions", "github"}
CLONE = re.compile(r"git\s+clone\b[^\n]*?(https://\S+)")
PIPE_SH = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b")


def check(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for wf in load_workflows(ctx):
        secret_sev = "medium" if references_secrets(wf) else "low"
        for ln, ref, job_level in uses_lines(wf):
            if job_level or ref.startswith("./"):
                continue  # reusable workflows are TW-CI2; local actions are in-repo
            if ref.startswith("docker://"):
                if "@sha256:" not in ref:
                    out.append(Finding(RULE["id"], "low", wf.rel, ln, f"Docker action {ref} is not pinned to a digest.",
                                       "Pin the image as docker://image@sha256:<digest>.", ref))
                continue
            if "@" not in ref:
                continue
            name, ver = ref.rsplit("@", 1)
            if SHA.match(ver):
                continue
            owner = name.split("/", 1)[0].lower()
            first = owner in FIRST_PARTY
            out.append(Finding(
                RULE["id"], "info" if first else secret_sev, wf.rel, ln,
                f"{'First-party' if first else 'Third-party'} action {name} is pinned to mutable ref '@{ver}'.",
                f"Pin {name} to its full 40-char commit SHA (keep '# {ver}' as a comment) and let Dependabot (github-actions) bump it.",
                f"uses: {ref}"))
        for i, line in enumerate(wf.lines, 1):
            m = CLONE.search(line)
            if m:
                window = "\n".join(wf.lines[i - 1:i + 4])
                if not re.search(r"git\s+(-C\s+\S+\s+)?(checkout|reset --hard)\s+[0-9a-f]{40}", window):
                    out.append(Finding(RULE["id"], "low", wf.rel, i,
                                       f"Workflow clones {m.group(1)} at a moving branch and runs it.",
                                       "Check out a fixed commit SHA after cloning (git -C <dir> checkout <sha>) or use a SHA-pinned action.",
                                       line.strip()[:120]))
            if PIPE_SH.search(line):
                out.append(Finding(RULE["id"], "medium", wf.rel, i, "Workflow pipes a downloaded script straight into a shell.",
                                   "Download to a file, verify its checksum, then run it.", line.strip()[:120]))
    return out
