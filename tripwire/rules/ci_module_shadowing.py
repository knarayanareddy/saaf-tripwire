"""TW-CI3: a CI gate runs `python -m <tool>` from the untrusted checkout's cwd, so the repo can ship its own <tool>."""
from __future__ import annotations
import re
from ..model import Context, Finding
from ..util.gha import load_workflows, references_secrets

RULE = {
    "id": "TW-CI3",
    "title": "CI guard can be replaced by a same-named module in the scanned repo",
    "severity": "low",
    "class": "supply-chain-and-release",
    "why": "`python -m pkg` puts cwd first on sys.path; an auditee adds pkg/ to its repo and the gate always passes.",
    "seen_in": ["saaf-guard"],  # SA-41
}

PY = re.compile(r"(?:^|[\s;&|(])(?:\S*/)?python(?:3(?:\.\d+)?)?((?:\s+-[A-Za-z]+)*)\s+(?:-m\s+([A-Za-z_][\w.]*)|-c\s+['\"][^'\"]*?\bimport\s+([A-Za-z_]\w*))")
OUTSIDE = re.compile(r"RUNNER_TEMP|runner\.temp|/tmp\b|action_path|\$HOME|~/|\.\./")
SKIP = {"pip", "venv", "ensurepip", "virtualenv", "build", "twine"}


def _top_dirs(ctx: Context) -> set[str]:
    names = set()
    for p in ctx.root.iterdir() if ctx.root.is_dir() else []:
        if p.is_dir() and (p / "__init__.py").exists():
            names.add(p.name)
    src = ctx.root / "src"
    if src.is_dir():
        names |= {p.name for p in src.iterdir() if p.is_dir() and (p / "__init__.py").exists()}
    return names


def check(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    own = _top_dirs(ctx)
    for wf in load_workflows(ctx):
        reusable = wf.kind == "action" or "workflow_call" in wf.triggers
        cloned = {re.sub(r"[-.]", "_", m.group(1).lower()) for m in
                  re.finditer(r"git\s+clone\b[^\n]*?/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[\s\"']|$)", wf.text)}
        sev = "medium" if references_secrets(wf) else "low"
        for st in wf.steps():
            wd = str(st.data.get("working-directory", ""))
            pyenv = str(st.env.get("PYTHONPATH", ""))
            for ln, text in st.run_lines():
                if re.search(r"\bcd\s+\S*(RUNNER_TEMP|runner\.temp|/tmp)", text) or OUTSIDE.search(wd):
                    continue
                for m in PY.finditer(text):
                    flags, pkg = m.group(1) or "", (m.group(2) or m.group(3) or "")
                    top = pkg.split(".")[0]
                    if not top or top in SKIP or re.search(r"-\w*[PI]", flags):
                        continue
                    ext_path = bool(OUTSIDE.search(pyenv)) or bool(re.search(r"PYTHONPATH=\S*(" + OUTSIDE.pattern + ")", text))
                    why = []
                    if ext_path:
                        why.append("PYTHONPATH points outside the checkout")
                    if top.lower() in cloned:
                        why.append("the tool is cloned outside the checkout")
                    if reusable and top in own:
                        why.append("this reusable workflow/action runs its own package inside callers' checkouts")
                    if not why:
                        continue
                    out.append(Finding(
                        RULE["id"], sev, wf.rel, ln,
                        f"`python -m {top}` runs with the scanned repo as cwd ({'; '.join(why)}), so a {top}/ folder in that repo replaces the tool.",
                        "Run with `python -P -m ...` (3.11+, cwd not on sys.path) or cd into the tool's directory and pass $GITHUB_WORKSPACE as an argument.",
                        text.strip()[:120]))
    return out
