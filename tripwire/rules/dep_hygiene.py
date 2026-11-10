"""TW-DEP1: offline dependency hygiene.

Flags HTTP-serving apps whose dependencies are not pinned and have no lockfile, and workflows that
`pip install` unpinned packages. The ONLINE advisory check (pip-audit / npm audit --audit-level=critical)
is run by the Tripwire CI wrapper, not by this rule, so the engine stays offline and deterministic.
"""
from __future__ import annotations
import json, re
from ..model import Context, Finding
from ..util.gha import files_of, rel, load_workflows

RULE = {
    "id": "TW-DEP1",
    "title": "Unpinned dependencies in a network-facing app or CI install",
    "severity": "medium",
    "class": "supply-chain-and-release",
    "why": "Unpinned installs pull whatever version is newest at build time, so a hijacked or broken release ships straight into a running server.",
    "seen_in": ["Team-HighTable", "Finding-analysis", "PBC-Assistant-Isabelle---IA-AI-Hackathon", "FieldworkOrchestration", "saaf-living-map"],
}

PY_HTTP = re.compile(r"@(app|router|bp|blueprint|api)\.(route|get|post|put|delete|patch)\(|\bFastAPI\(|\bFlask\(|\bAPIRouter\(|"
                     r"\burlpatterns\s*=|web\.Application\(|\bHTTPServer\(|\bStarlette\(")
SAMPLE = re.compile(r"(^|/)(sample_data|samples?|examples?|fixtures?|testdata|tests?)/")
JS_HTTP = {"express", "fastify", "koa", "next", "hono", "@nestjs/core", "@hapi/hapi"}
PY_LOCKS = {"poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock", "conda-lock.yml"}
JS_LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"}
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-\[\],]*)\s*(.*)$")


def _req_unpinned(text: str):
    for i, line in enumerate(text.splitlines(), 1):
        s = line.split(" #", 1)[0].strip()
        if not s or s.startswith(("#", "-", "git+", "http", ".", "/")) or "@" in s.split(";")[0]:
            continue
        m = REQ_LINE.match(s)
        if m and not re.match(r"^===?\s*[\w.]+\s*(;.*)?(\\)?$", m.group(2).strip()):
            yield i, m.group(1)


def check(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    files = files_of(ctx)
    rels = {rel(ctx, p): p for p in files}
    names = {r.rsplit("/", 1)[-1] for r in rels}
    http_dirs = []  # folders holding Python files that serve HTTP routes
    for r, p in rels.items():
        if r.endswith(".py") and not SAMPLE.search(r):
            try:
                if PY_HTTP.search(p.read_text(errors="replace")):
                    http_dirs.append(r.rsplit("/", 1)[0] if "/" in r else "")
            except OSError:
                pass
    if http_dirs and not (names & PY_LOCKS):
        for r, p in rels.items():
            base = r.rsplit("/", 1)[-1]
            folder = r.rsplit("/", 1)[0] if "/" in r else ""
            # only the requirements file that belongs to the server (same folder or a parent of it)
            serves = any(d == folder or ((folder == "" or d.startswith(folder + "/")) and base == "requirements.txt") for d in http_dirs)
            if serves and not SAMPLE.search(r) and re.match(r"^requirements[\w.-]*\.(txt|in)$", base) and "dev" not in base and "test" not in base:
                bad = list(_req_unpinned(p.read_text(errors="replace")))
                if bad:
                    out.append(Finding(
                        RULE["id"], "medium", r, bad[0][0],
                        f"HTTP-serving app installs {len(bad)} unpinned dependencies (e.g. {', '.join(n for _, n in bad[:3])}) and has no lockfile.",
                        "Pin exact versions (pip-compile --generate-hashes / uv lock) and let Dependabot raise updates.",
                        f"{len(bad)} unpinned: {', '.join(n for _, n in bad[:5])}"))
    for r, p in rels.items():
        if r.rsplit("/", 1)[-1] != "package.json" or "node_modules" in r or SAMPLE.search(r):
            continue
        try:
            pkg = json.loads(p.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        deps = pkg.get("dependencies") or {}
        folder = r.rsplit("/", 1)[0] if "/" in r else ""
        has_lock = any((folder + "/" + l if folder else l) in rels for l in JS_LOCKS) or bool(names & JS_LOCKS and not folder)
        if deps and set(deps) & JS_HTTP and not has_lock:
            out.append(Finding(RULE["id"], "medium", r, 1,
                               "HTTP-serving Node app has no committed lockfile, so every install resolves fresh versions.",
                               "Commit package-lock.json (or yarn/pnpm lock) and install with npm ci.", f"{len(deps)} dependencies, no lockfile"))
    for wf in load_workflows(ctx):
        for st in wf.steps():
            if "github-script" in str(st.data.get("uses", "")):
                continue  # script: is JavaScript, not a shell install
            for ln, text in st.run_lines():
                m = re.search(r"\bpip3?\s+install\s+(.+)$", text)
                if not m:
                    continue
                cmd = re.sub(r"\$\{\{[^}]*\}\}", "$EXPR", m.group(1))  # ${{ github.action_path }} -> one token
                args = [a for a in re.split(r"\s+", cmd) if a]
                pkgs, skip = [], False
                for a in args:
                    a = a.strip("'\"")  # "$TW_ACTION_PATH/" -> $TW_ACTION_PATH/ (a local path, not a package)
                    if skip:
                        skip = False
                        continue
                    if a in ("-r", "-c", "--requirement", "--constraint", "-e", "--editable", "-i", "--index-url", "--target", "-t"):
                        skip = True
                        continue
                    if a.startswith("-") or a.startswith((".", "/", "$", "~", "git+", "http", "file:")) or "/" in a or a in ("&&", "||", ";", "|"):
                        if a in ("&&", "||", ";", "|"):
                            break
                        continue
                    pkgs.append(a.strip("'\""))
                bad = [x for x in pkgs if not re.search(r"==|@", x)]
                if bad:
                    out.append(Finding(RULE["id"], "low", wf.rel, ln,
                                       f"Workflow installs unpinned package(s) {', '.join(bad[:4])}.",
                                       "Pin with == (or install from a hashed requirements file).", text.strip()[:120]))
    return out
