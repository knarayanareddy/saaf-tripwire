"""TW-NET2: CORS lets any website call the API (wildcard, bare CORS(app), reflected Origin, allow-all callback)."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-NET2",
    "title": "CORS allows any origin",
    "severity": "medium",
    "class": "web-protocol-and-auth",
    "why": "Any web page the operator visits can call the API from their browser (even on localhost) and read the answers.",
    "seen_in": ["Agent-Auditor", "PBC-Assistant-Isabelle---IA-AI-Hackathon", "Team-HighTable"],
}
FIX = "List the exact front-end origins you serve (e.g. ['http://localhost:5173']); never combine '*' or a reflected Origin with credentials."
STAR = re.compile(r"""^\s*[\[\(\{]?\s*['"]\*['"]\s*,?\s*[\]\)\}]?\s*$""")
# header name followed by '*' or the caller's Origin, in any syntax: h['ACAO'] = x, h.add('ACAO', x), {'ACAO': x}, setHeader('ACAO', x)
HDR = re.compile(r"""(?i)['"]access-control-allow-origin['"]\s*\]?\s*[,:=]\s*(['"]\*['"]|"""
                 r"""(req|request|ctx|c)\.(headers\.get\(\s*['"]origin|headers\.origin|headers\[\s*['"]origin|origin\b|get\(\s*['"]origin|"""
                 r"""header\(\s*['"]origin|environ\.get\(\s*['"]HTTP_ORIGIN))""")


def _consts(tree, text):
    return {n.targets[0].id: w.src(n.value, text) for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}


def _star(node, text, consts):
    s = w.src(node, text)
    if isinstance(node, ast.Name):
        s = consts.get(node.id, "")
    return bool(STAR.match(s))


def _py(ctx):
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        if not tree:
            continue
        text = w.read(p)
        consts = None
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            name = w.call_name(n)
            last = name.split(".")[-1]
            kws = {k.arg: k.value for k in n.keywords if k.arg}
            cred = any(k in kws and w.src(kws[k], text) == "True" for k in ("allow_credentials", "supports_credentials"))
            if last in ("add_middleware", "Middleware") and n.args and "CORS" in w.src(n.args[0], text):
                consts = consts if consts is not None else _consts(tree, text)
                rx = w.src(kws["allow_origin_regex"], text).strip("'\" r") if "allow_origin_regex" in kws else ""
                if ("allow_origins" in kws and _star(kws["allow_origins"], text, consts)) or rx in (".*", "^.*$", ".+", "^.+$"):
                    yield p, n.lineno, text, cred
            elif last in ("CORS", "cross_origin"):
                consts = consts if consts is not None else _consts(tree, text)
                if "origins" in kws:
                    if _star(kws["origins"], text, consts):
                        yield p, n.lineno, text, cred
                elif "resources" in kws:
                    if re.search(r"""['"]origins['"]\s*:\s*(\[\s*)?['"]\*['"]""", w.src(kws["resources"], text)):
                        yield p, n.lineno, text, cred
                else:  # flask-cors default is origins='*'
                    yield p, n.lineno, text, cred
        for m in HDR.finditer(text):
            ln = w.line_of(text, m.start())
            if not text.splitlines()[ln - 1].lstrip().startswith("#"):
                yield p, ln, text, "credentials" in text.lower()


JS_PATTERNS = [
    re.compile(r"\bcors\(\s*\)"),
    re.compile(r"""\bcors\(\s*\{[^}]*origin\s*:\s*(true|['"]\*['"])"""),
    re.compile(r"""\borigin\s*:\s*(\([^)]*\)|[A-Za-z_$][\w$]*|function\s*\w*\s*\([^)]*\))\s*(=>)?\s*\{?\s*(return\s+)?\w+\(\s*null\s*,\s*true\s*\)"""),
    HDR,
    re.compile(r"""(?i)key\s*:\s*['"]access-control-allow-origin['"]\s*,\s*value\s*:\s*['"]\*['"]"""),
]


def _js(ctx):
    for p in w.files(ctx, w.JS):
        raw = w.read(p)
        low = raw.lower()
        if "cors" not in low and "access-control" not in low:
            continue
        s = w.strip_js_comments(raw)
        cred = bool(re.search(r"credentials\s*:\s*true|allow-credentials", s, re.I))
        for pat in JS_PATTERNS:
            for m in pat.finditer(s):
                yield p, w.line_of(s, m.start()), raw, cred
        for m in re.finditer(r"\bcors\(\s*\{", s):  # cors({...}) without an origin key -> origin '*'
            body = s[m.end() - 1:w.match_close(s, m.end() - 1) + 1]
            if not re.search(r"\borigin\s*:", body):
                yield p, w.line_of(s, m.start()), raw, cred


def check(ctx: Context) -> list[Finding]:
    out, seen = [], set()
    for p, ln, text, cred in [*_py(ctx), *_js(ctx)]:
        if (p, ln) in seen:
            continue
        seen.add((p, ln))
        msg = "CORS admits any origin" + (" together with credentials (the browser reflects the caller's Origin)" if cred else "") + \
              ", so any website can drive this API from a visitor's browser."
        out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), ln, msg, FIX, w.line_text(text, ln)))
    return out
