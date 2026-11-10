"""TW-NET4: unauthenticated routes that delete/reset/seed data or spend the server's LLM key."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-NET4",
    "title": "Unauthenticated route deletes data or spends the LLM key",
    "severity": "medium",
    "class": "web-protocol-and-auth",
    "why": "One anonymous request wipes evidence, resets the database or burns the operator's paid API quota.",
    "seen_in": ["SAAF-circuit-breaker", "OWASP-top-10-LLM-assessment", "PBC-Assistant-Isabelle---IA-AI-Hackathon",
                "Track-4-Audit-Report-Generator"],
}
FIX = "Require an authenticated session or API key on this handler (or app-wide middleware) and disable seed/reset routes outside development."
LLM = re.compile(r"\.messages\.(create|stream)\(|chat\.completions\.create\(|\.responses\.create\(|generate_content\(|"
                 r"\b(generateText|streamText|generateObject|streamObject)\(|new (Anthropic|OpenAI)\(|anthropic\.Anthropic\(")
DESTROY_PY = re.compile(r"\.unlink\(|shutil\.rmtree\((?![^)]*tmp)|os\.remove\(|\bDROP\s+TABLE|\bTRUNCATE\b|DELETE\s+FROM|\.delete\(\s*\)|session\.delete\(")
DESTROY_JS = re.compile(r"\b(?!ensure|maybe|is|has|should|can)\w*(seed|reset|wipe|purge|truncate|destroy|deleteMany|deleteAll|dropTable)\w*\s*\(|\bdb\.delete\(|"
                        r"\.delete\(\s*\w+\s*\)|DELETE\s+FROM|\bfs\.(rm|unlink|rmSync|unlinkSync)\(", re.I)
DANGER_PATH = re.compile(r"seed|reset|wipe|purge|clear|truncate|drop|nuke", re.I)
JS_AUTH = re.compile(r"getServerSession|\bauth\(\)|getToken\(|currentUser\(|@clerk|verify\w*\(|authorization|x-api-key|"
                     r"requireAuth|withAuth|isAuthenticated|getSession\(|supabase\.auth|cookies\(\)\.get\(\s*['\"]\w*(session|token)", re.I)
CONST_WRITE = re.compile(r"open\(\s*[A-Z_][A-Z0-9_]*\s*,\s*['\"]w")


def _danger_helpers(ctx):
    """Names of Python functions anywhere in the repo that call an LLM, destroy data or overwrite a fixed config file."""
    names = set()
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        if not tree:
            continue
        text = w.read(p)
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not w.route_info(n):
                body = w.src(n, text)
                if LLM.search(body) or DESTROY_PY.search(body):
                    names.add(n.name)
    return names


def _py(ctx):
    helpers = None
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        if not tree:
            continue
        text = w.read(p)
        routes = list(w.iter_routes(tree))
        if not routes or w.py_unauth_routes(ctx, p.parent)[0]:
            continue
        if helpers is None:
            helpers = _danger_helpers(ctx)
        for fn, methods, path in routes:
            if w.route_has_auth(fn, text):
                continue
            body = w.src(fn, text)
            called = {w.call_name(c).split(".")[-1] for c in ast.walk(fn) if isinstance(c, ast.Call)}
            why = None
            if LLM.search(body):
                why = "calls the LLM with the server's key"
            elif "DELETE" in methods or DESTROY_PY.search(body):
                why = "deletes data"
            elif DANGER_PATH.search(path):
                why = f"is a {DANGER_PATH.search(path).group(0)} route"
            elif called & helpers:
                why = f"calls {sorted(called & helpers)[0]}() which spends the LLM key or deletes data"
            if why:
                yield p, fn.lineno, text, f"{'/'.join(sorted(methods))} {path} has no authentication and {why}."


ROUTE_FILE = re.compile(r"(^|/)(app/(.*/)?api/.*route|pages/api/.*)\.(t|j)sx?$")
HANDLER = re.compile(r"export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=|"
                     r"export\s+default\s+(async\s+)?function")


def _js(ctx):
    mw_auth = any(JS_AUTH.search(w.read(p)) for p in w.files(ctx, w.JS) if re.match(r"middleware\.(t|j)s$", p.name))
    if mw_auth:
        return
    for p in w.files(ctx, w.JS):
        r = w.rel(ctx, p)
        if not ROUTE_FILE.search(r):
            continue
        raw = w.read(p)
        s = w.strip_js_comments(raw)
        for m in HANDLER.finditer(s):
            brace = s.find("{", s.find(")", m.end()) if "function" in m.group(0) else m.end())
            if brace < 0:
                continue
            body = s[brace:w.match_close(s, brace) + 1]
            if JS_AUTH.search(body):
                continue
            method = m.group(2) or m.group(3) or "handler"
            why = "calls the LLM with the server's key" if LLM.search(body) else \
                  "deletes or reseeds data" if (DESTROY_JS.search(body) or method == "DELETE") else None
            if why:
                ln = w.line_of(s, m.start())
                yield p, ln, raw, f"{method} handler in {r} has no authentication and {why}."


def check(ctx: Context) -> list[Finding]:
    out = []
    for p, ln, text, msg in [*_py(ctx), *_js(ctx)]:
        out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), ln, msg, FIX, w.line_text(text, ln)))
    return out
