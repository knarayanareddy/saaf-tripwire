"""TW-KEY1: a server secret (API key / token from env or config) is rendered into HTML/JS or returned by a route."""
from __future__ import annotations

import ast
import re

from ..model import Context, Finding
from ..util.llmscan import call_name, functions, last, line_text, own_statements, py_files

RULE = {
    "id": "TW-KEY1",
    "title": "Server secret reaches the browser",
    "severity": "high",
    "class": "client-side",
    "why": "Anyone who can open the page (or any site via DNS rebinding) reads the operator's API key from the "
           "HTML form, template or JSON and spends or abuses it.",
    "seen_in": ["Finding-analysis"],
}
FIX = "Never send the server key to the client: render an empty field and fall back to the env key server-side."
SECRET_NAME = re.compile(r"(api[_-]?key|secret|token|password|passwd|pat\b|_pat$|private[_-]?key|credential|access[_-]?key)", re.I)
SINKS = {"render_template", "render_template_string", "TemplateResponse", "jsonify", "JSONResponse", "HTMLResponse",
         "make_response", "Response", "render", "text_input", "markdown", "write", "code", "json", "html", "send"}
ROUTE_DECO = re.compile(r"(^|\.)(route|get|post|put|patch|delete|api_route|websocket)$")
ENV_CALLS = {"os.getenv", "os.environ.get", "getenv", "environ.get", "os.environ.__getitem__"}


SAFE_WRAP = {"bool", "len", "isinstance", "hash", "callable", "mask", "redact", "masked", "startswith", "endswith", "hexdigest"}


def _nodes(e):
    """Walk e but do not descend into boolean/length wrappers or comparisons (they leak no secret)."""
    stack = [e]
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.Compare, ast.UnaryOp)) or (isinstance(n, ast.Call) and last(call_name(n)) in SAFE_WRAP):
            continue
        if isinstance(n, ast.BoolOp) and isinstance(getattr(n, "op", None), ast.And):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def _secret_expr(e, secret_vars) -> str | None:
    for n in _nodes(e):
        if isinstance(n, ast.Call) and call_name(n) in ENV_CALLS and n.args:
            a = n.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and SECRET_NAME.search(a.value):
                return a.value
        if isinstance(n, ast.Subscript) and call_name(n.value) in {"os.environ", "environ", "app.config", "current_app.config", "st.secrets", "settings"}:
            k = n.slice
            if isinstance(k, ast.Constant) and isinstance(k.value, str) and SECRET_NAME.search(k.value):
                return k.value
        if isinstance(n, ast.Name) and n.id in secret_vars:
            return secret_vars[n.id]
    return None


def check(ctx: Context) -> list[Finding]:
    found = []
    for rel, src, tree in py_files(ctx):
        if not re.search(r"flask|fastapi|starlette|django|streamlit|aiohttp|bottle|quart|gradio", src, re.I):
            continue
        for fn in functions(tree):
            if fn is tree:
                continue
            is_route = any(ROUTE_DECO.search(call_name(d.func if isinstance(d, ast.Call) else d)) for d in fn.decorator_list)
            secret_vars: dict[str, str] = {}
            for st in own_statements(fn):
                if isinstance(st, ast.Assign):
                    s = _secret_expr(st.value, secret_vars)
                    for t in st.targets:
                        if isinstance(t, ast.Name):
                            if s and not isinstance(st.value, (ast.BoolOp, ast.Compare)):
                                secret_vars[t.id] = s
                            else:
                                secret_vars.pop(t.id, None)
                hit = None
                for n in ast.walk(st) if not isinstance(st, (ast.If, ast.For, ast.While, ast.With, ast.Try)) else []:
                    if isinstance(n, ast.Call) and last(call_name(n)) in SINKS:
                        if last(call_name(n)) in {"markdown", "write", "code", "json", "html", "text_input", "send"} \
                                and not call_name(n).startswith(("st.", "streamlit.", "ws.", "websocket.")):
                            continue
                        for arg in list(n.args[1:] if last(call_name(n)) in {"render_template", "TemplateResponse", "render"} else n.args) + [k.value for k in n.keywords]:
                            s = _secret_expr(arg, secret_vars)
                            if s:
                                hit = (n.lineno, f"{s} is passed to {call_name(n)}() and ends up in the page/response")
                                break
                    if hit:
                        break
                if not hit and is_route and isinstance(st, ast.Return) and st.value is not None:
                    s = _secret_expr(st.value, secret_vars)
                    if s:
                        hit = (st.lineno, f"route {fn.name}() returns {s} to the caller")
                if hit:
                    found.append(Finding(RULE["id"], RULE["severity"], rel, hit[0], "Secret to client: " + hit[1] + ".",
                                         FIX, line_text(src, hit[0])))
    return found
