"""TW-NET5: the server fetches or clones a URL/path the caller controls (SSRF, file://, path injection into upstream APIs)."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-NET5",
    "title": "Server fetches a caller-controlled URL or path",
    "severity": "high",
    "class": "web-protocol-and-auth",
    "why": "A caller points the server at file://, an internal host or another API path and the server fetches it with its own network position and tokens.",
    "seen_in": ["OWASP-top-10-LLM-assessment", "SAAF-Project", "saaf-portal"],
}
FIX = "Never pass request data straight into fetch/clone: use a fixed URL or an allowlist of hosts and schemes (https only), and encodeURIComponent / validate path segments."
PY_SINKS = re.compile(r"^(requests|httpx|session|s|client)\.(get|post|put|delete|head|patch|request|stream)$|(^|\.)urlopen$|"
                      r"^urllib\.request\.Request$|^Request$|(^|\.)clone_from$|^aiohttp\..*")
SUBPROC = re.compile(r"^(subprocess\.)?(run|Popen|check_output|check_call|call)$|^os\.system$")


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _sink_arg(call):
    name = w.call_name(call)
    if PY_SINKS.search(name):
        for k in call.keywords:
            if k.arg == "url":
                return k.value
        if name.endswith(".request") and len(call.args) > 1:
            return call.args[1]
        return call.args[0] if call.args else None
    if SUBPROC.search(name) and call.args:
        a = call.args[0]
        s = ast.dump(a)
        if "'clone'" in s or "git clone" in s or "'fetch'" in s:
            return a
    return None


def _fetch_helpers(ctx):
    """name -> index of the parameter that reaches a fetch/clone sink, for every Python function in the repo."""
    out = {}
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        for fn in ast.walk(tree) if tree else []:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or w.route_info(fn):
                continue
            params = [a.arg for a in fn.args.args]
            for c in ast.walk(fn):
                if isinstance(c, ast.Call):
                    a = _sink_arg(c)
                    if a is not None:
                        hit = [i for i, prm in enumerate(params) if prm in _names(a)]
                        if hit and not _validated(fn, {params[hit[0]]}):
                            out[fn.name] = hit[0]
    return out


def _validated(fn, tainted) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare) and not all(isinstance(o, (ast.Is, ast.IsNot)) for o in n.ops):
            if _names(n) & tainted and not any(isinstance(c, ast.Constant) and c.value in (None, "", 0) for c in n.comparators):
                return True
        if isinstance(n, ast.Call):
            nm = w.call_name(n)
            if (nm.endswith(("startswith", "fullmatch", "match")) or "urlparse" in nm or "urlsplit" in nm or "allow" in nm.lower()) \
                    and _names(n) & tainted:
                return True
    return False


def _py(ctx):
    helpers = None
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        if not tree:
            continue
        text = w.read(p)
        for fn, _m, path in w.iter_routes(tree):
            if helpers is None:
                helpers = _fetch_helpers(ctx)
            tainted = {a.arg for a in fn.args.args + fn.args.kwonlyargs
                       if not (a.annotation is not None and "Request" == w.src(a.annotation, text))}
            tainted |= {"request"}
            for _ in range(2):
                for n in ast.walk(fn):
                    if isinstance(n, ast.Assign) and _names(n.value) & tainted:
                        for t in n.targets:
                            tainted |= _names(t)
            tainted_vals = tainted - {"request"}
            for c in ast.walk(fn):
                if not isinstance(c, ast.Call):
                    continue
                a = _sink_arg(c)
                short = w.call_name(c).split(".")[-1]
                if a is None and short in helpers and len(c.args) > helpers[short]:
                    a = c.args[helpers[short]]
                if a is None or not (_names(a) & tainted):
                    continue
                if _validated(fn, (_names(a) & tainted_vals) or tainted_vals):
                    continue
                yield p, c.lineno, text, f"{path} passes request data into {w.call_name(c)}()"


JS_SOURCE = re.compile(r"searchParams\.get\(|\breq\.(query|params|body)\b|\brequest\.(json|formData)\(\)|\breq\.json\(\)|\bparams\.\w+|"
                       r"\bcontext\.params\b")
JS_SINK = re.compile(r"\b(fetch|axios(\.(get|post|put|delete|request))?|got|ky|https?\.get|execSync|exec|spawn|simpleGit\(\)\.clone|git\.clone)\s*\(")


def _js(ctx):
    for p in w.files(ctx, w.JS):
        raw = w.read(p)
        if not JS_SOURCE.search(raw) or not JS_SINK.search(raw):
            continue
        s = w.strip_js_comments(raw)
        tainted = set()
        decl = re.compile(r"\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
        for _ in range(3):
            for m in decl.finditer(s):
                rhs = m.group(2)
                if JS_SOURCE.search(rhs) or any(re.search(rf"(?<![\w$.]){re.escape(t)}\b", rhs) for t in tainted):
                    tainted |= set(re.findall(r"[A-Za-z_$][\w$]*", m.group(1)) if m.group(1).startswith("{") else [m.group(1)])
        validated = {t for t in tainted if re.search(rf"\.test\(\s*{re.escape(t)}\b|\b{re.escape(t)}\s*\.\s*(match|startsWith)\(|"
                                                       rf"includes\(\s*{re.escape(t)}\b|new URL\(\s*{re.escape(t)}\b", s)}
        live = tainted - validated
        for m in JS_SINK.finditer(s):
            close = w.match_close(s, m.end() - 1)
            arg = s[m.end():close]
            first = arg.split(",")[0] if not arg.lstrip().startswith("`") else arg[:arg.find("`", arg.find("`") + 1) + 1]
            exprs = [e for _a, _b, _st, ex in w.template_literals(first) for e, _o in ex] or [first]
            hit = [t for e in exprs if "encodeURIComponent" not in e for t in live if re.search(rf"(?<![\w$.]){re.escape(t)}\b", e)]
            if not hit and JS_SOURCE.search(first):
                hit = ["request data"]
            if hit:
                ln = w.line_of(s, m.start())
                yield p, ln, raw, f"`{hit[0]}` from the request reaches {m.group(1)}() unvalidated"


def check(ctx: Context) -> list[Finding]:
    out, seen = [], set()
    for p, ln, text, msg in [*_py(ctx), *_js(ctx)]:
        if (p, ln) in seen:
            continue
        seen.add((p, ln))
        out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), ln, msg + " (SSRF / file:// / path injection).", FIX,
                           w.line_text(text, ln)))
    return out
