"""TW-NET1: a server listens on every network interface and (some of) its routes have no authentication."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-NET1",
    "title": "Server listens on all interfaces with no authentication",
    "severity": "medium",
    "class": "web-protocol-and-auth",
    "why": "Anyone on the same network (cafe Wi-Fi, office LAN, cloud VPC) can call every route, spend the API key and read or change data.",
    "seen_in": ["OWASP-top-10-LLM-assessment", "SAAF-Project", "PBC-Assistant-Isabelle---IA-AI-Hackathon",
                "Track-4-Audit-Report-Generator"],
}
FIX = "Bind to 127.0.0.1 by default (make 0.0.0.0 an explicit opt-in) or put an auth dependency/middleware on every route."
ALL = {"0.0.0.0", "::", "[::]", "*"}
RUN_CALLS = re.compile(r"(^|\.)(run|run_app|serve|run_simple|Config|run_server|launch)$")
# --host 0.0.0.0 / --host=0.0.0.0 / "--host", "0.0.0.0" (Dockerfile exec form) / --bind 0.0.0.0:8000 / address = "0.0.0.0"
CLI_BIND = re.compile(r"""(--host|--bind|--hostname|--server\.address|--server-address|--listen|(?<![\w-])-[bH])"""
                      r"""(?:\s*["']?\s*[,= ]\s*["']?\s*)(0\.0\.0\.0|::|\*)(?![\d.])|^\s*address\s*=\s*["'](0\.0\.0\.0|::)["']""", re.M)
BARE_HOST = re.compile(r"""\b(vite|next\s+dev|next\s+start|astro\s+dev|nuxt\s+dev)\b[^"\n]*\s--host(?=["\s]|$)(?!\s+(127\.|localhost))""")
CLI_FILES = {"Dockerfile", "Procfile", "Makefile", "package.json", "docker-compose", "compose", "config.toml", "start", "run", "entrypoint"}
CLI_EXT = {".sh", ".toml", ".yml", ".yaml", ".json", ".cfg", ".ini", ".dockerfile"}
JS_SERVER = re.compile(r"\bexpress\(\)|http\.createServer|https\.createServer|\bfastify\(|new Koa\(|new Hono\(")


def _file_strs(tree) -> dict:
    """Every NAME = 'literal' / NAME: T = 'literal' in the file (module, function and class level), by target name or attr."""
    out = {}
    for n in ast.walk(tree):
        tgts, val = [], None
        if isinstance(n, ast.Assign):
            tgts, val = n.targets, n.value
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            tgts, val = [n.target], n.value
        for t in tgts:
            key = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            if key:
                r = _lit(val)
                if r is not None:
                    out[key] = r
    return out


def _lit(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call):  # os.getenv("HOST", "0.0.0.0"), Field(default="0.0.0.0")
        strs = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        strs += [k.value.value for k in node.keywords if k.arg == "default" and isinstance(k.value, ast.Constant)]
        return strs[-1] if (len(strs) >= 2 or any(k.arg == "default" for k in node.keywords)) and strs else None
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            r = _lit(v)
            if r is not None:
                return r
    return None


def _resolve(node, strs):
    r = _lit(node)
    if r is not None:
        return r
    if isinstance(node, ast.Name):
        return strs.get(node.id)
    if isinstance(node, ast.Attribute):  # settings.host -> class attribute `host: str = "0.0.0.0"`
        return strs.get(node.attr)
    return None


def _is_all(v):
    return v is not None and (v in ALL or v.split(":")[0] in ("0.0.0.0", "*") or v.startswith("[::]"))


def _py_binds(ctx):
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        if not tree:
            continue
        text, strs = w.read(p), _file_strs(tree)
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                name = w.call_name(n)
                if not RUN_CALLS.search(name) or name in ("asyncio.run", "subprocess.run", "trio.run", "anyio.run"):
                    continue
                host = next((k.value for k in n.keywords if k.arg in ("host", "server_name", "bind")), None)
                if host is None and n.args and name.endswith(".run") and not name.startswith("uvicorn"):
                    host = n.args[0]  # Flask app.run('0.0.0.0', 5000)
                if host is not None and _is_all(_resolve(host, strs)):
                    yield p, n.lineno, w.line_text(text, n.lineno)
        if re.match(r"gunicorn.*\.py$", p.name) and _is_all(strs.get("bind")):
            ln = next((i + 1 for i, l in enumerate(text.splitlines()) if l.strip().startswith("bind")), 1)
            yield p, ln, w.line_text(text, ln)


def _cli_binds(ctx):
    for p in w.files(ctx, CLI_EXT, names=CLI_FILES):
        text = w.read(p)
        for pat in (CLI_BIND, BARE_HOST):
            for m in pat.finditer(text):
                ln = w.line_of(text, m.start())
                yield p, ln, w.line_text(text, ln)


def _js_binds(ctx):
    for p in w.files(ctx, w.JS):
        raw = w.read(p)
        if not JS_SERVER.search(raw):
            continue
        s = w.strip_js_comments(raw)
        consts = {m.group(1): m.group(3) for m in
                  re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:process\.env\.\w+\s*(?:\|\||\?\?)\s*)?(['\"])([^'\"]*)\2", s)}
        for m in re.finditer(r"(?:\b[A-Za-z_$][\w$]*|\))\s*\.listen\s*\(", s):
            close = w.match_close(s, m.end() - 1)
            args = [a.strip() for a in s[m.end():close].split(",")]
            hosts = []
            for a in args[1:]:
                lit = re.fullmatch(r"(['\"])(.*)\1", a)
                if lit:
                    hosts.append(lit.group(2))
                elif re.fullmatch(r"[A-Za-z_$][\w$]*", a) and a in consts:
                    hosts.append(consts[a])
                elif re.match(r"\{", a) or re.fullmatch(r"[A-Za-z_$][\w$.]*", a) and re.search(r"host", a, re.I):
                    hosts.append("?")
            hm = re.search(r"host\s*:\s*(['\"])([^'\"]*)\1", s[m.end():close])
            if hm:
                hosts.append(hm.group(2))
            if any(_is_all(h) for h in hosts) or not hosts:
                ln = w.line_of(s, m.start())
                yield p, ln, w.line_text(raw, ln)


def _compose_localhost_only(ctx) -> bool:
    ports = []
    for p in w.files(ctx, {".yml", ".yaml"}):
        if "compose" in p.name:
            ports += re.findall(r"^\s*-\s*['\"]?([\d.]+:)?(\d+):\d+", w.read(p), re.M)
    return bool(ports) and all(h.startswith("127.") for h, _ in ports)


def check(ctx: Context) -> list[Finding]:
    out, seen = [], set()
    local_publish = _compose_localhost_only(ctx)
    for p, ln, ev in [*_py_binds(ctx), *_cli_binds(ctx), *_js_binds(ctx)]:
        if (p, ln) in seen:
            continue
        seen.add((p, ln))
        if local_publish and (p.name.startswith("Dockerfile") or "compose" in p.name):
            continue  # container listens on 0.0.0.0 but the host only publishes it on 127.0.0.1
        scope = ctx.root if p.parent == ctx.root else p.parent
        app_auth, nroutes, bare = w.py_unauth_routes(ctx, scope)
        js_auth = any(w.js_app_auth(w.strip_js_comments(w.read(f))) for f in w.files(ctx, w.JS)
                      if _under(f, scope))
        if app_auth or js_auth or (nroutes and not bare):
            continue
        detail = f" Unauthenticated route: {'/'.join(sorted(bare[0][2]))} {bare[0][3]}." if bare else ""
        out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), ln,
                           "Server binds every network interface and no authentication guards its routes." + detail, FIX, ev))
    return out


def _under(f, scope):
    try:
        f.relative_to(scope)
        return True
    except ValueError:
        return False
