"""Shared helpers for the web / network / output rules (TW-NET*, TW-OUT*, TW-FS*)."""
from __future__ import annotations
import ast, re
from functools import lru_cache
from pathlib import Path

PY = {".py"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
HTML = {".html", ".htm", ".jinja", ".jinja2", ".j2"}
CODE = PY | JS | HTML
SKIP_PARTS = {"tests", "test", "__tests__", "fixtures", "spec", "specs", "testdata", "e2e", "node_modules",
              ".venv", "venv", "site-packages", "dist", "build", ".next", "vendor", "__pycache__", ".git"}
_TESTNAME = re.compile(r"(^test_.*\.py$|_test\.py$|^conftest\.py$|\.(test|spec)\.[jt]sx?$)")


def rel(ctx, p: Path) -> str:
    try:
        return p.relative_to(ctx.root).as_posix()
    except ValueError:
        return p.as_posix()


def is_test_path(relpath: str) -> bool:
    parts = relpath.split("/")
    return any(x.lower() in SKIP_PARTS for x in parts[:-1]) or bool(_TESTNAME.search(parts[-1]))


def files(ctx, exts=None, names=None):
    pool = ctx.files or [p for p in ctx.root.rglob("*") if p.is_file()]
    out = []
    for p in pool:
        r = rel(ctx, p)
        if is_test_path(r):
            continue
        if (exts and p.suffix.lower() in exts) or (names and (p.name in names or any(p.name.startswith(n) for n in names))):
            try:
                if p.stat().st_size > 1_500_000:
                    continue
            except OSError:
                continue
            out.append(p)
    return out


@lru_cache(maxsize=4096)
def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@lru_cache(maxsize=4096)
def parse_py(p: Path):
    try:
        return ast.parse(read(p))
    except (SyntaxError, ValueError):
        return None


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def line_text(text: str, line: int, limit: int = 160) -> str:
    lines = text.splitlines()
    s = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    return s[:limit]


def src(node, text: str) -> str:
    return ast.get_source_segment(text, node) or ""


def call_name(node) -> str:
    """Dotted name of a call's function, e.g. 'uvicorn.run', 'app.run', 'urlopen'."""
    f = node.func if isinstance(node, ast.Call) else node
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr); f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    elif isinstance(f, ast.Call):
        parts.append(call_name(f) + "()")
    return ".".join(reversed(parts))


def module_consts(tree) -> dict:
    """Module-level NAME = 'literal' (also NAME = os.getenv('X', 'literal') -> literal default)."""
    out = {}
    for n in tree.body if tree else []:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            v = n.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out[n.targets[0].id] = v.value
            elif isinstance(v, ast.Call):
                strs = [a.value for a in v.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if strs:
                    out[n.targets[0].id] = strs[-1]
    return out


# ---------- Python web routes ----------
ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch", "api_route"}


def route_info(fn):
    """(methods, path) if fn is a Flask/FastAPI route handler, else None."""
    for d in getattr(fn, "decorator_list", []):
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_ATTRS:
            path = d.args[0].value if d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str) else None
            if path is None or not path.startswith("/"):
                continue
            if d.func.attr in ("route", "api_route"):
                methods = {"GET"}
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        methods = {e.value.upper() for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            else:
                methods = {d.func.attr.upper()}
            return methods, path
    return None


def iter_routes(tree):
    for n in ast.walk(tree) if tree else []:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info = route_info(n)
            if info:
                yield n, info[0], info[1]


AUTHISH = re.compile(r"auth|login|jwt|token|bearer|permission|require|protect|api_?key|current_user|verify|session|security|credential|guard", re.I)
_ROUTE_AUTH_TEXT = re.compile(
    r"""headers\.get\(\s*['"](authorization|x-api-key|x-auth|api-key)|headers\[\s*['"](authorization|x-api-key)|"""
    r"""abort\(\s*40[13]|status_code\s*=\s*40[13]|HTTP_40[13]|current_user|session\[\s*['"]user|"""
    r"""getServerSession|auth\(\)|getToken\(|currentUser\(|verifyToken|requireAuth|withAuth|isAuthenticated|status:\s*40[13]""", re.I)


def route_has_auth(fn, text: str) -> bool:
    for d in fn.decorator_list:
        is_route = isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_ATTRS
        if is_route:
            if any(k.arg == "dependencies" and AUTHISH.search(src(k.value, text)) for k in d.keywords):
                return True
        elif AUTHISH.search(src(d, text)):
            return True
    for dflt in fn.args.defaults + fn.args.kw_defaults:
        if dflt is not None and "Depends" in src(dflt, text) and AUTHISH.search(src(dflt, text)):
            return True
    return bool(_ROUTE_AUTH_TEXT.search(src(fn, text)))


# App / scope-wide authentication markers (any file in the app's directory tree).
SCOPE_AUTH = re.compile(
    r"HTTPBearer\(|OAuth2PasswordBearer|APIKeyHeader|APIKeyQuery|HTTPBasic\(|login_required|LoginManager|flask_login|"
    r"jwt_required|JWTManager|HTTPBasicAuth|HTTPTokenAuth|auth_required|requires_auth|token_required|"
    r"streamlit_authenticator|st\.login\(|next-auth|getServerSession|passport\.|express-jwt|basicAuth|@clerk|"
    r"supabase\.auth\.getUser|headers\.get\(\s*['\"](authorization|x-api-key)['\"]|req\.headers\[?\.?['\"]?authorization|"
    r"Depends\(\s*(get_current_user|verify\w*|require\w*|check_\w*auth\w*|\w*api_key\w*|\w*token\w*)", re.I)


def scope_has_auth(ctx, scope: Path) -> bool:
    for p in files(ctx, CODE):
        try:
            p.relative_to(scope)
        except ValueError:
            continue
        if SCOPE_AUTH.search(read(p)):
            return True
    return False


# ---------- JS helpers ----------
def strip_js_comments(s: str) -> str:
    """Blank out // and /* */ comments (keeps offsets and newlines); strings and template literals are respected."""
    out = list(s); i = 0; n = len(s)
    while i < n:
        c = s[i]
        if c in "'\"`":
            j = i + 1
            while j < n and s[j] != c:
                if s[j] == "\\":
                    j += 1
                elif c != "`" and s[j] == "\n":
                    break
                j += 1
            i = j + 1; continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = s.find("\n", i); j = n if j < 0 else j
            for k in range(i, j): out[k] = " "
            i = j; continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            j = s.find("*/", i + 2); j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n": out[k] = " "
            i = j; continue
        i += 1
    return "".join(out)


def match_close(s: str, i: int) -> int:
    """s[i] is an opening bracket; return index of its matching close (or len(s))."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = [pairs[s[i]]]; j = i + 1; n = len(s)
    while j < n and stack:
        c = s[j]
        if c in "'\"":
            k = j + 1
            while k < n and s[k] != c and s[k] != "\n":
                k += 2 if s[k] == "\\" else 1
            j = k + 1; continue
        if c == "`":
            j = _skip_template(s, j); continue
        if c in pairs:
            stack.append(pairs[c])
        elif stack and c == stack[-1]:
            stack.pop()
            if not stack:
                return j
        j += 1
    return n


def _skip_template(s: str, i: int) -> int:
    j = i + 1; n = len(s)
    while j < n:
        if s[j] == "\\":
            j += 2; continue
        if s[j] == "`":
            return j + 1
        if s[j] == "$" and j + 1 < n and s[j + 1] == "{":
            j = match_close(s, j + 1) + 1; continue
        j += 1
    return n


def template_literals(s: str):
    """Yield (start, end, static_text, [(expr, abs_offset), ...]) for every template literal, nested ones included."""
    i = 0; n = len(s)
    while i < n:
        c = s[i]
        if c in "'\"":
            k = i + 1
            while k < n and s[k] != c and s[k] != "\n":
                k += 2 if s[k] == "\\" else 1
            i = k + 1; continue
        if c == "`":
            end = _skip_template(s, i)
            static, exprs, j = [], [], i + 1
            while j < end - 1:
                if s[j] == "\\":
                    static.append(s[j:j + 2]); j += 2; continue
                if s[j] == "$" and s[j + 1:j + 2] == "{":
                    close = match_close(s, j + 1)
                    exprs.append((s[j + 2:close], j + 2))
                    j = close + 1; continue
                static.append(s[j]); j += 1
            yield i, end, "".join(static), exprs
            for e, off in exprs:
                for (a, b, st, ex) in template_literals(e):
                    yield a + off, b + off, st, [(x, o + off) for x, o in ex]
            i = end; continue
        i += 1


# ---------- real authentication constructs (no keyword matching on comments) ----------
_GATE_BODY = re.compile(r"authorization|api[_-]?key|x-api-key|token|session|auth|password|credential", re.I)
_GATE_DENY = re.compile(r"40[13]|abort\(|Unauthorized|Forbidden|HTTPException")
AUTHISH_DEP = re.compile(r"auth|login|jwt|token|bearer|api_?key|current_user|verify|require|security|credential|guard|session", re.I)


def py_app_auth(tree, text) -> bool:
    """App-wide auth: Flask before_request gate, FastAPI(dependencies=[auth]), auth middleware, Streamlit authenticator."""
    if not tree:
        return False
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in n.names] + ([n.module] if isinstance(n, ast.ImportFrom) and n.module else [])
            if any(m and m.split(".")[0] in ("streamlit_authenticator", "flask_httpauth") for m in mods):
                return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decos = " ".join(src(d, text) for d in n.decorator_list).replace("'", '"')
            if "before_request" in decos or 'middleware("http")' in decos or "before_app_request" in decos:
                body = src(n, text)
                if _GATE_BODY.search(body) and _GATE_DENY.search(body):
                    return True
        if isinstance(n, ast.Call):
            nm = call_name(n)
            if nm.split(".")[-1] in ("FastAPI", "APIRouter", "include_router", "Starlette"):
                for k in n.keywords:
                    if k.arg == "dependencies" and AUTHISH_DEP.search(src(k.value, text)):
                        return True
                    if k.arg == "middleware" and re.search(r"Auth|Session|Key", src(k.value, text)):
                        return True
            if nm.endswith("add_middleware") and n.args and re.search(r"Auth|Key|Token|Session|Basic", src(n.args[0], text)) \
                    and "CORS" not in src(n.args[0], text):
                return True
            if nm in ("st.login", "st.experimental_user"):
                return True
    return False


_JS_STRONG = re.compile(r"passport\.authenticate|expressjwt\(|\bjwt\(\s*\{|basicAuth\(|clerkMiddleware|requiresAuth\(|"
                        r"getServerSession|auth\(\)\s*\.protect|express-openid-connect")


def js_app_auth(s: str) -> bool:
    """s = comment-stripped JS. True if an auth middleware is mounted with .use() (or a known auth lib is wired)."""
    if _JS_STRONG.search(s):
        return True
    for m in re.finditer(r"\.use\(\s*(?:['\"][^'\"]*['\"]\s*,\s*)?([A-Za-z_$][\w$]*)\s*[,)]", s):
        name = m.group(1)
        d = re.search(rf"function\s+{re.escape(name)}\s*\(|(?:const|let|var)\s+{re.escape(name)}\s*=", s)
        if not d:
            continue
        b = s.find("{", d.end())
        body = s[b:match_close(s, b) + 1] if b >= 0 else ""
        if _GATE_BODY.search(body) and re.search(r"40[13]|unauthori[sz]ed|forbidden", body, re.I):
            return True
    return False


def py_unauth_routes(ctx, scope: Path):
    """(has_app_auth, routes, unauthenticated_routes) for Python apps under scope."""
    app_auth, routes, bare = False, 0, []
    for p in files(ctx, PY):
        try:
            p.relative_to(scope)
        except ValueError:
            continue
        tree = parse_py(p)
        if not tree:
            continue
        text = read(p)
        app_auth = app_auth or py_app_auth(tree, text)
        for fn, methods, path in iter_routes(tree):
            routes += 1
            if not route_has_auth(fn, text):
                bare.append((p, fn, methods, path))
    return app_auth, routes, bare
