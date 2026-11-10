"""TW-OUT1: HTML built from data without escaping (f-strings, .format, %, concatenation, innerHTML templates,
Markup(), dangerouslySetInnerHTML, v-html, Jinja without autoescape)."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-OUT1",
    "title": "Data written into HTML without escaping",
    "severity": "medium",
    "class": "client-side",
    "why": "A PR title, file name, model answer or uploaded document that contains <script> runs in the reader's browser and can steal tokens kept there.",
    "seen_in": ["Audit-criteria", "Track-1---Planning-en-Orientatie", "Track-2---IAM-final", "SAAF-Project", "Finding-analysis"],
}
FIX = "Escape every data value at the point it enters HTML (html.escape / an esc() helper / textContent), or render through Jinja with autoescape on."
TAG = re.compile(r"<(td|tr|th|div|span|p|li|ul|ol|a|h[1-6]|table|tbody|thead|b|strong|em|i|pre|code|img|section|article|small|label|"
                 r"button|option|select|input|form|title|body|html|details|summary|blockquote|footer|header|nav|main|dd|dt|caption|mark|u|"
                 r"figure|figcaption|font|iframe|textarea|br|hr|meta|link|script)\b", re.I)
# Real escaping calls only (a property called "description" is not an escape).
PY_ESC = re.compile(r"(^|\.)(_?esc|_?escape|escape_html|html_escape|_?h|quote|quoteattr|sanitize\w*|sanitise\w*|clean|urlencode|quote_plus|"
                    r"escape_silent|xhtml_escape|conditional_escape|strip_tags|tojson|dumps)$", re.I)
JS_ESC = re.compile(r"\b(esc|escape|escapeHtml|escapeHTML|escHtml|escapeAttr|htmlEscape|encodeHTML|encodeURIComponent|encodeURI|"
                    r"sanitize\w*|sanitise\w*|DOMPurify\.sanitize|purify\.sanitize|he\.encode|_\.escape|xss|filterXSS)\s*\(")
NUMERIC = re.compile(r"(^|_)(count|counts|num|n|i|j|k|total|pct|percent|score|scores|idx|index|len|length|size|width|height|"
                     r"id|year|rank|rate|ratio|amount|price|qty|quantity|cost|sum|avg|mean|min|max|toFixed|toLocaleString|getTime|"
                     r"toISOString|ms|seconds|minutes|hours|days|at|date|time|timestamp|ts)$|"
                     r"(Count|Total|Num|Score|Pct|Percent|Id|Index|Size|Len|Length|Amount|At|Date|Time)$")
STR_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "replace", "splitlines", "casefold", "format"}
HTMLISH_PARAM = re.compile(r"html|svg|markup|^self$|^cls$|^request$|^req$|template|tpl|css|style|_cls$|class_?name", re.I)
LOG_CALL = re.compile(r"(^|\.)(debug|info|warning|warn|error|critical|exception|print|log|echo|secho|write)$")


# ---------------- Python ----------------
def _last_ident(node):
    while isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        sl = node.slice
        return sl.value if isinstance(sl, ast.Constant) and isinstance(sl.value, str) else _last_ident(node.value)
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _raw(node, names, depth=0) -> bool:
    """True when the expression is plain data (dict/attr/subscript/param/loop var) that has not been escaped."""
    if depth > 5:
        return False
    if isinstance(node, ast.Call):
        fn = w.call_name(node)
        if PY_ESC.search(fn):
            return False
        if isinstance(node.func, ast.Attribute) and node.func.attr in STR_METHODS:
            return _raw(node.func.value, names, depth + 1)
        if fn.endswith(".get") and node.args:
            key = node.args[0].value if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) else ""
            return not NUMERIC.search(key) and _base_ok(node.func.value)
        if fn in ("str", "getattr") and node.args:
            return _raw(node.args[0], names, depth + 1)
        return False
    if isinstance(node, ast.BoolOp):
        return any(_raw(v, names, depth + 1) for v in node.values)
    if isinstance(node, ast.IfExp):
        return _raw(node.body, names, depth + 1) or _raw(node.orelse, names, depth + 1)
    if isinstance(node, (ast.Subscript, ast.Attribute)):
        return _base_ok(node) and not NUMERIC.search(_last_ident(node))
    if isinstance(node, ast.Name):
        return names.get(node.id, False) and not NUMERIC.search(node.id)
    return False


def _base_ok(node) -> bool:
    base = node
    while isinstance(base, (ast.Subscript, ast.Attribute, ast.Call)):
        base = base.func if isinstance(base, ast.Call) else base.value
    # operator CLI args / constants / config are not attacker data
    return not (isinstance(base, ast.Name) and (base.id in ("args", "self", "cls", "os", "sys", "settings", "config", "math")
                                                 or base.id.isupper()))


def _scope_names(fn) -> dict:
    names = {}
    if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        for a in fn.args.args + fn.args.kwonlyargs:
            names[a.arg] = not HTMLISH_PARAM.search(a.arg)
    nodes = sorted((n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.For, ast.AnnAssign, ast.comprehension))),
                   key=lambda n: n.lineno if hasattr(n, "lineno") else n.target.lineno)
    for n in nodes:
        if isinstance(n, (ast.For, ast.comprehension)):
            for t in ast.walk(n.target):
                if isinstance(t, ast.Name):
                    names[t.id] = True
        elif n.value is not None:
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                if isinstance(t, ast.Name):
                    names[t.id] = _raw(n.value, names) and not HTMLISH_PARAM.search(t.id)
    return names


def _flatten_add(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _is_html_const(x):
    return isinstance(x, ast.Constant) and isinstance(x.value, str) and bool(TAG.search(x.value))


def _py_file(p):
    tree = w.parse_py(p)
    if not tree:
        return
    text = w.read(p)
    skip = set()  # f-strings that go to a log line / exception / PDF markup, not a browser
    for c in ast.walk(tree):
        if isinstance(c, ast.Call) and (LOG_CALL.search(w.call_name(c)) or w.call_name(c).split(".")[-1] in ("Paragraph", "Markdown")):
            skip |= {id(a) for a in c.args}
        if isinstance(c, ast.Raise) and isinstance(c.exc, ast.Call):
            skip |= {id(a) for a in c.exc.args}
    scopes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] or [tree]
    for fn in scopes:
        names = _scope_names(fn)
        for n in ast.walk(fn):
            if id(n) in skip:
                continue
            if isinstance(n, ast.JoinedStr):
                static = "".join(v.value for v in n.values if isinstance(v, ast.Constant))
                if TAG.search(static):
                    for v in n.values:
                        if isinstance(v, ast.FormattedValue) and (v.format_spec is None) and _raw(v.value, names):
                            yield v.value.lineno, w.src(v.value, text)
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                parts = _flatten_add(n)
                if any(_is_html_const(x) for x in parts):
                    for x in parts:
                        if _raw(x, names):
                            yield x.lineno, w.src(x, text)
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) and _is_html_const(n.left):
                vals = n.right.elts if isinstance(n.right, ast.Tuple) else [n.right]
                for x in vals:
                    if _raw(x, names):
                        yield x.lineno, w.src(x, text)
            elif isinstance(n, ast.Call):
                fname = w.call_name(n)
                if isinstance(n.func, ast.Attribute) and n.func.attr == "format" and _is_html_const(n.func.value):
                    for x in list(n.args) + [k.value for k in n.keywords]:
                        if _raw(x, names):
                            yield x.lineno, w.src(x, text)
                elif fname.split(".")[-1] == "Markup" and n.args and not isinstance(n.args[0], ast.Constant) and \
                        _raw(n.args[0], names):
                    yield n.lineno, "Markup(" + w.src(n.args[0], text) + ")"
    # Jinja2 rendering HTML without autoescape
    if "jinja2" in text and re.search(r"html", text, re.I):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                name = w.call_name(n)
                if name in ("Template", "jinja2.Template", "Environment", "jinja2.Environment"):
                    if name.endswith("Template") and not re.search(r"from jinja2 import[^\n]*\bTemplate\b|jinja2\.Template", text):
                        continue
                    ae = next((k.value for k in n.keywords if k.arg == "autoescape"), None)
                    if ae is None or w.src(ae, text) == "False":
                        yield n.lineno, "jinja2 " + name.split(".")[-1] + "(...) without autoescape"


# ---------------- JS / HTML / Vue / React ----------------
SINK = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|\.html\(|v-html|\{@html")
MEMBER = re.compile(r"^\s*[A-Za-z_$][\w$]*(\??\.[A-Za-z_$][\w$]*|\[[^\]]+\])*(\s*\.\s*[A-Za-z_$][\w$]*\([^()]*\))*\s*$")
NOT_HTML_TARGET = re.compile(r"(textContent|innerText|\.value|\.title|placeholder|console\.\w+\(|alert\(|\.log\()\s*[=(]?\s*$")


def _script_only(raw: str) -> str:
    keep = [" " if c != "\n" else "\n" for c in raw]
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", raw, re.S | re.I):
        a, b = m.span(1)
        keep[a:b] = raw[a:b]
    return "".join(keep)


def _js_raw(e: str, raw_names: set) -> bool:
    e = re.split(r"\?\?|\|\|", e)[0].strip()  # `row.name ?? ''` -> row.name
    if not e or JS_ESC.search(e) or not MEMBER.match(e):
        return False
    ids = re.findall(r"[A-Za-z_$][\w$]*", e)
    if ids[0] in ("Math", "JSON", "window", "document", "CSS", "Number", "Date", "String", "this", "props") and len(ids) == 1:
        return False
    if NUMERIC.search(ids[-1]) or ids[0] in ("Math", "JSON", "window", "document", "CSS", "Number", "Date"):
        return False
    if len(ids) == 1 and not e.endswith(")"):
        return ids[0] in raw_names
    return True


def _js_file(p):
    raw = w.read(p)
    if not SINK.search(raw):
        return
    is_markup = p.suffix.lower() in (".html", ".htm", ".vue", ".svelte")
    s = w.strip_js_comments(_script_only(raw) if p.suffix.lower() in (".html", ".htm") else raw)
    # names that hold plain data: destructured from an object, or copied from a member
    raw_names = set()
    for m in re.finditer(r"\b(?:const|let|var)\s+\{([^}]*)\}\s*=\s*[A-Za-z_$][\w$.]*\s*[;\n]", s):
        raw_names |= {x.split(":")[-1].strip() for x in m.group(1).split(",") if x.strip()}
    for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+)\s*[;\n]", s):
        if not NUMERIC.search(m.group(1)):
            raw_names.add(m.group(1))
    for _a, _b, static, exprs in w.template_literals(s):
        if not TAG.search(static):
            continue
        before = s[s.rfind("\n", 0, _a) + 1:_a]
        if NOT_HTML_TARGET.search(before):
            continue
        for expr, off in exprs:
            if _js_raw(expr, raw_names):
                yield w.line_of(s, off), expr.strip()
    # innerHTML = '<b>' + user.name + '</b>'
    for m in re.finditer(r"(innerHTML|outerHTML)\s*\+?=\s*([^;\n]+)|insertAdjacentHTML\(\s*[^,]+,\s*([^;\n]+)\)|document\.write\(([^;\n]+)\)", s):
        rhs = next(g for g in m.groups()[1:] if g)
        if "`" in rhs or "+" not in rhs:
            continue
        for part in rhs.split("+"):
            if _js_raw(part, raw_names):
                yield w.line_of(s, m.start()), part.strip()
    # React / Vue / Svelte raw-HTML sinks
    for m in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}|v-html\s*=\s*\"([^\"]+)\"|\{@html\s+([^}]+)\}",
                         raw if is_markup or p.suffix.lower() in (".jsx", ".tsx") else s):
        expr = next(g for g in m.groups() if g)
        if not JS_ESC.search(expr) and not re.fullmatch(r"\s*['\"][^'\"]*['\"]\s*", expr):
            src_text = raw
            yield w.line_of(src_text, m.start()), expr.strip()


def _jinja(p):
    raw = w.read(p)
    for m in re.finditer(r"\{\{[^}]*\|\s*safe\b[^}]*\}\}|\{%\s*autoescape\s+false\s*%\}", raw):
        if re.search(r"svg|logo|icon|_html|html_|json|chart|css", m.group(0), re.I):
            continue  # server-built markup / JSON blobs, by convention
        yield w.line_of(raw, m.start()), m.group(0)


def check(ctx: Context) -> list[Finding]:
    out = []
    for p in w.files(ctx, w.PY | w.JS | w.HTML | {".vue", ".svelte"}):
        suf = p.suffix.lower()
        hits = {}
        gens = []
        if suf == ".py":
            gens.append(_py_file(p))
        if suf in w.JS or suf in (".html", ".htm", ".vue", ".svelte"):
            gens.append(_js_file(p))
        if suf in w.HTML:
            gens.append(_jinja(p))
        for g in gens:
            for ln, expr in g or ():
                hits.setdefault(ln, expr)
        if not hits:
            continue
        lines = sorted(hits)  # one finding per file: first site + count, keeps CI output readable
        ln = lines[0]
        more = f" ({len(lines) - 1} more unescaped sites in this file, lines {', '.join(map(str, lines[1:8]))}{'...' if len(lines) > 8 else ''})" if len(lines) > 1 else ""
        out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), ln,
                           f"`{hits[ln][:60]}` is placed into HTML without escaping{more}.", FIX, w.line_text(w.read(p), ln)))
    return out
