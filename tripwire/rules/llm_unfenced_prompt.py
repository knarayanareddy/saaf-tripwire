"""TW-LLM1: untrusted document/file/ticket text interpolated into an LLM prompt without a fence."""
from __future__ import annotations

import ast
import re

from ..model import Context, Finding
from ..util.llmscan import (call_name, functions, last, line_text, own_statements, py_files,
                            repo_uses_llm, str_consts)

RULE = {
    "id": "TW-LLM1",
    "title": "Untrusted content reaches an LLM prompt without a fence",
    "severity": "high",
    "class": "ai-and-llm",
    "why": "Auditee documents, files, tickets or scanned code can close a static delimiter (```, <document>, "
           "</untrusted_input x>) or forge an auditor block and steer the verdict (prompt injection).",
    "seen_in": ["llm_owasp", "CUEC_Crosscheck", "Track-2-Evidence-Collection-Extraction",
                "OWASP-AI-Testing-Agent", "joiners-movers-leavers-agent", "Vendor_Guard"],
}
FIX = ("Wrap the content with tripwire.fence.fence(text, source) (random-nonce tag, boundary attacks neutralised) "
       "and add tripwire.fence.SYSTEM_RULE to the system prompt.")

# identifier tokens that name content the auditee / a third party controls
UNTRUSTED_TOK = re.compile(
    r"^(documents?|docs?|pdfs?|tickets?|material|vendor|policy|policies|evidence|uploads?|uploaded|contents?|"
    r"texts?|pages?|description|payload|transcripts?|attachments?|emails?|html|markdown|source|code|files?|"
    r"context|findings?|response|responses|extracted|scanned|repo|readme|chunks?|passages?|excerpts?|summary|issue|"
    r"issues|comments?|fields|tweet|post|article|reviews?|feedback|submission|answer)$")
CLEAN_TOK = re.compile(r"^(prompt|system|template|instructions?|model|label|lang|language|name|path|dir|id|ids|"
                       r"count|len|size|type|max|min|url|key|token|tokens|hash|sha|format|fmt|mode|kind|"
                       r"question|title|date|status|exit|return|error|http|zip|country|postal|area|num|number|line|lineno)$")
# Only a real boundary counts: tripwire.fence / a nonce-tag wrapper. html.escape, sanitise() etc. stop markup, not instructions.
FENCE_FN = re.compile(r"fence|untrusted|delimit|neutrali[sz]|defang|wrap_data", re.I)
NONCE_FN = re.compile(r"(^|\.)(token_hex|token_urlsafe|token_bytes|uuid4|uuid1|randbits|urandom)$")
HTTP_POST = re.compile(r"(^|\.)(post|request|fetch|urlopen|Request)$")
LLM_URL = re.compile(r"api\.anthropic\.com|api\.openai\.com|/v1/messages|/chat/completions|generativelanguage\.googleapis|"
                     r"openai\.azure\.com|/v1/responses|bedrock-runtime")
SOURCE_FN = {"read_text", "read", "readlines", "extract_text", "get_text", "read_bytes", "decode"}
LLM_TAIL = re.compile(r"(^|\.)(messages\.(create|stream)|chat\.completions\.create|completions\.create|"
                      r"responses\.create|generate_content|send_message|beta\.messages\.create)$")
LLM_FN = re.compile(r"^(complete|complete_json|completion|acompletion|chat|ask_llm|call_llm|call_claude|call_model|"
                    r"call_with_cached_system|query_llm|llm_call|run_llm|invoke_llm|ask_claude|llm_complete|"
                    r"query)$|claude|_llm|llm_|gpt", re.I)
LLM_RECV = re.compile(r"llm|claude|chain|anthropic|openai|gpt|chat_model|agent", re.I)
LLM_METHODS = {"invoke", "ainvoke", "predict", "complete", "complete_json", "run", "generate", "chat", "stream", "query"}
PROMPT_KW = {"messages", "system", "prompt", "input", "user", "user_message", "user_prompt", "content", "contents",
             "text", "query", "question", "system_prompt", "instructions"}
NONPROMPT_KW = {"model", "max_tokens", "temperature", "timeout", "tools", "stop", "top_p", "metadata", "stream",
                "cwd", "capture_output", "check", "env", "response_format", "output_format", "betas", "thinking"}
PROMPT_BUILDER = re.compile(r"prompt|^_?(build|make|render|format|compose|create|construct)_\w*(user|message|messages|input|request)|_user$", re.I)
STATIC_DELIM = re.compile(r"(```[\w+.-]*|~~~[\w+.-]*|<\s*/?\s*[A-Za-z_][\w\-]*\s*>)\s*$")
STATIC_DELIM_AFTER = re.compile(r"^\s*(```|~~~|<\s*/\s*[A-Za-z_][\w\-]*\s*>)")


def tokens(name: str) -> list[str]:
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    return [t for t in re.split(r"[_\W]+", name.lower()) if t]


def vocab_untrusted(name: str) -> bool:
    if not name or name.isupper():
        return False
    toks = tokens(name)
    for sep in ("by", "for", "per"):  # pdf_text_by_id: the head noun is before 'by'
        if sep in toks[1:]:
            toks = toks[:toks.index(sep)]
            break
    if any(CLEAN_TOK.match(t) for t in toks):
        return False
    return any(UNTRUSTED_TOK.match(t) for t in toks)


def is_llm_call(call: ast.Call, fn_is_claude_cli: bool, wrappers: frozenset = frozenset()) -> bool:
    name = call_name(call)
    tail = last(name)
    if LLM_TAIL.search(name) or (tail in wrappers and isinstance(call.func, ast.Name)):
        return True
    if HTTP_POST.search(name) and call.args and any(isinstance(c, ast.Constant) and isinstance(c.value, str)
                                                    and LLM_URL.search(c.value) for c in ast.walk(call.args[0])):
        return True
    if fn_is_claude_cli and name in {"subprocess.run", "subprocess.Popen", "run", "Popen", "subprocess.check_output"}:
        return any(k.arg == "input" for k in call.keywords)
    if isinstance(call.func, ast.Name) and LLM_FN.search(tail):
        return True
    if isinstance(call.func, ast.Attribute):
        recv = call_name(call.func.value)
        if tail in LLM_METHODS and LLM_RECV.search(recv):
            return True
        if LLM_FN.search(tail) and tail not in {"query", "chat", "complete"}:
            return True
    return False


class FnScan:
    """Flow-ordered taint over one function. state: name -> None (tainted, no interp) | int (interp line) | False (clean)."""

    def __init__(self, fn, cli, wrappers=frozenset()):
        self.fn, self.cli, self.wrappers = fn, cli, wrappers
        self.state: dict[str, object] = {}
        self.nonces: set[str] = set()
        self.hits: list[tuple[int, str]] = []
        for a in getattr(getattr(fn, "args", None), "args", []) + getattr(getattr(fn, "args", None), "kwonlyargs", []):
            if a.arg in ("self", "cls"):
                continue
            ann = ast.unparse(a.annotation) if a.annotation is not None else ""
            numeric = ann in {"int", "float", "bool"}
            self.state[a.arg] = "P" if vocab_untrusted(a.arg) and not numeric else False

    def nonce_fenced(self, e) -> bool:
        return isinstance(e, ast.JoinedStr) and any(
            isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and v.value.id in self.nonces for v in e.values)

    def llm(self, call):
        return is_llm_call(call, self.cli, self.wrappers)

    # --- expression taint -------------------------------------------------
    def tainted(self, e) -> bool:
        if e is None or isinstance(e, ast.Constant):
            return False
        if isinstance(e, ast.Name):
            v = self.state.get(e.id, "unset")
            if v == "unset":
                return vocab_untrusted(e.id)
            return v is not False
        if isinstance(e, ast.Attribute):
            if isinstance(e.value, ast.Name) and e.value.id in ("self", "cls"):
                return vocab_untrusted(e.attr)
            return vocab_untrusted(e.attr) or self.tainted(e.value)
        if isinstance(e, ast.Subscript):
            key = e.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and vocab_untrusted(key.value):
                return True
            return self.tainted(e.value)
        if self.nonce_fenced(e):
            return False
        if isinstance(e, ast.Call):
            name = call_name(e)
            if FENCE_FN.search(last(name)) or FENCE_FN.search(name.split(".")[0]):
                return False
            if last(name) in SOURCE_FN:
                # the repo's own files (relative to __file__ or a literal path) are trusted
                recv = e.func.value if isinstance(e.func, ast.Attribute) else None
                if recv is not None and any((isinstance(n, ast.Name) and n.id == "__file__") for n in ast.walk(recv)):
                    return False
                return True
            if last(name) in {"len", "bool", "int", "float", "isinstance", "hash", "sha256", "hexdigest", "count", "exists"}:
                return False
            parts = list(e.args) + [k.value for k in e.keywords]
            if isinstance(e.func, ast.Attribute):
                parts.append(e.func.value)
            return any(self.tainted(p) for p in parts)
        if isinstance(e, (ast.Lambda, ast.Compare)):
            return False
        return any(self.tainted(c) for c in ast.iter_child_nodes(e) if isinstance(c, ast.expr))

    def interp_line(self, e) -> int | None:
        """Line where tainted data is spliced into a string inside e (f-string, +, %, .format, .replace, .join)."""
        for n in ast.walk(e):
            if isinstance(n, ast.JoinedStr):
                if self.nonce_fenced(n):
                    return None
                if any(isinstance(v, ast.FormattedValue) and self.tainted(v.value) for v in n.values):
                    return n.lineno
            elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
                sides = (n.left, n.right)
                if any(isinstance(s, ast.JoinedStr) or (isinstance(s, ast.Constant) and isinstance(s.value, str)) for s in sides) \
                        and any(self.tainted(s) for s in sides):
                    return n.lineno
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                m = n.func.attr
                if m == "format" and any(self.tainted(a) for a in list(n.args) + [k.value for k in n.keywords]):
                    return n.lineno
                if m == "replace" and len(n.args) >= 2 and self.tainted(n.args[1]):
                    return n.lineno
                if m == "join" and n.args and self.tainted(n.args[0]) and isinstance(n.func.value, ast.Constant):
                    return n.lineno
            elif isinstance(n, ast.Name) and type(self.state.get(n.id)) is int:
                return self.state[n.id]
        return None

    def direct(self, e) -> bool:
        """A vocab-untrusted name/attr placed straight into a prompt slot (no fence)."""
        for n in ast.walk(e):
            if isinstance(n, ast.Call) and FENCE_FN.search(last(call_name(n))):
                return False
        if isinstance(e, (ast.Name, ast.Attribute, ast.Subscript)):
            return self.tainted(e) and (not isinstance(e, ast.Name) or self.state.get(e.id, "unset") in ("unset", "P", "S"))
        if isinstance(e, ast.Dict):
            return any(self.direct(v) for v in e.values)
        if isinstance(e, (ast.List, ast.Tuple)):
            return any(self.direct(x) for x in e.elts)
        return False

    # --- statements -------------------------------------------------------
    def assign(self, target, value_tainted, iline, from_call=False):
        if isinstance(target, ast.Name):
            if not value_tainted and from_call and vocab_untrusted(target.id):
                value_tainted = True  # e.g. material = collect(target): trust the name
            self.state[target.id] = (iline if iline else None) if value_tainted else False
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self.assign(t, value_tainted, iline)

    def sink(self, call: ast.Call):
        slots = [a for a in call.args] + [k.value for k in call.keywords
                                          if k.arg is None or k.arg in PROMPT_KW or (k.arg not in NONPROMPT_KW and k.arg not in {"model", "headers"})]
        if LLM_TAIL.search(call_name(call)):
            slots = [k.value for k in call.keywords if k.arg is None or k.arg in PROMPT_KW] + list(call.args)
        for s in slots:
            if isinstance(s, ast.Name) and re.search(r"model|max_tokens|temperature|client", s.id, re.I):
                continue
            if not self.tainted(s):
                continue
            il = self.interp_line(s)
            if il:
                self.hits.append((il, "untrusted text is spliced into the prompt sent by "
                                      f"{call_name(call) or 'an LLM call'}() at line {call.lineno} without a fence"))
                return
            if self.direct(s):
                self.hits.append((call.lineno, f"untrusted text is passed straight into {call_name(call)}() with no fence"))
                return

    def run(self):
        stmts = own_statements(self.fn)
        is_builder = isinstance(self.fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and PROMPT_BUILDER.search(self.fn.name)
        for st in stmts:
            heads = []
            if isinstance(st, ast.Assign):
                heads = [st.value]
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)):
                heads = [st.value] if st.value else []
            elif isinstance(st, (ast.Expr, ast.Return)):
                heads = [st.value] if st.value else []
            elif isinstance(st, (ast.If, ast.While)):
                heads = [st.test]
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                heads = [st.iter]
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                heads = [i.context_expr for i in st.items]
            for h in heads:
                for n in ast.walk(h):
                    if isinstance(n, ast.Call) and self.llm(n):
                        self.sink(n)
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and NONCE_FN.search(call_name(st.value)):
                self.nonces.update(t.id for t in st.targets if isinstance(t, ast.Name))
            if isinstance(st, ast.Assign):
                t, il = self.tainted(st.value), self.interp_line(st.value)
                fc = isinstance(st.value, ast.Call) and not FENCE_FN.search(last(call_name(st.value))) \
                    and last(call_name(st.value)) in SOURCE_FN | {"collect", "load", "extract", "fetch", "get", "loads"} \
                    or (isinstance(st.value, ast.Call) and not FENCE_FN.search(last(call_name(st.value))) and not self.llm(st.value))
                for tg in st.targets:
                    self.assign(tg, t, il, fc)
                if t and not il and isinstance(st.value, ast.Call) and last(call_name(st.value)) in SOURCE_FN:
                    for tg in st.targets:
                        if isinstance(tg, ast.Name):
                            self.state[tg.id] = "S"  # raw file/upload text
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                self.assign(st.target, self.tainted(st.value), self.interp_line(st.value))
            elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                if self.tainted(st.value):
                    il = self.interp_line(st.value) or (st.lineno if isinstance(st.op, ast.Add) else None)
                    prev = self.state.get(st.target.id)
                    keep = isinstance(prev, int) and not isinstance(prev, bool)
                    self.state[st.target.id] = prev if keep else il
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                self.assign(st.target, self.tainted(st.iter), None)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for i in st.items:
                    if i.optional_vars is not None:
                        self.assign(i.optional_vars, self.tainted(i.context_expr), None)
            elif isinstance(st, ast.Return) and is_builder and st.value is not None:
                if self.tainted(st.value):
                    il = self.interp_line(st.value)
                    if il:
                        self.hits.append((il, f"prompt builder {self.fn.name}() splices untrusted text into the prompt without a fence"))
        return self.hits


HTML_TAGS = set("html head body div span p a b i u em strong td tr th table thead tbody tfoot ul ol li h1 h2 h3 h4 h5 h6 "
                "pre code script style title section article header footer nav main label button option select "
                "textarea small br hr img details summary blockquote dl dt dd caption mark sup sub".split())
WEAK_TAG_RE = re.compile(r"<.{0,12}/.{0,12}[A-Za-z_]{4,}.{0,20}>")


def _weak_neutraliser(tree, rel, src):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = call_name(n)
        pat = None
        if name in {"re.compile", "re.sub", "re.subn", "re.search", "re.findall", "re.match", "re.fullmatch", "compile", "sub"} and n.args \
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
            pat = n.args[0].value
            if WEAK_TAG_RE.search(pat) and "/" in pat and "[^>]" not in pat and r"\b" not in pat and ".*" not in pat:
                out.append((n.lineno, "delimiter neutraliser only matches the bare tag; attribute/whitespace variants such as "
                                      "'</untrusted_input x>' survive and close the trust boundary"))
        elif isinstance(n.func, ast.Attribute) and n.func.attr == "replace" and len(n.args) >= 2 \
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) \
                and re.fullmatch(r"</[A-Za-z_][\w\-]*>", n.args[0].value):
            out.append((n.lineno, f"exact-string neutraliser for {n.args[0].value!r} misses case, whitespace, attribute "
                                  "and unicode-lookalike variants"))
    return out


def _static_delim(tree, scan_states, rel):
    """f-string that frames tainted content with a fixed ``` / <tag> delimiter (content can reproduce it)."""
    out = []
    for fn in functions(tree):
        s = FnScan(fn, False)
        s.run()
        for n in ast.walk(fn) if fn is not tree else []:
            if not isinstance(n, ast.JoinedStr):
                continue
            vals = n.values
            for i, v in enumerate(vals):
                if not (isinstance(v, ast.FormattedValue) and s.tainted(v.value)):
                    continue
                before = "".join(x.value if isinstance(x, ast.Constant) else "" for x in vals[max(0, i - 3):i])
                after = vals[i + 1].value if i + 1 < len(vals) and isinstance(vals[i + 1], ast.Constant) else ""
                m = re.search(r"<\s*/?\s*([A-Za-z_][\w\-]*)[^<]*$", before)
                if m and m.group(1).lower() in HTML_TAGS:
                    continue
                if STATIC_DELIM.search(before.rstrip()) and STATIC_DELIM_AFTER.search(after.lstrip()):
                    out.append((n.lineno, "untrusted content is framed by a fixed delimiter "
                                          f"({before.strip()[-20:]!r}...{after.strip()[:20]!r}) that the content itself can close"))
                    break
    return out


def _wrappers(tree, cli) -> frozenset:
    """Local functions that pass one of their parameters into an LLM call (ask(text) -> messages.create)."""
    out = set()
    for _ in range(2):
        for fn in functions(tree):
            if fn is tree:
                continue
            params = {a.arg for a in fn.args.args + fn.args.kwonlyargs} - {"self", "cls"}
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and is_llm_call(n, cli, frozenset(out)):
                    slot_names = {x.id for a in list(n.args) + [k.value for k in n.keywords if k.arg not in NONPROMPT_KW]
                                  for x in ast.walk(a) if isinstance(x, ast.Name)}
                    if params & slot_names:
                        out.add(fn.name)
    return frozenset(out)


JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
JS_LLM = re.compile(r"\.messages\.create\s*\(|\.chat\.completions\.create\s*\(|\.responses\.create\s*\(|generateText\s*\(|"
                    r"streamText\s*\(|generateContent\s*\(|\.invoke\s*\(|fetch\s*\(\s*[`'\"][^`'\"]*(?:api\.anthropic\.com|api\.openai\.com|/v1/messages|/chat/completions)")
JS_INTERP = re.compile(r"\$\{\s*([A-Za-z_$][\w$.]*)\s*\}")


def _js_hits(ctx):
    out = []
    for p in ctx.files:
        if p.suffix not in JS_EXT or "node_modules" in p.parts or not p.is_file():
            continue
        rel = p.relative_to(ctx.root).as_posix()
        if TEST_JS.search(rel):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(src) > 1_000_000 or not JS_LLM.search(src):
            continue
        for m in re.finditer(r"`[^`]*`", src):
            lit = m.group(0)
            for im in JS_INTERP.finditer(lit):
                expr = im.group(1)
                if re.search(r"fence|untrusted|nonce", lit, re.I):
                    break
                if vocab_untrusted(expr.split(".")[-1]) or vocab_untrusted(expr.split(".")[0]):
                    line = src.count("\n", 0, m.start() + im.start()) + 1
                    out.append((rel, line, f"untrusted value ${{{expr}}} is spliced into an LLM prompt template without a fence",
                                src.splitlines()[line - 1].strip()[:120]))
                    break
    return out


TEST_JS = re.compile(r"(^|/)(tests?|__tests__|fixtures|e2e)/|\.(test|spec)\.[jt]sx?$")


def check(ctx: Context) -> list[Finding]:
    found, seen = [], set()
    for rel, line, msg, ev in _js_hits(ctx):
        found.append(Finding(RULE["id"], RULE["severity"], rel, line, msg[0].upper() + msg[1:] + ".", FIX, ev))
    if not repo_uses_llm(ctx):
        return found
    for rel, src, tree in py_files(ctx):
        cli = "claude" in src.lower() and ('"-p"' in src or "'-p'" in src)
        wrappers = _wrappers(tree, cli)
        hits = []
        for fn in functions(tree):
            hits += FnScan(fn, cli, wrappers).run()
        hits += _static_delim(tree, None, rel)
        hits += _weak_neutraliser(tree, rel, src)
        for line, msg in sorted(hits):
            if (rel, line) in seen:
                continue
            seen.add((rel, line))
            found.append(Finding(RULE["id"], RULE["severity"], rel, line, msg[0].upper() + msg[1:] + ".", FIX,
                                 line_text(src, line)))
    return found
