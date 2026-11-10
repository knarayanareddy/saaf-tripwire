"""TW-LLM2: model output trusted for a verdict/status/control decision without validation or grounding."""
from __future__ import annotations

import ast
import re

from ..model import Context, Finding
from ..util.llmscan import call_name, functions, last, line_text, own_statements, py_files, repo_uses_llm, str_consts
from .llm_unfenced_prompt import is_llm_call

RULE = {
    "id": "TW-LLM2",
    "title": "LLM verdict accepted without validation or quote check",
    "severity": "high",
    "class": "ai-and-llm",
    "why": "A hallucinated or injected 'found: yes' / SUPPORTED / priority 4 / is_ai_system=false from the model "
           "becomes the audit verdict, because nothing checks the value against an allowlist or the source text.",
    "seen_in": ["judging-found-controls", "hallucination-detection-agent", "Compliance-Report-Generator",
                "Vendor_Guard", "SAAF-Project"],
}
VERDICT_KEY = re.compile(r"^(found|verdict|status|approved|approve|decision|risk|risk_rating|rating|priority|passed|pass|"
                         r"compliant|result|match_status|supported|ai_assisted|severity|outcome|is_\w+|has_\w+|requires_\w+)$")
REPLY_PARAM = re.compile(r"^(raw|raw_json|raw_response|raw_text|reply|response_text|model_output|llm_output|completion_text|answer)$")
PARSE_FN = re.compile(r"json|parse|loads|extract", re.I)
VALIDATE_FN = re.compile(r"valid|verify|check_quotes|ground|schema|normali[sz]e|allowlist|whitelist|enforce|coerce|sanit", re.I)
GROUND_KEYS = {"quote", "exact_quote", "quotes", "paragraph", "citation", "citations", "evidence_quote", "SUPPORTED",
               "source_quote", "verbatim"}
GROUND_CHECK = re.compile(r"check_quotes|_check_grounding|verify_quote|_validate_evidence|_enforce_grounding|"
                          r"(quote|paragraph|citation)[^\n#]*\s(not\s+)?in\s[^\n#]*(text|context|source|doc|page|norm)", re.I)
FIX = ("Validate the reply before using it: allowlist enum fields (found in {'yes','no'}), pin fields the agent owns "
       "(ids, priority floor, status), and verify every quoted span with tripwire.fence.check_quotes(); fail closed.")


def _reply_expr(e, cli=False) -> bool:
    if isinstance(e, ast.Call) and is_llm_call(e, cli):
        return True
    # complete(...).strip() / client.messages.create(...).content[0].text
    inner = e
    while isinstance(inner, (ast.Call, ast.Attribute, ast.Subscript)):
        inner = inner.func if isinstance(inner, ast.Call) else inner.value
        if isinstance(inner, ast.Call) and is_llm_call(inner, cli):
            return True
    txt = ast.unparse(e) if isinstance(e, (ast.Attribute, ast.Subscript, ast.Call)) else ""
    return bool(re.search(r"\.content\[0\]\.text|\.choices\[0\]\.message\.content|\.output_text|structured_output", txt))


class Scan:
    def __init__(self, fn, returns_parsed: set[str]):
        self.fn = fn
        self.reply: set[str] = set()
        self.parsed: dict[str, int] = {}
        self.returns_parsed = returns_parsed
        args = getattr(getattr(fn, "args", None), "args", [])
        for a in args:
            if REPLY_PARAM.match(a.arg):
                self.reply.add(a.arg)

    def uses(self, e, names) -> bool:
        return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(e))

    def run(self):
        marker, uses, ret_parsed = False, [], False
        for st in own_statements(self.fn):
            if isinstance(st, ast.Assign):
                v = st.value
                names = [t.id for t in st.targets if isinstance(t, ast.Name)]
                if _reply_expr(v) or (isinstance(v, (ast.Attribute, ast.Subscript, ast.Call)) and self.uses(v, self.reply)
                                      and not (isinstance(v, ast.Call) and PARSE_FN.search(last(call_name(v))))):
                    self.reply.update(names)
                if isinstance(v, ast.Call) and ((PARSE_FN.search(last(call_name(v))) and (self.uses(v, self.reply) or any(_reply_expr(a) for a in v.args)))
                                                or last(call_name(v)) in self.returns_parsed):
                    for nm in names:
                        self.parsed[nm] = v.lineno
                elif self.uses(v, self.parsed):  # evidence = c.get("evidence") or []
                    for nm in names:
                        self.parsed[nm] = v.lineno
            if isinstance(st, (ast.For, ast.AsyncFor)) and self.uses(st.iter, self.parsed):
                tgt = [n.id for n in ast.walk(st.target) if isinstance(n, ast.Name)]
                for nm in tgt:
                    self.parsed[nm] = st.lineno
            heads = [] if not self.parsed else [st]
            if heads and isinstance(st, (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor)):
                heads = [getattr(st, "test", None) or getattr(st, "iter", None)]
            for h in [h for h in heads if h is not None]:
                for n in ast.walk(h):
                    if isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops) \
                            and self.uses(n.left, self.parsed) and isinstance(n.comparators[0], (ast.Set, ast.Tuple, ast.List, ast.Name)) \
                            and (not isinstance(n.comparators[0], ast.Name) or n.comparators[0].id.isupper()):
                        marker = True
                    if isinstance(n, ast.Call) and last(call_name(n)) in {"check_quotes", "verify_quotes"}:
                        marker = True  # tripwire.fence.check_quotes grounding check
                    if isinstance(n, ast.Call) and (VALIDATE_FN.search(last(call_name(n))) or last(call_name(n)) in {"model_validate", "parse_obj", "validate_python"}) \
                            and self.uses(n, self.parsed):
                        marker = True
                    if isinstance(n, ast.Call) and any(k.arg is None and self.uses(k.value, self.parsed) for k in n.keywords):
                        uses.append((n.lineno, f"model JSON is splatted wholesale into {call_name(n)}(**...): every field, "
                                               "including ones the agent should own, is model-controlled"))
                    if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in self.parsed \
                            and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str) and VERDICT_KEY.match(n.slice.value) \
                            and not isinstance(getattr(n, "ctx", None), ast.Store):
                        uses.append((n.lineno, f"model-supplied {n.slice.value!r} is used without an allowlist/grounding check"))
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" \
                            and isinstance(n.func.value, ast.Name) and n.func.value.id in self.parsed and n.args \
                            and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) and VERDICT_KEY.match(n.args[0].value):
                        uses.append((n.lineno, f"model-supplied {n.args[0].value!r} is used without an allowlist/grounding check"))
            if isinstance(st, ast.Return) and st.value is not None and self.uses(st.value, self.parsed):
                ret_parsed = True
                if isinstance(st.value, ast.Name) or (isinstance(st.value, ast.Call) and not schema_arg and PARSE_FN.search(last(call_name(st.value)))):
                    uses.append((st.lineno, "parsed model output is returned as the verdict with no value check"))
            schema_arg = isinstance(getattr(st, "value", None), ast.Call) and any(
                isinstance(x, ast.Name) and x.id[:1].isupper() and not x.id.isupper() for x in st.value.args)
            if isinstance(st, ast.Return) and not schema_arg and isinstance(st.value, ast.Call) and PARSE_FN.search(last(call_name(st.value))) \
                    and (self.uses(st.value, self.reply) or any(_reply_expr(a) for a in st.value.args)):
                ret_parsed = True
                uses.append((st.lineno, "parsed model output is returned as the verdict with no value check"))
        if PARSE_FN.search(getattr(self.fn, "name", "")):  # extract_json()/parse helpers: judge their callers
            uses = [u for u in uses if "returned" not in u[1]]
        return (None if marker else (uses[0] if uses else None)), ret_parsed, bool(self.parsed) or ret_parsed


def check(ctx: Context) -> list[Finding]:
    if not repo_uses_llm(ctx):
        return []
    files = list(py_files(ctx))
    repo_grounded = any(GROUND_CHECK.search(src) for _, src, _ in files)
    found = []
    for rel, src, tree in files:
        returns_parsed: set[str] = set()
        for _ in range(2):  # one level of "this local function returns model JSON"
            for fn in functions(tree):
                if fn is not tree and Scan(fn, returns_parsed).run()[1]:
                    returns_parsed.add(fn.name)
        parse_seen, hits = None, []
        for fn in functions(tree):
            if fn is tree:
                continue
            hit, _, has_parsed = Scan(fn, returns_parsed).run()
            if hit:
                hits.append(hit)
            if has_parsed and parse_seen is None:
                parse_seen = fn.lineno
        consts = set(str_consts(tree))
        if parse_seen and not repo_grounded and consts & GROUND_KEYS:
            hits.append((parse_seen, "verdicts that cite quotes/evidence (" + ", ".join(sorted(consts & GROUND_KEYS))
                         + ") are accepted with no check that the quoted text occurs in the source"))
        for line, msg in sorted(set(hits)):
            found.append(Finding(RULE["id"], RULE["severity"], rel, line, "Unvalidated model output: " + msg + ".", FIX,
                                 line_text(src, line)))
    return found
