"""TW-GATE1: fail-open gates - a validation/compliance/QA gate that only logs on failure, or that
defaults to PASS/APPROVE/Green/MATCH/LOW on missing, unknown or NaN input."""
from __future__ import annotations

import ast
import re

from ..model import Context, Finding
from ..util.llmscan import call_name, functions, last, line_text, own_statements, py_files, str_consts

RULE = {
    "id": "TW-GATE1",
    "title": "Fail-open gate: failure is only logged, or unknown input defaults to PASS",
    "severity": "high",
    "class": "resource-exhaustion",
    "why": "A crafted record (unknown PO, schema violation, NaN amount, AC-1 hidden behind AC-10, low-confidence "
           "hallucination) slips through a gate that logs instead of blocking, and is approved or paid.",
    "seen_in": ["threewaysecurity", "CUEC_Crosscheck", "three-way-match-audit", "Audit-criteria", "SAAF-Project",
                "hallucination-detection-agent"],
}

PASS = {"approve", "approved", "pass", "passed", "green", "match", "matched", "low", "ok", "compliant", "allow",
        "allowed", "go", "voldaan", "supported", "verified", "effective", "accept", "accepted", "clean", "safe",
        "released", "success", "valid"}
BLOCK = {"block", "blocked", "reject", "rejected", "fail", "failed", "deny", "denied", "red", "amber", "high", "medium",
         "mismatch", "no match", "no_match", "escalate", "no-go", "nogo", "flag", "hold", "niet voldaan", "unverified",
         "partial", "ineffective", "critical", "invalid", "error", "abort", "stop", "review", "warning", "not_found"}
FAIL_MSG = re.compile(r"\b(fail(ed|s|ure)?|skipp?(ed|ing)|invalid|mismatch(es)?|violations?|reject(ed|ion)?|unsafe|"
                      r"not (found|valid|verified|accounted)|missing|incomplete|tamper(ed)?)\b", re.I)
LOG_FN = re.compile(r"^(print|warn|warning|error|exception|critical|log|log_event|info|debug|write|echo|secho|"
                    r"st\.warning|st\.error|append)$")
LOG_RECV = re.compile(r"log|logger|logging|warnings|st|console|click|typer|sys\.stderr|security_log|audit_log|stats", re.I)
GATE_CTX = re.compile(r"valid|verif|check|schema|sanitis|sanitiz|guard|gate|secur|complian|integrity|polic|inject|"
                      r"safe|approv|match|audit|control|qa\b|quality", re.I)
GATE_EXC = re.compile(r"Validation|Schema|Security|Injection|Policy|Integrity|Violation|Reject|Tamper|Verification")
VERDICT_WORD = re.compile(r"status|verdict|result|decision|outcome|match|rating|risk|check|approv|found|state", re.I)
ID_KEY = re.compile(r"(^|_)(id|ac|co|code|ref|control|criterion|cuec)$", re.I)
TEXT_NAME = re.compile(r"(text|deviations?|document|section|body|content|markdown|_md|report|output|summary|notes|blob)$", re.I)
FIX = {
    "except": "Fail closed: re-raise, return a BLOCK/REJECT result, or mark the record failed so the next stage cannot approve it.",
    "branch": "Make the failure branch stop the pipeline (raise / exit non-zero / return a blocking verdict), not just log.",
    "default": "Default to the blocking verdict: enumerate the states that may pass and send everything else (unknown, SKIP, missing) to BLOCK/ESCALATE.",
    "get": "Do not default a missing verdict/status to a passing value; treat a missing key as a failure.",
    "nan": "Reject non-finite numbers at parse time (math.isfinite) - NaN makes every 'abs(a-b) > tol' check false.",
    "substr": "Match identifiers as whole tokens (re.search(rf'\\b{re.escape(id)}\\b', text)) or against a parsed set, not with 'in' on raw text.",
}


def _verdict_const(stmts, vocab):
    """String constant assigned/returned by the top-level statements of a branch that lies in vocab."""
    for s in stmts:
        val = None
        if isinstance(s, ast.Return):
            val = s.value
        elif isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], (ast.Name, ast.Subscript, ast.Attribute)):
            val = s.value
        if isinstance(val, ast.Constant) and isinstance(val.value, str) and val.value.strip().lower() in vocab:
            return val.value
        if isinstance(val, ast.Tuple) and val.elts and isinstance(val.elts[0], ast.Constant) \
                and isinstance(val.elts[0].value, str) and val.elts[0].value.strip().lower() in vocab:
            return val.elts[0].value
    return None


def _is_log_stmt(s) -> bool:
    if isinstance(s, ast.Pass):
        return True
    if isinstance(s, ast.AugAssign):  # stats["rejected"] += 1
        return True
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
        name = call_name(s.value)
        tail = last(name)
        recv = name.rsplit(".", 1)[0] if "." in name else ""
        if tail == "print" or (LOG_FN.match(tail) and (LOG_RECV.search(recv) or tail in {"warn", "print"})):
            return tail != "append" or bool(re.search(r"warn|log|note|message", recv, re.I))
    return False


def _log_only(body) -> bool:
    return bool(body) and all(_is_log_stmt(s) for s in body) and any(not isinstance(s, ast.Pass) for s in body) or \
        (len(body) == 1 and isinstance(body[0], ast.Pass))


def _numeric_threshold(test) -> bool:
    if isinstance(test, ast.BoolOp):
        return all(_numeric_threshold(v) for v in test.values)
    if isinstance(test, ast.Compare) and all(isinstance(c, ast.Constant) and isinstance(c.value, (int, float))
                                            and not isinstance(c.value, bool) for c in test.comparators):
        return not (isinstance(test.left, ast.Call) and call_name(test.left) == "len")
    return False


def _chain(node: ast.If):
    """Flatten if/elif/else -> ([(test, body)], else_body)."""
    out, cur = [], node
    while True:
        out.append((cur.test, cur.body))
        if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
            cur = cur.orelse[0]
            continue
        return out, cur.orelse


def check_file(rel, src, tree):
    hits = []  # (line, kind, message)
    elif_nodes = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.If) and len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If):
            elif_nodes.add(id(n.orelse[0]))

    for fn in functions(tree):
        fname = getattr(fn, "name", "")
        stmts = own_statements(fn)
        for st in stmts:
            # (a) except handler that only logs around a gate
            if isinstance(st, ast.Try):
                body_calls = [call_name(c) for b in st.body for c in ast.walk(b) if isinstance(c, ast.Call)]
                gate_body = any(GATE_CTX.search(last(c)) or (last(c)[:1].isupper() and "Schema" in last(c)) for c in body_calls)
                for h in st.handlers:
                    tname = call_name(h.type) if h.type is not None else ""
                    if not (gate_body or GATE_EXC.search(tname or "")):
                        continue
                    approving = [c for c in ast.walk(ast.Module(body=h.body, type_ignores=[])) if isinstance(c, ast.Call)
                                 and isinstance(c.func, ast.Attribute) and c.func.attr in {"append", "add", "extend"}
                                 and re.search(r"approv|pass|accept|good|valid|clean|ok|ready|release|keep", call_name(c.func.value), re.I)]
                    if approving and not any(isinstance(x, ast.Raise) for x in ast.walk(ast.Module(body=h.body, type_ignores=[]))):
                        hits.append((h.lineno, "except", f"gate failure in {fname or 'module'}() is logged and the record is still "
                                     f"added to {call_name(approving[0].func.value)!r}"))
                    elif _log_only(h.body) and not st.orelse:
                        hits.append((h.lineno, "except", f"gate failure in {fname or 'module'}() is caught and only "
                                     "logged/counted; processing continues as if it passed"))
            # (b)/(c) if-chains
            if isinstance(st, ast.If) and id(st) not in elif_nodes:
                chain, else_body = _chain(st)
                for test, body in chain:
                    msgs = " ".join(str_consts(ast.Module(body=body, type_ignores=[])))
                    if _log_only(body) and not all(isinstance(s, ast.Pass) for s in body) and FAIL_MSG.search(msgs) \
                            and not re.search(r"\b(passed|ok)\b", msgs, re.I):
                        hits.append((body[0].lineno, "branch", "failure branch only logs: '" + msgs.strip()[:60] + "'"))
                if else_body:
                    msgs = " ".join(str_consts(ast.Module(body=else_body, type_ignores=[])))
                    if _log_only(else_body) and FAIL_MSG.search(msgs):
                        hits.append((else_body[0].lineno, "branch", "failure branch only logs: '" + msgs.strip()[:60] + "'"))
                blocks = [_verdict_const(b, BLOCK) for _, b in chain]
                if any(blocks) and not all(_numeric_threshold(t) for t, _ in chain):
                    pv = _verdict_const(else_body, PASS) if else_body else None
                    if pv:
                        hits.append((else_body[0].lineno, "default", f"decision chain blocks only on listed states; "
                                     f"anything else (unknown, SKIP, missing) falls to the else branch -> {pv!r}"))
        for st in stmts:
            if isinstance(st, ast.Match):
                blk = any(_verdict_const(c.body, BLOCK) for c in st.cases)
                for c in st.cases:
                    if isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None and c.guard is None:
                        pv = _verdict_const(c.body, PASS)
                        if pv and blk:
                            hits.append((c.body[0].lineno, "default", f"match falls through to 'case _' -> {pv!r}: "
                                         "any unknown or missing state passes"))
        # (c') sequential "if bad: return BLOCK ... return PASS" at function end
        body = getattr(fn, "body", [])
        if fname and body and isinstance(body[-1], ast.Return):
            pv = _verdict_const([body[-1]], PASS)
            guards = [s for s in body[:-1] if isinstance(s, ast.If) and _verdict_const(s.body, BLOCK)
                      and not s.orelse and not _numeric_threshold(s.test)
                      and not re.search(r"\babs\(|tol|toler|threshold|isna|isnan|isnull", ast.unparse(s.test))]
            if pv and guards:
                hits.append((body[-1].lineno, "default", f"{fname}() returns {pv!r} by default once the listed "
                             "failure checks miss - empty or unknown input passes"))

    for n in ast.walk(tree):
        # (d) .get("status", "PASS") / getattr(x, "status", "PASS") / VERDICTS.get(status, "APPROVE")
        kd = None
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and len(n.args) == 2:
            kd = (n.args[0], n.args[1], call_name(n.func.value))
        elif isinstance(n, ast.Call) and call_name(n) == "getattr" and len(n.args) == 3:
            kd = (n.args[1], n.args[2], "")
        if kd:
            k, d, recv = kd
            kname = k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else (ast.unparse(k) if isinstance(k, (ast.Name, ast.Attribute, ast.Subscript)) else "")
            if isinstance(d, ast.Constant) and isinstance(d.value, str) and d.value.strip().lower() in PASS \
                    and (VERDICT_WORD.search(kname) or VERDICT_WORD.search(recv)):
                hits.append((n.lineno, "get", f"missing/unknown {kname!r} defaults to passing value {d.value!r}"))
        if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or) and len(n.values) >= 2:
            d = n.values[-1]
            if isinstance(d, ast.Constant) and isinstance(d.value, str) and d.value.strip().lower() in PASS \
                    and any(VERDICT_WORD.search(ast.unparse(v)) for v in n.values[:-1]):
                hits.append((n.lineno, "get", f"empty/missing verdict falls back to passing value {d.value!r} via 'or'"))
        # (f) identifier substring match against free text
        if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn)):
            left, right = n.left, n.comparators[0]
            lkey = None
            if isinstance(left, ast.Subscript) and isinstance(left.slice, ast.Constant) and isinstance(left.slice.value, str):
                lkey = left.slice.value
            elif isinstance(left, ast.Name):
                lkey = left.id
            elif isinstance(left, ast.Attribute):
                lkey = left.attr
            while isinstance(right, ast.Call) and isinstance(right.func, ast.Attribute) and right.func.attr in {"lower", "upper", "casefold", "strip"}:
                right = right.func.value
            if lkey and ID_KEY.search(lkey) and isinstance(right, ast.Name) and TEXT_NAME.search(right.id) \
                    and not re.search(r"ids$|set$|list$|keys$", right.id):
                hits.append((n.lineno, "substr", f"identifier {lkey!r} is matched as a substring of {right.id!r} "
                             "('AC-1' is found inside 'AC-10')"))

    # (e) NaN: tolerance comparisons with no finiteness check anywhere in the file
    if not re.search(r"isfinite|isnan|isinf|isna|isnull|notna|notnull|math\.inf|allow_nan\s*=\s*False", src):
        absvars = {t.id for a in ast.walk(tree) if isinstance(a, ast.Assign) and isinstance(a.value, ast.Call)
                   and call_name(a.value) == "abs" for t in a.targets if isinstance(t, ast.Name)}
        tol = [n for n in ast.walk(tree) if isinstance(n, ast.Compare) and len(n.ops) == 1
               and isinstance(n.ops[0], (ast.Gt, ast.GtE))
               and ((isinstance(n.left, ast.Call) and call_name(n.left) == "abs") or (isinstance(n.left, ast.Name) and n.left.id in absvars))
               and re.search(r"tol|toler|threshold|margin|eps|max_dev|allowed", ast.unparse(n.comparators[0]), re.I)]
        if tol:
            hits.append((tol[0].lineno, "nan", f"{len(tol)} tolerance check(s) like 'abs(a-b) > tol' with no NaN/inf guard: "
                         "a NaN amount makes every check false and the record matches"))
    return hits


SKIP_PATH = re.compile(r"(^|/)(generators?|mocks?|samples?|seeds?|synthetic)/|(^|/)gen_[^/]*\.py$")
SEV = {"except": "high", "default": "high", "branch": "medium", "get": "medium", "nan": "high", "substr": "high"}


def check(ctx: Context) -> list[Finding]:
    found, seen = [], set()
    for rel, src, tree in py_files(ctx):
        if SKIP_PATH.search(rel):
            continue
        for line, kind, msg in sorted(check_file(rel, src, tree)):
            if (rel, line) in seen:
                continue
            seen.add((rel, line))
            found.append(Finding(RULE["id"], SEV[kind], rel, line, "Fail-open: " + msg + ".", FIX[kind], line_text(src, line)))
    return found
