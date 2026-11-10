"""TW-OUT2: CSV / Excel written from untrusted strings without neutralising leading = + - @ (formula injection)."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-OUT2",
    "title": "CSV/Excel export without formula neutralisation",
    "severity": "low",
    "class": "client-side",
    "why": "A ticket, vendor or user field starting with = runs as a formula when the auditor opens the export in Excel (data exfiltration via HYPERLINK/WEBSERVICE).",
    "seen_in": ["CUEC_Crosscheck", "Track-2---IAM-final", "joiners-movers-leavers-agent"],
}
FIX = "Prefix any cell that starts with = + - @ tab or CR with a single quote before writing (one helper used by every writer)."
NEUTRAL = re.compile(r"""startswith\(\s*\(?\s*['"][=+\-@]|['"]=['"]\s*,\s*['"][+\-@]|\[=\+\-@|\^\[=|neutrali[sz]|formula|csv_?safe|safe_?cell|"""
                     r"""defuse|escape_csv|sanitize_cell|sanitise_cell""", re.I)
WRITE = re.compile(r"(^|\.)(writerow|writerows|to_csv|to_excel|append|write_row|write_string|write)$")
CSVISH = re.compile(r"csv\.(writer|DictWriter)|\.to_csv\(|\.to_excel\(|openpyxl|xlsxwriter")


def check(ctx: Context) -> list[Finding]:
    out = []
    for p in w.files(ctx, w.PY):
        text = w.read(p)
        if not CSVISH.search(text) or NEUTRAL.search(text) or re.search(r"(^|/)(generate|make|create)_?(sample|demo|fake|synthetic)", w.rel(ctx, p)):
            continue
        tree = w.parse_py(p)
        if not tree:
            continue
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call) or not WRITE.search(w.call_name(n)):
                continue
            nm = w.call_name(n)
            if nm.endswith(("append", "write")) and not re.search(r"\b(ws|sheet|worksheet)\b", nm):
                continue  # list.append / file.write are not spreadsheet writes
            args = n.args[0] if n.args else None
            if args is None and not nm.endswith(("to_csv", "to_excel")):
                continue
            if args is not None and all(isinstance(e, ast.Constant) for e in getattr(args, "elts", [args])):
                continue  # header row
            out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), n.lineno,
                               "Spreadsheet export writes data cells with no formula neutralisation (=, +, -, @).", FIX,
                               w.line_text(text, n.lineno)))
            break
    return out
