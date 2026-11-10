"""TW-FS1: walking a scanned/uploaded tree follows symlinks, or upload filenames are joined into paths unsanitised."""
from __future__ import annotations
import ast, re
from ..model import Context, Finding
from ..util import webscan as w

RULE = {
    "id": "TW-FS1",
    "title": "Tree walk follows symlinks / upload filename path traversal",
    "severity": "medium",
    "class": "data-isolation",
    "why": "A scanned repo or upload with a symlink to ~/.ssh or ../../ makes the tool read operator files and ship them to the LLM or the caller.",
    "seen_in": ["llm_owasp", "agent-rogue-risk-assessor", "agent-drift-rater", "OWASP-top-10-LLM-assessment"],
}
FIX = "Skip symlinks (p.is_symlink()/os.path.islink) and check p.resolve().is_relative_to(root) before reading; pass upload names through secure_filename / Path(name).name."
GUARD = re.compile(r"is_symlink\(|islink\(|\.lstat\(|S_ISLNK|is_relative_to\(|commonpath\(|realpath\(|O_NOFOLLOW|resolve\(\)\s*\.relative_to\(")
READ = re.compile(r"\.read_text\(|\.read_bytes\(|\bopen\(|shutil\.copy")
SAFE_NAME = re.compile(r"secure_filename|basename|\.name\b|sanitize|sanitise|uuid")


def _walks(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            nm = w.call_name(n)
            kws = {k.arg: k.value for k in n.keywords}
            if nm.endswith("walk") and "followlinks" in kws and getattr(kws["followlinks"], "value", False) is True:
                yield n, "os.walk(followlinks=True)", True
            elif nm.endswith(("rglob", "os.walk")) or nm == "walk" or \
                    (nm.endswith("glob") and (getattr(kws.get("recursive"), "value", False) is True or
                                              any(isinstance(a, ast.Constant) and "**" in str(a.value) for a in n.args))):
                yield n, nm, False


def check(ctx: Context) -> list[Finding]:
    out = []
    for p in w.files(ctx, w.PY):
        tree = w.parse_py(p)
        if not tree:
            continue
        text = w.read(p)
        guarded = bool(GUARD.search(text))
        if READ.search(text):
            for n, what, always in _walks(tree):
                if always or not guarded:
                    out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), n.lineno,
                                       f"{what} walks a tree and files are read with no symlink / stay-inside-root check.", FIX,
                                       w.line_text(text, n.lineno)))
                    break
        for n in ast.walk(tree):  # upload.filename joined into a path
            if isinstance(n, ast.Call) and (w.call_name(n).endswith(("path.join", "save", "open")) or w.call_name(n) in ("Path", "open")):
                for a in n.args:
                    s = w.src(a, text)
                    if re.search(r"\.filename\b", s) and not SAFE_NAME.search(s):
                        out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), n.lineno,
                                           "Upload filename used in a filesystem path without secure_filename / basename.", FIX,
                                           w.line_text(text, n.lineno)))
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div) and re.search(r"\.filename\b", w.src(n.right, text)) \
                    and not SAFE_NAME.search(w.src(n.right, text)):
                out.append(Finding(RULE["id"], RULE["severity"], w.rel(ctx, p), n.lineno,
                                   "Upload filename joined into a path without secure_filename / Path(name).name.", FIX,
                                   w.line_text(text, n.lineno)))
    return out
