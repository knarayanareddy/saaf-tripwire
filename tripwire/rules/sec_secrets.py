"""TW-SEC1: secrets in tracked files and in reachable git history. Never emits a secret value (4 chars + length).

Detection layers (all offline, deterministic):
  1. provider-format tokens (Anthropic, OpenAI, GitHub, AWS, Slack, Google, Stripe, Hugging Face, PEM private keys),
     also after joining split string literals ("sk-ant-" + "...") and inside base64 literals;
  2. generic high-entropy assignments to secret-named variables in any text file (.env, .py, .js, YAML, compose,
     shell exports, JSON), with token-based name rules (KEYCLOAK_*_PATH, *_SHA, *_ANON_KEY, AUTH_SCOPES are not secrets);
  3. passwords inside connection URLs (postgres://user:pass@host).
Files are read as UTF-8, or UTF-16 when a BOM/NUL pattern says so. Lines are not truncated.
"""
from __future__ import annotations
import base64, binascii, collections, hashlib, math, re, subprocess
from ..model import Context, Finding
from ..util.gha import files_of, rel

RULE = {
    "id": "TW-SEC1",
    "title": "Credential committed to the repository (tree or git history)",
    "severity": "critical",
    "class": "supply-chain-and-release",
    "why": "Anyone who can read or clone the repo can use a committed key; deleting the file does not remove it from history.",
    "seen_in": ["Team-HighTable", "ExecGRC"],  # SA-03; ExecGRC 22177ad was missed by the audit (see evidence)
}

PEM = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")
PROVIDERS = [
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{32,}")),
    ("openai", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("aws", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("stripe", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{24,}")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
]
QUICK = re.compile(r"sk-|sk_live|rk_live|hf_|gh[pousr]_|github_pat_|AKIA|ASIA|xox|AIza")
B64_LIT = re.compile(r"""["'`]([A-Za-z0-9+/]{40,2048}={0,2})["'`]""")  # keys are short; skip embedded media
CONCAT = re.compile(r"""(["'])\s*(?:\+|\.|\.\.)?\s*\1""")  # "a" + "b", "a" "b", 'a' . 'b'
URL_PW = re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:([^@\s/'\"]{6,})@[^\s'\"]+", re.I)

# generic assignment: NAME = "v" | NAME: v | - NAME=v | export NAME=v | "name": "v"
ASSIGN = re.compile(r"""(?:^|[\s,{(;\-])(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*(?::=|=>|:|=)\s*(["'`]?)([^\s"'`,;)]+)(\2)""")
SECRET_TOK = {"key", "apikey", "secret", "token", "password", "passwd", "pwd", "pat", "credential", "credentials", "privatekey"}
NOT_SECRET_TOK = {"path", "url", "uri", "file", "dir", "endpoint", "sha", "hash", "digest", "checksum", "commit", "id",
                  "name", "public", "anon", "publishable", "scope", "scopes", "header", "alg", "algorithm", "type",
                  "length", "len", "ttl", "expiry", "expires", "max", "min", "count", "region", "version", "prefix",
                  "field", "env", "var", "location", "format", "mode", "size", "limit", "label", "hint"}
LOOSE_EXT = (".env", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".properties", ".toml", ".envrc")
PLACEHOLDER = re.compile(r"x{4,}|X{4,}|\*{3,}|\.\.\.|<[^>]*>|your|example|placeholder|change.?me|dummy|fake|sample|redacted|"
                         r"replace|insert|todo|generate|test|0{6,}|1234|abcdefgh|^pass(word)?$", re.I)
LOOKUP = re.compile(r"os\.environ|os\.getenv|process\.env|import\.meta\.env|\$\{|\$\(|secrets\.|env\(|getenv|\{\{")
WORDY = re.compile(r"[A-Za-z][a-z0-9]*(?:[-_. :][A-Za-z][a-z0-9]*){2,}")  # "change-this-to-something-random", "verander.dit.naar..."
FIXTURE_DIR = re.compile(r"(^|/)(tests?|spec|__tests__)/(.*/)?(fixtures?|testdata|__fixtures__)/|(^|/)fixtures?/")
FIXTURE_MARK = re.compile(r"tripwire:\s*fixture|gitleaks:allow|pragma:\s*allowlist secret|not a real (key|secret)|fake[-_ ]?(key|secret|token)", re.I)
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|e2e)/|(^|/)test_[^/]*$|\.(spec|test)\.[jt]sx?$")
B64_CHARS = re.compile(r"^\s*[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*$")


def is_env_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name.startswith(".env") or name.endswith(".env") or name == ".envrc"


def entropy(v: str) -> float:
    c = collections.Counter(v)
    return -sum(n / len(v) * math.log2(n / len(v)) for n in c.values()) if v else 0.0


def mask(v: str) -> str:
    return f"{v[:4]}… (len {len(v)})"


def _placeholder(v: str) -> bool:
    if PLACEHOLDER.search(v):
        return True
    body = re.sub(r"^(sk-ant-(api\d\d-)?|sk-(proj-)?|gh[pousr]_|github_pat_|AKIA|ASIA|xox.-|AIza|[rs]k_live_|hf_)", "", v)
    return len(set(body)) < 10 or entropy(body) < 3.3


def _name_is_secret(name: str) -> bool:
    toks = [t.lower() for t in re.split(r"[_.\-]|(?<=[a-z])(?=[A-Z])", name) if t]
    joined = "".join(toks)
    secret = bool(set(toks) & SECRET_TOK) or joined.endswith(("apikey", "secretkey", "privatekey", "accesskey"))
    return secret and not (set(toks) & NOT_SECRET_TOK)


def _generic_ok(v: str) -> bool:
    return (len(v) >= 20 and not LOOKUP.search(v) and not _placeholder(v) and not WORDY.fullmatch(v)
            and entropy(v) >= 3.3 and not re.match(r"^(/|\.{1,2}/|~)", v) and "://" not in v
            and not re.fullmatch(r"\d+(\.\d+)*", v))


def _providers(text: str):
    """Provider tokens, found by locating cheap prefixes first and matching only a window around each one
    (keeps multi-MB minified/data-URI lines linear)."""
    done: set[str] = set()
    for q in QUICK.finditer(text):
        lo = max(0, q.start() - 12)
        window = text[lo:q.start() + 400]
        for kind, rx in PROVIDERS:
            for m in rx.finditer(window):
                v = m.group(0)
                if v not in done and not _placeholder(v):
                    done.add(v)
                    yield kind, v


def scan_line(path: str, line: str, nxt: str = ""):
    """Yield (kind, value) for secrets on one line. Values never leave this module unmasked."""
    hits = set()
    joined = CONCAT.sub("", line) if len(line) < 20000 and ("+" in line or '" "' in line or "' '" in line or "." in line) else line
    for variant in {line, joined}:
        for kind, v in _providers(variant):
            if v not in hits and not any(v in h or h in v for h in hits):
                hits.add(v)
                yield kind, v
    if "-----BEGIN" in line:
        for m in PEM.finditer(line):
            rest = line[m.end():]
            if re.match(r"(\\\\n|\\n)[A-Za-z0-9+/=]{20,}", rest) or (rest.strip(" \t'\"`,;)") == "" and B64_CHARS.match(nxt)):
                yield "private-key", m.group(0)
    big = len(line) > 200_000  # data URIs / embedded media: provider prefixes above still run, the costly layers below do not
    for m in (() if big else B64_LIT.finditer(line)):
        try:
            dec = base64.b64decode(m.group(1), validate=True).decode("ascii")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        for kind, v in _providers(dec):
            yield f"{kind} (base64-encoded)", v
    for m in (URL_PW.finditer(line) if "://" in line and not big else ()):
        pw = m.group(1)
        if not LOOKUP.search(pw) and not _placeholder(pw) and entropy(pw) >= 3.3 and len(pw) >= 10:
            yield "url-password", pw
    loose = is_env_file(path) or path.lower().endswith(LOOSE_EXT) or "docker-compose" in path.lower()
    if len(line) < 2000 and ("=" in line or ":" in line):
        for m in ASSIGN.finditer(line):
            name, quote, v = m.group(1), m.group(2), m.group(3)
            if not quote and not loose:
                continue  # in code, only literal strings count (avoids `key = get_key()`)
            if _name_is_secret(name) and _generic_ok(v) and v not in hits and not any(rx.search(v) for _, rx in PROVIDERS):
                hits.add(v)
                yield "secret-assignment", v


def _fixture(path: str, line: str, text_head: str) -> bool:
    return bool(FIXTURE_DIR.search(path)) and bool(FIXTURE_MARK.search(line) or FIXTURE_MARK.search(text_head))


def _severity(kind: str, v: str, path: str, line: str, head: str, history: bool) -> str:
    provider = kind not in ("secret-assignment", "url-password")
    if not provider:
        # a fixture marker (or a test file) is believable only for generic values; a real-shaped provider key is a key
        if _fixture(path, line, head):
            return "info"
        if TEST_PATH.search(path):
            return "medium"
    return "high" if history or not provider else "critical"


def _fp(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def read_text(data: bytes) -> str | None:
    """UTF-8, or UTF-16 (BOM or interleaved NULs); None for binary."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    head = data[:8192]
    if b"\0" in head:
        if len(head) > 16 and head[1::2].count(0) > len(head) * 0.4:
            return data.decode("utf-16-le", errors="replace")
        if len(head) > 16 and head[0::2].count(0) > len(head) * 0.4:
            return data.decode("utf-16-be", errors="replace")
        return None
    return data.decode("utf-8", errors="replace")


def check(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for p in files_of(ctx):
        r = rel(ctx, p)
        try:
            text = read_text(p.read_bytes())
        except OSError:
            continue
        if text is None:
            continue
        head = text[:2000]
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            nxt = lines[i] if i < len(lines) else ""
            for kind, v in scan_line(r, line, nxt):
                fp = _fp(v)
                if fp in seen and kind == "secret-assignment":
                    continue
                seen.add(fp)
                sev = _severity(kind, v, r, line, head, False)
                findings.append(Finding(
                    RULE["id"], sev, r, i,
                    f"{kind} credential in the current tree" + (" (marked as test fixture)" if sev == "info" else ""),
                    "Rotate the key at the provider now, move it to a secret store / untracked .env, then purge history (git filter-repo).",
                    f"{kind}: {mask(v)}"))
    if ctx.history and (ctx.root / ".git").exists():
        findings.extend(_history(ctx, seen))
    return findings


def _history(ctx: Context, seen: set[str]) -> list[Finding]:
    try:
        out = subprocess.run(
            ["git", "-C", str(ctx.root), "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
             "--no-renames", "--format=%x00commit %H"],
            capture_output=True, text=True, errors="replace", timeout=60).stdout
    except Exception:
        return []
    found: dict[str, Finding] = {}
    commit, path = "", ""
    lines = out.splitlines()
    # git log is newest-first; keep overwriting so the oldest (introducing) commit wins.
    for idx, line in enumerate(lines):
        if line.startswith("\0commit "):
            commit = line[8:].strip()
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("+") and path and not line.startswith("+++"):
            nxt = lines[idx + 1][1:] if idx + 1 < len(lines) and lines[idx + 1].startswith("+") else ""
            for kind, v in scan_line(path, line[1:], nxt):
                fp = _fp(v)
                if fp in seen:
                    continue  # already reported at HEAD; history adds nothing
                sev = _severity(kind, v, path, line, "", True)
                found[fp] = Finding(
                    RULE["id"], sev, path, 0,
                    f"{kind} credential reachable in git history (commit {commit[:7]}, {path}); removed from the tree but still cloneable",
                    "Rotate the key at the provider (purging history alone is not enough), then git filter-repo --path "
                    f"{path} --invert-paths and force-push.",
                    f"{kind}: {mask(v)} @ {commit[:7]}")
    return list(found.values())
